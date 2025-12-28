// WebSocket server with OpenPGP challenge-response auth and relay-only messaging.
// - Stores public keys in memory (username -> public key + key id/fingerprint).
// - Performs login via PGP-encrypted nonce challenge.
// - After login, clients join a session and relay messages (no plaintext inspection).

const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const WebSocket = require('ws');
const openpgp = require('openpgp');
const selfsigned = require('selfsigned');

const PORT = process.env.PORT || 6969;
const HEALTH_PATH = '/health';
const SERVER_VERSION = '1.1.0';
const MIN_CLIENT_VERSION = process.env.MIN_CLIENT_VERSION || '';
const DEBUG_FRAMES = process.env.DEBUG_FRAMES === '1' || process.env.DEBUG_FRAMES === 'true';
const DEBUG_CIPHERTEXT = process.env.DEBUG_CIPHERTEXT === '1' || process.env.DEBUG_CIPHERTEXT === 'true';
const RELAY_URL = process.env.RELAY_URL || '';
const RELAY_PEERS = (process.env.RELAY_PEERS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const RELAY_SEEDS_URL = process.env.RELAY_SEEDS_URL || '';
const parsePositiveInt = (value, fallback) => {
  const num = Number.parseInt(value, 10);
  return Number.isFinite(num) && num > 0 ? num : fallback;
};
const parseNonNegativeInt = (value, fallback) => {
  const num = Number.parseInt(value, 10);
  return Number.isFinite(num) && num >= 0 ? num : fallback;
};
const RELAY_SAMPLE_SIZE = parsePositiveInt(process.env.RELAY_SAMPLE_SIZE || '3', 3);
const RELAY_SHARED_SECRET = process.env.RELAY_SHARED_SECRET || '';
const RELAY_ID = crypto.randomUUID();
const CHALLENGE_TTL_MS = parsePositiveInt(process.env.CHALLENGE_TTL_MS, 5 * 60 * 1000);
const CHALLENGE_MAX = parseNonNegativeInt(process.env.CHALLENGE_MAX, 200);
const SEEN_MESSAGES_MAX = parsePositiveInt(process.env.SEEN_MESSAGES_MAX, 5000);
const CHALLENGE_SWEEP_MS = Math.min(CHALLENGE_TTL_MS, 60000);
const RATE_LIMIT_WINDOW_MS = parsePositiveInt(process.env.RATE_LIMIT_WINDOW_MS, 60000);
const RATE_LIMIT_REGISTER = parsePositiveInt(process.env.RATE_LIMIT_REGISTER, 20);
const RATE_LIMIT_LOGIN_INIT = parsePositiveInt(process.env.RATE_LIMIT_LOGIN_INIT, 60);
const RATE_LIMIT_SWEEP_MS = Math.min(RATE_LIMIT_WINDOW_MS * 2, 5 * 60 * 1000);
const TLS_KEY_PATH = process.env.TLS_KEY_PATH || '';
const TLS_CERT_PATH = process.env.TLS_CERT_PATH || '';
const TLS_CA_PATH = process.env.TLS_CA_PATH || '';
const TLS_ENABLED = Boolean(TLS_KEY_PATH && TLS_CERT_PATH);
const TLS_INSECURE_SELF_SIGNED = process.env.TLS_INSECURE_SELF_SIGNED === '1' || process.env.TLS_INSECURE_SELF_SIGNED === 'true';
const WS_INSECURE_SKIP_VERIFY = process.env.WS_INSECURE_SKIP_VERIFY === '1' || process.env.WS_INSECURE_SKIP_VERIFY === 'true';
const RELAY_DISABLE_SEEDS = process.env.RELAY_DISABLE_SEEDS === '1' || process.env.RELAY_DISABLE_SEEDS === 'true';
const RELAY_BACKOFF_BASE_MS = parsePositiveInt(process.env.RELAY_BACKOFF_BASE_MS, 15000);
const RELAY_BACKOFF_MAX_MS = parsePositiveInt(process.env.RELAY_BACKOFF_MAX_MS, 5 * 60 * 1000);
const MAX_PAYLOAD_BYTES = parsePositiveInt(process.env.MAX_PAYLOAD_BYTES, 51200);
const MAX_CONNECTIONS_PER_IP = parsePositiveInt(process.env.MAX_CONNECTIONS_PER_IP, 200);

// username -> { keyId, publicKeyArmored, publicKeyObj }
const users = new Map();
// challengeId -> { username, nonce, ws }
const challenges = new Map();
// sessionId -> Set<WebSocket>
const sessions = new Map();
// relayId -> { id, url, ws, lastSeen }
const relays = new Map();
// url -> lastSeen
const knownRelayUrls = new Map();
// url -> { attempts, nextRetry }
const relayFailures = new Map();
// msgId -> timestamp (for loop prevention)
const seenMessages = new Map();
// ip -> { windowStart, counts: Map<bucket, count> }
const rateLimits = new Map();
// ip -> count (open connections)
const connectionCounts = new Map();

const requestHandler = (req, res) => {
  if (req.url === HEALTH_PATH) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      users: users.size,
      relay_id: RELAY_ID,
      relay_url: RELAY_URL,
      known_relays: knownRelayUrls.size + (RELAY_URL ? 1 : 0),
      connected_relays: relays.size,
      pending_challenges: challenges.size,
      seen_messages: seenMessages.size,
    }));
    return;
  }
  if (req.url === '/directory') {
    const urls = new Set();
    if (RELAY_URL) urls.add(RELAY_URL);
    for (const url of knownRelayUrls.keys()) urls.add(url);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ relays: [...urls] }));
    return;
  }
  res.writeHead(404);
  res.end();
};

let server;
if (TLS_ENABLED || TLS_INSECURE_SELF_SIGNED) {
  let options;
  if (TLS_ENABLED) {
    options = {
      key: fs.readFileSync(TLS_KEY_PATH),
      cert: fs.readFileSync(TLS_CERT_PATH),
    };
    if (TLS_CA_PATH) {
      options.ca = fs.readFileSync(TLS_CA_PATH);
    }
  } else if (TLS_INSECURE_SELF_SIGNED) {
    const cert = selfsigned.generate([{ name: 'commonName', value: 'localhost' }], { days: 365, keySize: 2048 });
    options = { key: cert.private, cert: cert.cert, ca: cert.public };
    console.warn('TLS self-signed mode enabled (TLS_INSECURE_SELF_SIGNED). Use for local testing only.');
  }
  server = https.createServer(options, requestHandler);
  console.log('TLS enabled (wss).');
} else {
  server = http.createServer(requestHandler);
}

const wss = new WebSocket.Server({
  server,
  maxPayload: MAX_PAYLOAD_BYTES,
  perMessageDeflate: false,
});

const heartbeat = (ws) => {
  ws.isAlive = true;
};

const safeSend = (ws, obj) => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
};

const debugFrame = (payload) => {
  if (!DEBUG_FRAMES) return;
  if (payload.type === 'ciphertext' && DEBUG_CIPHERTEXT) {
    console.log('[debug] ciphertext meta', {
      msg_id: payload.msg_id,
      session_id: payload.session_id,
      sender_id: payload.sender_id,
      epoch: payload.epoch,
      counter: payload.counter,
      ciphertext_len: payload.ciphertext ? payload.ciphertext.length : 0,
      tag_len: payload.tag ? payload.tag.length : 0,
    });
    return;
  }
  console.log('[debug]', payload.type, {
    session_id: payload.session_id,
    sender_id: payload.sender_id,
    epoch: payload.epoch,
    counter: payload.counter,
  });
};

const checkRateLimit = (ip, bucket, limit) => {
  if (!ip || !limit || !RATE_LIMIT_WINDOW_MS) return true;
  const now = Date.now();
  let record = rateLimits.get(ip);
  if (!record || now - record.windowStart > RATE_LIMIT_WINDOW_MS) {
    record = { windowStart: now, counts: new Map() };
  }
  const used = record.counts.get(bucket) || 0;
  if (used >= limit) return false;
  record.counts.set(bucket, used + 1);
  rateLimits.set(ip, record);
  return true;
};

const incrementConnection = (ip) => {
  if (!ip) return true;
  const current = connectionCounts.get(ip) || 0;
  if (MAX_CONNECTIONS_PER_IP && current >= MAX_CONNECTIONS_PER_IP) return false;
  connectionCounts.set(ip, current + 1);
  return true;
};

const decrementConnection = (ip) => {
  if (!ip) return;
  const current = connectionCounts.get(ip) || 0;
  if (current <= 1) {
    connectionCounts.delete(ip);
  } else {
    connectionCounts.set(ip, current - 1);
  }
};

const compareVersions = (a, b) => {
  const pa = String(a).split('.').map((n) => parseInt(n, 10));
  const pb = String(b).split('.').map((n) => parseInt(n, 10));
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const av = Number.isFinite(pa[i]) ? pa[i] : 0;
    const bv = Number.isFinite(pb[i]) ? pb[i] : 0;
    if (av > bv) return 1;
    if (av < bv) return -1;
  }
  return 0;
};

const trackRelay = (relayId, url, ws) => {
  if (!relayId) return;
  if (url) knownRelayUrls.set(url, Date.now());
  relays.set(relayId, { id: relayId, url, ws, lastSeen: Date.now() });
};

const rememberRelayUrl = (url) => {
  if (!url || url === RELAY_URL) return;
  knownRelayUrls.set(url, Date.now());
};

const markRelayFailure = (url) => {
  if (!url) return;
  const current = relayFailures.get(url) || { attempts: 0, nextRetry: Date.now() };
  const attempts = current.attempts + 1;
  const backoff = Math.min(RELAY_BACKOFF_MAX_MS, RELAY_BACKOFF_BASE_MS * (2 ** (attempts - 1)));
  relayFailures.set(url, { attempts, nextRetry: Date.now() + backoff });
};

const clearRelayFailure = (url) => {
  if (!url) return;
  relayFailures.delete(url);
};

const canRetryRelay = (url) => {
  if (!url) return false;
  const entry = relayFailures.get(url);
  if (!entry) return true;
  return Date.now() >= entry.nextRetry;
};

const markSeen = (msgId) => {
  if (!msgId) return false;
  if (seenMessages.has(msgId)) return true;
  seenMessages.set(msgId, Date.now());
  enforceSeenLimit();
  return false;
};

const isAsciiSafe = (str) => typeof str === 'string' && /^[\x20-\x7E]+$/.test(str);
const isValidUsername = (username) => {
  if (!isAsciiSafe(username)) return false;
  const trimmed = username.trim();
  return trimmed.length > 0 && trimmed.length <= 64;
};
const isValidSessionId = (sessionId) => {
  if (!isAsciiSafe(sessionId)) return false;
  const trimmed = sessionId.trim();
  return trimmed.length > 0 && trimmed.length <= 128;
};
const isValidPublicKey = (armored) => {
  if (typeof armored !== 'string') return false;
  const len = armored.length;
  return len > 0 && len <= 10000;
};

const signRelayHello = (relayId) => {
  if (!RELAY_SHARED_SECRET || !relayId) return '';
  return crypto.createHmac('sha256', RELAY_SHARED_SECRET).update(relayId).digest('hex');
};

const isRelayAuthValid = (relayId, auth) => {
  if (!RELAY_SHARED_SECRET) return true;
  if (!relayId || !auth) return false;
  return signRelayHello(relayId) === auth;
};

const forwardToRelays = (payload, originRelayId) => {
  const msgId = crypto.randomUUID();
  seenMessages.set(msgId, Date.now());
  enforceSeenLimit();
  const frame = {
    type: 'relay-forward',
    msg_id: msgId,
    origin: originRelayId || RELAY_ID,
    payload,
  };
  for (const relay of relays.values()) {
    if (relay.ws && relay.ws.readyState === WebSocket.OPEN) {
      safeSend(relay.ws, frame);
    }
  }
};

async function encryptForUser(username, plaintext) {
  const entry = users.get(username);
  if (!entry) throw new Error('user-not-found');

  if (!entry.publicKeyObj) {
    entry.publicKeyObj = await openpgp.readKey({ armoredKey: entry.publicKeyArmored });
  }

  const message = await openpgp.createMessage({ text: plaintext });
  return openpgp.encrypt({
    message,
    encryptionKeys: entry.publicKeyObj,
  });
}

wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  ws.authedUser = null;
  ws.sessionId = null;
  ws.challengeId = null;
  ws.isRelay = false;
  const clientAddr = req.socket.remoteAddress;
  if (!incrementConnection(clientAddr)) {
    console.warn(`connection limit exceeded for ${clientAddr}`);
    safeSend(ws, { type: 'error', message: 'too many connections from this IP' });
    ws.close();
    return;
  }
  console.log(`connection from ${clientAddr}`);

  ws.on('pong', () => heartbeat(ws));

  ws.on('message', async (raw) => {
    let payload;
    try {
      payload = JSON.parse(raw.toString());
    } catch {
      return;
    }

    const { type } = payload || {};
    if (!type) return;

    try {
      switch (type) {
        case 'register': {
          const { username, public_key: publicKeyArmored, key_id: keyId } = payload;
          if (!checkRateLimit(clientAddr, 'register', RATE_LIMIT_REGISTER)) {
            console.warn(`register rate-limited from ${clientAddr}`);
            return safeSend(ws, { type: 'error', message: 'rate limit exceeded, try later' });
          }
          if (!username || !publicKeyArmored) {
            console.warn(`register missing data from ${clientAddr}`);
            return safeSend(ws, { type: 'error', message: 'username and public_key required' });
          }
          if (!isValidUsername(username) || !isValidPublicKey(publicKeyArmored)) {
            console.warn(`register invalid input from ${clientAddr}`);
            return safeSend(ws, { type: 'error', message: 'invalid username or public_key' });
          }
          users.set(username, { keyId: keyId || null, publicKeyArmored, publicKeyObj: null });
          console.log(`registered user ${username} key ${keyId || 'n/a'}`);
          forwardToRelays({ type: 'register-sync', username, public_key: publicKeyArmored, key_id: keyId || null });
          return safeSend(ws, { type: 'register-ok', username });
        }
        case 'register-sync': {
          if (!ws.isRelay) return;
          const { username, public_key: publicKeyArmored, key_id: keyId } = payload;
          if (!username || !publicKeyArmored) return;
          users.set(username, { keyId: keyId || null, publicKeyArmored, publicKeyObj: null });
          return;
        }
        case 'login-init': {
          const { username, client_version: clientVersion } = payload;
          if (!checkRateLimit(clientAddr, 'login-init', RATE_LIMIT_LOGIN_INIT)) {
            console.warn(`login-init rate-limited from ${clientAddr}`);
            return safeSend(ws, { type: 'error', message: 'rate limit exceeded, try later' });
          }
          if (!isValidUsername(username)) {
            console.warn(`login-init invalid username from ${clientAddr}`);
            return safeSend(ws, { type: 'error', message: 'invalid username' });
          }
          if (!username || !users.has(username)) {
            console.warn(`login-init unknown user=${username} from ${clientAddr}`);
            return safeSend(ws, { type: 'error', message: 'unknown user' });
          }
          if (challenges.size >= CHALLENGE_MAX) {
            console.warn(`login-init rejected: too many pending challenges (${challenges.size})`);
            return safeSend(ws, { type: 'error', message: 'too many pending challenges, try again shortly' });
          }
          if (MIN_CLIENT_VERSION && compareVersions(clientVersion || '0.0.0', MIN_CLIENT_VERSION) < 0) {
            console.warn(`login-init rejected client ${clientVersion} < ${MIN_CLIENT_VERSION}`);
            return safeSend(ws, { type: 'error', message: 'client version not allowed' });
          }
          const nonce = crypto.randomBytes(24).toString('base64');
          const challengeId = crypto.randomUUID();
          challenges.set(challengeId, { username, nonce, ws, createdAt: Date.now() });
          const armored = await encryptForUser(username, nonce);
          ws.challengeId = challengeId;
          console.log(`login challenge for ${username}`);
          return safeSend(ws, {
            type: 'login-challenge',
            challenge_id: challengeId,
            username,
            armored,
            key_id: users.get(username).keyId || null,
          });
        }
        case 'login-response': {
          const { challenge_id: challengeId, response } = payload;
          if (!challengeId || !challenges.has(challengeId)) {
            console.warn(`login-response invalid challenge from ${clientAddr}`);
            return safeSend(ws, { type: 'error', message: 'invalid challenge' });
          }
          const record = challenges.get(challengeId);
          if (record.createdAt && Date.now() - record.createdAt > CHALLENGE_TTL_MS) {
            challenges.delete(challengeId);
            console.warn(`login-response expired for ${record.username}`);
            return safeSend(ws, { type: 'error', message: 'challenge expired, retry login' });
          }
          if (record.ws !== ws) {
            console.warn(`login-response mismatch socket for ${record.username}`);
            return safeSend(ws, { type: 'error', message: 'challenge mismatch' });
          }
          if (record.nonce !== response) {
            console.warn(`login-response failed for ${record.username}`);
            return safeSend(ws, { type: 'error', message: 'challenge verification failed' });
          }
          ws.authedUser = record.username;
          challenges.delete(challengeId);
          console.log(`login success for ${record.username}`);
          return safeSend(ws, { type: 'login-success', username: record.username, server_version: SERVER_VERSION });
        }
        case 'join': {
          if (!ws.authedUser) return safeSend(ws, { type: 'error', message: 'unauthenticated' });
          const { session_id: sessionId } = payload;
          if (!sessionId) return safeSend(ws, { type: 'error', message: 'session_id required' });
          if (!isValidSessionId(sessionId)) return safeSend(ws, { type: 'error', message: 'invalid session_id' });

          // Clean up prior session membership if any.
          if (ws.sessionId && sessions.has(ws.sessionId)) {
            sessions.get(ws.sessionId).delete(ws);
          }

          ws.sessionId = sessionId;
          const peers = sessions.get(sessionId) || new Set();
          peers.add(ws);
          sessions.set(sessionId, peers);
          safeSend(ws, { type: 'joined', session_id: sessionId });
          console.log(`user ${ws.authedUser} joined session ${sessionId}`);

          // Inform others someone joined (clients decide how to react).
          for (const peer of peers) {
            if (peer !== ws && peer.readyState === WebSocket.OPEN) {
              safeSend(peer, { type: 'peer-joined', session_id: sessionId, username: ws.authedUser });
            }
          }
          forwardToRelays({ type: 'peer-joined', session_id: sessionId, username: ws.authedUser });
          return;
        }
        case 'relay-hello': {
      const { relay_id: relayId, relay_url: relayUrl } = payload;
      if (!isRelayAuthValid(relayId, payload.auth)) {
        console.warn(`relay auth failed for ${relayId || 'unknown'} from ${clientAddr}`);
        ws.close();
        return;
      }
      ws.isRelay = true;
      trackRelay(relayId, relayUrl, ws);
      console.log(`relay hello from ${relayId} ${relayUrl || ''}`);
          // Share our directory list.
          const urls = new Set();
          if (RELAY_URL) urls.add(RELAY_URL);
          for (const url of knownRelayUrls.keys()) urls.add(url);
          safeSend(ws, { type: 'relay-list', relays: [...urls] });
          return;
        }
        case 'relay-list': {
          if (!ws.isRelay) return;
          const { relays: list } = payload;
          if (Array.isArray(list)) {
            for (const url of list) {
              rememberRelayUrl(url);
            }
          }
          return;
        }
        case 'relay-forward': {
          if (!ws.isRelay) return;
          const { msg_id: msgId, origin, payload: inner } = payload;
          if (origin === RELAY_ID) return;
          if (markSeen(msgId)) return;
          if (!inner || !inner.type) return;
          // Deliver to local clients if applicable.
          if (inner.session_id) {
            const peers = sessions.get(inner.session_id);
            if (peers) {
              for (const peer of peers) {
                if (peer.readyState === WebSocket.OPEN) {
                  safeSend(peer, inner);
                }
              }
            }
          }
          // Forward to other relays (except origin).
          const forward = {
            type: 'relay-forward',
            msg_id: msgId,
            origin,
            payload: inner,
          };
          for (const relay of relays.values()) {
            if (relay.ws && relay.ws.readyState === WebSocket.OPEN && relay.ws !== ws && relay.id !== origin) {
              safeSend(relay.ws, forward);
            }
          }
          return;
        }
        case 'announce':
        case 'ciphertext':
        case 'signal': {
          if (!ws.authedUser || !ws.sessionId) return safeSend(ws, { type: 'error', message: 'unauthenticated or not joined' });
          const sessionId = payload.session_id;
          if (!sessionId || sessionId !== ws.sessionId) return;
          const peers = sessions.get(sessionId);
          if (!peers) return;
          debugFrame(payload);
          console.log(`relay ${type} from ${ws.authedUser} in session ${sessionId}`);
          for (const peer of peers) {
            if (peer !== ws && peer.readyState === WebSocket.OPEN) {
              safeSend(peer, payload);
            }
          }
          forwardToRelays(payload);
          return;
        }
        default:
          return safeSend(ws, { type: 'error', message: `unknown type: ${type}` });
      }
    } catch (err) {
      console.error(`handler error for ${type}:`, err);
      return safeSend(ws, { type: 'error', message: err.message || 'server error' });
    }
  });

  ws.on('close', () => {
    if (ws.isRelay) {
      for (const [relayId, relay] of relays.entries()) {
        if (relay.ws === ws) {
          relays.delete(relayId);
          break;
        }
      }
    }
    // Remove pending challenge.
    if (ws.challengeId && challenges.has(ws.challengeId)) {
      challenges.delete(ws.challengeId);
    }

    // Remove from session.
    const sessionId = ws.sessionId;
    if (sessionId && sessions.has(sessionId)) {
      const peers = sessions.get(sessionId);
      peers.delete(ws);
      console.log(`disconnect ${ws.authedUser || clientAddr} from session ${sessionId}`);
      const notice = { type: 'peer-left', session_id: sessionId, username: ws.authedUser };
      for (const peer of peers) {
        if (peer.readyState === WebSocket.OPEN) {
          safeSend(peer, notice);
        }
      }
      forwardToRelays(notice);
      if (peers.size === 0) sessions.delete(sessionId);
    }
    decrementConnection(clientAddr);
  });
});

// Simple liveness checks to avoid stale sockets.
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => clearInterval(interval));

// Prune stale challenges to avoid leaks and replay windows.
setInterval(() => {
  const now = Date.now();
  for (const [id, record] of challenges.entries()) {
    if (now - (record.createdAt || 0) > CHALLENGE_TTL_MS) {
      challenges.delete(id);
      if (record.ws) {
        safeSend(record.ws, { type: 'error', message: 'challenge expired' });
      }
    }
  }
}, CHALLENGE_SWEEP_MS);

// Prune rate limit buckets to avoid unbounded growth.
setInterval(() => {
  sweepRateLimits();
}, RATE_LIMIT_SWEEP_MS);

// Prune seen message ids to avoid unbounded memory.
setInterval(() => {
  const now = Date.now();
  for (const [msgId, ts] of seenMessages.entries()) {
    if (now - ts > 60000) seenMessages.delete(msgId);
  }
  enforceSeenLimit();
}, 30000);

server.listen(PORT, () => {
  const proto = TLS_ENABLED ? 'https/wss' : 'http/ws';
  console.log(`relay listening on ${proto} :${PORT} (health at ${HEALTH_PATH})`);
});

// Connect to peers and discover others.
const connectToRelay = (url) => {
  if (!url || url === RELAY_URL) return;
  if ([...relays.values()].some((r) => r.url === url)) return;
  if (!canRetryRelay(url)) return;
  const options = {
    perMessageDeflate: false,
    maxPayload: MAX_PAYLOAD_BYTES,
  };
  if (WS_INSECURE_SKIP_VERIFY) {
    options.rejectUnauthorized = false;
  }
  const ws = new WebSocket(url, options);
  ws.on('open', () => {
    ws.isRelay = true;
    clearRelayFailure(url);
    safeSend(ws, { type: 'relay-hello', relay_id: RELAY_ID, relay_url: RELAY_URL, auth: signRelayHello(RELAY_ID) });
  });
  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (msg.type === 'relay-hello') {
      const { relay_id: relayId, relay_url: relayUrl, auth } = msg;
      if (!isRelayAuthValid(relayId, auth)) {
        console.warn(`relay auth failed from ${url}`);
        ws.close();
        return;
      }
      trackRelay(relayId, relayUrl, ws);
      return;
    }
    if (msg.type === 'relay-list' && Array.isArray(msg.relays)) {
      for (const relayUrl of msg.relays) {
        rememberRelayUrl(relayUrl);
      }
      return;
    }
    if (msg.type === 'relay-forward') {
      const { msg_id: msgId, origin, payload } = msg;
      if (origin === RELAY_ID) return;
      if (markSeen(msgId)) return;
      if (!payload || !payload.type) return;
      if (payload.session_id) {
        const peers = sessions.get(payload.session_id);
        if (peers) {
          for (const peer of peers) {
            if (peer.readyState === WebSocket.OPEN) {
              safeSend(peer, payload);
            }
          }
        }
      }
      for (const relay of relays.values()) {
        if (relay.ws && relay.ws.readyState === WebSocket.OPEN && relay.ws !== ws && relay.id !== origin) {
          safeSend(relay.ws, msg);
        }
      }
      return;
    }
  });
  ws.on('close', () => {
    for (const [relayId, relay] of relays.entries()) {
      if (relay.ws === ws) relays.delete(relayId);
    }
    markRelayFailure(url);
  });
  ws.on('error', (err) => {
    console.warn(`relay connection error ${url}: ${err.message}`);
    markRelayFailure(url);
  });
};

const fetchRelayList = async () => {
  if (!RELAY_SEEDS_URL || RELAY_DISABLE_SEEDS) return [];
  try {
    const res = await fetch(RELAY_SEEDS_URL);
    if (!res.ok) return [];
    const json = await res.json();
    return Array.isArray(json.relays) ? json.relays : [];
  } catch {
    return [];
  }
};

const pickRandom = (list, count) => {
  const copy = [...list];
  const out = [];
  while (copy.length > 0 && out.length < count) {
    const idx = Math.floor(Math.random() * copy.length);
    out.push(copy.splice(idx, 1)[0]);
  }
  return out;
};

const refreshRelayPeers = async () => {
  const list = await fetchRelayList();
  for (const url of list) rememberRelayUrl(url);
  const targets = pickRandom(list, RELAY_SAMPLE_SIZE);
  for (const url of targets) connectToRelay(url);
};

// Seed connections on boot.
for (const peer of RELAY_PEERS) {
  connectToRelay(peer);
  rememberRelayUrl(peer);
}
refreshRelayPeers();

// Periodically try to connect to discovered relays.
setInterval(() => {
  for (const url of knownRelayUrls.keys()) {
    connectToRelay(url);
  }
}, 15000);

// Periodically resample peers from relay list (keeps mesh sparse).
setInterval(() => {
  refreshRelayPeers();
}, 60000);

// Trim memory for seen messages if limits are exceeded.
function enforceSeenLimit() {
  if (seenMessages.size <= SEEN_MESSAGES_MAX) return;
  const excess = seenMessages.size - SEEN_MESSAGES_MAX;
  let removed = 0;
  for (const key of seenMessages.keys()) {
    seenMessages.delete(key);
    removed += 1;
    if (removed >= excess) break;
  }
}

function sweepRateLimits() {
  if (rateLimits.size === 0) return;
  const now = Date.now();
  for (const [ip, record] of rateLimits.entries()) {
    if (!record || now - (record.windowStart || 0) > RATE_LIMIT_WINDOW_MS * 2) {
      rateLimits.delete(ip);
    }
  }
}
