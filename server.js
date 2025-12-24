// WebSocket server with OpenPGP challenge-response auth and relay-only messaging.
// - Stores public keys in memory (username -> public key + key id/fingerprint).
// - Performs login via PGP-encrypted nonce challenge.
// - After login, clients join a session and relay messages (no plaintext inspection).

const http = require('http');
const crypto = require('crypto');
const WebSocket = require('ws');
const openpgp = require('openpgp');

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
const RELAY_SAMPLE_SIZE = Number.parseInt(process.env.RELAY_SAMPLE_SIZE || '3', 10);
const RELAY_ID = crypto.randomUUID();

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
// msgId -> timestamp (for loop prevention)
const seenMessages = new Map();

const server = http.createServer((req, res) => {
  if (req.url === HEALTH_PATH) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      users: users.size,
      relay_id: RELAY_ID,
      relay_url: RELAY_URL,
      known_relays: knownRelayUrls.size + (RELAY_URL ? 1 : 0),
      connected_relays: relays.size,
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
});

const wss = new WebSocket.Server({ server });

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
    console.log('[debug] ciphertext', JSON.stringify({
      msg_id: payload.msg_id,
      session_id: payload.session_id,
      sender_id: payload.sender_id,
      epoch: payload.epoch,
      counter: payload.counter,
      nonce: payload.nonce,
      tag: payload.tag,
      ciphertext: payload.ciphertext,
    }));
    return;
  }
  console.log('[debug]', payload.type, {
    session_id: payload.session_id,
    sender_id: payload.sender_id,
    epoch: payload.epoch,
    counter: payload.counter,
  });
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

const markSeen = (msgId) => {
  if (!msgId) return false;
  if (seenMessages.has(msgId)) return true;
  seenMessages.set(msgId, Date.now());
  return false;
};

const forwardToRelays = (payload, originRelayId) => {
  const msgId = crypto.randomUUID();
  seenMessages.set(msgId, Date.now());
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
          if (!username || !publicKeyArmored) {
            console.warn(`register missing data from ${clientAddr}`);
            return safeSend(ws, { type: 'error', message: 'username and public_key required' });
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
          if (!username || !users.has(username)) {
            console.warn(`login-init unknown user=${username} from ${clientAddr}`);
            return safeSend(ws, { type: 'error', message: 'unknown user' });
          }
          if (MIN_CLIENT_VERSION && compareVersions(clientVersion || '0.0.0', MIN_CLIENT_VERSION) < 0) {
            console.warn(`login-init rejected client ${clientVersion} < ${MIN_CLIENT_VERSION}`);
            return safeSend(ws, { type: 'error', message: 'client version not allowed' });
          }
          const nonce = crypto.randomBytes(24).toString('base64');
          const challengeId = crypto.randomUUID();
          challenges.set(challengeId, { username, nonce, ws });
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

// Prune seen message ids to avoid unbounded memory.
setInterval(() => {
  const now = Date.now();
  for (const [msgId, ts] of seenMessages.entries()) {
    if (now - ts > 60000) seenMessages.delete(msgId);
  }
}, 30000);

server.listen(PORT, () => {
  console.log(`relay listening on :${PORT} (health at ${HEALTH_PATH})`);
});

// Connect to peers and discover others.
const connectToRelay = (url) => {
  if (!url || url === RELAY_URL) return;
  if ([...relays.values()].some((r) => r.url === url)) return;

  const ws = new WebSocket(url);
  ws.on('open', () => {
    ws.isRelay = true;
    safeSend(ws, { type: 'relay-hello', relay_id: RELAY_ID, relay_url: RELAY_URL });
  });
  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (msg.type === 'relay-hello') {
      const { relay_id: relayId, relay_url: relayUrl } = msg;
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
  });
  ws.on('error', () => {});
};

const fetchRelayList = async () => {
  if (!RELAY_SEEDS_URL) return [];
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
