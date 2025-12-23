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

// username -> { keyId, publicKeyArmored, publicKeyObj }
const users = new Map();
// challengeId -> { username, nonce, ws }
const challenges = new Map();
// sessionId -> Set<WebSocket>
const sessions = new Map();

const server = http.createServer((req, res) => {
  if (req.url === HEALTH_PATH) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', users: users.size }));
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
          return safeSend(ws, { type: 'register-ok', username });
        }
        case 'login-init': {
          const { username } = payload;
          if (!username || !users.has(username)) {
            console.warn(`login-init unknown user=${username} from ${clientAddr}`);
            return safeSend(ws, { type: 'error', message: 'unknown user' });
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
          return safeSend(ws, { type: 'login-success', username: record.username });
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
          console.log(`relay ${type} from ${ws.authedUser} in session ${sessionId}`);
          for (const peer of peers) {
            if (peer !== ws && peer.readyState === WebSocket.OPEN) {
              safeSend(peer, payload);
            }
          }
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

server.listen(PORT, () => {
  console.log(`relay listening on :${PORT} (health at ${HEALTH_PATH})`);
});
