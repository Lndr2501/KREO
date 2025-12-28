// Dev client: auto-generates PGP + X25519 identity, registers, logins, joins, and sends a demo ciphertext.
// Usage: node dev-client.js --server ws://localhost:6969 --user alice --session demo --nick "Alice" --message "hi"
// Defaults: random user/session/nick, empty passphrase, auto message "hello from dev-client".

const crypto = require('crypto');
const readline = require('readline');
const WebSocket = require('ws');
const openpgp = require('openpgp');

const args = parseArgs(process.argv.slice(2));
const serverUrl = normalizeWs(args.server || process.env.DEV_SERVER || 'ws://localhost:6969');
const username = args.user || args.username || `dev-${randHex(4)}`;
const sessionId = args.session || args.session_id || `sess-${randHex(6)}`;
const nickname = args.nick || args.nickname || username;
const passphrase = args.passphrase || '';
const clientVersion = 'dev-1.0.0';
const minParticipants = Number.parseInt(args.min_participants || '1', 10) || 1;

let ws;
let pgpKeys = null;
let groupKey = null;
let currentEpoch = 1;
let messageCounter = 0;
let identity = generateIdentity();
const peers = new Map(); // senderId -> { publicDer, epoch }
const seen = new Set();
let rl;
let inputBound = false;
let reconnectAttempts = 0;
let shuttingDown = false;
let groupReady = false;

bootstrap().catch((e) => {
  console.error('[fatal]', e);
  process.exit(1);
});

async function bootstrap() {
  console.log(`[dev-client] server=${serverUrl} user=${username} session=${sessionId}`);
  pgpKeys = await generatePgpKey(username);
  connect();
}

function connect() {
  ws = new WebSocket(serverUrl);
  ws.on('open', onOpen);
  ws.on('message', onMessage);
  ws.on('close', () => {
    if (shuttingDown) return;
    console.warn('[dev-client] disconnected, reconnecting...');
    scheduleReconnect();
  });
  ws.on('error', (err) => {
    console.error('[dev-client] error', err.message);
    if (err.message && err.message.includes('ECONNREFUSED')) {
      scheduleReconnect();
    }
  });
}

async function onOpen() {
  reconnectAttempts = 0;
  console.log('[dev-client] connected, registering pubkey');
  send({ type: 'register', username, key_id: pgpKeys.fingerprint, public_key: pgpKeys.publicKey });
}

async function onMessage(raw) {
  let msg;
  try {
    msg = JSON.parse(raw.toString());
  } catch {
    return;
  }
  switch (msg.type) {
    case 'register-ok':
      console.log('[dev-client] register-ok, starting login');
      send({ type: 'login-init', username, client_version: clientVersion });
      break;
    case 'login-challenge': {
      console.log('[dev-client] challenge received, decrypting');
      const nonce = await decryptArmored(msg.armored, pgpKeys.privateKey);
      send({ type: 'login-response', challenge_id: msg.challenge_id, response: nonce });
      break;
    }
    case 'login-success':
      console.log('[dev-client] login-success, joining session');
      send({ type: 'join', session_id: sessionId });
      break;
    case 'joined':
      console.log('[dev-client] joined session', msg.session_id);
      announce('join');
      bindInput();
      break;
    case 'peer-joined':
      console.log('[dev-client] peer-joined', msg.username || '');
      // Re-announce to help late peers derive the key.
      announce('peer-joined');
      break;
    case 'announce':
      handleAnnounce(msg);
      break;
    case 'ciphertext':
      handleCiphertext(msg);
      break;
    case 'error':
      console.warn('[dev-client] error', msg.message);
      break;
    default:
      break;
  }
}

function announce(reason = 'announce') {
  const frame = {
    type: 'announce',
    session_id: sessionId,
    public_key: identity.publicDer.toString('base64'),
    epoch: currentEpoch,
    reason,
    nickname,
    username,
  };
  send(frame);
  deriveGroupKey();
}

function handleAnnounce(msg) {
  const der = Buffer.from(msg.public_key, 'base64');
  const peerId = senderIdFromPublic(der);
  if (peerId === identity.senderId) return;
  peers.set(peerId, { publicDer: der, epoch: msg.epoch || 1 });
  deriveGroupKey();
}

function deriveGroupKey() {
  const activePeers = [...peers.entries()].filter(([, p]) => p.epoch === currentEpoch);
  const participants = [
    { senderId: identity.senderId, publicDer: identity.publicDer },
    ...activePeers.map(([id, p]) => ({ senderId: id, publicDer: p.publicDer })),
  ].sort((a, b) => a.senderId.localeCompare(b.senderId));
  if (participants.length === 0) return;
  groupKey = deriveKey(participants, sessionId, passphrase, currentEpoch);
  messageCounter = 0;
  console.log('[dev-client] group key ready with', participants.length, 'participants');
  groupReady = participants.length >= minParticipants;
}

function handleCiphertext(msg) {
  if (!groupKey) {
    console.warn('[dev-client] no group key, skipping ciphertext');
    return;
  }
  if (!peers.has(msg.sender_id)) {
    console.warn('[dev-client] unknown sender, requesting announce');
    announce('need-announce');
    return;
  }
  if (seen.has(msg.msg_id)) return;
  seen.add(msg.msg_id);
  try {
    const nonce = Buffer.from(msg.nonce, 'base64');
    const tag = Buffer.from(msg.tag, 'base64');
    const cipher = Buffer.from(msg.ciphertext, 'base64');
    const aad = buildAad(sessionId, msg.sender_id, msg.counter);
    const decipher = crypto.createDecipheriv('aes-256-gcm', groupKey, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(cipher), decipher.final()]).toString('utf8');
    console.log(`[dev-client] received from ${msg.sender_id}: ${plaintext}`);
  } catch (err) {
    console.warn('[dev-client] failed to decrypt', err.message);
  }
}

function bindInput() {
  if (inputBound) return;
  inputBound = true;
  rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  console.log('[dev-client] type messages to send (CTRL+C to exit)');
  rl.setPrompt('> ');
  rl.prompt();
  rl.on('line', (line) => {
    const text = line.trim();
    if (!text) {
      rl.prompt();
      return;
    }
    sendPlaintext(text);
    rl.prompt();
  });
  rl.on('SIGINT', () => {
    console.log('\n[dev-client] exiting');
    shuttingDown = true;
    if (ws) ws.close();
    process.exit(0);
  });
}

function sendPlaintext(text) {
  if (!groupKey || !groupReady) {
    console.warn('[dev-client] waiting for group key/participants');
    return;
  }
  const frame = encryptFrame(identity, groupKey, sessionId, text, currentEpoch, messageCounter);
  messageCounter += 1;
  send(frame);
  console.log('[dev-client] sent');
}

function scheduleReconnect() {
  reconnectAttempts += 1;
  const delay = Math.min(15000, 1000 * reconnectAttempts);
  setTimeout(() => {
    if (shuttingDown) return;
    console.log(`[dev-client] reconnecting (attempt ${reconnectAttempts})...`);
    connect();
  }, delay);
}

// Helpers
function send(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function randHex(n) {
  return crypto.randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.replace(/^--/, '');
      const next = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true;
      out[key] = next;
      if (next === argv[i + 1]) i += 1;
    }
  }
  return out;
}

function normalizeWs(url) {
  if (!url) return url;
  if (url.startsWith('ws://') || url.startsWith('wss://')) return url;
  return `ws://${url}`;
}

async function generatePgpKey(name) {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'rsa',
    rsaBits: 2048,
    userIDs: [{ name }],
  });
  const publicKeyObj = await openpgp.readKey({ armoredKey: publicKey });
  return { privateKey, publicKey, fingerprint: publicKeyObj.getFingerprint() };
}

async function decryptArmored(armored, privateKey) {
  const privKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKey });
  const message = await openpgp.readMessage({ armoredMessage: armored });
  const { data } = await openpgp.decrypt({ message, decryptionKeys: privKeyObj });
  return data;
}

function generateIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const senderId = senderIdFromPublic(publicDer);
  const noncePrefix = crypto.randomBytes(4);
  return { publicKey, privateKey, publicDer, senderId, noncePrefix };
}

function senderIdFromPublic(publicDer) {
  return crypto.createHash('sha256').update(publicDer).digest('hex').slice(0, 16);
}

function deriveKey(participants, sessionId, pass, epoch) {
  const inputMaterial = Buffer.concat(participants.map((p) => p.publicDer));
  const salt = crypto.createHash('sha256').update(`${sessionId}|${pass}|${epoch}`).digest();
  const info = Buffer.concat([Buffer.from('group-key'), Buffer.from(sessionId)]);
  return Buffer.from(crypto.hkdfSync('sha256', salt, inputMaterial, info, 32));
}

function buildAad(sessionId, senderId, counter) {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  return Buffer.concat([Buffer.from('v1'), Buffer.from(sessionId), Buffer.from(senderId, 'hex'), counterBuf]);
}

function encryptFrame(id, key, sessionId, plaintext, epoch, counter) {
  const nonce = Buffer.alloc(12);
  id.noncePrefix.copy(nonce, 0);
  nonce.writeBigUInt64BE(BigInt(counter), 4);
  const aad = buildAad(sessionId, id.senderId, counter);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    type: 'ciphertext',
    msg_id: crypto.randomUUID(),
    session_id: sessionId,
    sender_id: id.senderId,
    epoch,
    counter,
    nonce: nonce.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}
