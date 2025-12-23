// CLI encrypted group chat client with PGP-based challenge/response login.
// Auth: Username + PGP key (server stores public key). Login via encrypted nonce challenge.
// Chat crypto (after login/join): X25519 (per rekey) -> HKDF-SHA256 -> AES-256-GCM, counter nonces, AAD bound to protocol/session/sender/counter.
// No keys or messages written to disk.

const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');
const WebSocket = require('ws');
const openpgp = require('openpgp');

const protocolVersion = 'v1';
const color = {
  reset: '\x1b[0m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  gray: '\x1b[90m',
  magenta: '\x1b[35m',
};
const paint = (code, text) => `${code}${text}${color.reset}`;
const label = (text) => paint(color.cyan, text);
const val = (text) => paint(color.green, text);
const muted = (text) => paint(color.gray, text);
const warn = (text) => paint(color.yellow, text);
const err = (text) => paint(color.red, text);

const args = parseArgs(process.argv.slice(2));
const autoGenerate = args.generate === true || args.gen === true;

let serverUrl = args.server;
let sessionId = args.session;
let passphrase = args.passphrase || '';
let nickname = sanitizeNick(args.nick || args.nickname || '');
let username = args.user || args.username || '';
let publicKeyId = args.keyid || args.key || '';
let registerPath = args.register || '';
let registerKeyArmored = null;
let authed = false;
let joined = false;
let pendingChallengeId = null;

let currentEpoch = 1;
let identity = generateIdentity();
let groupKey = null;
let messageCounter = 0;
let noncePrefix = crypto.randomBytes(4);

// senderId -> { publicKey: KeyObject, epoch: number, nickname?: string }
let peers = new Map();
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
let ws = null;
let shutdownRequested = false;

bootstrap().catch((e) => {
  console.error(err('fatal error'), e.message);
  process.exit(1);
});

async function bootstrap() {
  if (!serverUrl) {
    serverUrl = await promptWithDefault(label('server'), 'ws://localhost:6969', false);
  }
  serverUrl = normalizeServer(serverUrl);
  if (!username) {
    username = await promptWithDefault(label('username'), '', true);
  }
  if (!sessionId) {
    if (autoGenerate) {
      sessionId = generateSessionId();
      console.log(`${label('generated session_id')}: ${val(sessionId)}`);
    } else {
      sessionId = await promptWithDefault(`${label('session_id')} (type "gen" to generate)`, '', true, true);
    }
  }
  if (!args.passphrase) {
    if (autoGenerate) {
      passphrase = generatePassphrase();
      console.log(`${label('generated passphrase')}: ${val(passphrase)}`);
    } else {
      passphrase = await promptWithDefault(`${label('passphrase')} (optional, type "gen" to create one)`, '', false, true);
    }
  }
  if (!nickname) {
    nickname = sanitizeNick(await promptWithDefault(`${label('nickname')} (optional)`, '', false));
  }
  if (!nickname && username) {
    nickname = sanitizeNick(username);
  }

  if (!registerPath) {
    registerPath = await promptWithDefault(`${label('path to public key for registration')} (optional)`, '', false);
  }
  if (registerPath) {
    try {
      registerKeyArmored = fs.readFileSync(registerPath, 'utf8');
      publicKeyId = publicKeyId || await deriveKeyId(registerKeyArmored);
      console.log(`${label('register pubkey')} from ${registerPath}, key id ${val(publicKeyId)}`);
    } catch (e) {
      console.log(warn(`could not read pubkey at ${registerPath}: ${e.message}`));
    }
  }

  if (!publicKeyId) {
    publicKeyId = await promptWithDefault(label('public key id / fingerprint'), '', true);
  }

  connect();
}

function connect() {
  ws = new WebSocket(serverUrl);

  ws.on('open', async () => {
    printLine(`${label('connected')} ${val(serverUrl)}, user ${val(username)}, session ${val(sessionId)}`);
    // Optional register before login.
    if (registerKeyArmored) {
      safeSend({ type: 'register', username, key_id: publicKeyId, public_key: registerKeyArmored });
    } else {
      safeSend({ type: 'login-init', username, key_id: publicKeyId });
    }
  });

  ws.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }
    handleMessage(msg).catch((e) => console.error(err('client error'), e.message));
  });

  ws.on('close', () => {
    printLine(warn('disconnected from relay'));
    if (shutdownRequested) process.exit(0);
    holdForExit();
  });

  ws.on('error', (e) => {
    printLine(`${err('relay error')} ${e.message}`);
  });

  rl.on('line', (line) => {
    if (!authed || !joined) {
      printLine(warn('not logged in / joined yet'));
      return;
    }
    if (!groupKey) {
      printLine(warn('group key not ready, wait for peers to rekey'));
      return;
    }
    sendEncrypted(line.trim());
  });

  process.on('SIGINT', () => {
    console.log('\n' + warn('exiting'));
    shutdownRequested = true;
    if (ws) ws.close();
    rl.close();
  });
}

async function handleMessage(msg) {
  switch (msg.type) {
    case 'register-ok':
      printLine(val(`public key registered for ${msg.username}`));
      safeSend({ type: 'login-init', username, key_id: publicKeyId });
      break;
    case 'error':
      printLine(err(msg.message || 'server error'));
      break;
    case 'login-challenge':
      await handleLoginChallenge(msg);
      break;
    case 'login-success':
      authed = true;
      printLine(val(`login success for ${msg.username}`));
      safeSend({ type: 'join', session_id: sessionId });
      break;
    case 'joined':
      joined = true;
      printLine(val(`joined session ${msg.session_id}`));
      renderChatUi();
      startRekey('login');
      break;
    case 'peer-joined':
      printLine(muted(`peer joined ${msg.session_id || ''}`));
      startRekey('peer-joined');
      break;
    case 'peer-left':
      printLine(warn('peer left, rekeying'));
      startRekey('peer-left');
      break;
    case 'announce':
      handleAnnounce(msg);
      break;
    case 'ciphertext':
      handleCiphertext(msg);
      break;
    default:
      break;
  }
}

async function handleLoginChallenge(msg) {
  pendingChallengeId = msg.challenge_id;
  printLine(label('PGP challenge received'));
  printLine(muted('Decrypt the following armored message with your private key and paste the plaintext nonce below:'));
  printLine(msg.armored);
  const response = await promptWithDefault(label('decrypted challenge (paste exact plaintext)'), '', true);
  safeSend({ type: 'login-response', challenge_id: pendingChallengeId, response });
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

function sanitizeNick(raw) {
  if (!raw || typeof raw !== 'string') return '';
  const trimmed = raw.trim().slice(0, 32);
  return /^[\x20-\x7E]+$/.test(trimmed) ? trimmed : '';
}

function promptWithDefault(promptLabel, defaultValue, required, allowGenerate = false) {
  const suffix = defaultValue ? ` [${defaultValue}]` : '';
  return new Promise((resolve) => {
    rl.question(`${promptLabel}${suffix ? ' ' + muted(suffix) : ''}: `, (answer) => {
      const trimmed = answer.trim();
      if (allowGenerate && trimmed.toLowerCase() === 'gen') {
        const generated = promptLabel.toLowerCase().includes('session') ? generateSessionId() : generatePassphrase();
        console.log(`${promptLabel} ${val(generated)}`);
        return resolve(generated);
      }
      const resolved = trimmed || defaultValue;
      if (required && !resolved) {
        console.log(warn('value required'));
        resolve(promptWithDefault(promptLabel, defaultValue, required, allowGenerate));
      } else {
        resolve(resolved);
      }
    });
  });
}

function generateSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

function generatePassphrase() {
  return crypto.randomBytes(24).toString('base64');
}

function holdForExit() {
  rl.question('Press Enter to exit...', () => {
    process.exit(0);
  });
}

function generateIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const senderId = crypto.createHash('sha256').update(publicDer).digest('hex').slice(0, 16);
  return { publicKey, privateKey, publicDer, senderId };
}

async function deriveKeyId(armored) {
  const key = await openpgp.readKey({ armoredKey: armored });
  return key.getFingerprint();
}

function startRekey(reason, targetEpoch) {
  const nextEpoch = typeof targetEpoch === 'number' && targetEpoch > currentEpoch
    ? targetEpoch
    : currentEpoch + 1;
  currentEpoch = nextEpoch;
  groupKey = null;
  peers = new Map();
  identity = generateIdentity();
  noncePrefix = crypto.randomBytes(4);
  messageCounter = 0;
  printLine(`${label('[rekey]')} ${reason} -> epoch ${val(currentEpoch)}, sender ${val(identity.senderId)}`);
  sendAnnounce(reason);
}

function sendAnnounce(reason) {
  const frame = {
    type: 'announce',
    session_id: sessionId,
    public_key: identity.publicDer.toString('base64'),
    epoch: currentEpoch,
    reason,
    nickname,
    username,
  };
  safeSend(frame);
}

function handleAnnounce(msg) {
  const { public_key: publicKeyB64, epoch = 1, reason = 'announce', nickname: peerNick = '' } = msg;
  const publicDer = Buffer.from(publicKeyB64, 'base64');
  const peerId = senderIdFromPublic(publicDer);
  if (peerId === identity.senderId) return;

  const peerKeyObj = crypto.createPublicKey({ key: publicDer, format: 'der', type: 'spki' });
  const known = peers.get(peerId);
  const peerEpoch = Number.isFinite(epoch) ? epoch : 1;

  if (peerEpoch > currentEpoch) {
    startRekey('adopt-peer-epoch', peerEpoch);
  } else if (peerEpoch < currentEpoch) {
    // Ask lagging peer to catch up.
    sendAnnounce('epoch-ahead');
  }

  peers.set(peerId, { publicKey: peerKeyObj, epoch: peerEpoch, nickname: sanitizeNick(peerNick) });
  deriveGroupKey();
}

function handlePeerLeft() {
  printLine(warn('peer left, rekeying'));
  startRekey('peer-left');
}

function deriveGroupKey() {
  const activePeers = [...peers.values()].filter((p) => p.epoch === currentEpoch);
  if (activePeers.length === 0) return;

  const secrets = activePeers.map((peer) => crypto.diffieHellman({
    privateKey: identity.privateKey,
    publicKey: peer.publicKey,
  }));
  secrets.sort(Buffer.compare);

  const inputMaterial = Buffer.concat(secrets);
  const salt = crypto.createHash('sha256')
    .update(`${sessionId}|${passphrase}`)
    .digest();
  const info = Buffer.concat([Buffer.from('group-key'), Buffer.from(sessionId)]);
  groupKey = Buffer.from(crypto.hkdfSync('sha256', salt, inputMaterial, info, 32));
  messageCounter = 0;

  const safetyCode = crypto.createHash('sha256').update(groupKey).digest('hex').slice(0, 16);
  printLine(`${label('[key]')} epoch ${val(currentEpoch)} ready. safety code ${val(safetyCode)}`);
}

function sendEncrypted(plaintext) {
  const counter = messageCounter;
  messageCounter += 1;

  const nonce = Buffer.alloc(12);
  noncePrefix.copy(nonce, 0);
  nonce.writeBigUInt64BE(BigInt(counter), 4);

  const aad = buildAad(identity.senderId, counter);

  const cipher = crypto.createCipheriv('aes-256-gcm', groupKey, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  const frame = {
    type: 'ciphertext',
    session_id: sessionId,
    sender_id: identity.senderId,
    epoch: currentEpoch,
    counter,
    nonce: nonce.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };

  safeSend(frame);
}

function handleCiphertext(msg) {
  if (!groupKey) return;
  if (msg.epoch !== currentEpoch) {
    printLine(muted('received message for different epoch, ignoring'));
    return;
  }
  const peer = peers.get(msg.sender_id);
  if (!peer || peer.epoch !== currentEpoch) {
    printLine(warn('unknown sender, request rekey'));
    return;
  }

  try {
    const nonce = Buffer.from(msg.nonce, 'base64');
    const tag = Buffer.from(msg.tag, 'base64');
    const ciphertext = Buffer.from(msg.ciphertext, 'base64');
    const aad = buildAad(msg.sender_id, msg.counter);

    const decipher = crypto.createDecipheriv('aes-256-gcm', groupKey, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    const displayLabel = peer.nickname ? `${msg.sender_id}|${peer.nickname}` : msg.sender_id;
    printLine(`${displayLabel ? paint(color.magenta, displayLabel) : ''}${displayLabel ? ' ' : ''}${plaintext}`);
  } catch {
    printLine(warn('failed to decrypt/authenticate message, rekey recommended'));
  }
}

function buildAad(senderId, counter) {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  return Buffer.concat([
    Buffer.from(protocolVersion),
    Buffer.from(sessionId),
    Buffer.from(senderId, 'hex'),
    counterBuf,
  ]);
}

function senderIdFromPublic(publicDer) {
  return crypto.createHash('sha256').update(publicDer).digest('hex').slice(0, 16);
}

function safeSend(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  } else {
    printLine(err('not connected'));
  }
}

function renderChatUi() {
  const pad = (text = '') => `│ ${text}`;
  const header = `╭──────────────── chat ${val(sessionId)} ────────────────`;
  printLine(header);
  printLine(pad(`user: ${username}  nick: ${nickname || username}`));
  printLine(pad(`server: ${serverUrl}`));
  printLine(pad('type to send; CTRL+C to exit'));
  printLine('╰─>');
  rl.setPrompt('╰─> ');
  rl.prompt();
}

function printLine(text) {
  console.log(text);
  if (joined) {
    rl.prompt();
  }
}
function normalizeServer(url) {
  if (!url) return url;
  if (url.startsWith('ws://') || url.startsWith('wss://')) return url;
  return `ws://${url}`;
}
