// CLI encrypted group chat client with PGP-based challenge/response login.
// Auth: Username + PGP key (server stores public key). Login via encrypted nonce challenge.
// Chat crypto (after login/join): X25519 (per rekey) -> HKDF-SHA256 -> AES-256-GCM, counter nonces, AAD bound to protocol/session/sender/counter.
// No keys or messages written to disk.

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const readline = require('readline');
const WebSocket = require('ws');
const openpgp = require('openpgp');

const protocolVersion = 'v1';
const clientVersion = '1.0.0';
const PROMPT = '> ';
const INPUT_DIVIDER = '==============================';
const BANNER = [
  ' /$$   /$$       /$$$$$$$        /$$$$$$$$        /$$$$$$ ',
  '| $$  /$$/      | $$__  $$      | $$_____/       /$$__  $$',
  '| $$ /$$/       | $$  \\ $$      | $$            | $$  \\ $$',
  '| $$$$$/        | $$$$$$$/      | $$$$$         | $$  | $$',
  '| $$  $$        | $$__  $$      | $$__/         | $$  | $$',
  '| $$\\  $$       | $$  \\ $$      | $$            | $$  | $$',
  '| $$ \\  $$      | $$  | $$      | $$$$$$$$      |  $$$$$$/',
  '|__/  \\__/      |__/  |__/      |________/       \\______/ ',
  '                                                          ',
  '                                                          ',
  '                                                          ',
];
const color = {
  reset: '\x1b[0m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  gray: '\x1b[90m',
  magenta: '\x1b[35m',
  blue: '\x1b[34m',
};
const paint = (code, text) => `${code}${text}${color.reset}`;
const label = (text) => paint(color.cyan, text);
const val = (text) => paint(color.green, text);
const muted = (text) => paint(color.gray, text);
const warn = (text) => paint(color.yellow, text);
const err = (text) => paint(color.red, text);

const args = parseArgs(process.argv.slice(2));
const autoGenerate = args.generate === true || args.gen === true;
const defaultRelayList = 'https://raw.githubusercontent.com/Lndr2501/KREO-Relays/refs/heads/main/relays.json';
const relayListUrls = (process.env.KREO_RELAYS_URL || defaultRelayList)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const seedList = (process.env.KREO_SEEDS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

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

// senderId -> { publicKey: KeyObject, publicDer: Buffer, epoch: number, nickname?: string }
let peers = new Map();
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
let ws = null;
let shutdownRequested = false;
let reconnectAttempts = 0;
let totalReconnects = 0;
let entryRelay = '';
let connectedRelay = '';
let uiActive = false;
let headerLines = [];
const logBuffer = [];
const MAX_LOG_LINES = 200;
const seenCipher = new Map();
const MAX_SEEN = 500;
let handlersBound = false;
let showEncrypted = false;
let lastServerVersion = '';
let lastSafetyCode = '';

bootstrap().catch((e) => {
  console.error(err('fatal error'), e.message);
  process.exit(1);
});

async function bootstrap() {
  for (const line of BANNER) {
    printLine(paint(color.blue, line));
  }
  if (!serverUrl) {
    const discovered = await discoverServerFromList();
    if (discovered) {
      serverUrl = discovered;
      printLine(`${label('discovery')} picked ${val(serverUrl)}`);
    } else {
      serverUrl = await promptWithDefault(label('server'), 'ws://localhost:6969', false);
    }
  }
  serverUrl = normalizeServer(serverUrl);
  if (!username) {
    username = await promptWithDefault(label('username'), '', true);
  }
  if (!sessionId) {
    if (autoGenerate) {
      sessionId = generateSessionId();
      printLine(`${label('generated session_id')}: ${val(sessionId)}`);
    } else {
      sessionId = await promptWithDefault(`${label('session_id')} (type "gen" to generate)`, '', true, true);
    }
  }
  if (!args.passphrase) {
    if (autoGenerate) {
      passphrase = generatePassphrase();
      printLine(`${label('generated passphrase')}: ${val(passphrase)}`);
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
      printLine(`${label('register pubkey')} from ${registerPath}, key id ${val(publicKeyId)}`);
    } catch (e) {
      printLine(warn(`could not read pubkey at ${registerPath}: ${e.message}`));
    }
  }

  if (!publicKeyId) {
    publicKeyId = await promptWithDefault(label('public key id / fingerprint'), '', true);
  }

  bindHandlers();
  connect();
}

function connect() {
  ws = new WebSocket(serverUrl);

  ws.on('open', async () => {
    reconnectAttempts = 0;
    connectedRelay = serverUrl;
    if (!entryRelay) entryRelay = serverUrl;
    printLine(`${label('connected')} ${val(serverUrl)}, user ${val(username)}, session ${val(sessionId)}`);
    if (uiActive) updateHeader();
    // Optional register before login.
    if (registerKeyArmored) {
      safeSend({ type: 'register', username, key_id: publicKeyId, public_key: registerKeyArmored });
    } else {
      safeSend({ type: 'login-init', username, key_id: publicKeyId, client_version: clientVersion });
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
    scheduleReconnect();
  });

  ws.on('error', (e) => {
    printLine(`${err('relay error')} ${e.message}`);
  });

  // input handlers are bound once in bindHandlers()
}

function bindHandlers() {
  if (handlersBound) return;
  handlersBound = true;

  rl.on('line', (line) => {
    if (!authed || !joined) {
      printLine(warn('not logged in / joined yet'));
      renderPrompt();
      return;
    }
    if (!groupKey) {
      printLine(warn('group key not ready, wait for peers to rekey'));
      renderPrompt();
      return;
    }
    const trimmed = line.trim();
    if (!trimmed) {
      renderPrompt();
      return;
    }
    if (trimmed.startsWith('/')) {
      handleCommand(trimmed);
      renderPrompt();
      return;
    }
    sendEncrypted(trimmed);
    const selfLabel = nickname ? `${identity.senderId}|${nickname}` : identity.senderId;
    printLine(`${paint(color.magenta, selfLabel)} ${trimmed}`);
    renderPrompt();
  });

  process.on('SIGINT', () => {
    printLine('\n' + warn('exiting'));
    shutdownRequested = true;
    if (ws) ws.close();
    rl.close();
  });
}

async function handleMessage(msg) {
  switch (msg.type) {
    case 'register-ok':
      printLine(val(`public key registered for ${msg.username}`));
      safeSend({ type: 'login-init', username, key_id: publicKeyId, client_version: clientVersion });
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
      if (msg.server_version) {
        lastServerVersion = msg.server_version;
      }
      if (lastServerVersion && lastServerVersion !== clientVersion) {
        printLine(warn(`server version ${lastServerVersion} differs from client ${clientVersion}`));
      }
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
        printLine(`${promptLabel} ${val(generated)}`);
        return resolve(generated);
      }
      const resolved = trimmed || defaultValue;
      if (required && !resolved) {
        printLine(warn('value required'));
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

  peers.set(peerId, {
    publicKey: peerKeyObj,
    publicDer,
    epoch: peerEpoch,
    nickname: sanitizeNick(peerNick),
  });
  deriveGroupKey();
}

function handlePeerLeft() {
  printLine(warn('peer left, rekeying'));
  startRekey('peer-left');
}

function deriveGroupKey() {
  const activePeers = [...peers.entries()]
    .filter(([, peer]) => peer.epoch === currentEpoch);
  if (activePeers.length === 0) return;

  // Deterministic group key: bind to all participant public keys + optional passphrase.
  const participants = [
    { id: identity.senderId, publicDer: identity.publicDer },
    ...activePeers.map(([id, peer]) => ({ id, publicDer: peer.publicDer })),
  ].sort((a, b) => a.id.localeCompare(b.id));

  const inputMaterial = Buffer.concat(participants.map((p) => p.publicDer));
  const salt = crypto.createHash('sha256')
    .update(`${sessionId}|${passphrase}|${currentEpoch}`)
    .digest();
  const info = Buffer.concat([Buffer.from('group-key'), Buffer.from(sessionId)]);
  groupKey = Buffer.from(crypto.hkdfSync('sha256', salt, inputMaterial, info, 32));
  messageCounter = 0;

  const safetyCode = crypto.createHash('sha256').update(groupKey).digest('hex').slice(0, 16);
  lastSafetyCode = safetyCode;
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
    msg_id: crypto.randomUUID(),
    session_id: sessionId,
    sender_id: identity.senderId,
    epoch: currentEpoch,
    counter,
    nonce: nonce.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };

  safeSend(frame);
  markSeen(frame.msg_id, frame.sender_id, frame.epoch, frame.counter);
  if (showEncrypted) {
    printLine(muted(`[encrypted] ${frame.ciphertext}`));
  }
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
  if (isSeen(msg)) return;

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
    if (showEncrypted) {
      printLine(muted(`[encrypted] ${msg.ciphertext}`));
    }
    printLine(`${displayLabel ? paint(color.magenta, displayLabel) : ''}${displayLabel ? ' ' : ''}${plaintext}`);
  } catch {
    printLine(warn('failed to decrypt/authenticate message, rekey recommended'));
  }
}

function handleCommand(input) {
  const parts = input.split(/\s+/);
  const cmd = parts[0].toLowerCase();
  if (cmd === '/relay') {
    printLine(muted(`relay ${connectedRelay || serverUrl} | entry ${entryRelay || serverUrl}`));
    return;
  }
  if (cmd === '/showencrypted') {
    const arg = (parts[1] || '').toLowerCase();
    if (arg === 'on') showEncrypted = true;
    if (arg === 'off') showEncrypted = false;
    printLine(muted(`showEncrypted ${showEncrypted ? 'on' : 'off'}`));
    return;
  }
  if (cmd === '/session') {
    printLine(muted(`session ${sessionId || '-'} | epoch ${currentEpoch}`));
    return;
  }
  if (cmd === '/who') {
    const list = [...peers.entries()]
      .filter(([, peer]) => peer.epoch === currentEpoch)
      .map(([id, peer]) => (peer.nickname ? `${id}|${peer.nickname}` : id));
    printLine(muted(`peers ${list.length}: ${list.join(', ') || '-'}`));
    return;
  }
  if (cmd === '/rekey') {
    startRekey('manual');
    return;
  }
  if (cmd === '/safety') {
    printLine(muted(`safety ${lastSafetyCode || '-'}`));
    return;
  }
  if (cmd === '/version') {
    printLine(muted(`client ${clientVersion} | server ${lastServerVersion || '-'}`));
    return;
  }
  if (cmd === '/help') {
    printLine(muted('/relay | /session | /who | /rekey | /safety | /version | /showencrypted on|off | /help'));
    return;
  }
  printLine(muted('unknown command. try /help'));
}

function isSeen(msg) {
  const key = msg.msg_id || `${msg.sender_id}|${msg.epoch}|${msg.counter}`;
  if (seenCipher.has(key)) return true;
  markSeen(msg.msg_id, msg.sender_id, msg.epoch, msg.counter);
  return false;
}

function markSeen(msgId, senderId, epoch, counter) {
  const key = msgId || `${senderId}|${epoch}|${counter}`;
  seenCipher.set(key, Date.now());
  if (seenCipher.size > MAX_SEEN) {
    for (const [k] of seenCipher) {
      seenCipher.delete(k);
      if (seenCipher.size <= MAX_SEEN) break;
    }
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

function scheduleReconnect() {
  reconnectAttempts += 1;
  totalReconnects += 1;
  if (uiActive) updateHeader();
  const delay = Math.min(15000, 1000 * reconnectAttempts);
  printLine(muted(`reconnecting in ${Math.floor(delay / 1000)}s...`));
  setTimeout(async () => {
    try {
      const discovered = await discoverServerFromList();
      if (discovered) serverUrl = discovered;
      connect();
    } catch (e) {
      printLine(err(`reconnect failed: ${e.message}`));
      scheduleReconnect();
    }
  }, delay);
}

function renderChatUi() {
  updateHeader();
  uiActive = true;
  rl.setPrompt(PROMPT);
  redrawScreen();
}

function updateHeader() {
  const pad = (text = '') => `│ ${text}`;
  const statusLine = `user ${val(username)} | relay ${val(connectedRelay || serverUrl)} | entry ${val(entryRelay || serverUrl)} | reconnects ${val(totalReconnects)}`;
  headerLines = [
    `╭─ ${statusLine}`,
    pad(`user: ${username}  nick: ${nickname || username}`),
    pad(`server: ${serverUrl}`),
    pad('type to send; CTRL+C to exit'),
  ];
  if (uiActive) redrawScreen();
}

function printLine(text) {
  logBuffer.push(text);
  if (logBuffer.length > MAX_LOG_LINES) {
    logBuffer.splice(0, logBuffer.length - MAX_LOG_LINES);
  }
  if (!uiActive) {
    console.log(text);
    return;
  }
  redrawScreen();
}

function renderPrompt(line = rl.line || '', cursor = rl.cursor || 0) {
  if (!uiActive) return;
  redrawScreen(line, cursor);
}

function redrawScreen(line = rl.line || '', cursor = rl.cursor || 0) {
  const rows = process.stdout.rows || 30;
  const available = Math.max(0, rows - headerLines.length - 2);
  const start = Math.max(0, logBuffer.length - available);
  const view = logBuffer.slice(start);
  const clear = '\x1b[2J\x1b[H';
  process.stdout.write(clear);
  for (const h of headerLines) process.stdout.write(`${h}\n`);
  for (const l of view) process.stdout.write(`${l}\n`);
  process.stdout.write(`${INPUT_DIVIDER}\n${PROMPT}`);
  rl.line = line;
  rl.cursor = cursor;
  rl.write(line);
  readline.cursorTo(process.stdout, PROMPT.length + cursor);
}
function normalizeServer(url) {
  if (!url) return url;
  if (url.startsWith('ws://') || url.startsWith('wss://')) return url;
  return `ws://${url}`;
}

function toHttp(url) {
  if (url.startsWith('wss://')) return `https://${url.slice('wss://'.length)}`;
  if (url.startsWith('ws://')) return `http://${url.slice('ws://'.length)}`;
  if (url.startsWith('http://') || url.startsWith('https://')) return url;
  return `http://${url}`;
}

async function discoverServer(seeds) {
  for (const seed of seeds) {
    try {
      const base = toHttp(seed);
      const json = await fetchJson(`${base}/directory`);
      const relays = Array.isArray(json.relays) ? json.relays : [];
      const options = relays.length > 0 ? relays : [seed];
      const { picked, onlineCount } = await pickReachableRelay(options);
      printLine(`${label('discovery')} relays ${val(options.length)} | online ${val(onlineCount)}`);
      if (picked) return picked;
    } catch {
      continue;
    }
  }
  // Fallback to first seed if all failed.
  return seeds[0];
}

async function discoverServerFromList() {
  // Prefer relay list URL(s), fallback to seeds.
  if (relayListUrls.length > 0) {
    for (const url of relayListUrls) {
      try {
        const json = await fetchJson(url);
        const relays = Array.isArray(json.relays) ? json.relays : [];
        if (relays.length > 0) {
          const { picked, onlineCount } = await pickReachableRelay(relays);
          printLine(`${label('discovery')} relays ${val(relays.length)} | online ${val(onlineCount)}`);
          if (picked) return picked;
        }
      } catch {
        continue;
      }
    }
  }
  if (seedList.length > 0) {
    return discoverServer(seedList);
  }
  return '';
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https://') ? https : http;
    const req = lib.get(url, { headers: { 'User-Agent': 'kreo-client' } }, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => req.destroy(new Error('timeout')));
  });
}

async function pickReachableRelay(relays) {
  const shuffled = [...new Set(relays)].sort(() => Math.random() - 0.5);
  let onlineCount = 0;
  let picked = '';
  for (const relay of shuffled) {
    const url = normalizeServer(relay);
    const httpBase = toHttp(url);
    try {
      const health = await fetchJson(`${httpBase}/health`);
      if (health && health.status === 'ok') {
        onlineCount += 1;
      }
    } catch {
      continue;
    }
    if (!picked && onlineCount > 0) {
      picked = url;
    }
  }
  return { picked, onlineCount };
}
