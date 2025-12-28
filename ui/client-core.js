const crypto = require('crypto');
const http = require('http');
const https = require('https');
const WebSocket = require('ws');
const openpgp = require('openpgp');
const EventEmitter = require('events');

class KreoClient extends EventEmitter {
  constructor(options = {}) {
    super();
    this.serverUrl = this.normalizeServer(options.serverUrl || '');
    this.username = options.username || '';
    this.sessionId = options.sessionId || '';
    this.passphrase = options.passphrase || '';
    this.nickname = options.nickname || '';
    this.clientVersion = options.clientVersion || 'gui-1.0.0';

    this.ws = null;
    this.authed = false;
    this.joined = false;
    this.pendingChallengeId = null;
    this.currentEpoch = 1;
    this.identity = this.generateIdentity();
    this.groupKey = null;
    this.messageCounter = 0;
    this.peers = new Map();
    this.seenCipher = new Map();
    this.MAX_SEEN = 500;
    this.pendingCipher = [];
    this.pgpKeys = null;
  }

  async initKeys(privateKeyArmored, publicKeyArmored) {
    if (privateKeyArmored && publicKeyArmored) {
      const publicKeyObj = await openpgp.readKey({ armoredKey: publicKeyArmored });
      this.pgpKeys = { privateKey: privateKeyArmored, publicKey: publicKeyArmored, fingerprint: publicKeyObj.getFingerprint() };
    }
    return this.pgpKeys;
  }

  async connect() {
    if (!this.serverUrl || !this.username || !this.sessionId) {
      this.emit('error', 'Server, username, and session are required');
      return;
    }
    if (!this.pgpKeys) {
      this.emit('error', 'PGP keys not loaded');
      return;
    }
    this.emit('status', `Connecting to ${this.serverUrl} ...`);
    this.ws = new WebSocket(this.serverUrl);
    this.ws.on('open', () => this.onOpen());
    this.ws.on('message', (data) => this.onMessage(data));
    this.ws.on('close', () => this.emit('status', 'Disconnected'));
    this.ws.on('error', (err) => this.emit('error', err.message || 'WebSocket error'));
  }

  disconnect() {
    if (this.ws) this.ws.close();
  }

  onOpen() {
    this.authed = false;
    this.joined = false;
    this.pendingChallengeId = null;
    this.emit('status', 'Connected, registering key ...');
    this.safeSend({
      type: 'register',
      username: this.username,
      key_id: this.pgpKeys.fingerprint,
      public_key: this.pgpKeys.publicKey,
    });
  }

  async onMessage(raw) {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }
    switch (msg.type) {
      case 'register-ok':
        this.emit('status', 'Registered, starting login ...');
        this.safeSend({ type: 'login-init', username: this.username, client_version: this.clientVersion });
        break;
      case 'error':
        this.emit('error', msg.message || 'server error');
        break;
      case 'login-challenge':
        this.pendingChallengeId = msg.challenge_id;
        this.emit('challenge', msg.armored, msg.key_id || '');
        break;
      case 'login-success':
        this.authed = true;
        this.emit('status', 'Login success, joining session ...');
        this.safeSend({ type: 'join', session_id: this.sessionId });
        break;
      case 'joined':
        this.joined = true;
        this.emit('status', `Joined session ${msg.session_id}`);
        this.startRekey('login');
        break;
      case 'peer-joined':
        this.emit('status', `Peer joined: ${msg.username || ''}`);
        this.startRekey('peer-joined');
        break;
      case 'peer-left':
        this.emit('status', 'Peer left, rekeying');
        this.startRekey('peer-left');
        break;
      case 'announce':
        this.handleAnnounce(msg);
        break;
      case 'ciphertext':
        this.handleCiphertext(msg);
        break;
      default:
        break;
    }
  }

  submitChallengeResponse(response) {
    if (!this.pendingChallengeId) {
      this.emit('error', 'No pending challenge');
      return;
    }
    this.safeSend({ type: 'login-response', challenge_id: this.pendingChallengeId, response });
  }

  startRekey(reason) {
    this.currentEpoch += 1;
    this.groupKey = null;
    this.peers.clear();
    this.identity = this.generateIdentity();
    this.messageCounter = 0;
    this.emit('status', `[rekey] ${reason} -> epoch ${this.currentEpoch}`);
    this.sendAnnounce(reason);
  }

  sendAnnounce(reason) {
    const frame = {
      type: 'announce',
      session_id: this.sessionId,
      public_key: this.identity.publicDer.toString('base64'),
      epoch: this.currentEpoch,
      reason,
      nickname: this.nickname,
      username: this.username,
    };
    this.safeSend(frame);
  }

  handleAnnounce(msg) {
    const publicDer = Buffer.from(msg.public_key, 'base64');
    const peerId = this.senderIdFromPublic(publicDer);
    if (peerId === this.identity.senderId) return;

    const peerKeyObj = crypto.createPublicKey({ key: publicDer, format: 'der', type: 'spki' });
    const peerEpoch = Number.isFinite(msg.epoch) ? msg.epoch : 1;
    const cleanNick = this.sanitizeNick(msg.nickname || '');

    this.peers.set(peerId, { publicKey: peerKeyObj, publicDer, epoch: peerEpoch, nickname: cleanNick });
    this.deriveGroupKey();
    this.processPending();
  }

  deriveGroupKey() {
    const activePeers = [...this.peers.entries()].filter(([, peer]) => peer.epoch === this.currentEpoch);
    const participants = [
      { id: this.identity.senderId, publicDer: this.identity.publicDer },
      ...activePeers.map(([id, peer]) => ({ id, publicDer: peer.publicDer })),
    ].sort((a, b) => a.id.localeCompare(b.id));
    if (participants.length === 0) return;

    const inputMaterial = Buffer.concat(participants.map((p) => p.publicDer));
    const salt = crypto.createHash('sha256')
      .update(`${this.sessionId}|${this.passphrase}|${this.currentEpoch}`)
      .digest();
    const info = Buffer.concat([Buffer.from('group-key'), Buffer.from(this.sessionId)]);
    this.groupKey = Buffer.from(crypto.hkdfSync('sha256', salt, inputMaterial, info, 32));
    this.messageCounter = 0;

    const safetyCode = crypto.createHash('sha256').update(this.groupKey).digest('hex').slice(0, 16);
    this.emit('status', `[key] epoch ${this.currentEpoch} ready. safety ${safetyCode}`);
  }

  sendMessage(text) {
    if (!this.groupKey) {
      this.emit('error', 'group key not ready');
      return;
    }
    const counter = this.messageCounter;
    this.messageCounter += 1;
    const nonce = Buffer.alloc(12);
    this.identity.noncePrefix.copy(nonce, 0);
    nonce.writeBigUInt64BE(BigInt(counter), 4);
    const aad = this.buildAad(this.identity.senderId, counter);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.groupKey, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const frame = {
      type: 'ciphertext',
      msg_id: crypto.randomUUID(),
      session_id: this.sessionId,
      sender_id: this.identity.senderId,
      epoch: this.currentEpoch,
      counter,
      nonce: nonce.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
    this.safeSend(frame);
    this.markSeen(frame.msg_id);
    this.emit('sent', { text, self: true, senderId: this.identity.senderId });
  }

  handleCiphertext(msg) {
    if (this.isSeen(msg)) return;
    if (msg.epoch !== this.currentEpoch) return;
    const peer = this.peers.get(msg.sender_id);
    if (!peer || peer.epoch !== this.currentEpoch) {
      this.enqueuePending(msg);
      this.sendAnnounce('need-announce');
      return;
    }
    if (!this.groupKey) {
      this.enqueuePending(msg);
      return;
    }
    try {
      const nonce = Buffer.from(msg.nonce, 'base64');
      const tag = Buffer.from(msg.tag, 'base64');
      const ciphertext = Buffer.from(msg.ciphertext, 'base64');
      const aad = this.buildAad(msg.sender_id, msg.counter);
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.groupKey, nonce);
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
      this.emit('message', { text: plaintext, senderId: msg.sender_id, nickname: peer.nickname });
    } catch {
      this.emit('error', 'failed to decrypt/authenticate message');
    }
  }

  safeSend(obj) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
    }
  }

  generateIdentity() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const publicDer = publicKey.export({ format: 'der', type: 'spki' });
    const senderId = this.senderIdFromPublic(publicDer);
    const noncePrefix = crypto.randomBytes(4);
    return { publicKey, privateKey, publicDer, senderId, noncePrefix };
  }

  senderIdFromPublic(publicDer) {
    return crypto.createHash('sha256').update(publicDer).digest('hex').slice(0, 16);
  }

  sanitizeNick(raw) {
    if (!raw || typeof raw !== 'string') return '';
    const trimmed = raw.trim().slice(0, 32);
    return /^[\x20-\x7E]+$/.test(trimmed) ? trimmed : '';
  }

  buildAad(senderId, counter) {
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));
    return Buffer.concat([
      Buffer.from('v1'),
      Buffer.from(this.sessionId),
      Buffer.from(senderId, 'hex'),
      counterBuf,
    ]);
  }

  decryptArmored(armored, privateKey) {
    return (async () => {
      const privKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKey });
      const message = await openpgp.readMessage({ armoredMessage: armored });
      const { data } = await openpgp.decrypt({ message, decryptionKeys: privKeyObj });
      return data;
    })();
  }

  normalizeServer(url) {
    if (!url) return '';
    if (url.startsWith('ws://') || url.startsWith('wss://')) return url;
    return `ws://${url}`;
  }

  isSeen(msg) {
    const key = msg.msg_id || `${msg.sender_id}|${msg.epoch}|${msg.counter}`;
    if (this.seenCipher.has(key)) return true;
    this.markSeen(key);
    return false;
  }

  markSeen(key) {
    this.seenCipher.set(key, Date.now());
    if (this.seenCipher.size > this.MAX_SEEN) {
      for (const k of this.seenCipher.keys()) {
        this.seenCipher.delete(k);
        if (this.seenCipher.size <= this.MAX_SEEN) break;
      }
    }
  }

  enqueuePending(msg) {
    if (this.pendingCipher.some((m) => m.msg_id === msg.msg_id)) return;
    this.pendingCipher.push(msg);
    if (this.pendingCipher.length > 200) this.pendingCipher.shift();
  }

  processPending() {
    if (!this.groupKey) return;
    const remaining = [];
    for (const msg of this.pendingCipher) {
      const peer = this.peers.get(msg.sender_id);
      if (!peer || peer.epoch !== this.currentEpoch) {
        remaining.push(msg);
        continue;
      }
      try {
        const nonce = Buffer.from(msg.nonce, 'base64');
        const tag = Buffer.from(msg.tag, 'base64');
        const ciphertext = Buffer.from(msg.ciphertext, 'base64');
        const aad = this.buildAad(msg.sender_id, msg.counter);
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.groupKey, nonce);
        decipher.setAAD(aad);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
        const peerNick = peer.nickname;
        this.emit('message', { text: plaintext, senderId: msg.sender_id, nickname: peerNick });
      } catch {
        remaining.push(msg);
      }
    }
    this.pendingCipher = remaining;
  }
}

module.exports = { KreoClient };
