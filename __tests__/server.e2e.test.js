const path = require('path');
const { fork } = require('child_process');
const crypto = require('crypto');
const WebSocket = require('ws');
const openpgp = require('openpgp');
const net = require('net');

jest.setTimeout(60000);

const serverPath = path.join(__dirname, '..', 'server.js');

async function generateKeyPair() {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'rsa',
    rsaBits: 2048,
    userIDs: [{ name: 'test' }],
  });
  const publicKeyObj = await openpgp.readKey({ armoredKey: publicKey });
  return { privateKey, publicKey, fingerprint: publicKeyObj.getFingerprint() };
}

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

const createIdentity = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const senderId = crypto.createHash('sha256').update(publicDer).digest('hex').slice(0, 16);
  const noncePrefix = crypto.randomBytes(4);
  return { publicKey, privateKey, publicDer, senderId, noncePrefix };
};

const deriveGroupKey = (participants, sessionId, passphrase = '', epoch = 1) => {
  const sorted = [...participants].sort((a, b) => a.senderId.localeCompare(b.senderId));
  const inputMaterial = Buffer.concat(sorted.map((p) => p.publicDer));
  const salt = crypto.createHash('sha256')
    .update(`${sessionId}|${passphrase}|${epoch}`)
    .digest();
  const info = Buffer.concat([Buffer.from('group-key'), Buffer.from(sessionId)]);
  return Buffer.from(crypto.hkdfSync('sha256', salt, inputMaterial, info, 32));
};

const buildAad = (sessionId, senderId, counter) => {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  return Buffer.concat([
    Buffer.from('v1'),
    Buffer.from(sessionId),
    Buffer.from(senderId, 'hex'),
    counterBuf,
  ]);
};

const encryptWithIdentity = (identity, groupKey, sessionId, plaintext, epoch = 1, counter = 0) => {
  const nonce = Buffer.alloc(12);
  identity.noncePrefix.copy(nonce, 0);
  nonce.writeBigUInt64BE(BigInt(counter), 4);

  const aad = buildAad(sessionId, identity.senderId, counter);
  const cipher = crypto.createCipheriv('aes-256-gcm', groupKey, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    frame: {
      type: 'ciphertext',
      msg_id: crypto.randomUUID(),
      session_id: sessionId,
      sender_id: identity.senderId,
      epoch,
      counter,
      nonce: nonce.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    },
    aad,
    nonce,
    tag,
    ciphertext,
  };
};

async function startServer(env = {}) {
  const port = await getFreePort();
  return new Promise((resolve, reject) => {
    const proc = fork(serverPath, {
      env: { ...process.env, PORT: String(port), ...env },
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    const timer = setTimeout(() => {
      cleanup();
      proc.kill();
      reject(new Error('server start timeout'));
    }, 10000);
    const cleanup = () => {
      proc.stdout.off('data', onData);
      proc.off('exit', onExit);
    };
    const onExit = (code) => {
      cleanup();
      reject(new Error(`server exited early with code ${code}`));
    };
    const onData = (chunk) => {
      const line = chunk.toString();
      if (line.includes('relay listening')) {
        clearTimeout(timer);
        cleanup();
        resolve({ proc, port });
      }
    };
    proc.on('exit', onExit);
    proc.stdout.on('data', onData);
  });
}

async function stopServer(proc) {
  if (!proc) return;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (proc.exitCode === null) {
        proc.kill('SIGKILL');
      }
    }, 1000);
    proc.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    proc.kill('SIGTERM');
  });
}

const waitForSocketOpen = (ws) => new Promise((resolve, reject) => {
  const onOpen = () => {
    cleanup();
    resolve();
  };
  const onError = (err) => {
    cleanup();
    reject(err);
  };
  const cleanup = () => {
    ws.off('open', onOpen);
    ws.off('error', onError);
  };
  ws.on('open', onOpen);
  ws.on('error', onError);
});

const waitForMessage = (ws, predicate, timeout = 10000) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => {
    cleanup();
    reject(new Error('message timeout'));
  }, timeout);
  const onMessage = (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }
    if (predicate(msg)) {
      cleanup();
      resolve(msg);
    }
  };
  const onClose = () => {
    cleanup();
    reject(new Error('socket closed'));
  };
  const cleanup = () => {
    clearTimeout(timer);
    ws.off('message', onMessage);
    ws.off('close', onClose);
  };
  ws.on('message', onMessage);
  ws.on('close', onClose);
});

const waitForClose = (ws, timeout = 2000) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => {
    cleanup();
    reject(new Error('close timeout'));
  }, timeout);
  const cleanup = () => {
    clearTimeout(timer);
    ws.off('close', onClose);
    ws.off('error', onError);
  };
  const onClose = () => {
    cleanup();
    resolve();
  };
  const onError = (err) => {
    cleanup();
    reject(err);
  };
  ws.on('close', onClose);
  ws.on('error', onError);
});

const waitForErrorOrClose = (ws, timeout = 5000) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => {
    cleanup();
    reject(new Error('error/close timeout'));
  }, timeout);
  const cleanup = () => {
    clearTimeout(timer);
    ws.off('close', onClose);
    ws.off('error', onError);
    ws.off('message', onMessage);
  };
  const onClose = () => {
    cleanup();
    resolve('close');
  };
  const onError = (err) => {
    cleanup();
    resolve(err.message || 'error');
  };
  const onMessage = (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'error') {
        cleanup();
        resolve(msg.message || 'error');
      }
    } catch {
      /* ignore parse issues */
    }
  };
  ws.on('close', onClose);
  ws.on('error', onError);
  ws.on('message', onMessage);
});

const waitForRelayList = (ws, timeout = 3000) => waitForMessage(ws, (m) => m.type === 'relay-list', timeout);

async function registerUser(ws, username, keys) {
  ws.send(JSON.stringify({
    type: 'register',
    username,
    key_id: keys.fingerprint,
    public_key: keys.publicKey,
  }));
  await waitForMessage(ws, (m) => m.type === 'register-ok');
}

async function decryptArmored(armored, privateKey) {
  const privKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKey });
  const message = await openpgp.readMessage({ armoredMessage: armored });
  const { data } = await openpgp.decrypt({ message, decryptionKeys: privKeyObj });
  return data;
}

describe('server e2e', () => {
  let keys;

  beforeAll(async () => {
    keys = await generateKeyPair();
  });

  test('happy path: register -> login -> join', async () => {
    const { proc, port } = await startServer();
    const ws = new WebSocket(`ws://localhost:${port}`);
    try {
      await waitForSocketOpen(ws);

      ws.send(JSON.stringify({
        type: 'register',
        username: 'alice',
        key_id: keys.fingerprint,
        public_key: keys.publicKey,
      }));
      await waitForMessage(ws, (m) => m.type === 'register-ok');

      ws.send(JSON.stringify({
        type: 'login-init',
        username: 'alice',
        client_version: '1.1.0',
      }));
      const challenge = await waitForMessage(ws, (m) => m.type === 'login-challenge');
      const nonce = await decryptArmored(challenge.armored, keys.privateKey);

      ws.send(JSON.stringify({
        type: 'login-response',
        challenge_id: challenge.challenge_id,
        response: nonce,
      }));
      await waitForMessage(ws, (m) => m.type === 'login-success');

      ws.send(JSON.stringify({ type: 'join', session_id: 'test-session' }));
      await waitForMessage(ws, (m) => m.type === 'joined');
    } finally {
      ws.close();
      await stopServer(proc);
    }
  });

  test('expired challenge is rejected', async () => {
    const { proc, port } = await startServer({ CHALLENGE_TTL_MS: '20' });
    const ws = new WebSocket(`ws://localhost:${port}`);
    try {
      await waitForSocketOpen(ws);
      ws.send(JSON.stringify({
        type: 'register',
        username: 'bob',
        key_id: keys.fingerprint,
        public_key: keys.publicKey,
      }));
      await waitForMessage(ws, (m) => m.type === 'register-ok');

      ws.send(JSON.stringify({
        type: 'login-init',
        username: 'bob',
        client_version: '1.1.0',
      }));
      const challenge = await waitForMessage(ws, (m) => m.type === 'login-challenge');
      const nonce = await decryptArmored(challenge.armored, keys.privateKey);

      await new Promise((r) => setTimeout(r, 60));

      ws.send(JSON.stringify({
        type: 'login-response',
        challenge_id: challenge.challenge_id,
        response: nonce,
      }));

      const errorMsg = await waitForMessage(ws, (m) => m.type === 'error');
      expect(errorMsg.message).toMatch(/expired|invalid/i);
    } finally {
      ws.close();
      await stopServer(proc);
    }
  });

  test('rate limit on login-init triggers error', async () => {
    const { proc, port } = await startServer({ RATE_LIMIT_LOGIN_INIT: '1', RATE_LIMIT_WINDOW_MS: '60000' });
    const ws = new WebSocket(`ws://localhost:${port}`);
    try {
      await waitForSocketOpen(ws);
      await registerUser(ws, 'carol', keys);

      ws.send(JSON.stringify({ type: 'login-init', username: 'carol', client_version: '1.1.0' }));
      await waitForMessage(ws, (m) => m.type === 'login-challenge');

      ws.send(JSON.stringify({ type: 'login-init', username: 'carol', client_version: '1.1.0' }));
      const errMsg = await waitForMessage(ws, (m) => m.type === 'error');
      expect(errMsg.message).toMatch(/rate limit/i);
    } finally {
      ws.close();
      await stopServer(proc);
    }
  });

  test('invalid username is rejected on register', async () => {
    const { proc, port } = await startServer();
    const ws = new WebSocket(`ws://localhost:${port}`);
    try {
      await waitForSocketOpen(ws);
      ws.send(JSON.stringify({
        type: 'register',
        username: 'bad♥',
        key_id: keys.fingerprint,
        public_key: keys.publicKey,
      }));
      const errMsg = await waitForMessage(ws, (m) => m.type === 'error');
      expect(errMsg.message).toMatch(/invalid username/i);
    } finally {
      ws.close();
      await stopServer(proc);
    }
  });

  test('connection limit per IP closes excess sockets', async () => {
    const { proc, port } = await startServer({ MAX_CONNECTIONS_PER_IP: '1' });
    const ws1 = new WebSocket(`ws://localhost:${port}`);
    const ws2 = new WebSocket(`ws://localhost:${port}`);
    try {
      await waitForSocketOpen(ws1);
      // Second connection should be dropped quickly.
      const result = await waitForErrorOrClose(ws2);
      expect(result).toBeDefined();
    } finally {
      ws1.close();
      ws2.close();
      await stopServer(proc);
    }
  });

  test('relay shared secret rejects bad auth and accepts good auth', async () => {
    const secret = 'supersecret';
    const { proc, port } = await startServer({ RELAY_SHARED_SECRET: secret });
    const badWs = new WebSocket(`ws://localhost:${port}`);
    const goodWs = new WebSocket(`ws://localhost:${port}`);
    try {
      await waitForSocketOpen(badWs);
      badWs.send(JSON.stringify({ type: 'relay-hello', relay_id: 'bad', relay_url: 'ws://bad', auth: 'invalid' }));
      await waitForErrorOrClose(badWs, 5000);

      await waitForSocketOpen(goodWs);
      const goodAuth = require('crypto').createHmac('sha256', secret).update('good').digest('hex');
      goodWs.send(JSON.stringify({ type: 'relay-hello', relay_id: 'good', relay_url: 'ws://good', auth: goodAuth }));
      const outcome = await Promise.race([
        waitForRelayList(goodWs, 4000),
        waitForErrorOrClose(goodWs, 4000).then((msg) => ({ type: 'error', message: String(msg || '') })),
      ]);
      expect(outcome.type).toBe('relay-list');
    } finally {
      badWs.close();
      goodWs.close();
      await stopServer(proc);
    }
  }, 10000);

  test('register rate limit enforces window', async () => {
    const { proc, port } = await startServer({ RATE_LIMIT_REGISTER: '1', RATE_LIMIT_WINDOW_MS: '60000' });
    const ws = new WebSocket(`ws://localhost:${port}`);
    try {
      await waitForSocketOpen(ws);
      await registerUser(ws, 'dave', keys);
      ws.send(JSON.stringify({ type: 'register', username: 'dave2', key_id: keys.fingerprint, public_key: keys.publicKey }));
      const errMsg = await waitForMessage(ws, (m) => m.type === 'error');
      expect(errMsg.message).toMatch(/rate limit/i);
    } finally {
      ws.close();
      await stopServer(proc);
    }
  });

  test('challenge max rejects overflow', async () => {
    // CHALLENGE_MAX=0 makes every login-init exceed the cap deterministically.
    const { proc, port } = await startServer({ CHALLENGE_MAX: '0' });
    const ws1 = new WebSocket(`ws://localhost:${port}`);
    const ws2 = new WebSocket(`ws://localhost:${port}`);
    try {
      await waitForSocketOpen(ws1);
      await waitForSocketOpen(ws2);
      await registerUser(ws1, 'eve', keys);
      await registerUser(ws2, 'frank', keys);

      ws1.send(JSON.stringify({ type: 'login-init', username: 'eve', client_version: '1.1.0' }));
      const err1 = await waitForMessage(ws1, (m) => m.type === 'error', 3000);
      expect((err1.message || '').toLowerCase()).toMatch(/too many pending/);

      ws2.send(JSON.stringify({ type: 'login-init', username: 'frank', client_version: '1.1.0' }));
      const outcome = await Promise.race([
        waitForMessage(ws2, (m) => m.type === 'error', 3000),
        waitForErrorOrClose(ws2, 3000).then((msg) => ({ message: String(msg || '') })),
        new Promise((_, rej) => setTimeout(() => rej(new Error('no overflow error')), 3000)),
      ]);
      expect((outcome.message || '').toLowerCase()).toMatch(/too many pending/);
    } finally {
      ws1.close();
      ws2.close();
      await stopServer(proc);
    }
  }, 15000);

  test('oversized payload is rejected (max payload)', async () => {
    const { proc, port } = await startServer({ MAX_PAYLOAD_BYTES: '1024' });
    const ws = new WebSocket(`ws://localhost:${port}`);
    try {
      await waitForSocketOpen(ws);
      const bigPayload = 'A'.repeat(2000);
      ws.send(bigPayload);
      const result = await waitForErrorOrClose(ws, 5000);
      expect(result).toBeDefined();
    } finally {
      ws.close();
      await stopServer(proc);
    }
  });
});
