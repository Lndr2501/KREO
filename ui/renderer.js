const { KreoClient } = require('./client-core');
const fs = require('fs');

let client = null;

const $ = (id) => document.getElementById(id);
const messagesEl = $('messages');
const statusEl = $('status');
const modal = $('challengeModal');
const modalArmored = $('challengeArmored');
const modalNonce = $('challengeNonce');

$('connect').addEventListener('click', () => {
  const server = $('server').value.trim() || 'ws://localhost:6969';
  const username = $('username').value.trim();
  const nickname = $('nickname').value.trim();
  const session = $('session').value.trim() || 'demo';
  const privFile = $('privkeyPath').files[0];
  const pubFile = $('pubkeyPath').files[0];

  if (!server || !username || !session || !privFile || !pubFile) {
    setStatus('Please select server, username, session, and both PGP key files.');
    return;
  }

  let priv = '';
  let pub = '';
  try {
    priv = fs.readFileSync(privFile.path, 'utf8');
    pub = fs.readFileSync(pubFile.path, 'utf8');
  } catch (e) {
    setStatus(`Failed to read key files: ${e.message}`);
    return;
  }

  client = new KreoClient({
    serverUrl: server,
    username: username || undefined,
    nickname: nickname || undefined,
    sessionId: session || 'demo',
  });

  client.on('status', (msg) => setStatus(msg));
  client.on('error', (err) => setStatus(`Error: ${err}`));
  client.on('message', (m) => addMessage(m.text, m.nickname || m.senderId, false));
  client.on('sent', (m) => addMessage(m.text, 'me', true));
  client.on('challenge', (armored, keyId) => {
    setStatus(`Challenge received (key ${keyId || 'n/a'}). Decrypt and paste nonce.`);
    showChallengeModal(armored);
  });

  client.initKeys(priv, pub)
    .then(() => client.connect())
    .catch((e) => setStatus(`Error: ${e.message}`));
});

$('send').addEventListener('click', sendMessage);
$('message').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    sendMessage();
  }
});

function sendMessage() {
  const text = $('message').value.trim();
  if (!text || !client) return;
  client.sendMessage(text);
  $('message').value = '';
}

function addMessage(text, sender, self) {
  const div = document.createElement('div');
  div.className = `msg ${self ? 'self' : 'remote'}`;
  const senderSpan = document.createElement('span');
  senderSpan.className = 'sender';
  senderSpan.textContent = sender + ':';
  const textSpan = document.createElement('span');
  textSpan.textContent = ' ' + text;
  div.appendChild(senderSpan);
  div.appendChild(textSpan);
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function setStatus(text) {
  statusEl.textContent = text;
}

function showChallengeModal(armored) {
  modalArmored.value = armored;
  modalNonce.value = '';
  modal.classList.remove('hidden');
  modalNonce.focus();
}

$('challengeSubmit').addEventListener('click', () => {
  const nonce = modalNonce.value.trim();
  if (nonce && client) {
    client.submitChallengeResponse(nonce);
    modal.classList.add('hidden');
  }
});

$('challengeCancel').addEventListener('click', () => {
  modal.classList.add('hidden');
});
