# KREO (Unofficial / Joke Project)

CLI-only PGP challenge/response login + AES E2E group chat. Built by AI, unaudited, use at your own risk.

## Features
- PGP login: server stores only public keys (in RAM), sends encrypted nonce, client decrypts locally.
- E2E chat: X25519 -> HKDF-SHA256 -> AES-256-GCM, counter nonces, AAD bound to protocol/session/sender/counter, safety code.
- Relay mesh with discovery (GitHub relay list), auto-failover, message dedupe.
- Client slash commands: /relay /session /who /rekey /safety /version /showencrypted on|off /help.
- Server debug flags to show that only ciphertext is handled.

## Single Relay (Docker)
```bash
docker build -t kreo-relay .
docker run -p 6969:6969 --name kreo-relay --rm \
  -e PORT=6969 \
  -e RELAY_URL=ws://your-host:6969 \
  -e RELAY_SEEDS_URL=https://raw.githubusercontent.com/Lndr2501/KREO-Relays/refs/heads/main/relays.json \
  -e RELAY_SAMPLE_SIZE=3 \
  kreo-relay
# health: curl http://localhost:6969/health
```

## Local Run (no Docker)
- Prereq: Node 20, npm.
- Install: `npm install`
- Start relay: `npm run server` (ws://localhost:6969, health at /health)
- Dev client (auto-identity, interactive): `npm run dev-client -- --server ws://localhost:6969 --session demo --min_participants 2`
- Regular client (Node): `npm run client` (CLI prompts) or Windows EXE `client.exe` as below.
- Optional WSS: set `TLS_KEY_PATH` + `TLS_CERT_PATH` (and optionally `TLS_CA_PATH`) and `RELAY_URL` to `wss://...`; point clients to `wss://...`.

## Multiple Relays (Wizard, Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/Lndr2501/KREO/main/scripts/setup-relays.sh -o setup-relays.sh \
  && KREO_BASE_DIR="$PWD" bash setup-relays.sh
```
Prompts for port range, count, host pattern (kreo{N}.domain), optional port in RELAY_URL. Creates docker-compose.yml, clones/builds automatically.

## Client (Windows EXE)
- Default discovery: https://raw.githubusercontent.com/Lndr2501/KREO-Relays/refs/heads/main/relays.json
- Launch via prompts (double-click) or:
  ```powershell
  client.exe --server ws://localhost:6969 ^
    --user alice ^
    --keyid <FINGERPRINT> ^
    --register C:\path\pub.asc ^
    --session <SESSION_ID> ^
    --passphrase "<PASS>" ^
    --nick "Alice"
  ```
- PGP challenge: armored message is shown; decrypt locally with your private key; return plaintext nonce.
- Auto-reconnect on relay loss (fresh PGP challenge).
- Slash commands:
  - /relay (current + entry relay)
  - /session (session, epoch)
  - /who (peers current epoch)
  - /rekey (manual)
  - /safety (safety code)
  - /version (client/server)
  - /showencrypted on|off (show ciphertext)
  - /help

## Discovery / Seeds
- Client: `KREO_RELAYS_URL` (JSON `{"relays":[...]}`) or `KREO_SEEDS=ws://relay1:6969,ws://relay2:6969`
- Relay: `RELAY_SEEDS_URL` (list), `RELAY_SAMPLE_SIZE` (default 3), optional `RELAY_PEERS` manual
- At least one seed required.

## Debug (Server)
- `DEBUG_FRAMES=1` logs frame types (announce/ciphertext/signal).
- `DEBUG_CIPHERTEXT=1` logs only ciphertext metadata (lengths, not contents).
- `/health` shows `known_relays`, `connected_relays`.

## Limits / Hardening (Server)
- `CHALLENGE_TTL_MS` (default 300000) sets PGP challenge expiry.
- `CHALLENGE_MAX` (default 200) caps concurrent PGP challenges.
- `SEEN_MESSAGES_MAX` (default 5000) limits cached message IDs for loop prevention.
- Rate limits: `RATE_LIMIT_WINDOW_MS` (default 60000), `RATE_LIMIT_REGISTER` (default 20), `RATE_LIMIT_LOGIN_INIT` (default 60) per IP/window.
- Relay auth: `RELAY_SHARED_SECRET` (optional HMAC) enforces mutual auth between relays.
- Transport guards: `MAX_PAYLOAD_BYTES` (default 51200) caps WebSocket frames; `MAX_CONNECTIONS_PER_IP` (default 200) caps concurrent connections per IP.
- Optional TLS/WSS: `TLS_KEY_PATH` + `TLS_CERT_PATH` (+ optional `TLS_CA_PATH`); set `RELAY_URL` to `wss://...`. For local tests without certs: `TLS_INSECURE_SELF_SIGNED=1` generates a temporary self-signed cert (not for production).
- Seeds/Discovery toggles: `RELAY_DISABLE_SEEDS=1` disables fetching the seed list; `WS_INSECURE_SKIP_VERIFY=1` allows self-signed/invalid certs when peering relays (debug only).

## Notes
- Unofficial, unaudited, fun-only. RAM-only state; registrations/sessions lost on restart.
- If port in use: adjust `PORT` or port mapping.
- PGP private keys stay local; server only sees public keys and ciphertext.

## Tests
- `npm test` runs E2E Jest tests for register/login/join and guardrails.

## Dev Client (Auto Identity)
- `node dev-client.js --server ws://localhost:6969 --session demo`
  - Auto-generates PGP + X25519, registers, answers challenge, joins session. You type messages interactively (random login, no Kleopatra).
- Optional: `--min_participants 2` waits until at least 2 participants (including you) are known before sending.
- Build EXE (Windows, Node18): `npm run build-dev-client` outputs `dist/dev-client.exe` (uses pkg).
