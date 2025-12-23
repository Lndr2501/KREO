# KREO (Unofficial / Joke Project)

> CLI-only PGP challenge/response login + AES E2E group chat relay. Built entirely by AI, for fun. Not audited, not official, use at your own risk.

## What This Is
- WebSocket relay with in-memory PGP public-key registry, no persistence.
- Login via PGP-encrypted nonce challenge; client decrypts with your private key (e.g. Kleopatra) and returns the plaintext.
- After login + session join: X25519 + HKDF-SHA256 → AES-256-GCM group chat, counter nonces, AAD bound to protocol/session/sender/counter.
- All CLI, no storage of private keys or messages on server.

## Quickstart
Requirements: Docker (for relay) and a PGP keypair (private key stays local).

1) Build and run relay (port 6969):
   ```bash
   docker build -t kreo-relay .
   docker run -p 6969:6969 --name kreo-relay --rm kreo-relay
   # health: curl http://localhost:6969/health
   # logs:   docker logs -f kreo-relay
   ```

2) Export your PGP public key (ASCII), note its fingerprint. Example: `C:\Users\You\my_pub.asc`.

3) Run client (Windows EXE) with prompts:
   ```powershell
   .\client.exe --server ws://localhost:6969
   ```
   (Oder einfach Doppelklick: Prompts erscheinen im Konsolenfenster.)
   - username: choose one
   - session_id: type `gen` or provide your own
   - passphrase: optional, `gen` to create one
   - nickname: optional (defaults to username if empty)
   - path to public key for registration: your `.asc` file (needed once per server boot)
   - public key id / fingerprint: your PGP fingerprint

   The client will show a PGP armored challenge (nonce). Decrypt it with your private key (Kleopatra), paste the plaintext back. After “login success” and “joined session …”, verify the safety code with peers, then chat at the `>` prompt.

4) Friends join:
   - Use `ws://<your-ip-or-dns>:6969`, same session_id and passphrase.
   - They register their own public key (once per server boot), solve their challenge, then join.

## Notes & Warnings
- Unofficial, unaudited, for laughs. Do not trust for real security.
- Registrations and sessions live only in RAM; server restart → re-register keys.
- Server sees only public keys and ciphertext; private keys never leave clients.
- If port 6969 is busy, change `PORT` env or docker `-p <host>:6969` mapping.
- WAN-Freigabe (Port-Forwarding) Beispiele:
  - FritzBox: Internet → Freigaben → Gerät wählen → Portfreigabe hinzufügen → Protokoll TCP → Port extern 6969 auf intern 6969 des Hosts mit dem Relay.
  - pfSense: Firewall → NAT → Port Forward → Interface WAN, Proto TCP, Dest Port 6969, Redirect auf interne IP:6969, Haken bei „Filter rule association“ setzen, anschließend Rules anwenden.

## Dev
- Relay: `server.js`
- Client: `client.js` (built to `client.exe` via `pkg client.js --targets node18-win-x64 --output client.exe`)
- Default server in client prompts: `ws://localhost:6969`
