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

## Lokaler Start (ohne Docker)
- Voraussetzungen: Node 20, npm.
- Installation: `npm install`
- Start Relay: `npm run server` (lauscht auf ws://localhost:6969, health unter /health)
- Dev-Client (auto-ident, interaktiv): `npm run dev-client -- --server ws://localhost:6969 --session demo --min_participants 2`
- Regulärer Client (Node): `npm run client` (CLI-Prompts) oder Windows-EXE `client.exe` wie unten.
- Optional WSS: `TLS_KEY_PATH` + `TLS_CERT_PATH` (und optional `TLS_CA_PATH`) setzen und `RELAY_URL` auf `wss://...`; Client/Dev-Client dann mit `--server wss://...`.

## Mehrere Relays (Wizard, Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/Lndr2501/KREO/main/scripts/setup-relays.sh -o setup-relays.sh \
  && KREO_BASE_DIR="$PWD" bash setup-relays.sh
```
Fragt nur Port-Range, Anzahl, Host-Pattern (kreo{N}.domain) und ob Port in RELAY_URL angehaengt wird. Erstellt docker-compose.yml im aktuellen Ordner, klont/baut automatisch.

## Client (Windows EXE)
- Default Discovery: https://raw.githubusercontent.com/Lndr2501/KREO-Relays/refs/heads/main/relays.json
- Start mit Prompts (Doppelklick) oder:
  ```powershell
  client.exe --server ws://localhost:6969 ^
    --user alice ^
    --keyid <FINGERPRINT> ^
    --register C:\path\pub.asc ^
    --session <SESSION_ID> ^
    --passphrase "<PASS>" ^
    --nick "Alice"
  ```
- PGP Challenge: gepanzerte Nachricht wird angezeigt; lokal mit Private Key entschluesseln; Klartext-Nonce zurueckgeben.
- Auto-Reconnect bei Relay-Ausfall (erneute PGP-Challenge noetig).
- Slash Commands:
  - /relay (aktueller + entry relay)
  - /session (Session, Epoch)
  - /who (Peers aktuelle Epoch)
  - /rekey (manuell)
  - /safety (Safety Code)
  - /version (Client/Server)
  - /showencrypted on|off (Ciphertext anzeigen)
  - /help

## Discovery / Seeds
- Client: `KREO_RELAYS_URL` (JSON `{"relays":[...]}`) oder `KREO_SEEDS=ws://relay1:6969,ws://relay2:6969`
- Relay: `RELAY_SEEDS_URL` (Liste), `RELAY_SAMPLE_SIZE` (Default 3), optional `RELAY_PEERS` manuell
- Mindestens ein Seed noetig (wie bei Tor).

## Debug (Server)
- `DEBUG_FRAMES=1` loggt Frame-Typen (announce/ciphertext/signal).
- `DEBUG_CIPHERTEXT=1` loggt nur Metadaten zu Ciphertext (Laengen, keine Inhalte).
- `/health` zeigt `known_relays`, `connected_relays`.

## Limits / Hardening (Server)
- `CHALLENGE_TTL_MS` (default 300000) setzt Ablauf fuer PGP-Challenges.
- `CHALLENGE_MAX` (default 200) begrenzt parallele PGP-Challenges.
- `SEEN_MESSAGES_MAX` (default 5000) limitiert zwischengespeicherte Message-IDs fuer Loop-Prevention.
- Rate Limits: `RATE_LIMIT_WINDOW_MS` (default 60000), `RATE_LIMIT_REGISTER` (default 20), `RATE_LIMIT_LOGIN_INIT` (default 60) pro IP/Window.
- Relay-Auth: `RELAY_SHARED_SECRET` (optional HMAC) erzwingt gegenseitige Authentifizierung zwischen Relays.
- Verbindung/Transport-Schutz: `MAX_PAYLOAD_BYTES` (default 51200) begrenzt WebSocket-Frames; `MAX_CONNECTIONS_PER_IP` (default 200) begrenzt parallele Verbindungen pro IP.
- TLS/WSS optional: `TLS_KEY_PATH` + `TLS_CERT_PATH` (und optional `TLS_CA_PATH`) aktivieren TLS; `RELAY_URL` auf `wss://...` setzen. Fuer lokale Tests ohne Zertifikat: `TLS_INSECURE_SELF_SIGNED=1` erzeugt ein temporäres selbstsigniertes Zertifikat (nicht fuer Produktion).
- Seeds/Discovery toggles: `RELAY_DISABLE_SEEDS=1` deaktiviert den Abruf der Seed-Liste; `WS_INSECURE_SKIP_VERIFY=1` akzeptiert self-signed/ungültige Zertifikate beim Relay-Peering (nur zum Debuggen!).
- Log-Dämpfung: `RELAY_ERROR_SUPPRESS_MS` (default 60000) unterdrueckt identische Relay-Verbindungsfehler und gibt periodisch Summaries aus.
- Peer-Listen: `RELAY_ACCEPT_PEER_LIST=0` ignoriert von Relays gesendete relay-list Frames (nur eigene Seeds/Peers werden genutzt).
- Relay-Discovery aktualisiert die bekannte Liste komplett bei jedem Fetch, sodass alte Einträge aus der Seed-Liste verworfen werden.

## Notes
- Unofficial, unaudited, fun-only. RAM-only state; Registrierungen/Sessions gehen beim Neustart verloren.
- Wenn Port belegt: `PORT` anpassen oder Port-Mapping aendern.
- PGP-Private Keys bleiben lokal; Server sieht nur Public Keys und Ciphertext.

## Tests
- `npm test` fuehrt einfache E2E-Jest-Tests fuer Register/Login/Join und Challenge-Expiry aus.

## Dev Client (Auto-Identitaet)
- `node dev-client.js --server ws://localhost:6969 --session demo`  
  - Generiert automatisch PGP-Key + X25519-Identitaet, registriert, beantwortet Challenge, joint Session. Du tippst Nachrichten interaktiv ins Terminal (random Login, keine Kleopatra noetig).
- Optional: `--min_participants 2` sendet erst, wenn mindestens 2 Teilnehmer (inkl. dir) bekannt sind.
- Build als EXE (Windows, Node18): `npm run build-dev-client` legt `dist/dev-client.exe` an (nutzt pkg).
