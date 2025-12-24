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

## Mehrere Relays (Wizard, Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/Lndr2501/KREO/main/scripts/setup-relays.sh -o setup-relays.sh \
  && KREO_BASE_DIR="$PWD" bash setup-relays.sh
```
Fragt nur Port-Range, Anzahl, Host-Pattern (kreo{N}.domain) und ob Port in RELAY_URL angehängt wird. Erstellt docker-compose.yml im aktuellen Ordner, klont/baut automatisch.

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
- PGP Challenge: gepanzerte Nachricht wird angezeigt; lokal mit Private Key entschlüsseln; Klartext-Nonce zurückgeben.
- Auto-Reconnect bei Relay-Ausfall (erneute PGP-Challenge nötig).
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
- Mindestens ein Seed nötig (wie bei Tor).

## Debug (Server)
- `DEBUG_FRAMES=1` loggt Frame-Typen (announce/ciphertext/signal).
- `DEBUG_CIPHERTEXT=1` loggt Ciphertext-Felder (kein Klartext).
- `/health` zeigt `known_relays`, `connected_relays`.

## Notes
- Unofficial, unaudited, fun-only. RAM-only state; Registrierungen/Sessions gehen beim Neustart verloren.
- Wenn Port belegt: `PORT` anpassen oder Port-Mapping ändern.
- PGP-Private Keys bleiben lokal; Server sieht nur Public Keys und Ciphertext.
