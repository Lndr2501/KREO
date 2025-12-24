#!/usr/bin/env bash
set -euo pipefail

echo "KREO Relay Setup (Docker)"
echo "This will generate a docker-compose.yml for multiple relay instances."
echo

read -r -p "Git repo URL [https://github.com/Lndr2501/KREO.git]: " REPO_URL
REPO_URL="${REPO_URL:-https://github.com/Lndr2501/KREO.git}"

read -r -p "Clone folder (default: ./KREO): " REPO_DIR
REPO_DIR="${REPO_DIR:-./KREO}"

if [[ ! -d "${REPO_DIR}" ]]; then
  git clone "${REPO_URL}" "${REPO_DIR}"
else
  echo "Repo folder exists, pulling latest..."
  git -C "${REPO_DIR}" pull
fi

read -r -p "Target folder for relays (will be created): " TARGET_DIR
if [[ -z "${TARGET_DIR}" ]]; then
  echo "Target folder is required."
  exit 1
fi

DEFAULT_RANGE="6969-6969"
read -r -p "Port range (start-end) [${DEFAULT_RANGE}]: " PORT_RANGE
PORT_RANGE="${PORT_RANGE:-$DEFAULT_RANGE}"
if ! [[ "${PORT_RANGE}" =~ ^[0-9]+-[0-9]+$ ]]; then
  echo "Invalid port range."
  exit 1
fi
START_PORT="${PORT_RANGE%-*}"
END_PORT="${PORT_RANGE#*-}"
if [[ "${START_PORT}" -lt 1 ]] || [[ "${END_PORT}" -gt 65535 ]] || [[ "${END_PORT}" -lt "${START_PORT}" ]]; then
  echo "Invalid port range values."
  exit 1
fi
RELAY_COUNT=$((END_PORT - START_PORT + 1))

DEFAULT_PUBLIC_HOST="localhost"
read -r -p "Default public hostname/IP (can override per relay) [${DEFAULT_PUBLIC_HOST}]: " DEFAULT_HOST
DEFAULT_HOST="${DEFAULT_HOST:-$DEFAULT_PUBLIC_HOST}"

read -r -p "Relay list URL (default: GitHub list) [press Enter]: " RELAY_SEEDS_URL
if [[ -z "${RELAY_SEEDS_URL}" ]]; then
  RELAY_SEEDS_URL="https://raw.githubusercontent.com/Lndr2501/KREO-Relays/refs/heads/main/relays.json"
fi

read -r -p "Relay sample size (default 3) [press Enter]: " RELAY_SAMPLE_SIZE
if [[ -z "${RELAY_SAMPLE_SIZE}" ]]; then
  RELAY_SAMPLE_SIZE="3"
fi

mkdir -p "${TARGET_DIR}"

echo "Building relay image..."
docker build -t kreo-relay "${REPO_DIR}"

COMPOSE_FILE="${TARGET_DIR}/docker-compose.yml"
cat > "${COMPOSE_FILE}" <<EOF
version: "3.8"
services:
EOF

for i in $(seq 1 "${RELAY_COUNT}"); do
  PORT=$((START_PORT + i - 1))
  read -r -p "Public host for relay ${i} (port ${PORT}) [${DEFAULT_HOST}]: " PUBLIC_HOST
  PUBLIC_HOST="${PUBLIC_HOST:-$DEFAULT_HOST}"
  cat >> "${COMPOSE_FILE}" <<EOF
  kreo-relay-${i}:
    image: kreo-relay
    restart: unless-stopped
    ports:
      - "${PORT}:6969"
    environment:
      - PORT=6969
      - RELAY_URL=ws://${PUBLIC_HOST}:${PORT}
      - RELAY_SEEDS_URL=${RELAY_SEEDS_URL}
      - RELAY_SAMPLE_SIZE=${RELAY_SAMPLE_SIZE}
EOF
done

cat <<EOF

Done. Compose file created at:
  ${COMPOSE_FILE}

Next steps:
  1) docker build -t kreo-relay .
  2) cd "${TARGET_DIR}"
  3) docker compose up -d
  4) Open/forward ports ${START_PORT}..${END_PORT} to this host.
EOF
