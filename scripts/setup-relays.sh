#!/usr/bin/env bash
set -euo pipefail

echo "KREO Relay Setup (Docker)"
echo "This will generate a docker-compose.yml for multiple relay instances."
echo

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

DEFAULT_COUNT="1"
read -r -p "How many relays? [${DEFAULT_COUNT}]: " RELAY_COUNT
RELAY_COUNT="${RELAY_COUNT:-$DEFAULT_COUNT}"
if ! [[ "${RELAY_COUNT}" =~ ^[0-9]+$ ]] || [[ "${RELAY_COUNT}" -lt 1 ]]; then
  echo "Invalid relay count."
  exit 1
fi

RANGE_SIZE=$((END_PORT - START_PORT + 1))
if [[ "${RELAY_COUNT}" -gt "${RANGE_SIZE}" ]]; then
  echo "Relay count exceeds port range size (${RANGE_SIZE})."
  exit 1
fi

DEFAULT_HOST_PATTERN="kreo{N}.domain"
read -r -p "Host pattern (use {N}) [${DEFAULT_HOST_PATTERN}]: " HOST_PATTERN
HOST_PATTERN="${HOST_PATTERN:-$DEFAULT_HOST_PATTERN}"

read -r -p "Append port to RELAY_URL? (y/N): " ADD_PORT
ADD_PORT="${ADD_PORT:-N}"

BASE_DIR="${KREO_BASE_DIR:-$(pwd)}"
TARGET_DIR="${BASE_DIR}"
REPO_URL="https://github.com/Lndr2501/KREO.git"
REPO_DIR="${TARGET_DIR}/_repo"
RELAY_SEEDS_URL="https://raw.githubusercontent.com/Lndr2501/KREO-Relays/refs/heads/main/relays.json"
RELAY_SAMPLE_SIZE="3"

mkdir -p "${REPO_DIR}"

if [[ -d "${REPO_DIR}/.git" ]]; then
  echo "Repo folder exists, pulling latest..."
  git -C "${REPO_DIR}" pull
else
  rm -rf "${REPO_DIR}"
  git clone "${REPO_URL}" "${REPO_DIR}"
fi

echo "Building relay image..."
docker build -t kreo-relay "${REPO_DIR}"

COMPOSE_FILE="${TARGET_DIR}/docker-compose.yml"
cat > "${COMPOSE_FILE}" <<EOF
version: "3.8"
services:
EOF

for i in $(seq 1 "${RELAY_COUNT}"); do
  PORT=$((START_PORT + i - 1))
  PUBLIC_HOST="${HOST_PATTERN/\{N\}/${i}}"
  RELAY_URL="ws://${PUBLIC_HOST}"
  if [[ "${ADD_PORT}" =~ ^[Yy]$ ]]; then
    RELAY_URL="${RELAY_URL}:${PORT}"
  fi
  cat >> "${COMPOSE_FILE}" <<EOF
  kreo-relay-${i}:
    image: kreo-relay
    restart: unless-stopped
    ports:
      - "${PORT}:6969"
    environment:
      - PORT=6969
      - RELAY_URL=${RELAY_URL}
      - RELAY_SEEDS_URL=${RELAY_SEEDS_URL}
      - RELAY_SAMPLE_SIZE=${RELAY_SAMPLE_SIZE}
EOF
done

cat <<EOF

Done. Compose file created at:
  ${COMPOSE_FILE}

Next steps:
  1) cd "${TARGET_DIR}"
  2) docker compose up -d
  3) Open/forward ports ${START_PORT}..${END_PORT} to this host.
EOF
