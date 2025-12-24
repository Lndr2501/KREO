#!/usr/bin/env bash
set -euo pipefail

# --- sudo wrapper ---
if command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  echo "sudo not found. Aborting."
  exit 1
fi

DOCKER="$SUDO docker"
GIT="$SUDO git"

echo "KREO Relay Setup (Docker, sudo-safe)"
echo "This will generate a docker-compose.yml for multiple relay instances."
echo

DEFAULT_RANGE="6969-6969"
read -r -p "Port range (start-end) [${DEFAULT_RANGE}]: " PORT_RANGE
PORT_RANGE="${PORT_RANGE:-$DEFAULT_RANGE}"
[[ "${PORT_RANGE}" =~ ^[0-9]+-[0-9]+$ ]] || { echo "Invalid port range."; exit 1; }

START_PORT="${PORT_RANGE%-*}"
END_PORT="${PORT_RANGE#*-}"
(( START_PORT >= 1 && END_PORT <= 65535 && END_PORT >= START_PORT )) || {
  echo "Invalid port range values."
  exit 1
}

DEFAULT_COUNT="1"
read -r -p "How many relays? [${DEFAULT_COUNT}]: " RELAY_COUNT
RELAY_COUNT="${RELAY_COUNT:-$DEFAULT_COUNT}"
[[ "${RELAY_COUNT}" =~ ^[0-9]+$ && "${RELAY_COUNT}" -ge 1 ]] || {
  echo "Invalid relay count."
  exit 1
}

RANGE_SIZE=$((END_PORT - START_PORT + 1))
(( RELAY_COUNT <= RANGE_SIZE )) || {
  echo "Relay count exceeds port range size (${RANGE_SIZE})."
  exit 1
}

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
  echo "Repo exists, pulling latest..."
  $GIT -C "${REPO_DIR}" pull
else
  rm -rf "${REPO_DIR}"
  $GIT clone "${REPO_URL}" "${REPO_DIR}"
fi

echo "Building relay image..."
$DOCKER build -t kreo-relay "${REPO_DIR}"

COMPOSE_FILE="${TARGET_DIR}/docker-compose.yml"
cat > "${COMPOSE_FILE}" <<EOF
version: "3.8"
services:
EOF

for i in $(seq 1 "${RELAY_COUNT}"); do
  PORT=$((START_PORT + i - 1))
  PUBLIC_HOST="${HOST_PATTERN/\{N\}/${i}}"
  RELAY_URL="ws://${PUBLIC_HOST}"
  [[ "${ADD_PORT}" =~ ^[Yy]$ ]] && RELAY_URL="${RELAY_URL}:${PORT}"

  cat >> "${COMPOSE_FILE}" <<EOF
  kreo-relay-${i}:
    image: kreo-relay
    container_name: kreo-relay-${i}
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
  2) sudo docker compose up -d
  3) Open/forward ports ${START_PORT}..${END_PORT} to this host.
EOF
