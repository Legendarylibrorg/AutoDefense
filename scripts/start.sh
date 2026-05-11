#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Desktop / Docker Engine and re-run." >&2
  exit 1
fi

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo "Docker Compose is required: install the Compose V2 plugin (docker compose) or docker-compose." >&2
    exit 1
  fi
}

if [ ! -f .env ]; then
  cp .env.example .env
fi

# Generate a 32-byte base64-encoded AES-256 key.
gen_key_b64() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32 | tr -d '\n'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode(),end='')"
  else
    echo "ERROR: openssl or python3 required to generate encryption keys" >&2
    exit 1
  fi
}

# Generate a 48-char hex token for API keys / passwords.
gen_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24 | tr -d '\n'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import os;print(os.urandom(24).hex(),end='')"
  else
    echo "ERROR: openssl or python3 required to generate tokens" >&2
    exit 1
  fi
}

# Fill an empty key variable in .env with a freshly generated value.
# "Empty" means missing value after = (optional trailing whitespace only counts as empty).
fill_key() {
  var="$1"
  generator="$2"
  if grep -qE "^${var}=.+$" .env 2>/dev/null; then
    return 0
  fi
  key=$($generator)
  tmp=$(mktemp "${TMPDIR:-/tmp}/autodefense.XXXXXX") || exit 1
  if ! sed "s|^${var}=.*|${var}=${key}|" .env >"$tmp"; then
    rm -f "$tmp"
    exit 1
  fi
  mv "$tmp" .env
  echo "Generated ${var}"
}

fill_key AUTODEFENSE_DATA_KEY_B64       gen_key_b64
fill_key AUTODEFENSE_TRANSPORT_KEY_B64  gen_key_b64
fill_key AUTODEFENSE_API_KEY            gen_token
fill_key AUTODEFENSE_SCANNER_HMAC_KEY   gen_token
fill_key AUTODEFENSE_REDIS_PASSWORD     gen_token

echo ""
echo "=============================="
echo "  API Key (save this): $(grep '^AUTODEFENSE_API_KEY=' .env | cut -d= -f2-)"
echo "=============================="
echo ""

# Fail fast if compose file or env is invalid (before a long image build).
compose config -q

compose up --build
