#!/usr/bin/env bash
# Start msfdb and msfrpcd using credentials from the project .env file.
# Linux/Kali equivalent of scripts/start-msfrpcd.ps1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

MSF_USER=""
MSF_PASSWORD=""
MSF_HOST="127.0.0.1"
MSF_PORT="55553"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "Error: .env file not found at $ENV_FILE. Copy .env.example and fill in credentials." >&2
    exit 1
fi

# Parse .env: skip empty lines, comment lines, and strip optional quotes.
while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"

    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue
    [[ "$line" != *"="* ]] && continue

    key="${line%%=*}"
    value="${line#*=}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
        value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
        value="${value:1:${#value}-2}"
    fi

    case "$key" in
        MSF_USER) MSF_USER="$value" ;;
        MSF_PASSWORD) MSF_PASSWORD="$value" ;;
        MSF_HOST) MSF_HOST="$value" ;;
        MSF_PORT) MSF_PORT="$value" ;;
    esac
done < "$ENV_FILE"

if [[ -z "$MSF_USER" || -z "$MSF_PASSWORD" ]]; then
    echo "Error: MSF_USER and MSF_PASSWORD must be set in .env" >&2
    exit 1
fi

echo "Starting msfdb..."
msfdb start 2>&1

echo "Checking for existing msfrpcd on port $MSF_PORT..."
if ss -tlnp 2>/dev/null | grep -q "$MSF_PORT"; then
    echo "msfrpcd already listening on $MSF_PORT"
else
    echo "Starting msfrpcd (user=$MSF_USER, host=$MSF_HOST, port=$MSF_PORT, no SSL)..."
    msfrpcd -U "$MSF_USER" -P "$MSF_PASSWORD" -S -a "$MSF_HOST" -p "$MSF_PORT" &
    sleep 3
fi

if ss -tlnp 2>/dev/null | grep -q "$MSF_PORT"; then
    echo "msfrpcd is listening on ${MSF_HOST}:${MSF_PORT}"
else
    echo "Error: msfrpcd failed to start on ${MSF_HOST}:${MSF_PORT}" >&2
    exit 1
fi
