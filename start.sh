#!/usr/bin/env sh
# Start PHP Migration Analyzer (Linux / macOS / Git Bash)
set -e
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
  echo "[ERROR] Node.js is not installed. Download it from https://nodejs.org/ (version 18 or newer)."
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "Installing dependencies..."
  npm install --omit=dev
fi

PORT="${PORT:-3000}"
export PORT
URL="http://localhost:$PORT"
echo "Starting PHP Migration Analyzer on $URL"

# open the browser after the server has had a moment to start
(
  sleep 2
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1
  elif command -v open >/dev/null 2>&1; then open "$URL"
  fi
) &

exec node server.js
