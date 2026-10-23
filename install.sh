#!/usr/bin/env sh
# Install PHP Migration Analyzer dependencies (Linux / macOS / Git Bash)
set -e
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
  echo "[ERROR] Node.js is not installed. Download it from https://nodejs.org/ (version 18 or newer)."
  exit 1
fi

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "[ERROR] Node.js 18 or newer is required. Found: $(node --version)"
  exit 1
fi

echo "Using Node.js $(node --version)"
echo "Installing dependencies..."
npm install --omit=dev

chmod +x start.sh 2>/dev/null || true

echo
echo "Install complete. Run ./start.sh to launch PHP Migration Analyzer."
if [ -t 0 ]; then
  printf "Start it now? [y/N] "
  read -r answer
  case "$answer" in
    [Yy]*) exec ./start.sh ;;
  esac
fi
