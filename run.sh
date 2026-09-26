#!/bin/bash

# Resolve workspace path
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR" || exit 1

echo "[*] Starting GOT JOED NIDS Launcher..."

# Clean up any lingering process on port 11050
if command -v fuser >/dev/null 2>&1; then
    fuser -k 11050/tcp >/dev/null 2>&1
else
    echo "[!] 'fuser' command not found. Port 11050 cleanup skipped."
fi

# Execute engine with unbuffered output (-u) for real-time logging
python3 -u core/engine.py

# Terminal reset guard on exit
stty sane 2>/dev/null
echo "[*] GOT JOED NIDS shut down cleanly."