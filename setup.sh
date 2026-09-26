#!/bin/bash

# ================================================================
# GOT JOED NIDS/IPS - Automated Host System Setup
# ================================================================

set -e # Halt immediately on execution failure

# 1. Root Execution Check
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run setup script as root: sudo bash setup.sh"
  exit 1
fi

# 2. Workspace Directory Resolution
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[*] Workspace directory resolved to: $PROJECT_DIR"

# 3. Target System User Detection
if [ -n "$SUDO_USER" ]; then
    TARGET_USER="$SUDO_USER"
    echo "[*] Target system user: $TARGET_USER"
else
    TARGET_USER="$(whoami)"
    echo "[*] Defaulting target user: $TARGET_USER"
fi

# 4. System Package Installation via APT
echo "[*] Installing core system & high-performance IPS (ipset) prerequisites..."
export DEBIAN_FRONTEND=noninteractive

# Pre-configure wireshark for non-root packet capturing
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

apt-get update -qq
apt-get install -y -qq tshark python3 python3-pip sqlite3 libcap2-bin iptables ipset net-tools

# 5. Group Permissions & Capture Capabilities
usermod -aG wireshark "$TARGET_USER"

if [ -f /usr/bin/dumpcap ]; then
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap
fi

# Grant network admin capability to Python3 executable for native IPSet manipulation
PYTHON_BIN=$(which python3)
if [ -f "$PYTHON_BIN" ]; then
    setcap cap_net_admin,cap_net_raw+eip "$PYTHON_BIN" 2>/dev/null || true
fi

# 6. Architecture Directory & File Isolation
echo "[*] Verifying project workspace layout..."
mkdir -p "$PROJECT_DIR/core" \
         "$PROJECT_DIR/db" \
         "$PROJECT_DIR/logs" \
         "$PROJECT_DIR/rules" \
         "$PROJECT_DIR/web"

touch "$PROJECT_DIR/core/engine.py"
touch "$PROJECT_DIR/db/feeds.db"
touch "$PROJECT_DIR/logs/threat_events.db"
touch "$PROJECT_DIR/rules/custom.rules"
touch "$PROJECT_DIR/web/index.html"

# 7. Global Python Dependencies Installation
echo "[*] Installing global Python requirements..."
pip3 install --upgrade --ignore-installed requests websockets fastapi uvicorn pydantic --break-system-packages -q

# 8. Folder Ownership & Strict Permissions Assignment
echo "[*] Applying secured workspace permissions for $TARGET_USER..."
chown -R "$TARGET_USER":"$TARGET_USER" "$PROJECT_DIR"
# Hardened permissions: 750 blocks other system users from tampering with rules/logs
chmod -R 750 "$PROJECT_DIR/db" "$PROJECT_DIR/logs" "$PROJECT_DIR/rules"

if [ -f "$PROJECT_DIR/run.sh" ]; then
    chmod +x "$PROJECT_DIR/run.sh"
fi

echo "----------------------------------------------------------------"
echo "[SUCCESS] GOT JOED NIDS/IPS environment fully initialized!"
echo "[INFO] Project Root: $PROJECT_DIR"
echo "[INFO] Active IPS Engine: O(1) IPSet + IPTables Integrated"
echo "[INFO] Log Retention: Dynamic (Configurable via Web UI Settings)"
echo "[INFO] Start Engine: sudo python3 core/engine.py"
echo "----------------------------------------------------------------"