#!/usr/bin/env bash
# ServerBuddy installer. Run as root from the repo folder:
#   sudo ./install.sh                     install or upgrade (keeps your config)
#   sudo ./install.sh --set-password      change the dashboard password
#   sudo ./install.sh --uninstall         remove the service (keeps /var/lib/serverbuddy data)
# Optional env: SB_PORT=7070  SB_HOST=127.0.0.1  SB_USER=admin  SB_INIT_PASSWORD=...
set -euo pipefail

APP_DIR=/opt/serverbuddy
ENV_DIR=/etc/serverbuddy
ENV_FILE=$ENV_DIR/serverbuddy.env
DATA_DIR=/var/lib/serverbuddy
UNIT=/etc/systemd/system/serverbuddy.service
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo ./install.sh). Root is needed to read other users' PM2, auth logs and file hashes."
command -v systemctl >/dev/null || die "systemd is required."

find_node() {
  local n
  n="$(command -v node || true)"
  if [ -n "$n" ] && [ "$("$n" -p 'process.versions.node.split(".")[0]')" -ge 20 ]; then echo "$n"; return 0; fi
  return 1
}

rand() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }

set_env() { # set_env KEY VALUE  (replace or append in $ENV_FILE)
  if grep -q "^$1=" "$ENV_FILE" 2>/dev/null; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"; else echo "$1=$2" >> "$ENV_FILE"; fi
}

if [ "${1:-}" = "--uninstall" ]; then
  say "Stopping and removing the service"
  systemctl disable --now serverbuddy 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload
  rm -rf "$APP_DIR"
  say "Removed. Config ($ENV_DIR) and data ($DATA_DIR) were kept; delete them by hand if you want."
  exit 0
fi

NODE_BIN="$(find_node || true)"
if [ -z "$NODE_BIN" ]; then
  say "Node.js >= 20 not found for root. Installing from apt..."
  apt-get update -qq && apt-get install -y -qq nodejs >/dev/null
  NODE_BIN="$(find_node || true)"
  [ -n "$NODE_BIN" ] || die "Node.js >= 20 is still missing. Install it system-wide (e.g. NodeSource) and re-run."
fi
say "Using Node $("$NODE_BIN" -v) at $NODE_BIN"

if [ "${1:-}" = "--set-password" ]; then
  [ -f "$ENV_FILE" ] || die "Not installed yet."
  PW="${SB_INIT_PASSWORD:-}"
  if [ -z "$PW" ]; then read -r -s -p "New dashboard password: " PW; echo; fi
  [ "${#PW}" -ge 10 ] || die "Use at least 10 characters."
  set_env SB_PASSWORD_HASH "$("$NODE_BIN" "$APP_DIR/scripts/hash-password.js" "$PW")"
  systemctl restart serverbuddy
  say "Password changed."
  exit 0
fi

say "Installing files to $APP_DIR"
mkdir -p "$APP_DIR" "$ENV_DIR" "$DATA_DIR"
# Copy the app but never the dev data/config.
(cd "$SRC" && tar --exclude=.git --exclude=node_modules --exclude=data --exclude=.env --exclude=.claude --exclude=.github -cf - .) | (cd "$APP_DIR" && tar -xf -)
chown -R root:root "$APP_DIR"
chmod 700 "$DATA_DIR"; chmod 700 "$ENV_DIR"

NEW_PW=""
if [ ! -f "$ENV_FILE" ]; then
  say "Creating $ENV_FILE"
  NEW_PW="${SB_INIT_PASSWORD:-$(rand 20)}"
  umask 077
  cat > "$ENV_FILE" <<EOF
SB_HOST=${SB_HOST:-127.0.0.1}
SB_PORT=${SB_PORT:-7070}
SB_USER=${SB_USER:-admin}
SB_PASSWORD_HASH=$("$NODE_BIN" "$APP_DIR/scripts/hash-password.js" "$NEW_PW")
SB_SECRET=$(rand 48)
SB_DATA_DIR=$DATA_DIR
# Public ports you expect to see open (anything else raises an alert):
SB_ALLOWED_PORTS=22,80,443
# Only these users may log in over SSH without raising a CRITICAL alert (empty = any known user):
SB_ALLOWED_LOGIN_USERS=
# Services to watch:
SB_SERVICES=ssh,nginx,postgresql,mosquitto,fail2ban
SB_NGINX_LOG=/var/log/nginx/access.log
# Set to 1 only when running behind nginx on the same host (trusts X-Forwarded-For/Proto):
SB_TRUST_PROXY=0
# Optional webhook (Slack/Discord/ntfy...) for new critical/high alerts:
SB_WEBHOOK_URL=
EOF
  chmod 600 "$ENV_FILE"
else
  say "Keeping existing $ENV_FILE"
fi

say "Installing systemd unit"
cat > "$UNIT" <<EOF
[Unit]
Description=ServerBuddy - VPS security and performance dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$NODE_BIN $APP_DIR/src/index.js
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
MemoryMax=300M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable serverbuddy >/dev/null
systemctl restart serverbuddy
sleep 1
systemctl is-active --quiet serverbuddy || { journalctl -u serverbuddy -n 20 --no-pager; die "Service failed to start."; }

PORT="$(grep '^SB_PORT=' "$ENV_FILE" | cut -d= -f2)"
say "ServerBuddy is running on 127.0.0.1:$PORT"
if [ -n "$NEW_PW" ]; then
  echo
  echo "  Username: $(grep '^SB_USER=' "$ENV_FILE" | cut -d= -f2)"
  echo "  Password: $NEW_PW     <-- shown once, save it now (change later with: sudo $APP_DIR/install.sh --set-password)"
fi
echo
echo "  Open it from your PC with an SSH tunnel:"
echo "    ssh -L 7070:127.0.0.1:$PORT <user>@<server-ip>   then browse http://localhost:7070"
echo "  Or put it behind nginx + HTTPS (see README.md)."
