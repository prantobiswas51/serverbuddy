#!/usr/bin/env bash
# Server-side deploy. Runs as root via sudo; installed to /usr/local/sbin/serverbuddy-deploy
# (a root-owned copy, so it is not overwritten while it runs and cannot be edited by the CI user).
#
# What it does: fetch origin/<branch> -> install -> health check -> roll back to the
# previous commit if the new version does not come up healthy.
set -euo pipefail

CONF=/etc/serverbuddy/deploy.env
[ -f "$CONF" ] || { echo "missing $CONF - run scripts/setup-deploy.sh first" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"
: "${DEPLOY_SRC:?}" "${DEPLOY_BRANCH:?}"

log() { printf '[deploy %s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# One deploy at a time (two quick pushes must not interleave).
exec 9>/var/lock/serverbuddy-deploy.lock
flock -w 120 9 || { log "another deploy is running"; exit 1; }

healthy() {
  local port; port="$(grep '^SB_PORT=' /etc/serverbuddy/serverbuddy.env | cut -d= -f2)"
  for _ in $(seq 1 15); do
    if curl -fsS --max-time 2 "http://127.0.0.1:${port:-7070}/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

cd "$DEPLOY_SRC"
PREV="$(git rev-parse HEAD)"
log "current: ${PREV:0:8}"

git fetch --quiet --prune origin "$DEPLOY_BRANCH"
NEW="$(git rev-parse "origin/$DEPLOY_BRANCH")"

if [ "$NEW" = "$PREV" ] && systemctl is-active --quiet serverbuddy && [ -z "${FORCE:-}" ]; then
  log "already up to date (${NEW:0:8}), nothing to do"
  exit 0
fi

log "deploying ${NEW:0:8}: $(git log -1 --format=%s "origin/$DEPLOY_BRANCH")"
git reset --hard --quiet "origin/$DEPLOY_BRANCH"
git clean -fdq

# Cheap safety net before touching production: the tests must pass with the server's own Node.
TESTLOG="$(mktemp)"
trap 'rm -f "$TESTLOG"' EXIT
if command -v node >/dev/null && ! node --test >"$TESTLOG" 2>&1; then
  log "tests FAILED on the server, aborting (nothing was installed)"
  tail -25 "$TESTLOG"
  git reset --hard --quiet "$PREV"
  exit 1
fi

bash ./install.sh

if healthy; then
  log "healthy on ${NEW:0:8}"
else
  log "NEW VERSION IS NOT HEALTHY - rolling back to ${PREV:0:8}"
  journalctl -u serverbuddy -n 25 --no-pager || true
  git reset --hard --quiet "$PREV"
  bash ./install.sh
  healthy && log "rolled back OK" || log "rollback also unhealthy: check 'journalctl -u serverbuddy'"
  exit 1
fi

# Refresh this script's own installed copy atomically (rename keeps the running inode intact).
if ! cmp -s scripts/deploy.sh /usr/local/sbin/serverbuddy-deploy; then
  install -m 755 -o root -g root scripts/deploy.sh /usr/local/sbin/serverbuddy-deploy.new
  mv -f /usr/local/sbin/serverbuddy-deploy.new /usr/local/sbin/serverbuddy-deploy
  log "deploy script itself updated"
fi
log "done"
