#!/usr/bin/env bash
# One-time VPS setup for push-to-deploy. Run as root (sudo) on the server:
#
#   sudo bash scripts/setup-deploy.sh \
#        --repo   https://github.com/prantobiswas51/serverbuddy.git \
#        --pubkey "ssh-ed25519 AAAA... serverbuddy-ci" \
#        [--user bongomaker] [--branch main] [--no-deploy]
#
# Result: GitHub Actions can SSH in as <user> with a key that can do exactly ONE thing:
# run `sudo /usr/local/sbin/serverbuddy-deploy`. No shell, no port forwarding, no other command.
# Safe to re-run.
set -euo pipefail

REPO=""; PUBKEY=""; DUSER="bongomaker"; BRANCH="main"; DEPLOY_NOW=1
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --pubkey) PUBKEY="$2"; shift 2 ;;
    --user) DUSER="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --no-deploy) DEPLOY_NOW=0; shift ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[[ "$REPO" =~ ^https://[A-Za-z0-9._/-]+$ ]] || die "--repo must be a plain https URL (public repo, no credentials)"
[[ "$PUBKEY" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ [A-Za-z0-9@._-]+)?$ ]] || die "--pubkey must be a single ssh-ed25519 public key line"
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || die "bad --branch"
id "$DUSER" >/dev/null 2>&1 || die "user '$DUSER' does not exist"
command -v git >/dev/null || { say "installing git"; apt-get update -qq && apt-get install -y -qq git >/dev/null; }

TMPKEY="$(mktemp)"; trap 'rm -f "$TMPKEY"' EXIT
echo "$PUBKEY" > "$TMPKEY"
ssh-keygen -lf "$TMPKEY" >/dev/null 2>&1 || die "the public key is not valid"

SRC=/opt/serverbuddy-src
if [ -d "$SRC/.git" ]; then
  say "Source clone exists at $SRC"
else
  say "Cloning $REPO -> $SRC"
  git clone --quiet --branch "$BRANCH" "$REPO" "$SRC"
fi

say "Writing /etc/serverbuddy/deploy.env"
mkdir -p /etc/serverbuddy && chmod 700 /etc/serverbuddy
cat > /etc/serverbuddy/deploy.env <<EOF
DEPLOY_SRC=$SRC
DEPLOY_BRANCH=$BRANCH
DEPLOY_REPO=$REPO
EOF
chmod 600 /etc/serverbuddy/deploy.env

say "Installing /usr/local/sbin/serverbuddy-deploy (root-owned)"
install -m 755 -o root -g root "$SRC/scripts/deploy.sh" /usr/local/sbin/serverbuddy-deploy

say "Allowing $DUSER to run only that script with sudo"
SUDOERS=/etc/sudoers.d/serverbuddy-deploy
echo "$DUSER ALL=(root) NOPASSWD: /usr/local/sbin/serverbuddy-deploy" > "$SUDOERS.tmp"
chmod 440 "$SUDOERS.tmp"
visudo -cf "$SUDOERS.tmp" >/dev/null || { rm -f "$SUDOERS.tmp"; die "sudoers check failed, nothing changed"; }
mv "$SUDOERS.tmp" "$SUDOERS"

say "Authorizing the CI key for $DUSER (forced command, no shell)"
HOME_DIR="$(getent passwd "$DUSER" | cut -d: -f6)"
install -d -m 700 -o "$DUSER" -g "$DUSER" "$HOME_DIR/.ssh"
AK="$HOME_DIR/.ssh/authorized_keys"
touch "$AK"; chown "$DUSER:$DUSER" "$AK"; chmod 600 "$AK"
KEYBODY="$(echo "$PUBKEY" | cut -d' ' -f2)"
if grep -qF "$KEYBODY" "$AK"; then
  say "Key already present"
else
  echo "command=\"sudo /usr/local/sbin/serverbuddy-deploy\",restrict $PUBKEY" >> "$AK"
fi

if [ "$DEPLOY_NOW" -eq 1 ]; then
  say "Running the first deploy"
  /usr/local/sbin/serverbuddy-deploy
fi

say "Setup complete. Add the GitHub secrets (see README: Push to deploy), then push to $BRANCH."
