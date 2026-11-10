# ServerBuddy

One dashboard for a single VPS: **system performance**, **security threats** and **PM2 errors for every user**.
Zero npm dependencies. Runs as a root systemd service so it can see all users' PM2 apps, the SSH journal and file hashes.

## What it watches

| Area | Checks |
|---|---|
| **System** | CPU, memory, swap, disks, network throughput, connections, top processes, 15 min history |
| **SSH** | Failed attempts (10m / 1h / 24h), top attacker IPs and usernames, active brute force not yet banned, every successful login (new source = alert), live sessions |
| **Posture** | `PermitRootLogin`, `PasswordAuthentication`, ufw, fail2ban (+ banned IPs), unexpected public ports, service status, TLS cert expiry, pending security updates, reboot-required |
| **Integrity** | SHA-256 baseline of `/etc/passwd`, `shadow`, `sudoers(.d)`, `sshd_config`, cron, `ld.so.preload`, every `authorized_keys`. Extra UID 0 accounts |
| **Web** | nginx access log: requests, 4xx/5xx, scanner probes (`.env`, `wp-login`, `phpmyadmin`...), top scanner IPs |
| **PM2** | Every user with a `~/.pm2`: status, restarts and crash loops, CPU/memory, **new error lines from each app's error log**, "daemon down but apps saved" (e.g. after a reboot without `pm2 startup`) |

Alerts have severity (critical / high / medium) and a stable id. **Acknowledge** marks a login source or changed file as expected (the file becomes the new integrity baseline). New critical/high alerts can also be pushed to a webhook.

## Install (on the VPS, as a sudoer)

```bash
git clone <your repo> ServerBuddy && cd ServerBuddy      # or scp the folder
sudo ./install.sh
```

The installer copies the app to `/opt/serverbuddy`, writes `/etc/serverbuddy/serverbuddy.env`, generates a random password (printed **once**), installs and starts the `serverbuddy` systemd service. Re-running it upgrades the code and keeps your config.

```bash
sudo ./install.sh --set-password     # change the password
sudo ./install.sh --uninstall        # remove the service
journalctl -u serverbuddy -f         # logs
```

First start only: every SSH login from the last 30 days is treated as a known source, so you are not flooded with alerts for your own history.

## Push to deploy (PC → GitHub → VPS)

`git push` to `main` runs the tests on GitHub, then deploys to the VPS. On the server the deploy fetches `origin/main`, re-runs the tests, installs, health-checks `/healthz`, and **rolls back to the previous commit automatically** if the new version doesn't come up healthy.

The CI key is locked down: in `authorized_keys` it carries `command="sudo /usr/local/sbin/serverbuddy-deploy",restrict`, and sudoers lets that user run only that one script. A leaked CI key can trigger a deploy of your own `main` branch and nothing else (no shell, no port forwarding, no other command).

**One-time setup**

1. **On your PC**, make a dedicated CI key (no passphrase, used by nothing else):
   ```powershell
   ssh-keygen -t ed25519 -N '""' -C serverbuddy-ci -f $HOME\.ssh\serverbuddy_ci
   ```
2. **On the VPS**, if the code isn't there yet, clone it once, then run the setup (paste your `serverbuddy_ci.pub` line):
   ```bash
   git clone https://github.com/prantobiswas51/serverbuddy.git ~/serverbuddy && cd ~/serverbuddy
   sudo bash scripts/setup-deploy.sh \
     --repo https://github.com/prantobiswas51/serverbuddy.git \
     --pubkey "ssh-ed25519 AAAA... serverbuddy-ci"
   ```
   This clones to `/opt/serverbuddy-src`, installs `/usr/local/sbin/serverbuddy-deploy`, adds the sudoers rule and the locked key, then runs the first deploy (the dashboard password is printed once).
3. **On GitHub** add four repository secrets (Settings → Secrets and variables → Actions), or with the `gh` CLI from your PC:
   ```powershell
   gh secret set VPS_HOST --body "144.79.218.184"
   gh secret set VPS_USER --body "bongomaker"
   gh secret set VPS_SSH_KEY < $HOME\.ssh\serverbuddy_ci
   ssh-keyscan -t ed25519 144.79.218.184 | gh secret set VPS_HOST_KEY
   ```
   Check that the `ssh-keyscan` fingerprint matches the one you trust: `ssh-keyscan -t ed25519 144.79.218.184 | ssh-keygen -lf -`.
4. `git push`. Watch it in the repo's **Actions** tab. Re-run a deploy any time with *Run workflow*.

**Security notes**

- Anyone who can push to `main` effectively gets root on the VPS (the deploy installs and runs that code as root). Keep the repo's write access to yourself and turn on branch protection for `main`. The workflow never runs on pull requests, and secrets are not exposed to forks.
- Logs of a deploy: the Actions run output, and `journalctl -u serverbuddy` on the server.
- Manual deploy from the server: `sudo serverbuddy-deploy` (`FORCE=1 sudo -E serverbuddy-deploy` to redeploy the same commit).

## Open the dashboard

It listens on **127.0.0.1:7070 only**. Pick one:

**SSH tunnel (simplest, nothing exposed):**
```powershell
ssh -L 7070:127.0.0.1:7070 bongomaker@YOUR_SERVER_IP
```
then open http://localhost:7070.

**nginx + HTTPS (e.g. `status.example.com`):** point DNS at the server, then
```nginx
server {
    listen 80;
    server_name status.example.com;
    location / {
        proxy_pass http://127.0.0.1:7070;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;          # needed for the live stream (SSE)
        proxy_read_timeout 1h;
    }
}
```
Run `certbot --nginx -d status.example.com`, then set `SB_TRUST_PROXY=1` in the env file and `sudo systemctl restart serverbuddy`. Login is rate-limited (5 failures / 15 min per IP) and sessions are HttpOnly + SameSite=Strict cookies, but a tunnel or an IP allow-list on that nginx server block is still safer.

## Configuration (`/etc/serverbuddy/serverbuddy.env`)

| Variable | Default | Meaning |
|---|---|---|
| `SB_HOST` / `SB_PORT` | `127.0.0.1` / `7070` | Bind address |
| `SB_USER` / `SB_PASSWORD_HASH` | `admin` / generated | Login (hash from `scripts/hash-password.js`) |
| `SB_ALLOWED_PORTS` | `22,80,443` | Public ports that are expected; others raise a HIGH alert |
| `SB_ALLOWED_LOGIN_USERS` | empty | If set, an SSH login by anyone else is CRITICAL |
| `SB_SERVICES` | `ssh,nginx,postgresql,mosquitto,fail2ban` | systemd units to watch |
| `SB_NGINX_LOG` | `/var/log/nginx/access.log` | Access log to analyse |
| `SB_WEBHOOK_URL` | empty | POST `{text, alert}` JSON on new critical/high alerts |
| `SB_TRUST_PROXY` | `0` | Trust `X-Forwarded-*` (only behind your own nginx) |
| `SB_DEPLOY_KEY_FPS` | auto | SHA256 fingerprint(s) of the CI deploy key. `install.sh` fills it in from `authorized_keys`; logins with it show as "deploy (CI)" and never raise new-login alerts |

## How multi-user PM2 works

For each account in `/etc/passwd` that has a `~/.pm2` folder, ServerBuddy finds that user's `pm2` binary (`~/.nvm/versions/node/*/bin/pm2`, volta, npm-global, `/usr/local/bin`), checks the daemon pid, and runs `pm2 jlist` as that user via `runuser`. Error lines are read straight from each app's `pm_err_log_path`, so new errors show up within seconds without touching the apps.

## Notes and limits

- **Cloudflare-proxied sites:** nginx logs Cloudflare's IPs, not visitors'. Add `set_real_ip_from` + `real_ip_header CF-Connecting-IP;` to nginx if you want real scanner IPs in the Web panel.
- SSH data comes from `journalctl -t sshd -t sshd-session` (falls back to `/var/log/auth.log`).
- Needs Linux + systemd. On Windows/macOS use `npm run dev` for the UI with mock data (login `admin` / `admin`, never used in production).
- It reports and alerts; it does not ban IPs itself. Use fail2ban for that.

## Development

```bash
npm run dev      # mock data on http://127.0.0.1:7070
npm test         # parser and alert-rule tests (node:test)
```
