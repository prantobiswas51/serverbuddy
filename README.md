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
