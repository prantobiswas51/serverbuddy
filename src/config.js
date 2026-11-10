'use strict';
const fs = require('fs');
const path = require('path');

// Minimal .env loader for local development. In production systemd injects
// the variables from /etc/serverbuddy/serverbuddy.env.
function loadDotEnv(file) {
  try {
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  } catch { /* no .env */ }
}
loadDotEnv(path.join(process.cwd(), '.env'));

const list = (v, d) => (v === undefined || v === '' ? d : v.split(',').map((s) => s.trim()).filter(Boolean));
const mock = process.argv.includes('--mock') || process.env.SB_MOCK === '1';

module.exports = {
  mock,
  // Safe default: listen on localhost only. Reach it via SSH tunnel or an nginx reverse proxy.
  host: mock ? '127.0.0.1' : process.env.SB_HOST || '127.0.0.1',
  port: Number(process.env.SB_PORT) || 7070,
  user: process.env.SB_USER || 'admin',
  passwordHash: process.env.SB_PASSWORD_HASH || '',
  secret: process.env.SB_SECRET || '',
  trustProxy: process.env.SB_TRUST_PROXY === '1',
  dataDir: process.env.SB_DATA_DIR || (process.platform === 'win32' ? path.join(process.cwd(), 'data') : '/var/lib/serverbuddy'),

  // Security policy
  allowedPorts: list(process.env.SB_ALLOWED_PORTS, ['22', '80', '443']).map(Number),
  allowedLoginUsers: list(process.env.SB_ALLOWED_LOGIN_USERS, []), // empty = don't restrict by user name
  // SHA256 fingerprints of the CI deploy key(s); install.sh fills this in from authorized_keys.
  deployKeyFps: list(process.env.SB_DEPLOY_KEY_FPS, []),
  services: list(process.env.SB_SERVICES, ['ssh', 'nginx', 'postgresql', 'mosquitto', 'fail2ban']),
  nginxLog: process.env.SB_NGINX_LOG || '/var/log/nginx/access.log',

  // Optional: POST JSON here whenever a new critical/high alert appears (Slack/Discord/ntfy/etc.)
  webhook: process.env.SB_WEBHOOK_URL || '',

  intervals: { system: 3000, pm2: 6000, sec: 20000, auth: 30000, web: 30000, slow: 300000 },
};
