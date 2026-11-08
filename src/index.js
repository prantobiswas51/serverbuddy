'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cfg = require('./config');
const { verifyPassword, hashPassword, sign, verify, LoginLimiter } = require('./auth');
const { Monitor } = require('./state');

// ---- safety checks before listening ------------------------------------------
if (cfg.mock && !cfg.passwordHash) cfg.passwordHash = hashPassword('admin'); // dev only
if (!cfg.passwordHash) {
  console.error('SB_PASSWORD_HASH is not set. Generate one with:  node scripts/hash-password.js "your password"');
  process.exit(1);
}
if (!cfg.secret) {
  if (!cfg.mock) console.warn('SB_SECRET not set: sessions will be invalidated on every restart. The installer sets one for you.');
  cfg.secret = crypto.randomBytes(32).toString('hex');
}
if (cfg.host !== '127.0.0.1' && cfg.host !== '::1') {
  console.warn(`WARNING: listening on ${cfg.host}. Put it behind HTTPS (nginx) or keep it on 127.0.0.1 and use an SSH tunnel.`);
}

const PUBLIC = path.join(__dirname, '..', 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
const limiter = new LoginLimiter();
const monitor = new Monitor(cfg);
const sseClients = new Set();

const clientIp = (req) => (cfg.trustProxy && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress);
const secure = (req) => req.socket.encrypted || (cfg.trustProxy && req.headers['x-forwarded-proto'] === 'https');

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
const session = (req) => verify(parseCookies(req).sb_session, cfg.secret);

function baseHeaders(extra = {}) {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ...extra,
  };
}

function json(res, code, obj, extra) {
  res.writeHead(code, baseHeaders({ 'Content-Type': 'application/json; charset=utf-8', ...extra }));
  res.end(JSON.stringify(obj));
}

function readBody(req, limit = 4096) {
  return new Promise((resolve, reject) => {
    let n = 0;
    const chunks = [];
    req.on('data', (c) => { n += c.length; if (n > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? '/index.html' : pathname;
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    res.writeHead(404, baseHeaders({ 'Content-Type': 'text/plain' }));
    return res.end('Not found');
  }
  res.writeHead(200, baseHeaders({ 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' }));
  fs.createReadStream(file).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  try {
    if (p === '/healthz') return json(res, 200, { ok: true });

    // ---- auth ---------------------------------------------------------------
    if (p === '/api/login' && req.method === 'POST') {
      const ip = clientIp(req);
      if (limiter.blocked(ip)) return json(res, 429, { error: 'Too many attempts. Try again in 15 minutes.' });
      let body;
      try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'Bad request' }); }
      const userOk = typeof body.user === 'string' && body.user === cfg.user;
      const passOk = typeof body.password === 'string' && verifyPassword(body.password, cfg.passwordHash);
      if (!(userOk && passOk)) {
        limiter.fail(ip);
        console.warn(`login failed from ${ip}`);
        return json(res, 401, { error: 'Invalid credentials' });
      }
      limiter.ok(ip);
      const token = sign({ u: cfg.user, exp: Date.now() + 12 * 3600e3 }, cfg.secret);
      const cookie = `sb_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${12 * 3600}${secure(req) ? '; Secure' : ''}`;
      return json(res, 200, { ok: true }, { 'Set-Cookie': cookie });
    }
    if (p === '/api/logout' && req.method === 'POST') {
      return json(res, 200, { ok: true }, { 'Set-Cookie': 'sb_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
    }

    // ---- static assets: login page + app shell are public, data is not -------
    if (!p.startsWith('/api/')) return serveStatic(req, res, p);

    if (!session(req)) return json(res, 401, { error: 'Unauthorized' });

    if (p === '/api/state') return json(res, 200, monitor.snapshot || {});

    if (p === '/api/stream') {
      res.writeHead(200, baseHeaders({ 'Content-Type': 'text/event-stream', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' }));
      res.write(`data: ${JSON.stringify(monitor.snapshot)}\n\n`);
      sseClients.add(res);
      req.on('close', () => sseClients.delete(res));
      return undefined;
    }

    if (p === '/api/ack' && req.method === 'POST') {
      if (!String(req.headers['content-type'] || '').includes('application/json')) return json(res, 415, { error: 'JSON only' });
      const body = JSON.parse(await readBody(req));
      return json(res, monitor.ack(String(body.id)) ? 200 : 404, { ok: true });
    }

    return json(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('request error:', e.message);
    if (!res.headersSent) json(res, 500, { error: 'Server error' });
  }
});

(async () => {
  await monitor.start();
  setInterval(() => {
    if (!sseClients.size || !monitor.snapshot) return;
    const msg = `data: ${JSON.stringify(monitor.snapshot)}\n\n`;
    for (const c of sseClients) c.write(msg);
  }, 3000);

  server.listen(cfg.port, cfg.host, () => {
    console.log(`ServerBuddy listening on http://${cfg.host}:${cfg.port}${cfg.mock ? '  (MOCK DATA, login admin/admin)' : ''}`);
    if (process.getuid && process.getuid() !== 0 && !cfg.mock) console.warn('Not running as root: other users\' PM2, auth logs and file integrity will be limited.');
  });
})();

for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { monitor.stop(); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 1500).unref(); });
