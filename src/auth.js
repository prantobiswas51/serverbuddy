'use strict';
const crypto = require('crypto');

const SCRYPT = { N: 16384, r: 8, p: 1 };

// Format: scrypt:<saltHex>:<hashHex>   (no "$" so it is safe in systemd env files)
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 32, SCRYPT);
  return `scrypt:${salt.toString('hex')}:${h.toString('hex')}`;
}

function verifyPassword(pw, stored) {
  try {
    const [alg, s, h] = String(stored).split(':');
    if (alg !== 'scrypt') return false;
    const got = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 32, SCRYPT);
    const exp = Buffer.from(h, 'hex');
    return exp.length === got.length && crypto.timingSafeEqual(got, exp);
  } catch {
    return false;
  }
}

const b64 = (b) => Buffer.from(b).toString('base64url');

function sign(payload, secret) {
  const body = b64(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function verify(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;
  const exp = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  const a = Buffer.from(mac);
  const b = Buffer.from(exp);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return p.exp > Date.now() ? p : null;
  } catch {
    return null;
  }
}

// Failed-login throttle per IP: 5 failures / 15 minutes.
class LoginLimiter {
  constructor(max = 5, windowMs = 15 * 60 * 1000) { this.max = max; this.windowMs = windowMs; this.m = new Map(); }
  blocked(ip) {
    const e = this.m.get(ip);
    if (!e) return false;
    if (Date.now() > e.reset) { this.m.delete(ip); return false; }
    return e.n >= this.max;
  }
  fail(ip) {
    const e = this.m.get(ip);
    if (!e || Date.now() > e.reset) this.m.set(ip, { n: 1, reset: Date.now() + this.windowMs });
    else e.n++;
  }
  ok(ip) { this.m.delete(ip); }
}

module.exports = { hashPassword, verifyPassword, sign, verify, LoginLimiter };
