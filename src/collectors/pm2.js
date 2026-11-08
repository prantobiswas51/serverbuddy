'use strict';
const fs = require('fs');
const path = require('path');
const { run, tailFile, readText, isLinux } = require('../util');

// Lines in PM2 error logs that look like real problems (not just any stderr noise).
// No leading \b on purpose: it must match TypeError, UnhandledPromiseRejection, MongoServerError...
const ERROR_RE = /(error|exception|unhandled|fatal|panic|crash|failed|ECONNREFUSED|ECONNRESET|ETIMEDOUT|EADDRINUSE|ENOENT|EACCES|ERR_[A-Z_]+|out of memory|heap out)/i;
const SAFE_USER = /^[a-z_][a-z0-9_-]*\$?$/i;

// ---- pure helpers (unit-tested) -------------------------------------------
function cmpVersionDesc(a, b) {
  const pa = a.replace(/^v/, '').split('.').map(Number);
  const pb = b.replace(/^v/, '').split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((pb[i] || 0) !== (pa[i] || 0)) return (pb[i] || 0) - (pa[i] || 0);
  return 0;
}

// `pm2 jlist` may print banner lines before the JSON array.
function parseJlist(out) {
  const start = out.search(/\[\s*(\{|\])/);
  const end = out.lastIndexOf(']');
  if (start < 0 || end < start) return null;
  try { return JSON.parse(out.slice(start, end + 1)); } catch { return null; }
}

function extractErrors(text) {
  return text.split('\n').filter((l) => l.trim() && ERROR_RE.test(l)).map((l) => l.trim().slice(0, 300));
}

// ---- discovery --------------------------------------------------------------
function discoverUsers() {
  const users = [];
  for (const line of readText('/etc/passwd').split('\n')) {
    const f = line.split(':');
    if (f.length < 7 || !SAFE_USER.test(f[0])) continue;
    const home = f[5];
    if (home && fs.existsSync(path.join(home, '.pm2'))) users.push({ user: f[0], uid: Number(f[2]), home });
  }
  return users;
}

function findPm2(home) {
  const nvmDir = path.join(home, '.nvm', 'versions', 'node');
  try {
    for (const v of fs.readdirSync(nvmDir).sort(cmpVersionDesc)) {
      const bin = path.join(nvmDir, v, 'bin', 'pm2');
      if (fs.existsSync(bin)) return { bin, binDir: path.dirname(bin) };
    }
  } catch { /* no nvm */ }
  for (const bin of [
    path.join(home, '.volta', 'bin', 'pm2'),
    path.join(home, '.npm-global', 'bin', 'pm2'),
    path.join(home, '.local', 'bin', 'pm2'),
    '/usr/local/bin/pm2',
    '/usr/bin/pm2',
  ]) if (fs.existsSync(bin)) return { bin, binDir: path.dirname(bin) };
  return null;
}

function daemonAlive(home) {
  const pid = Number(readText(path.join(home, '.pm2', 'pm2.pid')).trim());
  if (!pid) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

function dumpCount(home) {
  try { const d = JSON.parse(readText(path.join(home, '.pm2', 'dump.pm2'))); return Array.isArray(d) ? d.length : 0; } catch { return 0; }
}

// ---- collector --------------------------------------------------------------
function create() {
  const logState = new Map(); // errLogPath -> { offset }
  const errors = new Map();   // appKey -> [{ t, msg }]  (t === null for pre-existing lines)
  const restarts = new Map(); // appKey -> [{ t, n }]

  async function scanErrLog(key, file) {
    if (!file) return;
    const st = logState.get(file);
    let list = errors.get(key);
    if (!list) { list = []; errors.set(key, list); }
    if (!st) {
      const f = await tailFile(file, 64 * 1024);
      if (!f) return;
      logState.set(file, { offset: f.size });
      for (const msg of extractErrors(f.text).slice(-20)) list.push({ t: null, msg });
      return;
    }
    const f = await tailFile(file, 512 * 1024, st.offset > 0 ? st.offset : 0);
    if (!f) return;
    if (f.size < st.offset) { st.offset = 0; return; } // rotated/truncated: re-read next tick
    st.offset = f.size;
    const now = Date.now();
    for (const msg of extractErrors(f.text)) list.push({ t: now, msg });
    while (list.length > 150) list.shift();
  }

  function errStats(key) {
    const list = errors.get(key) || [];
    const now = Date.now();
    return {
      m5: list.filter((e) => e.t && now - e.t <= 300e3).length,
      h1: list.filter((e) => e.t && now - e.t <= 3600e3).length,
      last: list.slice(-6).reverse().map((e) => ({ t: e.t, msg: e.msg })),
    };
  }

  function restartsIn10m(key, current) {
    let h = restarts.get(key);
    if (!h) { h = []; restarts.set(key, h); }
    const now = Date.now();
    h.push({ t: now, n: current });
    while (h.length && now - h[0].t > 15 * 60e3) h.shift();
    const base = h.find((x) => now - x.t <= 600e3) || h[0];
    return Math.max(0, current - base.n);
  }

  async function collectUser(u) {
    const res = { user: u.user, home: u.home, daemon: daemonAlive(u.home), apps: [], note: '' };
    const bin = findPm2(u.home);
    if (!bin) { res.note = 'pm2 binary not found for this user'; return res; }
    res.bin = bin.bin;
    if (!res.daemon) {
      const saved = dumpCount(u.home);
      res.note = saved ? `PM2 daemon is not running, but ${saved} app(s) are saved. They will not serve traffic.` : 'PM2 daemon not running';
      res.savedApps = saved;
      return res;
    }
    const env = [`PM2_HOME=${path.join(u.home, '.pm2')}`, `HOME=${u.home}`, `PATH=${bin.binDir}:/usr/local/bin:/usr/bin:/bin`];
    const me = process.getuid ? process.getuid() : -1;
    let r;
    if (me === 0) r = await run('runuser', ['-u', u.user, '--', 'env', ...env, bin.bin, 'jlist'], { timeout: 20000 });
    else if (me === u.uid) r = await run(bin.bin, ['jlist'], { timeout: 20000, env: Object.fromEntries(env.map((e) => e.split(/=(.*)/s).slice(0, 2))) });
    else { res.note = 'Run ServerBuddy as root to inspect other users'; return res; }
    const list = r.ok ? parseJlist(r.out) : null;
    if (!list) { res.note = `pm2 jlist failed: ${(r.err || r.out).trim().slice(0, 160)}`; return res; }

    for (const p of list) {
      const e = p.pm2_env || {};
      const key = `${u.user}:${p.name}:${p.pm_id}`;
      await scanErrLog(key, e.pm_err_log_path);
      res.apps.push({
        id: p.pm_id,
        name: p.name,
        status: e.status || 'unknown',
        restarts: e.restart_time || 0,
        restarts10m: restartsIn10m(key, e.restart_time || 0),
        unstable: e.unstable_restarts || 0,
        uptimeMs: e.status === 'online' && e.pm_uptime ? Date.now() - e.pm_uptime : 0,
        cpu: (p.monit && p.monit.cpu) || 0,
        mem: (p.monit && p.monit.memory) || 0,
        mode: e.exec_mode || '',
        errors: errStats(key),
        errLog: e.pm_err_log_path || '',
      });
    }
    return res;
  }

  return {
    async collect() {
      if (!isLinux) return { users: [], total: { apps: 0, online: 0, bad: 0, errors5m: 0 }, note: 'PM2 discovery needs Linux' };
      const users = [];
      for (const u of discoverUsers()) users.push(await collectUser(u));
      const apps = users.flatMap((u) => u.apps);
      return {
        users,
        total: {
          apps: apps.length,
          online: apps.filter((a) => a.status === 'online').length,
          bad: apps.filter((a) => a.status === 'errored' || a.status === 'stopped').length,
          errors5m: apps.reduce((n, a) => n + a.errors.m5, 0),
        },
      };
    },
  };
}

module.exports = { create, parseJlist, extractErrors, cmpVersionDesc, ERROR_RE };
