'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { run, readText, isLinux } = require('../util');

// ============================================================================
// Pure parsers (unit-tested)
// ============================================================================

// journalctl "-o short-iso" can print +0600; Date.parse wants +06:00.
const normTs = (s) => Date.parse(String(s).replace(/([+-]\d\d)(\d\d)$/, '$1:$2'));

const PFX = '^(\\S+)\\s+\\S+\\s+sshd(?:-session)?\\[\\d+\\]:\\s+';
const reFailed = new RegExp(PFX + 'Failed (\\S+) for (invalid user )?(\\S+) from (\\S+) port \\d+');
const reInvalid = new RegExp(PFX + 'Invalid user (\\S*) from (\\S+)');
const reAccepted = new RegExp(PFX + 'Accepted (\\S+) for (\\S+) from (\\S+) port \\d+');
const reAuthClose = new RegExp(PFX + '(?:Connection closed by|Disconnected from) authenticating user (\\S+) (\\S+) port \\d+');

/**
 * Turn sshd journal lines into attack attempts and successful logins.
 * An "attempt" is: an Invalid-user line, a failed login for a VALID user, or a
 * pre-auth disconnect for a valid user (what key-only servers log). Failed
 * password lines for invalid users are not counted again (the Invalid-user line covers them).
 */
function parseAuth(text) {
  const attempts = [];
  const accepted = [];
  for (const line of text.split('\n')) {
    if (!line.includes('sshd')) continue;
    let m;
    if ((m = reAccepted.exec(line))) {
      accepted.push({ t: normTs(m[1]), method: m[2], user: m[3], ip: m[4] });
    } else if ((m = reInvalid.exec(line))) {
      attempts.push({ t: normTs(m[1]), user: m[2] || '(empty)', ip: m[3] });
    } else if ((m = reFailed.exec(line))) {
      if (!m[3]) attempts.push({ t: normTs(m[1]), user: m[4], ip: m[5] });
    } else if ((m = reAuthClose.exec(line))) {
      attempts.push({ t: normTs(m[1]), user: m[2], ip: m[3] });
    }
  }
  return { attempts: attempts.filter((a) => !Number.isNaN(a.t)), accepted: accepted.filter((a) => !Number.isNaN(a.t)) };
}

function aggregateAuth(parsed, now = Date.now()) {
  const H = 3600e3;
  const { attempts, accepted } = parsed;
  const inWin = (a, ms) => now - a.t <= ms;
  const byIp = new Map();
  const byUser = new Map();
  for (const a of attempts) {
    let e = byIp.get(a.ip);
    if (!e) { e = { ip: a.ip, n24: 0, n1h: 0, n10m: 0, last: 0, users: new Set() }; byIp.set(a.ip, e); }
    e.n24++;
    if (inWin(a, H)) e.n1h++;
    if (inWin(a, 600e3)) e.n10m++;
    e.last = Math.max(e.last, a.t);
    if (e.users.size < 6) e.users.add(a.user);
    byUser.set(a.user, (byUser.get(a.user) || 0) + 1);
  }
  const topIps = [...byIp.values()]
    .sort((a, b) => b.n24 - a.n24)
    .slice(0, 12)
    .map((e) => ({ ...e, users: [...e.users] }));
  const topUsers = [...byUser.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([user, n]) => ({ user, n }));
  return {
    attempts10m: attempts.filter((a) => inWin(a, 600e3)).length,
    attempts1h: attempts.filter((a) => inWin(a, H)).length,
    attempts24h: attempts.length,
    uniqueIps24h: byIp.size,
    hot: [...byIp.values()].filter((e) => e.n10m >= 10).map((e) => e.ip),
    topIps,
    topUsers,
    accepted: accepted.sort((a, b) => b.t - a.t).slice(0, 25),
  };
}

// `ss -tlnpH`
function parseSs(text) {
  const seen = new Map();
  for (const line of text.split('\n')) {
    const p = line.trim().split(/\s+/);
    if (p.length < 5 || p[0] !== 'LISTEN') continue;
    const local = p[3];
    const i = local.lastIndexOf(':');
    const addr = local.slice(0, i).replace(/^\[|\]$/g, '');
    const port = Number(local.slice(i + 1));
    const proc = (line.match(/users:\(\("([^"]+)"/) || [])[1] || '';
    const isLocal = /^127\./.test(addr) || addr === '::1' || /%lo$/.test(addr);
    const key = `${port}`;
    const prev = seen.get(key);
    if (!prev || (!isLocal && !prev.public)) seen.set(key, { port, addr, proc, public: !isLocal });
  }
  return [...seen.values()].sort((a, b) => a.port - b.port);
}

function parseSshdT(text) {
  const o = {};
  for (const line of text.split('\n')) {
    const m = line.match(/^(\w+)\s+(.*)$/);
    if (m) o[m[1].toLowerCase()] = m[2].trim();
  }
  return o;
}

function parseFail2ban(text) {
  const num = (re) => Number((text.match(re) || [])[1] || 0);
  const list = (text.match(/Banned IP list:\s*(.*)/) || [])[1] || '';
  return {
    banned: num(/Currently banned:\s*(\d+)/),
    totalBanned: num(/Total banned:\s*(\d+)/),
    failed: num(/Currently failed:\s*(\d+)/),
    ips: list.split(/\s+/).filter(Boolean),
  };
}

function parseUfw(text) {
  const active = /Status:\s*active/i.test(text);
  const rules = text.split('\n').filter((l) => /\b(ALLOW|DENY|REJECT|LIMIT)\b/.test(l)).length;
  return { installed: /Status:/i.test(text), active, rules };
}

function parseWho(text) {
  return text.split('\n').filter(Boolean).map((l) => {
    // `who -u`: user tty date time idle pid (host)  -- host is only present for remote sessions
    const m = l.match(/^(\S+)\s+(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d)/);
    const from = l.match(/\(([^)]*)\)\s*$/);
    return m ? { user: m[1], tty: m[2], since: m[3], from: (from && from[1]) || 'local' } : null;
  }).filter(Boolean);
}

function parsePasswd(text) {
  return text.split('\n').filter(Boolean).map((l) => {
    const f = l.split(':');
    return { name: f[0], uid: Number(f[2]), home: f[5], shell: f[6] };
  });
}

function parseGroupMembers(text, groups = ['sudo', 'wheel', 'admin']) {
  const out = new Set();
  for (const l of text.split('\n')) {
    const f = l.split(':');
    if (groups.includes(f[0]) && f[3]) f[3].split(',').forEach((u) => out.add(u));
  }
  return [...out];
}

function parseUpdatesAvailable(text) {
  const total = Number((text.match(/(\d+)\s+update/) || [])[1] || 0);
  const security = Number((text.match(/(\d+)\s+(?:of these updates are standard security|standard security update)/) || [])[1] || 0);
  return { total, security };
}

function parseSystemctlShow(text, units) {
  return text.split(/\n\n+/).filter(Boolean).map((blk, i) => {
    const kv = Object.fromEntries(blk.split('\n').map((l) => l.split(/=(.*)/s).slice(0, 2)));
    return { name: units[i], load: kv.LoadState, active: kv.ActiveState, sub: kv.SubState };
  }).filter((s) => s.name);
}

// ============================================================================
// File integrity monitoring
// ============================================================================
function fimTargets() {
  const t = ['/etc/passwd', '/etc/group', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config', '/etc/crontab', '/etc/ld.so.preload', '/etc/hosts', '/root/.ssh/authorized_keys'];
  for (const d of ['/etc/sudoers.d', '/etc/ssh/sshd_config.d', '/etc/cron.d', '/var/spool/cron/crontabs']) {
    try { for (const f of fs.readdirSync(d)) t.push(path.join(d, f)); } catch { /* absent */ }
  }
  try { for (const u of fs.readdirSync('/home')) t.push(`/home/${u}/.ssh/authorized_keys`); } catch { /* absent */ }
  return t;
}

const hashFile = (f) => { try { return crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'); } catch { return null; } };
const CRITICAL_FILES = /(\/etc\/passwd|\/etc\/sudoers|sudoers\.d|authorized_keys|ld\.so\.preload)/;

function diffBaseline(baseline, current) {
  const changes = [];
  for (const [f, h] of Object.entries(current)) {
    if (!(f in baseline)) changes.push({ file: f, kind: 'added', hash: h });
    else if (baseline[f] !== h) changes.push({ file: f, kind: 'modified', hash: h });
  }
  for (const f of Object.keys(baseline)) if (!(f in current)) changes.push({ file: f, kind: 'removed', hash: null });
  return changes.map((c) => ({ ...c, critical: CRITICAL_FILES.test(c.file) }));
}

// ============================================================================
// Collectors
// ============================================================================
const AUTH_ARGS = ['-t', 'sshd', '-t', 'sshd-session', '-o', 'short-iso', '--no-pager', '-q'];

async function readAuthText(since) {
  const r = await run('journalctl', [...AUTH_ARGS, '--since', since], { timeout: 20000 });
  if (r.ok && r.out.trim()) return r.out;
  return readText('/var/log/auth.log'); // fallback for rsyslog-only systems (ISO timestamps)
}

/** Successful logins in the last 30 days — used once to seed the "known sources" baseline. */
async function historicLogins() {
  return parseAuth(await readAuthText('30 days ago')).accepted;
}

function createAuth() {
  return { async collect() { return aggregateAuth(parseAuth(await readAuthText('24 hours ago'))); } };
}

// Fast-changing posture data (every ~20s): ports, firewall, fail2ban, sshd config, sessions, services
function createSec(cfg) {
  return {
    async collect() {
      if (!isLinux) return { ports: [], firewall: {}, fail2ban: null, sshd: {}, sessions: [], services: [] };
      const [ss, ufw, f2b, sshd, who, sc] = await Promise.all([
        run('ss', ['-tlnpH']),
        run('ufw', ['status']),
        run('fail2ban-client', ['status', 'sshd']),
        run('sshd', ['-T']),
        run('who', ['-u']),
        run('systemctl', ['show', ...cfg.services, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '--no-pager']),
      ]);
      return {
        ports: parseSs(ss.out),
        firewall: ufw.ok ? parseUfw(ufw.out) : { installed: false, active: false, rules: 0 },
        fail2ban: f2b.ok ? { active: true, ...parseFail2ban(f2b.out) } : { active: false, banned: 0, totalBanned: 0, ips: [] },
        sshd: parseSshdT(sshd.out),
        sessions: parseWho(who.out),
        services: parseSystemctlShow(sc.out, cfg.services).filter((s) => s.load !== 'not-found'),
      };
    },
  };
}

// Slow checks (every ~5 min): integrity, users, certificates, pending updates
function createSlow(store) {
  return {
    async collect() {
      if (!isLinux) return { integrity: { changes: [], tracked: 0 }, users: {}, certs: [], updates: { total: 0, security: 0 }, rebootRequired: false, current: {} };

      const current = {};
      for (const f of fimTargets()) { const h = hashFile(f); if (h) current[f] = h; }
      let baseline = store.load('fim-baseline.json', null);
      if (!baseline) { baseline = current; store.save('fim-baseline.json', baseline); }
      const changes = diffBaseline(baseline, current);

      const passwd = parsePasswd(readText('/etc/passwd'));
      const users = {
        extraUid0: passwd.filter((u) => u.uid === 0 && u.name !== 'root').map((u) => u.name),
        sudoers: parseGroupMembers(readText('/etc/group')),
        loginUsers: passwd.filter((u) => (u.uid >= 1000 || u.uid === 0) && !/(nologin|false)$/.test(u.shell || '')).map((u) => u.name),
      };

      const certs = [];
      try {
        for (const d of fs.readdirSync('/etc/letsencrypt/live')) {
          const f = path.join('/etc/letsencrypt/live', d, 'cert.pem');
          try {
            const c = new crypto.X509Certificate(fs.readFileSync(f));
            certs.push({ name: d, validTo: c.validTo, daysLeft: Math.floor((Date.parse(c.validTo) - Date.now()) / 864e5) });
          } catch { /* not a cert dir */ }
        }
      } catch { /* no letsencrypt */ }

      return {
        integrity: { changes, tracked: Object.keys(current).length },
        users,
        certs,
        updates: parseUpdatesAvailable(readText('/var/lib/update-notifier/updates-available')),
        rebootRequired: fs.existsSync('/var/run/reboot-required'),
        current, // used internally to accept changes; stripped before sending to the browser
      };
    },
    acceptChange(file, hash) {
      const b = store.load('fim-baseline.json', {});
      if (hash) b[file] = hash; else delete b[file];
      store.save('fim-baseline.json', b);
    },
  };
}

module.exports = {
  createAuth, createSec, createSlow, historicLogins,
  parseAuth, aggregateAuth, parseSs, parseSshdT, parseFail2ban, parseUfw, parseWho, parsePasswd,
  parseGroupMembers, parseUpdatesAvailable, parseSystemctlShow, diffBaseline, normTs,
};
