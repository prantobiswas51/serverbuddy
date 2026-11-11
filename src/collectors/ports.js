'use strict';
const fs = require('fs');
const { readText } = require('../util');

const isLocalAddr = (a) => /^127\./.test(a) || a === '::1' || /%lo$/.test(a);

// ---- pure parsers (unit-tested) -------------------------------------------
/**
 * One row per (protocol, port, owning process) from `ss -tlnpH` / `ss -ulnpH`.
 * IPv4 + IPv6 sockets of the same process are merged into one row.
 */
function parseListeners(text, proto) {
  const want = proto === 'udp' ? 'UNCONN' : 'LISTEN';
  const rows = new Map();
  for (const line of text.split('\n')) {
    const p = line.trim().split(/\s+/);
    if (p.length < 5 || p[0] !== want) continue;
    const local = p[3];
    const i = local.lastIndexOf(':');
    const addr = local.slice(0, i).replace(/^\[|\]$/g, '');
    const port = Number(local.slice(i + 1));
    if (!port) continue;
    // Several processes can share one socket (nginx workers). The lowest pid is the master.
    const owners = [...line.matchAll(/\("([^"]*)",pid=(\d+)/g)].map((m) => ({ name: m[1], pid: Number(m[2]) }));
    owners.sort((a, b) => a.pid - b.pid);
    const o = owners[0] || { name: '', pid: 0 };
    const key = `${proto}/${port}/${o.pid}`;
    let r = rows.get(key);
    if (!r) { r = { proto, port, pid: o.pid, proc: o.name, addrs: [], public: false }; rows.set(key, r); }
    if (!r.addrs.includes(addr)) r.addrs.push(addr);
    if (!isLocalAddr(addr)) r.public = true;
  }
  return [...rows.values()].sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
}

// "0::/system.slice/nginx.service" -> "nginx". Ignores the per-user manager unit (user@1000.service).
function serviceFromCgroup(text) {
  const names = [...text.matchAll(/([A-Za-z0-9@_.:\\-]+)\.service/g)].map((m) => m[1]).filter((n) => !n.startsWith('user@'));
  return names.length ? names[names.length - 1] : '';
}

/**
 * Attach the PM2 app that owns each listener. A listener belongs to a PM2 app when the app's
 * pid is the listening process or one of its parents (covers cluster workers and `npm start` wrappers).
 */
function attachApps(listeners, pm2) {
  const byPid = new Map();
  for (const u of (pm2 && pm2.users) || []) {
    for (const a of u.apps) if (a.pid) byPid.set(a.pid, { user: u.user, name: a.name, status: a.status });
  }
  return listeners.map((l) => {
    let app = null;
    for (const pid of l.chain && l.chain.length ? l.chain : [l.pid]) {
      if (byPid.has(pid)) { app = byPid.get(pid); break; }
    }
    return { ...l, app };
  });
}

// ---- /proc readers (Linux only) -------------------------------------------
function readStatus(pid) {
  const s = readText(`/proc/${pid}/status`);
  if (!s) return null;
  return {
    uid: Number((s.match(/^Uid:\s*(\d+)/m) || [])[1]),
    ppid: Number((s.match(/^PPid:\s*(\d+)/m) || [])[1]),
  };
}

function describe(pid, users) {
  const none = { user: '?', service: '', cwd: '', cmd: '', chain: [] };
  if (!pid) return none;
  const st = readStatus(pid);
  if (!st) return none;
  const chain = [pid];
  let cur = st.ppid;
  for (let i = 0; i < 5 && cur > 1; i++) {
    chain.push(cur);
    const p = readStatus(cur);
    if (!p) break;
    cur = p.ppid;
  }
  let cwd = '';
  try { cwd = fs.readlinkSync(`/proc/${pid}/cwd`); } catch { /* process gone or not readable */ }
  return {
    user: users.get(st.uid) || String(st.uid),
    service: serviceFromCgroup(readText(`/proc/${pid}/cgroup`)),
    cwd,
    cmd: readText(`/proc/${pid}/cmdline`).split('\0').join(' ').trim().slice(0, 160),
    chain,
  };
}

module.exports = { parseListeners, serviceFromCgroup, attachApps, describe };
