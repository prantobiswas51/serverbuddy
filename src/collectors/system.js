'use strict';
const os = require('os');
const { run, readText, isLinux, clamp } = require('../util');

// ---- pure parsers (unit-tested) -------------------------------------------
function parseCpuStat(text) {
  const l = text.split('\n')[0].trim().split(/\s+/).slice(1).map(Number);
  return { idle: (l[3] || 0) + (l[4] || 0), total: l.slice(0, 8).reduce((a, b) => a + (b || 0), 0) };
}

function parseMeminfo(text) {
  const m = {};
  for (const line of text.split('\n')) {
    const r = line.match(/^(\w+):\s+(\d+)/);
    if (r) m[r[1]] = Number(r[2]) * 1024;
  }
  const total = m.MemTotal || 0;
  const avail = m.MemAvailable ?? m.MemFree ?? 0;
  const swapTotal = m.SwapTotal || 0;
  return {
    total,
    used: total - avail,
    pct: total ? ((total - avail) / total) * 100 : 0,
    swapTotal,
    swapUsed: swapTotal - (m.SwapFree || 0),
  };
}

function parseDf(text) {
  const rows = [];
  for (const line of text.trim().split('\n').slice(1)) {
    const p = line.trim().split(/\s+/);
    if (p.length < 6) continue;
    const total = Number(p[1]);
    const used = Number(p[2]);
    if (!total) continue;
    rows.push({ fs: p[0], mount: p.slice(5).join(' '), total, used, pct: (used / total) * 100 });
  }
  return rows;
}

function parseNetDev(text) {
  let rx = 0;
  let tx = 0;
  for (const line of text.split('\n').slice(2)) {
    const m = line.match(/^\s*([^:]+):\s*(.*)$/);
    if (!m) continue;
    const name = m[1];
    if (name === 'lo' || /^(docker|veth|br-|virbr)/.test(name)) continue;
    const f = m[2].trim().split(/\s+/).map(Number);
    rx += f[0] || 0;
    tx += f[8] || 0;
  }
  return { rx, tx };
}

function parsePs(text) {
  const out = [];
  for (const line of text.trim().split('\n')) {
    const m = line.trim().match(/^(\d+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(.+)$/);
    if (m) out.push({ pid: +m[1], user: m[2], cpu: +m[3], mem: +m[4], rss: +m[5] * 1024, cmd: m[6] });
  }
  return out;
}

// ---- collector ------------------------------------------------------------
function create() {
  let prevCpu = null;
  let prevNet = null;
  let prevAt = 0;

  return {
    async collect() {
      const now = Date.now();
      const dt = prevAt ? (now - prevAt) / 1000 : 0;
      prevAt = now;

      let cpuNow;
      let mem;
      let net = null;
      let disks = [];
      let procs = [];
      let conns = null;

      if (isLinux) {
        cpuNow = parseCpuStat(readText('/proc/stat'));
        mem = parseMeminfo(readText('/proc/meminfo'));
        net = parseNetDev(readText('/proc/net/dev'));
        const [df, ps, ss] = await Promise.all([
          run('df', ['-P', '-B1', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'squashfs', '-x', 'overlay', '-x', 'efivarfs']),
          run('ps', ['-eo', 'pid,user:20,pcpu,pmem,rss,comm', '--sort=-pcpu', '--no-headers']),
          run('ss', ['-Htn', 'state', 'established']),
        ]);
        disks = parseDf(df.out);
        procs = parsePs(ps.out).slice(0, 8);
        conns = ss.ok ? ss.out.split('\n').filter(Boolean).length : null;
      } else {
        // Dev fallback (Windows/macOS): coarse numbers from the os module.
        const t = os.cpus().reduce((a, c) => {
          a.idle += c.times.idle;
          a.total += c.times.user + c.times.nice + c.times.sys + c.times.idle + c.times.irq;
          return a;
        }, { idle: 0, total: 0 });
        cpuNow = t;
        const total = os.totalmem();
        const used = total - os.freemem();
        mem = { total, used, pct: (used / total) * 100, swapTotal: 0, swapUsed: 0 };
      }

      let cpuPct = 0;
      if (prevCpu) {
        const dT = cpuNow.total - prevCpu.total;
        const dI = cpuNow.idle - prevCpu.idle;
        if (dT > 0) cpuPct = clamp((1 - dI / dT) * 100, 0, 100);
      }
      prevCpu = cpuNow;

      let rxBps = 0;
      let txBps = 0;
      if (net && prevNet && dt > 0) {
        rxBps = Math.max(0, (net.rx - prevNet.rx) / dt);
        txBps = Math.max(0, (net.tx - prevNet.tx) / dt);
      }
      if (net) prevNet = net;

      return {
        cpu: { pct: cpuPct, cores: os.cpus().length, load: os.loadavg() },
        mem,
        disks,
        net: { rxBps, txBps },
        procs,
        conns,
        uptimeSec: os.uptime(),
      };
    },
  };
}

module.exports = { create, parseCpuStat, parseMeminfo, parseDf, parseNetDev, parsePs };
