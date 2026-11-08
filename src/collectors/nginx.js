'use strict';
const { tailFile } = require('../util');

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
// 08/Nov/2026:14:24:01 +0600
function parseNginxTime(s) {
  const m = s.match(/^(\d+)\/(\w+)\/(\d+):(\d+):(\d+):(\d+) ([+-])(\d\d)(\d\d)$/);
  if (!m) return NaN;
  const utc = Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]);
  const off = (m[7] === '-' ? -1 : 1) * (+m[8] * 60 + +m[9]) * 60000;
  return utc - off;
}

const reLine = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?/;
// Paths that legitimate visitors to a Node/Next site never request.
const PROBE = /(\.env|\.git(\/|$)|wp-(login|admin|content|includes)|xmlrpc\.php|phpmyadmin|\/pma\/|\.php($|\?)|\/cgi-bin|\/actuator|\/vendor\/phpunit|\.aws|\.ssh|id_rsa|\/etc\/passwd|\/boot\.ini|\/solr|\/manager\/html|\.DS_Store|\.sql($|\?)|\.bak($|\?)|\/backup|\/config\.json|\/\.well-known\/security)/i;

function parseAccess(text) {
  const rows = [];
  for (const line of text.split('\n')) {
    const m = reLine.exec(line);
    if (!m) continue;
    const t = parseNginxTime(m[2]);
    if (Number.isNaN(t)) continue;
    rows.push({ ip: m[1], t, method: m[3], path: m[4], status: +m[5], ua: m[8] || '' });
  }
  return rows;
}

function aggregateWeb(rows, now = Date.now()) {
  const H = 3600e3;
  const recent = rows.filter((r) => now - r.t <= H);
  const probes = recent.filter((r) => PROBE.test(r.path));
  const ipMap = new Map();
  for (const r of probes) ipMap.set(r.ip, (ipMap.get(r.ip) || 0) + 1);
  const pathMap = new Map();
  for (const r of probes) { const p = r.path.slice(0, 80); pathMap.set(p, (pathMap.get(p) || 0) + 1); }
  const series = new Array(60).fill(0);
  for (const r of recent) {
    const idx = 59 - Math.floor((now - r.t) / 60000);
    if (idx >= 0 && idx < 60) series[idx]++;
  }
  return {
    ok: true,
    requests1h: recent.length,
    s4xx: recent.filter((r) => r.status >= 400 && r.status < 500).length,
    s5xx: recent.filter((r) => r.status >= 500).length,
    s5xx10m: recent.filter((r) => r.status >= 500 && now - r.t <= 600e3).length,
    probes1h: probes.length,
    probeIps: [...ipMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([ip, n]) => ({ ip, n })),
    probePaths: [...pathMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([p, n]) => ({ path: p, n })),
    series,
  };
}

function create(cfg) {
  return {
    async collect() {
      const f = await tailFile(cfg.nginxLog, 2 * 1024 * 1024);
      if (!f) return { ok: false, note: `Cannot read ${cfg.nginxLog}` };
      return aggregateWeb(parseAccess(f.text));
    },
  };
}

module.exports = { create, parseAccess, aggregateWeb, parseNginxTime, PROBE };
