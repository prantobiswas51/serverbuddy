'use strict';
// Fake data in the exact shape of the real collectors, for developing the UI off-server.
const rnd = (a, b) => a + Math.random() * (b - a);
const GB = 1024 ** 3;

function create() {
  let cpu = 22;
  let mem = 41;
  let t0 = Date.now();
  const startedAt = Date.now() - 3 * 864e5;
  const errLines = [
    "TypeError: Cannot read properties of undefined (reading 'id')",
    'Error: connect ECONNREFUSED 127.0.0.1:5432',
    'UnhandledPromiseRejection: MQTT client disconnected',
  ];
  const errList = [];

  return {
    system: {
      async collect() {
        cpu = Math.min(98, Math.max(3, cpu + rnd(-6, 6)));
        mem = Math.min(95, Math.max(30, mem + rnd(-1.5, 1.5)));
        return {
          cpu: { pct: cpu, cores: 2, load: [rnd(0.2, 1.4), rnd(0.3, 1), rnd(0.3, 0.9)] },
          mem: { total: 4 * GB, used: (mem / 100) * 4 * GB, pct: mem, swapTotal: 2 * GB, swapUsed: 0.1 * GB },
          disks: [{ fs: '/dev/vda1', mount: '/', total: 47 * GB, used: 8.1 * GB, pct: 17.2 }, { fs: '/dev/vdb1', mount: '/var/lib/postgresql', total: 20 * GB, used: 16.4 * GB, pct: 82 }],
          net: { rxBps: rnd(20e3, 600e3), txBps: rnd(10e3, 900e3) },
          procs: [
            { pid: 2211, user: 'bongomaker', cpu: rnd(5, 30), mem: 4.1, rss: 180e6, cmd: 'next-server' },
            { pid: 2340, user: 'postgres', cpu: rnd(1, 8), mem: 2.2, rss: 90e6, cmd: 'postgres' },
            { pid: 2290, user: 'bongomaker', cpu: rnd(1, 6), mem: 3.4, rss: 140e6, cmd: 'node' },
            { pid: 981, user: 'mosquitto', cpu: 0.4, mem: 0.3, rss: 12e6, cmd: 'mosquitto' },
            { pid: 744, user: 'root', cpu: 0.2, mem: 0.5, rss: 20e6, cmd: 'serverbuddy' },
          ],
          conns: Math.round(rnd(30, 70)),
          uptimeSec: (Date.now() - startedAt) / 1000,
        };
      },
    },
    sec: {
      async collect() {
        return {
          ports: [
            { port: 22, addr: '0.0.0.0', proc: 'sshd', public: true }, { port: 80, addr: '0.0.0.0', proc: 'nginx', public: true },
            { port: 443, addr: '0.0.0.0', proc: 'nginx', public: true }, { port: 1883, addr: '127.0.0.1', proc: 'mosquitto', public: false },
            { port: 3001, addr: '127.0.0.1', proc: 'next-server', public: false }, { port: 5432, addr: '127.0.0.1', proc: 'postgres', public: false },
            { port: 8080, addr: '0.0.0.0', proc: 'node', public: true },
          ],
          listeners: [
            { proto: 'tcp', port: 22, pid: 701, proc: 'sshd', addrs: ['0.0.0.0', '::'], public: true, user: 'root', service: 'ssh', cwd: '/', cmd: 'sshd: /usr/sbin/sshd -D', chain: [701, 1] },
            { proto: 'tcp', port: 80, pid: 810, proc: 'nginx', addrs: ['0.0.0.0', '::'], public: true, user: 'root', service: 'nginx', cwd: '/', cmd: 'nginx: master process', chain: [810, 1] },
            { proto: 'tcp', port: 443, pid: 810, proc: 'nginx', addrs: ['0.0.0.0', '::'], public: true, user: 'root', service: 'nginx', cwd: '/', cmd: 'nginx: master process', chain: [810, 1] },
            { proto: 'tcp', port: 1883, pid: 981, proc: 'mosquitto', addrs: ['127.0.0.1'], public: false, user: 'mosquitto', service: 'mosquitto', cwd: '/', cmd: '/usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf', chain: [981, 1] },
            { proto: 'tcp', port: 3001, pid: 2211, proc: 'next-server (v1', addrs: ['127.0.0.1'], public: false, user: 'bongomaker', service: '', cwd: '/var/www/bongomaker/ecom/front', cmd: 'next-server (v16.4.3)', chain: [2211, 1190, 1] },
            { proto: 'tcp', port: 3002, pid: 2290, proc: 'node', addrs: ['127.0.0.1'], public: false, user: 'bongomaker', service: '', cwd: '/var/www/bongomaker/control', cmd: 'node dist/main.js', chain: [2290, 1190, 1] },
            { proto: 'tcp', port: 5432, pid: 2340, proc: 'postgres', addrs: ['127.0.0.1', '::1'], public: false, user: 'postgres', service: 'postgresql@18-main', cwd: '/var/lib/postgresql', cmd: '/usr/lib/postgresql/18/bin/postgres', chain: [2340, 1] },
            { proto: 'tcp', port: 7070, pid: 744, proc: 'node', addrs: ['127.0.0.1'], public: false, user: 'root', service: 'serverbuddy', cwd: '/opt/serverbuddy', cmd: '/usr/bin/node /opt/serverbuddy/src/index.js', chain: [744, 1] },
            { proto: 'tcp', port: 8080, pid: 3999, proc: 'node', addrs: ['0.0.0.0'], public: true, user: 'deploy', service: '', cwd: '/home/deploy/test', cmd: 'node server.js', chain: [3999, 3990, 1] },
            { proto: 'udp', port: 68, pid: 612, proc: 'systemd-network', addrs: ['10.0.0.5%ens3'], public: true, user: 'systemd-network', service: 'systemd-networkd', cwd: '/', cmd: '/lib/systemd/systemd-networkd', chain: [612, 1] },
            { proto: 'udp', port: 323, pid: 688, proc: 'chronyd', addrs: ['127.0.0.1'], public: false, user: '_chrony', service: 'chrony', cwd: '/', cmd: '/usr/sbin/chronyd', chain: [688, 1] },
          ],
          firewall: { installed: true, active: true, rules: 4 },
          fail2ban: { active: true, banned: 3, totalBanned: 41, failed: 2, ips: ['45.135.232.10', '185.224.128.17', '91.92.241.5'] },
          sshd: { permitrootlogin: 'no', passwordauthentication: 'no', pubkeyauthentication: 'yes' },
          sessions: [{ user: 'bongomaker', tty: 'pts/0', since: '2026-11-08 14:24', from: '103.45.12.9' }],
          services: ['ssh', 'nginx', 'postgresql', 'mosquitto', 'fail2ban'].map((name) => ({ name, load: 'loaded', active: 'active', sub: 'running' })),
        };
      },
    },
    auth: {
      async collect() {
        const now = Date.now();
        return {
          attempts10m: 38, attempts1h: 212, attempts24h: 1840, uniqueIps24h: 96, hot: ['62.210.7.3'],
          topIps: [
            { ip: '62.210.7.3', n24: 310, n1h: 80, n10m: 31, last: now - 20e3, users: ['root', 'admin', 'ubuntu'] },
            { ip: '45.135.232.10', n24: 240, n1h: 0, n10m: 0, last: now - 5400e3, users: ['root', 'test'] },
            { ip: '185.224.128.17', n24: 171, n1h: 12, n10m: 4, last: now - 300e3, users: ['oracle', 'postgres'] },
            { ip: '91.92.241.5', n24: 96, n1h: 3, n10m: 0, last: now - 900e3, users: ['git', 'user'] },
          ],
          topUsers: [{ user: 'root', n: 702 }, { user: 'admin', n: 301 }, { user: 'ubuntu', n: 120 }, { user: '<script>alert(1)</script>', n: 9 }],
          accepted: [
            { t: now - 900e3, user: 'bongomaker', ip: '52.242.245.243', method: 'publickey', fp: 'SHA256:ci', deploy: true },
            { t: now - 3600e3, user: 'bongomaker', ip: '103.45.12.9', method: 'publickey' },
            { t: now - 7200e3, user: 'root', ip: '203.0.113.77', method: 'password' },
          ],
        };
      },
    },
    web: {
      async collect() {
        return {
          ok: true, requests1h: 1420, s4xx: 188, s5xx: 6, s5xx10m: 2, probes1h: 131,
          probeIps: [{ ip: '147.185.132.4', n: 44 }, { ip: '20.169.51.210', n: 31 }, { ip: '205.210.31.88', n: 12 }],
          probePaths: [{ path: '/.env', n: 40 }, { path: '/wp-login.php', n: 31 }, { path: '/phpmyadmin/', n: 17 }, { path: '/.git/config', n: 9 }],
          series: Array.from({ length: 60 }, () => Math.round(rnd(5, 40))),
        };
      },
    },
    pm2: {
      async collect() {
        if (Date.now() - t0 > 4000 && Math.random() < 0.45) errList.unshift({ t: Date.now(), msg: errLines[Math.floor(Math.random() * errLines.length)] });
        t0 = t0 || Date.now();
        const now = Date.now();
        const m5 = errList.filter((e) => now - e.t < 300e3).length;
        const app = (id, name, status, over = {}) => ({
          id, name, status, restarts: 0, restarts10m: 0, unstable: 0, uptimeMs: status === 'online' ? 2 * 864e5 : 0,
          cpu: rnd(0, 8), mem: rnd(60, 220) * 1e6, mode: 'fork', errors: { m5: 0, h1: 0, last: [] }, errLog: '', ...over,
        });
        return {
          users: [
            {
              user: 'bongomaker', home: '/home/bongomaker', daemon: true, note: '', apps: [
                app(0, 'bmfront-prod', 'online', { pid: 2211 }),
                app(1, 'bmcontrol-api', 'online', { pid: 2290, restarts: 4, errors: { m5, h1: m5, last: errList.slice(0, 5) } }),
                app(2, 'bmcontrol-mqtt', 'errored', { pid: 0, restarts: 16, restarts10m: 5, errors: { m5: 12, h1: 40, last: [{ t: now - 20e3, msg: 'Error: connect ECONNREFUSED 127.0.0.1:1883' }] } }),
              ],
            },
            { user: 'deploy', home: '/home/deploy', daemon: false, note: 'PM2 daemon is not running, but 2 app(s) are saved. They will not serve traffic.', savedApps: 2, apps: [] },
            { user: 'root', home: '/root', daemon: true, note: '', apps: [app(0, 'serverbuddy', 'online')] },
          ],
          total: { apps: 4, online: 3, bad: 1, errors5m: m5 + 12 },
        };
      },
    },
    slow: {
      async collect() {
        return {
          integrity: { changes: [{ file: '/home/bongomaker/.ssh/authorized_keys', kind: 'modified', hash: 'abcdef1234567890', critical: true }], tracked: 14 },
          users: { extraUid0: [], sudoers: ['bongomaker'], loginUsers: ['root', 'bongomaker'] },
          certs: [{ name: 'bongomaker.com', validTo: 'Feb  6 2027', daysLeft: 90 }],
          updates: { total: 7, security: 2 }, rebootRequired: true, current: {},
        };
      },
      acceptChange() {},
    },
  };
}

module.exports = { create };
