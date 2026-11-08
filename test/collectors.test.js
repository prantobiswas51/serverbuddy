'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

const sys = require('../src/collectors/system');
const sec = require('../src/collectors/security');
const web = require('../src/collectors/nginx');
const pm2 = require('../src/collectors/pm2');

// ---------------------------------------------------------------- system ------
test('parseCpuStat sums the first 8 fields and treats iowait as idle', () => {
  assert.deepEqual(sys.parseCpuStat('cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 1 1 1 1 1 1 1'), { idle: 850, total: 1000 });
});

test('parseMeminfo uses MemAvailable', () => {
  const m = sys.parseMeminfo('MemTotal: 4000000 kB\nMemFree: 100 kB\nMemAvailable: 1000000 kB\nSwapTotal: 2000000 kB\nSwapFree: 1500000 kB\n');
  assert.equal(Math.round(m.pct), 75);
  assert.equal(m.swapUsed, 500000 * 1024);
});

test('parseDf reads df -P -B1 output', () => {
  const rows = sys.parseDf('Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/vda1 50000000000 8000000000 42000000000 17% /\n');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].mount, '/');
  assert.equal(Math.round(rows[0].pct), 16);
});

test('parseNetDev ignores lo and docker interfaces', () => {
  const txt = `Inter-|   Receive |  Transmit
 face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  ens3: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0
docker0: 99 1 0 0 0 0 0 0 99 1 0 0 0 0 0 0
`;
  assert.deepEqual(sys.parseNetDev(txt), { rx: 5000, tx: 7000 });
});

test('parsePs parses ps output', () => {
  const p = sys.parsePs('  2211 bongomaker  21.1  4.1 176128 next-server\n');
  assert.equal(p[0].cmd, 'next-server');
  assert.equal(p[0].rss, 176128 * 1024);
});

// ------------------------------------------------------------ ssh / auth ------
const AUTH = [
  '2026-11-08T14:00:01+0600 bmvps sshd-session[1111]: Invalid user admin from 62.210.7.3 port 5555',
  '2026-11-08T14:00:02+0600 bmvps sshd-session[1111]: Failed password for invalid user admin from 62.210.7.3 port 5555 ssh2',
  '2026-11-08T14:01:00+0600 bmvps sshd-session[2222]: Failed password for root from 1.2.3.4 port 22 ssh2',
  '2026-11-08T14:02:00+0600 bmvps sshd-session[3333]: Connection closed by authenticating user root 5.6.7.8 port 4444 [preauth]',
  '2026-11-08T14:03:00+0600 bmvps sshd-session[4444]: Accepted publickey for bongomaker from 103.45.12.9 port 50000 ssh2: ED25519 SHA256:abc',
  '2026-11-08T14:03:30+0600 bmvps sshd-session[5555]: Disconnected from invalid user test 9.9.9.9 port 1 [preauth]',
  'Nov  8 14:04:00 bmvps cron[1]: unrelated line',
].join('\n');

test('parseAuth counts each attempt once and finds logins', () => {
  const p = sec.parseAuth(AUTH);
  assert.equal(p.attempts.length, 3); // Invalid user + valid-user failure + pre-auth close
  assert.equal(p.accepted.length, 1);
  assert.deepEqual([p.accepted[0].user, p.accepted[0].ip, p.accepted[0].method], ['bongomaker', '103.45.12.9', 'publickey']);
});

test('aggregateAuth windows and ranks sources', () => {
  const now = Date.parse('2026-11-08T14:05:00+06:00');
  const a = sec.aggregateAuth(sec.parseAuth(AUTH), now);
  assert.equal(a.attempts24h, 3);
  assert.equal(a.attempts10m, 3);
  assert.equal(a.uniqueIps24h, 3);
  assert.equal(a.accepted.length, 1);
});

test('normTs handles +0600 and +06:00', () => {
  assert.equal(sec.normTs('2026-11-08T14:00:00+0600'), sec.normTs('2026-11-08T14:00:00+06:00'));
});

test('parseSs dedupes ports and flags local vs public', () => {
  const txt = [
    'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))',
    'LISTEN 0 4096 [::]:22 [::]:*',
    'LISTEN 0 511 127.0.0.1:3001 0.0.0.0:* users:(("next-server",pid=2,fd=20))',
    'LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*',
    'LISTEN 0 511 *:8080 *:* users:(("node",pid=3,fd=9))',
  ].join('\n');
  const ports = sec.parseSs(txt);
  assert.deepEqual(ports.map((p) => [p.port, p.public]), [[22, true], [53, false], [3001, false], [8080, true]]);
  assert.equal(ports.find((p) => p.port === 8080).proc, 'node');
});

test('parseSshdT, parseFail2ban, parseUfw', () => {
  assert.equal(sec.parseSshdT('permitrootlogin no\npasswordauthentication yes\n').passwordauthentication, 'yes');
  const f = sec.parseFail2ban(`Status for the jail: sshd
|- Filter
|  |- Currently failed: 2
|  \`- Total failed:     50
\`- Actions
   |- Currently banned: 3
   |- Total banned:     41
   \`- Banned IP list:   1.1.1.1 2.2.2.2 3.3.3.3
`);
  assert.deepEqual([f.banned, f.totalBanned, f.ips.length], [3, 41, 3]);
  const u = sec.parseUfw('Status: active\n\nTo   Action  From\n--   ------  ----\n22/tcp ALLOW Anywhere\n80,443/tcp ALLOW Anywhere\n');
  assert.deepEqual([u.active, u.rules], [true, 2]);
  assert.equal(sec.parseUfw('Status: inactive').active, false);
});

test('parseWho, parsePasswd, parseGroupMembers, parseUpdatesAvailable, parseSystemctlShow', () => {
  assert.equal(sec.parseWho('bongomaker pts/0 2026-11-08 14:24 . 1234 (103.45.12.9)\n')[0].from, '103.45.12.9');
  const pw = sec.parsePasswd('root:x:0:0:root:/root:/bin/bash\nevil:x:0:0::/home/evil:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n');
  assert.deepEqual(pw.filter((u) => u.uid === 0 && u.name !== 'root').map((u) => u.name), ['evil']);
  assert.deepEqual(sec.parseGroupMembers('sudo:x:27:bongomaker,deploy\nusers:x:100:x\n'), ['bongomaker', 'deploy']);
  assert.deepEqual(sec.parseUpdatesAvailable('7 updates can be applied immediately.\n2 of these updates are standard security updates.'), { total: 7, security: 2 });
  const s = sec.parseSystemctlShow('LoadState=loaded\nActiveState=active\nSubState=running\n\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n', ['nginx', 'mosquitto']);
  assert.deepEqual(s.map((x) => [x.name, x.load, x.active]), [['nginx', 'loaded', 'active'], ['mosquitto', 'not-found', 'inactive']]);
});

test('diffBaseline finds added, modified, removed and flags critical files', () => {
  const d = sec.diffBaseline({ '/etc/passwd': 'a', '/etc/hosts': 'b', '/gone': 'c' }, { '/etc/passwd': 'z', '/etc/hosts': 'b', '/root/.ssh/authorized_keys': 'n' });
  const by = Object.fromEntries(d.map((c) => [c.file, c]));
  assert.equal(by['/etc/passwd'].kind, 'modified');
  assert.equal(by['/etc/passwd'].critical, true);
  assert.equal(by['/root/.ssh/authorized_keys'].kind, 'added');
  assert.equal(by['/gone'].kind, 'removed');
  assert.equal(by['/etc/hosts'], undefined);
});

// ------------------------------------------------------------------ nginx -----
const NGX = [
  '1.2.3.4 - - [08/Nov/2026:14:00:00 +0600] "GET /.env HTTP/1.1" 404 153 "-" "curl/8"',
  '1.2.3.4 - - [08/Nov/2026:14:00:05 +0600] "GET /wp-login.php HTTP/1.1" 404 153 "-" "curl/8"',
  '5.6.7.8 - - [08/Nov/2026:14:01:00 +0600] "GET / HTTP/1.1" 200 5000 "-" "Mozilla/5.0"',
  '5.6.7.8 - - [08/Nov/2026:14:01:30 +0600] "GET /api/x HTTP/1.1" 502 100 "-" "Mozilla/5.0"',
  'garbage line',
].join('\n');

test('nginx parse + aggregate', () => {
  const rows = web.parseAccess(NGX);
  assert.equal(rows.length, 4);
  const now = Date.parse('2026-11-08T14:02:00+06:00');
  const a = web.aggregateWeb(rows, now);
  assert.equal(a.requests1h, 4);
  assert.equal(a.s4xx, 2);
  assert.equal(a.s5xx, 1);
  assert.equal(a.probes1h, 2);
  assert.deepEqual(a.probeIps[0], { ip: '1.2.3.4', n: 2 });
  assert.equal(a.series.reduce((x, y) => x + y, 0), 4);
});

test('probe regex catches scanners but not normal pages', () => {
  for (const p of ['/.env', '/wp-login.php', '/phpmyadmin/index.php', '/.git/config', '/backup.sql']) assert.ok(web.PROBE.test(p), p);
  for (const p of ['/', '/products/shirt', '/api/orders', '/_next/static/chunk.js']) assert.ok(!web.PROBE.test(p), p);
});

// -------------------------------------------------------------------- pm2 -----
test('parseJlist tolerates banner lines', () => {
  const out = '[PM2] Spawning PM2 daemon\n[PM2] PM2 Successfully daemonized\n[{"name":"a","pm_id":0,"pm2_env":{"status":"online"}}]\n';
  assert.equal(pm2.parseJlist(out)[0].name, 'a');
  assert.deepEqual(pm2.parseJlist('[]'), []);
  assert.equal(pm2.parseJlist('no json here'), null);
});

test('extractErrors keeps real errors and drops noise', () => {
  const lines = pm2.extractErrors('⚠ "next start" does not work with standalone\nError: connect ECONNREFUSED 127.0.0.1:5432\n\nUnhandledPromiseRejection: x\nready on :3001\n');
  assert.equal(lines.length, 2);
});

test('cmpVersionDesc sorts newest node first', () => {
  assert.deepEqual(['v20.1.0', 'v24.2.0', 'v22.9.1'].sort(pm2.cmpVersionDesc), ['v24.2.0', 'v22.9.1', 'v20.1.0']);
});
