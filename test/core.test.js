'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

const { evaluate, summarize } = require('../src/threat');
const auth = require('../src/auth');

const cfg = { allowedLoginUsers: [], allowedPorts: [22, 80, 443] };
const base = () => ({
  sec: { fail2ban: { active: true, ips: [] }, firewall: { installed: true, active: true }, sshd: { permitrootlogin: 'no', passwordauthentication: 'no' }, ports: [], services: [] },
  auth: { topIps: [], accepted: [] }, slow: { integrity: { changes: [] }, users: {}, certs: [], updates: { total: 0, security: 0 } },
  system: { disks: [], mem: { pct: 20 } }, history: { cpu: [] }, web: { ok: true, s5xx10m: 0, probeIps: [] }, pm2: { users: [] }, secReady: true,
});
const ids = (a) => a.map((x) => x.id);

// ------------------------------------------------------------------ threat ----
test('a healthy server raises no alerts', () => {
  const a = evaluate(base(), cfg);
  assert.deepEqual(a, []);
  assert.equal(summarize(a).level, 'ok');
});

test('active brute force alerts, but not when fail2ban already banned the IP', () => {
  const d = base();
  d.auth.topIps = [{ ip: '1.1.1.1', n10m: 20, users: ['root'] }];
  assert.ok(ids(evaluate(d, cfg)).includes('bf:1.1.1.1'));
  d.sec.fail2ban.ips = ['1.1.1.1'];
  assert.ok(!ids(evaluate(d, cfg)).includes('bf:1.1.1.1'));
});

test('password or root logins are critical; allowedLoginUsers restricts others', () => {
  const d = base();
  d.auth.accepted = [{ user: 'root', ip: '9.9.9.9', method: 'publickey' }, { user: 'bob', ip: '8.8.8.8', method: 'publickey' }];
  let a = evaluate(d, cfg);
  assert.equal(a.find((x) => x.id === 'login:root@9.9.9.9').sev, 'critical');
  assert.equal(a.find((x) => x.id === 'login:bob@8.8.8.8').sev, 'high');
  a = evaluate(d, { ...cfg, allowedLoginUsers: ['alice'] });
  assert.equal(a.find((x) => x.id === 'login:bob@8.8.8.8').sev, 'critical');
});

test('risky sshd config, open firewall, unexpected port', () => {
  const d = base();
  d.sec.sshd = { permitrootlogin: 'yes', passwordauthentication: 'yes' };
  d.sec.firewall = { installed: true, active: false };
  d.sec.ports = [{ port: 8080, addr: '0.0.0.0', proc: 'node', public: true }, { port: 443, addr: '0.0.0.0', public: true }, { port: 5432, addr: '127.0.0.1', public: false }];
  const got = ids(evaluate(d, cfg));
  for (const id of ['sshd:rootlogin', 'sshd:password', 'fw:off', 'port:8080']) assert.ok(got.includes(id), id);
  assert.ok(!got.includes('port:443') && !got.includes('port:5432'));
});

test('integrity change on authorized_keys is critical and ackable', () => {
  const d = base();
  d.slow.integrity.changes = [{ file: '/root/.ssh/authorized_keys', kind: 'modified', hash: 'abcdef123456', critical: true }];
  const a = evaluate(d, cfg)[0];
  assert.equal(a.sev, 'critical');
  assert.ok(a.ackable && a.fim.file === '/root/.ssh/authorized_keys');
});

test('PM2: errored, crash loop, error burst, daemon down', () => {
  const d = base();
  const app = (name, over) => ({ name, status: 'online', restarts: 0, restarts10m: 0, errors: { m5: 0, h1: 0, last: [{ msg: 'boom' }] }, ...over });
  d.pm2.users = [
    { user: 'bongomaker', daemon: true, apps: [app('a', { status: 'errored', restarts: 9 }), app('b', { restarts10m: 4 }), app('c', { errors: { m5: 12, h1: 12, last: [{ msg: 'boom' }] } }), app('d', { errors: { m5: 2, h1: 2, last: [{ msg: 'x' }] } })] },
    { user: 'deploy', daemon: false, savedApps: 2, note: 'down', apps: [] },
  ];
  const a = evaluate(d, cfg);
  const byId = Object.fromEntries(a.map((x) => [x.id, x]));
  assert.equal(byId['pm2:err:bongomaker:a'].sev, 'critical');
  assert.equal(byId['pm2:loop:bongomaker:b'].sev, 'high');
  assert.equal(byId['pm2:errs:bongomaker:c'].sev, 'high');
  assert.equal(byId['pm2:errs:bongomaker:d'].sev, 'medium');
  assert.equal(byId['pm2:daemon:deploy'].sev, 'high');
});

test('summarize ignores acknowledged alerts', () => {
  const s = summarize([{ sev: 'critical', acked: true }, { sev: 'medium' }]);
  assert.equal(s.level, 'notice');
  assert.equal(s.counts.critical, 0);
});

// -------------------------------------------------------------------- auth ----
test('password hashing round trip', () => {
  const h = auth.hashPassword('correct horse battery');
  assert.ok(!h.includes('$'));
  assert.ok(auth.verifyPassword('correct horse battery', h));
  assert.ok(!auth.verifyPassword('wrong', h));
  assert.ok(!auth.verifyPassword('x', 'garbage'));
});

test('session tokens: valid, tampered and expired', () => {
  const t = auth.sign({ u: 'a', exp: Date.now() + 1000 }, 'secret');
  assert.equal(auth.verify(t, 'secret').u, 'a');
  assert.equal(auth.verify(t, 'other'), null);
  assert.equal(auth.verify(t.slice(0, -2) + 'xx', 'secret'), null);
  assert.equal(auth.verify(auth.sign({ u: 'a', exp: Date.now() - 1 }, 'secret'), 'secret'), null);
});

test('login limiter blocks after 5 failures', () => {
  const l = new auth.LoginLimiter(5, 1000);
  for (let i = 0; i < 5; i++) { assert.equal(l.blocked('ip'), false); l.fail('ip'); }
  assert.equal(l.blocked('ip'), true);
  l.ok('ip');
  assert.equal(l.blocked('ip'), false);
});

// ----------------------------------------------------------------- monitor ----
test('Monitor (mock): builds a snapshot and acknowledging a login alert hides it', async () => {
  const { Monitor } = require('../src/state');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sb-test-'));
  const m = new Monitor({ ...cfg, mock: true, dataDir: dir, webhook: '', intervals: { system: 60000, pm2: 60000, sec: 60000, auth: 60000, web: 60000, slow: 60000 }, services: [] });
  await m.start();
  try {
    const s = m.snapshot;
    assert.ok(s.system && s.pm2 && s.security.ssh);
    assert.equal(s.security.ports.find((p) => p.port === 8080).allowed, false);
    const login = s.alerts.find((a) => a.id.startsWith('login:'));
    assert.ok(login && !login.acked);
    assert.equal(m.ack(login.id), true);
    assert.equal(m.snapshot.alerts.find((a) => a.id === login.id).acked, true);
    assert.equal(m.ack('pm2:err:bongomaker:bmcontrol-mqtt'), false); // not ackable: must be fixed, not hidden
    assert.ok(fs.existsSync(path.join(dir, 'acks.json')));
  } finally {
    m.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
