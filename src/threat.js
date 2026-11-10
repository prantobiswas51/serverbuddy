'use strict';

const SEV_RANK = { critical: 4, high: 3, medium: 2, info: 1 };

/**
 * Turn raw collector output into a prioritised list of alerts.
 * Every alert has a STABLE id so it can be acknowledged and de-duplicated.
 * `d` is the snapshot: { system, sec, auth, slow, web, pm2, history }.
 */
function evaluate(d, cfg) {
  const A = [];
  const add = (id, sev, cat, title, detail, extra = {}) => A.push({ id, sev, cat, title, detail, ...extra });
  const sec = d.sec || {};
  const auth = d.auth || {};
  const slow = d.slow || {};

  // ---- SSH ---------------------------------------------------------------
  const banned = new Set((sec.fail2ban && sec.fail2ban.ips) || []);
  for (const e of auth.topIps || []) {
    if (e.n10m >= 10 && !banned.has(e.ip)) {
      add(`bf:${e.ip}`, 'high', 'ssh', `Active SSH brute force from ${e.ip}`,
        `${e.n10m} attempts in 10 min, not banned. Users tried: ${e.users.join(', ')}`, { ip: e.ip });
    }
  }
  for (const a of auth.accepted || []) {
    if (a.deploy) continue; // the CI deploy key logging in from a GitHub runner: expected, not an alert
    const id = `login:${a.user}@${a.ip}`;
    const restricted = cfg.allowedLoginUsers.length && !cfg.allowedLoginUsers.includes(a.user);
    const sev = a.user === 'root' || a.method === 'password' || restricted ? 'critical' : 'high';
    add(id, sev, 'ssh', `New SSH login source: ${a.user} from ${a.ip}`,
      `Method: ${a.method}. If this was you, acknowledge it to add it to the known list.`, { ip: a.ip, user: a.user, ackable: true });
  }
  const s = sec.sshd || {};
  if (s.permitrootlogin === 'yes') add('sshd:rootlogin', 'critical', 'ssh', 'SSH root login with password is enabled', 'PermitRootLogin yes');
  if (s.passwordauthentication === 'yes') add('sshd:password', 'high', 'ssh', 'SSH password authentication is enabled', 'Use keys only: PasswordAuthentication no');
  if (sec.fail2ban && !sec.fail2ban.active && sec.fail2ban !== null && d.secReady) add('f2b:down', 'medium', 'ssh', 'fail2ban sshd jail is not running', 'Brute-force attempts will not be banned automatically.');
  if (sec.firewall && d.secReady) {
    if (!sec.firewall.installed) add('fw:none', 'medium', 'network', 'No ufw firewall detected', 'Install/enable ufw or confirm another firewall is in place.');
    else if (!sec.firewall.active) add('fw:off', 'high', 'network', 'Firewall (ufw) is inactive', 'All listening ports are reachable from the internet.');
  }

  // ---- Network -----------------------------------------------------------
  for (const p of sec.ports || []) {
    if (p.public && !cfg.allowedPorts.includes(p.port)) {
      add(`port:${p.port}`, 'high', 'network', `Unexpected public port ${p.port}${p.proc ? ` (${p.proc})` : ''}`,
        `Listening on ${p.addr}. Bind to 127.0.0.1 or block it in the firewall, or add it to SB_ALLOWED_PORTS.`, { ackable: true });
    }
  }

  // ---- Integrity / users -------------------------------------------------
  for (const c of (slow.integrity && slow.integrity.changes) || []) {
    add(`fim:${c.file}:${(c.hash || 'gone').slice(0, 8)}`, c.critical ? 'critical' : 'high', 'integrity',
      `Watched file ${c.kind}: ${c.file}`, 'Unexpected? Investigate. Expected? Acknowledge to accept as the new baseline.',
      { ackable: true, fim: { file: c.file, hash: c.hash } });
  }
  for (const u of (slow.users && slow.users.extraUid0) || []) add(`uid0:${u}`, 'critical', 'integrity', `Extra root-level account: ${u}`, 'UID 0 account other than root.');

  // ---- Certificates / updates / services --------------------------------
  for (const c of slow.certs || []) {
    if (c.daysLeft < 7) add(`cert:${c.name}`, 'high', 'system', `TLS certificate for ${c.name} expires in ${c.daysLeft}d`, 'Renewal is probably failing: sudo certbot renew --dry-run');
    else if (c.daysLeft < 21) add(`cert:${c.name}`, 'medium', 'system', `TLS certificate for ${c.name} expires in ${c.daysLeft}d`, 'Auto-renewal should happen soon; verify with certbot renew --dry-run');
  }
  if (slow.updates && slow.updates.security > 0) add('updates:sec', 'medium', 'system', `${slow.updates.security} security update(s) pending`, 'sudo apt update && sudo apt upgrade');
  if (slow.rebootRequired) add('reboot', 'medium', 'system', 'Reboot required', 'A package update needs a reboot to take effect.');
  for (const svc of sec.services || []) {
    if (svc.active !== 'active' && svc.name !== 'fail2ban') add(`svc:${svc.name}`, 'high', 'system', `Service ${svc.name} is ${svc.active}`, `systemctl status ${svc.name}`);
  }

  // ---- System performance -----------------------------------------------
  const sys = d.system || {};
  for (const dk of sys.disks || []) {
    if (dk.pct >= 90) add(`disk:${dk.mount}`, 'high', 'system', `Disk ${dk.mount} is ${dk.pct.toFixed(0)}% full`, 'Clean logs/old builds or grow the volume.');
    else if (dk.pct >= 80) add(`disk:${dk.mount}`, 'medium', 'system', `Disk ${dk.mount} is ${dk.pct.toFixed(0)}% full`, '');
  }
  if (sys.mem && sys.mem.pct >= 92) add('mem', 'high', 'system', `Memory ${sys.mem.pct.toFixed(0)}% used`, 'OOM killer risk; check the top processes.');
  else if (sys.mem && sys.mem.pct >= 85) add('mem', 'medium', 'system', `Memory ${sys.mem.pct.toFixed(0)}% used`, '');
  const cpuHist = (d.history && d.history.cpu) || [];
  const recent = cpuHist.slice(-100); // ~5 min at 3s
  if (recent.length >= 40 && recent.reduce((a, b) => a + b, 0) / recent.length >= 90) add('cpu', 'medium', 'system', 'CPU has been above 90% for 5 minutes', 'Check the top processes (possible runaway process or miner).');

  // ---- Web ---------------------------------------------------------------
  const web = d.web || {};
  if (web.ok && web.s5xx10m >= 20) add('web:5xx', 'medium', 'web', `${web.s5xx10m} HTTP 5xx responses in 10 minutes`, 'An upstream app is failing; check PM2 errors.');
  for (const p of web.probeIps || []) {
    if (p.n >= 20 && !banned.has(p.ip)) add(`probe:${p.ip}`, 'medium', 'web', `Web scanner ${p.ip}`, `${p.n} probe requests in 1h (.env, wp-login, phpmyadmin...). Block with: sudo ufw deny from ${p.ip}`, { ip: p.ip });
  }

  // ---- PM2 (all users) ---------------------------------------------------
  for (const u of (d.pm2 && d.pm2.users) || []) {
    if (!u.daemon && u.savedApps) add(`pm2:daemon:${u.user}`, 'high', 'pm2', `PM2 for "${u.user}" is not running`, u.note);
    for (const a of u.apps) {
      const who = `${u.user}/${a.name}`;
      if (a.status === 'errored') add(`pm2:err:${u.user}:${a.name}`, 'critical', 'pm2', `${who} is errored`, `Crashed ${a.restarts} time(s). See the error log below.`);
      else if (a.status === 'stopped') add(`pm2:stop:${u.user}:${a.name}`, 'medium', 'pm2', `${who} is stopped`, 'Stopped on purpose? Otherwise: pm2 start ' + a.name);
      if (a.restarts10m >= 3) add(`pm2:loop:${u.user}:${a.name}`, 'high', 'pm2', `${who} is crash-looping`, `${a.restarts10m} restarts in 10 min`);
      if (a.errors.m5 >= 10) add(`pm2:errs:${u.user}:${a.name}`, 'high', 'pm2', `${who}: ${a.errors.m5} error lines in 5 min`, (a.errors.last[0] || {}).msg || '');
      else if (a.errors.m5 >= 1) add(`pm2:errs:${u.user}:${a.name}`, 'medium', 'pm2', `${who}: ${a.errors.m5} new error line(s) in 5 min`, (a.errors.last[0] || {}).msg || '');
    }
  }

  A.sort((x, y) => SEV_RANK[y.sev] - SEV_RANK[x.sev]);
  return A;
}

function summarize(alerts) {
  const open = alerts.filter((a) => !a.acked);
  const n = (s) => open.filter((a) => a.sev === s).length;
  const counts = { critical: n('critical'), high: n('high'), medium: n('medium'), info: n('info') };
  const score = Math.min(100, counts.critical * 40 + counts.high * 15 + counts.medium * 5);
  const level = counts.critical ? 'critical' : counts.high ? 'elevated' : counts.medium ? 'notice' : 'ok';
  return { level, score, counts };
}

module.exports = { evaluate, summarize, SEV_RANK };
