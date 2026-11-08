(() => {
  'use strict';
  // NOTE: everything shown comes from logs/attackers (usernames, URL paths...).
  // All DOM is built with textContent via h() -- never innerHTML -- so it cannot inject markup.

  const root = document.getElementById('app');
  const open = new Set(); // expanded pm2 apps
  let state = null;
  let live = false;
  let es = null;

  // ---- helpers ---------------------------------------------------------------
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const svg = (tag, attrs) => {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    return el;
  };

  const fmtBytes = (n) => {
    if (!isFinite(n)) return '-';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(1)} ${u[i]}`;
  };
  const fmtRate = (n) => `${fmtBytes(n)}/s`;
  const fmtDur = (ms) => {
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400); const hh = Math.floor((s % 86400) / 3600); const m = Math.floor((s % 3600) / 60);
    return d ? `${d}d ${hh}h` : hh ? `${hh}h ${m}m` : m ? `${m}m` : `${s}s`;
  };
  const ago = (t) => (t ? `${fmtDur(Date.now() - t)} ago` : 'earlier');
  const clsPct = (p) => (p >= 90 ? 'bad' : p >= 75 ? 'warn' : '');
  const chip = (text, cls) => h('span', { class: `chip ${cls}` }, text);

  function spark(series, { max, color = 'var(--accent)', second } = {}) {
    const W = 300; const H = 44;
    const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', class: 'spark' });
    const m = max || Math.max(1, ...series, ...(second || []));
    const line = (arr, c, fill) => {
      if (arr.length < 2) return;
      const pts = arr.map((v, i) => `${((i / (arr.length - 1)) * W).toFixed(1)},${(H - 2 - (v / m) * (H - 4)).toFixed(1)}`);
      if (fill) s.append(svg('polygon', { points: `0,${H} ${pts.join(' ')} ${W},${H}`, fill: c, opacity: '.14' }));
      s.append(svg('polyline', { points: pts.join(' '), fill: 'none', stroke: c, 'stroke-width': '1.6', 'vector-effect': 'non-scaling-stroke' }));
    };
    line(series, color, true);
    if (second) line(second, 'var(--ok)', false);
    return s;
  }

  const bar = (pct) => h('div', { class: 'bar' }, h('i', { class: clsPct(pct), style: `width:${Math.min(100, pct).toFixed(1)}%` }));
  const kv = (k, v) => h('div', { class: 'kv' }, h('span', { class: 'muted' }, k), h('span', null, v));

  async function api(path, opts) {
    const r = await fetch(path, { credentials: 'same-origin', ...opts });
    if (r.status === 401) { showLogin(); throw new Error('unauthorized'); }
    return r;
  }

  // ---- login ------------------------------------------------------------------
  function showLogin(msg) {
    if (es) { es.close(); es = null; }
    const err = h('div', { class: 'err' }, msg || '');
    const user = h('input', { type: 'text', autocomplete: 'username', placeholder: 'Username', value: 'admin' });
    const pass = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Password' });
    const form = h('form', { class: 'card login', onsubmit: async (e) => {
      e.preventDefault();
      const r = await fetch('/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user: user.value, password: pass.value }) });
      if (r.ok) start();
      else err.textContent = (await r.json().catch(() => ({}))).error || 'Login failed';
    } }, h('h1', null, 'ServerBuddy'), h('div', { class: 'muted small' }, 'Sign in to view server status'), h('br'), user, pass, err, h('button', { class: 'btn', type: 'submit' }, 'Sign in'));
    root.replaceChildren(form);
    pass.focus();
  }

  // ---- sections ---------------------------------------------------------------
  function header(s) {
    return h('div', { class: 'top' },
      h('div', { class: 'brand' }, h('div', { class: 'logo' }, (() => { const s = svg('svg', { width: 18, height: 18, viewBox: '0 0 32 32' }); s.append(svg('path', { d: 'M6 21l6-7 5 5 9-11', stroke: '#fff', 'stroke-width': '3.2', fill: 'none', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })); return s; })()), 'ServerBuddy',
        h('span', { class: 'muted small mono' }, `${s.host.name} · ${s.host.os}`)),
      h('div', { class: 'top-r' },
        s.host.mock && chip('MOCK DATA', 'medium'),
        !s.host.root && !s.host.mock && chip('not root: limited view', 'warn'),
        s.system && h('span', { class: 'muted small' }, `up ${fmtDur(s.system.uptimeSec * 1000)}`),
        h('span', { class: 'live' }, h('span', { class: `dot ${live ? '' : 'off'}` }), live ? 'live' : 'reconnecting'),
        h('button', { class: 'btn sm', onclick: async () => { await fetch('/api/logout', { method: 'POST' }); showLogin(); } }, 'Log out')));
  }

  const LEVEL_TEXT = { ok: 'All clear', notice: 'Minor notices', elevated: 'Elevated risk', critical: 'Critical: act now' };
  function banner(s) {
    const t = s.threat;
    const c = t.counts;
    return h('div', { class: `banner ${t.level}` },
      h('div', null, h('div', { class: 'lvl' }, LEVEL_TEXT[t.level]), h('div', { class: 'muted small' }, `Threat score ${t.score}/100`)),
      h('div', { class: 'counts' },
        c.critical > 0 && chip(`${c.critical} critical`, 'critical'), c.high > 0 && chip(`${c.high} high`, 'high'),
        c.medium > 0 && chip(`${c.medium} medium`, 'medium'), !c.critical && !c.high && !c.medium && chip('nothing open', 'ok')));
  }

  async function ack(id) { await api('/api/ack', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id }) }); }

  function alertsPanel(s) {
    const openA = s.alerts.filter((a) => !a.acked);
    const done = s.alerts.filter((a) => a.acked);
    const row = (a) => h('div', { class: `alert ${a.acked ? 'acked' : ''}` },
      chip(a.sev, a.sev),
      h('div', null, h('div', { class: 't' }, a.title), a.detail && h('div', { class: 'd' }, a.detail), h('div', { class: 'd' }, a.cat)),
      a.ackable && !a.acked && h('button', { class: 'btn sm', title: 'Mark as expected / known', onclick: () => ack(a.id) }, 'Acknowledge'));
    return h('section', { class: 'section' }, h('h2', null, 'Alerts'),
      h('div', { class: 'card' },
        h('div', { class: 'alerts-scroll' },
          openA.length ? openA.map(row) : h('div', { class: 'allclear' }, 'No open alerts. Nothing needs your attention.'),
          done.length > 0 && h('details', null, h('summary', { class: 'muted small', style: 'cursor:pointer;margin-top:8px' }, `${done.length} acknowledged`), done.map(row)))));
  }

  function systemPanel(s) {
    const y = s.system;
    if (!y) return h('section', { class: 'section' }, h('h2', null, 'System'), h('div', { class: 'card empty' }, 'Waiting for data...'));
    const hist = s.history;
    return h('section', { class: 'section' }, h('h2', null, 'System performance'),
      h('div', { class: 'grid g4' },
        h('div', { class: 'card' }, h('h3', null, 'CPU'), h('div', { class: 'big' }, `${y.cpu.pct.toFixed(0)}%`, h('small', null, `${y.cpu.cores} cores`)),
          spark(hist.cpu, { max: 100 }), h('div', { class: 'muted small' }, `load ${y.cpu.load.map((n) => n.toFixed(2)).join(' · ')}`)),
        h('div', { class: 'card' }, h('h3', null, 'Memory'), h('div', { class: 'big' }, `${y.mem.pct.toFixed(0)}%`, h('small', null, `${fmtBytes(y.mem.used)} / ${fmtBytes(y.mem.total)}`)),
          spark(hist.mem, { max: 100, color: 'var(--high)' }), h('div', { class: 'muted small' }, `swap ${fmtBytes(y.mem.swapUsed)} / ${fmtBytes(y.mem.swapTotal)}`)),
        h('div', { class: 'card' }, h('h3', null, 'Network'),
          h('div', { class: 'big' }, fmtRate(y.net.rxBps), h('small', null, 'in')), h('div', { class: 'muted' }, `${fmtRate(y.net.txBps)} out`),
          spark(hist.rx, { color: 'var(--accent)', second: hist.tx }), h('div', { class: 'muted small' }, y.conns != null ? `${y.conns} established connections` : '')),
        h('div', { class: 'card' }, h('h3', null, 'Disks'),
          y.disks.length ? y.disks.map((d) => h('div', { class: 'diskrow' }, h('div', { class: 'l' }, h('span', { class: 'mono' }, d.mount), h('span', { class: 'muted' }, `${fmtBytes(d.used)} / ${fmtBytes(d.total)} · ${d.pct.toFixed(0)}%`)), bar(d.pct))) : h('div', { class: 'empty' }, 'n/a'))),
      y.procs.length > 0 && h('div', { class: 'card' }, h('h3', null, 'Top processes by CPU'),
        h('table', null, h('thead', null, h('tr', null, ['PID', 'User', 'Command', 'CPU %', 'Mem'].map((t, i) => h('th', { class: i > 2 ? 'num' : '' }, t)))),
          h('tbody', null, y.procs.map((p) => h('tr', null, h('td', { class: 'mono' }, p.pid), h('td', null, p.user), h('td', { class: 'mono' }, p.cmd), h('td', { class: 'num' }, p.cpu.toFixed(1)), h('td', { class: 'num' }, fmtBytes(p.rss))))))));
  }

  function appRow(u, a) {
    const key = `${u.user}:${a.name}:${a.id}`;
    const errTotal = a.errors.last.length;
    return h('details', { class: 'app', open: open.has(key), ontoggle: (e) => { if (e.target.open) open.add(key); else open.delete(key); } },
      h('summary', null,
        h('span', null, h('b', null, a.name), h('span', { class: 'muted small' }, `  #${a.id} ${a.mode}`)),
        h('span', null, chip(a.status, a.status)),
        h('span', { class: a.restarts10m >= 3 ? 'bad-t' : '' }, `${a.restarts} `, h('span', { class: 'muted small' }, `(${a.restarts10m} /10m)`)),
        h('span', null, a.uptimeMs ? fmtDur(a.uptimeMs) : '-'),
        h('span', { class: 'num' }, `${Math.round(a.cpu)}%`),
        h('span', { class: 'num' }, a.mem ? fmtBytes(a.mem) : '-'),
        h('span', null, a.errors.m5 ? chip(`${a.errors.m5} in 5m`, 'bad') : errTotal ? chip('old errors', 'neutral') : chip('no errors', 'ok'))),
      h('div', { class: 'errs' },
        errTotal ? a.errors.last.map((e) => h('div', { class: 'errline' }, h('time', null, ago(e.t)), e.msg)) : h('div', { class: 'muted small' }, 'No error lines in the log tail.'),
        a.errLog && h('div', { class: 'muted small mono', style: 'margin-top:6px' }, a.errLog)));
  }

  function pm2Panel(s) {
    const p = s.pm2;
    if (!p) return h('section', { class: 'section' }, h('h2', null, 'PM2'), h('div', { class: 'card empty' }, 'Waiting for data...'));
    const t = p.total;
    return h('section', { class: 'section' }, h('h2', null, 'PM2 processes (all users)'),
      h('div', { class: 'card' },
        h('div', { class: 'stats' },
          h('div', null, h('b', null, t.apps), h('span', null, 'apps')), h('div', null, h('b', null, t.online), h('span', null, 'online')),
          h('div', null, h('b', { style: t.bad ? 'color:var(--critical)' : '' }, t.bad), h('span', null, 'errored/stopped')),
          h('div', null, h('b', { style: t.errors5m ? 'color:var(--high)' : '' }, t.errors5m), h('span', null, 'error lines /5m'))),
        p.note && h('div', { class: 'note' }, p.note),
        !p.users.length && !p.note && h('div', { class: 'empty' }, 'No users with a ~/.pm2 directory were found.'),
        p.users.map((u) => h('div', { class: 'puser' },
          h('div', { class: 'puser-h' }, h('b', null, u.user), chip(u.daemon ? 'daemon up' : 'daemon down', u.daemon ? 'ok' : 'bad'), h('span', { class: 'muted small mono' }, u.home)),
          u.note && h('div', { class: 'note' }, u.note),
          u.apps.length > 0 && h('div', { class: 'apphead' }, ['App', 'Status', 'Restarts', 'Uptime', 'CPU', 'Memory', 'Errors'].map((x) => h('span', null, x))),
          u.apps.map((a) => appRow(u, a))))));
  }

  const check = (label, ok, detail) => h('div', { class: 'kv' }, h('span', null, label), h('span', null, detail && h('span', { class: 'muted small' }, `${detail}  `), chip(ok === 'n/a' ? 'n/a' : ok ? 'ok' : 'risk', ok === 'n/a' ? 'neutral' : ok ? 'ok' : 'bad')));

  function securityPanel(s, cfgPorts) {
    const sec = s.security;
    const ssh = sec.ssh;
    const banned = new Set((sec.fail2ban && sec.fail2ban.ips) || []);
    const sshd = sec.sshd || {};
    const fim = sec.integrity;
    const certMin = (sec.certs || []).reduce((m, c) => Math.min(m, c.daysLeft), 999);
    const hasData = !!ssh;
    return h('section', { class: 'section' }, h('h2', null, 'Security'),
      h('div', { class: 'grid g2' },
        h('div', { class: 'card' }, h('h3', null, 'SSH attack traffic'),
          !hasData ? h('div', { class: 'empty' }, 'Reading journal...') : [
            h('div', { class: 'stats' }, [['attempts10m', 'last 10 min'], ['attempts1h', 'last hour'], ['attempts24h', 'last 24h'], ['uniqueIps24h', 'unique IPs']].map(([k, l]) => h('div', null, h('b', null, ssh[k]), h('span', null, l)))),
            ssh.topIps.length ? h('table', null, h('thead', null, h('tr', null, ['Source IP', '24h', '10m', 'Users tried', ''].map((t, i) => h('th', { class: i === 1 || i === 2 ? 'num' : '' }, t)))),
              h('tbody', null, ssh.topIps.slice(0, 8).map((e) => h('tr', null, h('td', { class: 'mono' }, e.ip), h('td', { class: 'num' }, e.n24), h('td', { class: 'num' }, e.n10m), h('td', { class: 'mono small' }, e.users.join(', ')),
                h('td', null, banned.has(e.ip) ? chip('banned', 'ok') : e.n10m >= 10 ? chip('active', 'bad') : null))))) : h('div', { class: 'empty' }, 'No failed attempts in 24h.'),
            ssh.topUsers.length > 0 && h('div', { class: 'chips', style: 'margin-top:10px' }, h('span', { class: 'muted small' }, 'Most targeted users:'), ssh.topUsers.map((u) => h('span', { class: 'chip neutral mono' }, `${u.user} ×${u.n}`)))]),
        h('div', { class: 'card' }, h('h3', null, 'Hardening checklist'),
          check('SSH root login disabled', sshd.permitrootlogin ? sshd.permitrootlogin !== 'yes' : 'n/a', sshd.permitrootlogin),
          check('SSH password login disabled', sshd.passwordauthentication ? sshd.passwordauthentication !== 'yes' : 'n/a', sshd.passwordauthentication),
          check('Firewall active', sec.firewall ? sec.firewall.active : 'n/a', sec.firewall && sec.firewall.installed ? `${sec.firewall.rules} rules` : 'ufw not found'),
          check('fail2ban running', sec.fail2ban ? sec.fail2ban.active : 'n/a', sec.fail2ban && sec.fail2ban.active ? `${sec.fail2ban.banned} banned now · ${sec.fail2ban.totalBanned} total` : ''),
          check('File integrity unchanged', fim ? fim.changes.length === 0 : 'n/a', fim ? `${fim.tracked} files watched` : ''),
          check('No unexpected public ports', sec.ports ? sec.ports.every((p) => !p.public || p.allowed) : 'n/a'),
          check('TLS certificates healthy', (sec.certs || []).length ? certMin >= 21 : 'n/a', (sec.certs || []).length ? `soonest expiry ${certMin}d` : 'none found'),
          check('No pending security updates', sec.updates ? sec.updates.security === 0 : 'n/a', sec.updates ? `${sec.updates.total} updates` : ''))),
      h('div', { class: 'grid g2' },
        h('div', { class: 'card' }, h('h3', null, 'Successful logins (24h) and active sessions'),
          (sec.sessions || []).length > 0 && h('div', { style: 'margin-bottom:8px' }, sec.sessions.map((x) => h('div', { class: 'kv' }, h('span', { class: 'mono' }, `${x.user} (${x.tty})`), h('span', { class: 'muted small mono' }, `${x.from} · since ${x.since}`)))),
          ssh && ssh.accepted.length ? h('table', null, h('thead', null, h('tr', null, ['When', 'User', 'From', 'Method'].map((t) => h('th', null, t)))),
            h('tbody', null, ssh.accepted.slice(0, 8).map((a) => h('tr', null, h('td', null, ago(a.t)), h('td', { class: 'mono' }, a.user), h('td', { class: 'mono' }, a.ip), h('td', null, chip(a.method, a.method === 'password' ? 'bad' : 'neutral')))))) : h('div', { class: 'empty' }, 'No successful logins in the last 24h.')),
        h('div', { class: 'card' }, h('h3', null, 'Listening ports, services, certificates'),
          h('div', { class: 'chips', style: 'margin-bottom:10px' }, (sec.ports || []).map((p) => chip(`${p.port} ${p.proc || ''} ${p.public ? '· public' : '· local'}`, p.public ? (p.allowed ? 'info' : 'bad') : 'neutral'))),
          h('div', { class: 'chips', style: 'margin-bottom:10px' }, (sec.services || []).map((x) => chip(`${x.name}: ${x.active}`, x.active === 'active' ? 'ok' : 'bad'))),
          (sec.certs || []).map((c) => h('div', { class: 'kv' }, h('span', { class: 'mono' }, c.name), chip(`${c.daysLeft} days left`, c.daysLeft < 7 ? 'bad' : c.daysLeft < 21 ? 'warn' : 'ok'))),
          sec.users && sec.users.sudoers && sec.users.sudoers.length > 0 && kv('Sudo users', sec.users.sudoers.join(', ')))));
  }

  function webPanel(s) {
    const w = s.web;
    if (!w) return null;
    if (!w.ok) return h('section', { class: 'section' }, h('h2', null, 'Web traffic (nginx)'), h('div', { class: 'card empty' }, w.note || 'No data'));
    return h('section', { class: 'section' }, h('h2', null, 'Web traffic (nginx, last hour)'),
      h('div', { class: 'grid g2' },
        h('div', { class: 'card' }, h('div', { class: 'stats' }, [['requests1h', 'requests'], ['s4xx', '4xx'], ['s5xx', '5xx'], ['probes1h', 'scanner probes']].map(([k, l]) => h('div', null, h('b', { style: k === 's5xx' && w[k] ? 'color:var(--high)' : '' }, w[k]), h('span', null, l)))),
          spark(w.series, { color: 'var(--info)' }), h('div', { class: 'muted small' }, 'requests per minute')),
        h('div', { class: 'card' }, h('h3', null, 'Top scanner IPs and probed paths'),
          w.probeIps.length ? [
            h('div', { class: 'chips', style: 'margin-bottom:8px' }, w.probeIps.map((p) => chip(`${p.ip} ×${p.n}`, p.n >= 20 ? 'bad' : 'neutral'))),
            h('div', { class: 'chips' }, w.probePaths.map((p) => h('span', { class: 'chip neutral mono' }, `${p.path} ×${p.n}`)))] : h('div', { class: 'empty' }, 'No probe traffic seen.'))));
  }

  function eventsPanel(s) {
    return h('section', { class: 'section' }, h('h2', null, 'Event timeline'),
      h('div', { class: 'card' }, s.events.length ? s.events.slice(0, 15).map((e) => h('div', { class: 'kv' }, h('span', null, chip(e.sev, e.sev), '  ', e.title), h('span', { class: 'muted small' }, ago(e.ts)))) : h('div', { class: 'empty' }, 'No events recorded yet.')));
  }

  // ---- render loop --------------------------------------------------------------
  function render() {
    if (!state || !state.host) return;
    const y = state.security;
    // The server marks which listening ports are allowed by policy.
    const frag = document.createDocumentFragment();
    frag.append(header(state), banner(state), alertsPanel(state), systemPanel(state), pm2Panel(state), securityPanel(state, y), webPanel(state) || '', eventsPanel(state));
    root.replaceChildren(frag);
  }

  function start() {
    root.replaceChildren(h('div', { class: 'card empty', style: 'margin-top:20vh;text-align:center' }, 'Loading...'));
    if (es) es.close();
    es = new EventSource('/api/stream');
    es.onmessage = (m) => { live = true; try { state = JSON.parse(m.data); render(); } catch { /* ignore bad frame */ } };
    es.onerror = async () => {
      live = false;
      const r = await fetch('/api/state', { credentials: 'same-origin' }).catch(() => null);
      if (r && r.status === 401) showLogin('Session expired. Please sign in again.');
      else if (state) render();
    };
  }

  fetch('/api/state', { credentials: 'same-origin' }).then((r) => (r.status === 401 ? showLogin() : start())).catch(() => showLogin());
})();
