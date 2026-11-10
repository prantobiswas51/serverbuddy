'use strict';
const os = require('os');
const { Store } = require('./store');
const { evaluate, summarize } = require('./threat');

const HISTORY_POINTS = 300; // 15 min at 3 s

class Monitor {
  constructor(cfg) {
    this.cfg = cfg;
    this.store = new Store(cfg.dataDir);
    this.data = {};
    this.errors = {};
    this.history = { t: [], cpu: [], mem: [], rx: [], tx: [] };
    this.acks = this.store.load('acks.json', {});
    this.firstRun = !this.store.exists('acks.json');
    this.events = this.store.load('events.json', []);
    this.knownAlertIds = new Set();
    this.snapshot = null;
    this.timers = [];

    if (cfg.mock) {
      this.collectors = require('./mock').create(cfg);
    } else {
      const sys = require('./collectors/system');
      const sec = require('./collectors/security');
      const web = require('./collectors/nginx');
      const pm2 = require('./collectors/pm2');
      this.slowCollector = sec.createSlow(this.store);
      this.collectors = {
        system: sys.create(),
        sec: sec.createSec(cfg),
        auth: sec.createAuth(cfg),
        web: web.create(cfg),
        pm2: pm2.create(),
        slow: this.slowCollector,
      };
      this.historicLogins = sec.historicLogins;
    }
  }

  async start() {
    // First start only: every login seen in the last 30 days becomes a "known source",
    // so you are not flooded with alerts for your own past logins.
    if (this.firstRun && this.historicLogins) {
      try {
        for (const a of await this.historicLogins()) this.acks[`login:${a.user}@${a.ip}`] = Date.now();
      } catch (e) { console.error('seeding known logins failed:', e.message); }
    }
    this.store.save('acks.json', this.acks);

    const iv = this.cfg.intervals;
    for (const name of Object.keys(this.collectors)) {
      const tick = async () => {
        try {
          this.data[name] = await this.collectors[name].collect();
          delete this.errors[name];
        } catch (e) {
          this.errors[name] = e.message;
          console.error(`collector ${name} failed:`, e.message);
        }
      };
      await tick();
      this.timers.push(setInterval(tick, iv[name]));
    }
    this.rebuild();
    this.timers.push(setInterval(() => this.rebuild(), 3000));
  }

  stop() { this.timers.forEach(clearInterval); }

  rebuild() {
    const d = this.data;
    const sys = d.system;
    if (sys) {
      const h = this.history;
      h.t.push(Date.now()); h.cpu.push(+sys.cpu.pct.toFixed(1)); h.mem.push(+sys.mem.pct.toFixed(1));
      h.rx.push(Math.round(sys.net.rxBps)); h.tx.push(Math.round(sys.net.txBps));
      if (h.t.length > HISTORY_POINTS) for (const k of Object.keys(h)) h[k].shift();
    }

    const view = { ...d, history: this.history, secReady: !!d.sec };
    let alerts = evaluate(view, this.cfg).map((a) => ({ ...a, acked: !!this.acks[a.id] }));

    // Timeline + webhook for alerts that appeared since the last rebuild.
    const ids = new Set(alerts.map((a) => a.id));
    for (const a of alerts) {
      if (!this.knownAlertIds.has(a.id) && !a.acked) {
        this.events.unshift({ ts: Date.now(), id: a.id, sev: a.sev, title: a.title });
        if (a.sev === 'critical' || a.sev === 'high') this.notify(a);
      }
    }
    this.knownAlertIds = ids;
    if (this.events.length > 300) this.events.length = 300;
    this.store.save('events.json', this.events);

    const slow = d.slow ? { ...d.slow } : null;
    if (slow) delete slow.current;

    this.snapshot = {
      ts: Date.now(),
      host: { name: os.hostname(), os: `${os.type()} ${os.release()}`, node: process.version, mock: !!this.cfg.mock, root: process.getuid ? process.getuid() === 0 : false },
      system: d.system || null,
      security: {
        ...(d.sec || {}),
        ports: ((d.sec && d.sec.ports) || []).map((p) => ({ ...p, allowed: !p.public || this.cfg.allowedPorts.includes(p.port) })),
        ssh: d.auth || null,
        ...(slow || {}),
      },
      web: d.web || null,
      pm2: d.pm2 || null,
      history: this.history,
      alerts,
      threat: summarize(alerts),
      events: this.events.slice(0, 40),
      collectorErrors: this.errors,
    };
  }

  /** Acknowledge an alert. Login alerts join the known list; integrity alerts become the new baseline. */
  ack(id) {
    const a = this.snapshot && this.snapshot.alerts.find((x) => x.id === id);
    if (!a || !a.ackable) return false;
    this.acks[id] = Date.now();
    this.store.save('acks.json', this.acks);
    if (a.fim && this.slowCollector) this.slowCollector.acceptChange(a.fim.file, a.fim.hash);
    this.rebuild();
    return true;
  }

  notify(a) {
    if (!this.cfg.webhook) return;
    fetch(this.cfg.webhook, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: `[ServerBuddy/${os.hostname()}] ${a.sev.toUpperCase()}: ${a.title}\n${a.detail || ''}`, alert: a }),
      signal: AbortSignal.timeout(8000),
    }).catch((e) => console.error('webhook failed:', e.message));
  }
}

module.exports = { Monitor };
