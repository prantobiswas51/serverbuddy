'use strict';
const fs = require('fs');
const path = require('path');

// Tiny JSON persistence (baselines, acknowledgements, event timeline).
class Store {
  constructor(dir) {
    this.dir = dir;
    try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch { /* ignore */ }
  }
  exists(name) { return fs.existsSync(path.join(this.dir, name)); }
  load(name, def) {
    try { return JSON.parse(fs.readFileSync(path.join(this.dir, name), 'utf8')); } catch { return def; }
  }
  save(name, data) {
    const f = path.join(this.dir, name);
    const tmp = f + '.tmp';
    try {
      fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
      fs.renameSync(tmp, f);
    } catch (e) {
      console.error('store: save failed for', name, e.message);
    }
  }
}

module.exports = { Store };
