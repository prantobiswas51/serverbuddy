'use strict';
const fs = require('fs');
const { execFile } = require('child_process');

// Run a command WITHOUT a shell (args are an array, so no injection). Never rejects.
function run(cmd, args = [], { timeout = 8000, env } = {}) {
  return new Promise((resolve) => {
    execFile(
      cmd,
      args,
      { timeout, maxBuffer: 16 * 1024 * 1024, env: env ? { ...process.env, ...env } : process.env, windowsHide: true },
      (err, stdout, stderr) => resolve({ ok: !err, out: stdout || '', err: stderr || '', code: err && err.code }),
    );
  });
}

// Read the last `bytes` of a file. Returns null if unreadable.
async function tailFile(file, bytes = 256 * 1024, from) {
  let fh;
  try {
    fh = await fs.promises.open(file, 'r');
    const st = await fh.stat();
    const start = from !== undefined ? Math.max(from, st.size - bytes) : Math.max(0, st.size - bytes);
    const len = Math.max(0, st.size - start);
    const buf = Buffer.alloc(len);
    if (len) await fh.read(buf, 0, len, start);
    return { text: buf.toString('utf8'), size: st.size, mtimeMs: st.mtimeMs };
  } catch {
    return null;
  } finally {
    if (fh) await fh.close().catch(() => {});
  }
}

const readText = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
const isLinux = process.platform === 'linux';
const clamp = (n, a, b) => Math.min(b, Math.max(a, n));

module.exports = { run, tailFile, readText, isLinux, clamp };
