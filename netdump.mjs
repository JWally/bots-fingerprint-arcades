#!/usr/bin/env node
/**
 * Full network dump of every FPJS request + response. Captures bodies
 * (binary as files), headers, status. Use to inspect the wire
 * protocol — the GET handshake (96-char base64 sealed_box), the POST
 * encrypted body (binary deflate-raw + custom cipher with
 * Content-Type: text/plain disguise), and the /api/fpjs/event response.
 *
 * Usage:  node netdump.mjs
 *         node netdump.mjs --target https://...
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { launchFor } from './_launch.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.join(__dirname, 'results');
fs.mkdirSync(RESULTS, { recursive: true });

const argv = process.argv.slice(2);
const val = (n, d) => {
  const i = argv.indexOf(`--${n}`);
  return i !== -1 && i + 1 < argv.length ? argv[i + 1] : d;
};
const TARGET = val('target', 'https://arcades.click/fpjs');
const STAMP = new Date().toISOString().replace(/[:.]/g, '-');
const OUT = path.join(RESULTS, `netdump-${STAMP}.json`);
const BODIES_DIR = path.join(RESULTS, `netdump-${STAMP}-bodies`);
fs.mkdirSync(BODIES_DIR, { recursive: true });

const isFpjs = (u) => /fpjs\.io|fpjscdn\.net|\/api\/fpjs/.test(u);

const { ctx, close } = await launchFor('netdump');
const page = await ctx.newPage();

const transactions = [];
let seq = 0;

page.on('request', (req) => {
  const url = req.url();
  if (!isFpjs(url)) return;
  const id = ++seq;
  const postData = req.postData();
  const rec = {
    id, t: Date.now(),
    dir: 'REQUEST',
    method: req.method(),
    url,
    headers: req.headers(),
    bodyBytes: postData ? Buffer.byteLength(postData, 'utf8') : 0,
  };
  if (postData) {
    const fname = `${String(id).padStart(3, '0')}-req-${req.method()}-${url.replace(/[^a-zA-Z0-9.]/g, '_').slice(0, 80)}.bin`;
    fs.writeFileSync(path.join(BODIES_DIR, fname), postData);
    rec.bodyFile = fname;
    const buf = Buffer.from(postData, 'utf8');
    rec.bodyHexHead = buf.slice(0, 32).toString('hex');
    const printable = [...buf.slice(0, 512)].filter((b) => b >= 32 && b < 127).length;
    rec.bodyPrintableRatio = +(printable / Math.min(512, buf.length)).toFixed(2);
  }
  transactions.push(rec);
});

page.on('response', async (res) => {
  const url = res.url();
  if (!isFpjs(url)) return;
  const id = ++seq;
  const rec = {
    id, t: Date.now(),
    dir: 'RESPONSE',
    url,
    status: res.status(),
    headers: res.headers(),
  };
  try {
    const buf = await res.body();
    rec.bodyBytes = buf.length;
    const fname = `${String(id).padStart(3, '0')}-resp-${res.status()}-${url.replace(/[^a-zA-Z0-9.]/g, '_').slice(0, 80)}.bin`;
    fs.writeFileSync(path.join(BODIES_DIR, fname), buf);
    rec.bodyFile = fname;
    rec.bodyHexHead = buf.slice(0, 32).toString('hex');
    const printable = [...buf.slice(0, 512)].filter((b) => b >= 32 && b < 127).length;
    rec.bodyPrintableRatio = +(printable / Math.min(512, buf.length)).toFixed(2);
    if (rec.bodyPrintableRatio > 0.85) rec.bodyPreview = buf.slice(0, 600).toString('utf8');
  } catch (e) {
    rec.bodyError = String(e.message);
  }
  transactions.push(rec);
});

await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 45_000 });
await new Promise((r) => setTimeout(r, 6_000));
await close();

fs.writeFileSync(OUT, JSON.stringify({
  target: TARGET, ts: new Date().toISOString(),
  bodiesDir: BODIES_DIR, transactions,
}, null, 2));

console.log(`\n─── FPJS NETWORK TIMELINE ───`);
for (const t of transactions) {
  if (t.dir === 'REQUEST') {
    console.log(`[REQ  ] ${t.method.padEnd(6)} ${t.url.replace(/^https?:\/\//, '').slice(0, 90)}`);
    if (t.bodyBytes) console.log(`        body ${t.bodyBytes}B  printable=${t.bodyPrintableRatio}  hex=${t.bodyHexHead}`);
  } else {
    console.log(`[RESP ${t.status}] ${t.url.replace(/^https?:\/\//, '').slice(0, 90)}`);
    if (t.bodyBytes) console.log(`        body ${t.bodyBytes}B  printable=${t.bodyPrintableRatio}  hex=${t.bodyHexHead}`);
    if (t.bodyPreview) console.log(`        preview: ${t.bodyPreview.replace(/\s+/g, ' ').slice(0, 300)}`);
  }
}
console.log(`\nfull JSON: ${OUT}`);
console.log(`body files: ${BODIES_DIR}/`);
