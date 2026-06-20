#!/usr/bin/env node
/**
 * Find the FPJS bundle on the target. Logs every JS response, flags
 * any chunk loaded from fpjscdn.net. Reports URL, byte size, version
 * (from the source comment), and SHA-256 of the bundle bytes.
 *
 * Run first to confirm fpjs is still deployed, find the public key
 * embedded in the URL, and detect bundle-hash drift between runs.
 *
 * Usage:
 *   node recon.mjs
 *   node recon.mjs --target https://...
 */

import crypto from 'crypto';
import { launchFor } from './_launch.mjs';

const argv = process.argv.slice(2);
const val = (n, d) => {
  const i = argv.indexOf(`--${n}`);
  return i !== -1 && i + 1 < argv.length ? argv[i + 1] : d;
};
const TARGET = val('target', 'https://arcades.click/fpjs');

console.log(`→ visiting ${TARGET}`);
const { ctx, close } = await launchFor('recon');
const page = await ctx.newPage();

const jsHits = [];
const fpjsHits = [];

page.on('response', async (res) => {
  const url = res.url();
  const ct = res.headers()['content-type'] || '';
  if (!/javascript|ecmascript/.test(ct) && !/\.(m?js)(\?|$)/.test(url)) return;
  const isFp = /fpjscdn\.net|fpjs\.io/.test(url);
  const rec = { url, status: res.status(), contentType: ct };
  try {
    const body = await res.body();
    rec.bytes = body.length;
    rec.sha256 = crypto.createHash('sha256').update(body).digest('hex').slice(0, 16);
    if (isFp) {
      const txt = body.toString('utf8');
      // version banner (FPJS minified bundles usually have `version:"4.0.3"` near the top)
      const vMatch = txt.match(/version\s*[:=]\s*['"]([\d.]+)['"]/);
      rec.version = vMatch ? vMatch[1] : null;
      // public key in the URL
      const keyMatch = url.match(/\/v\d+\/([A-Za-z0-9]{16,24})/);
      rec.publicKey = keyMatch ? keyMatch[1] : null;
      // does it touch the encrypted-POST chokepoint?
      rec.usesCompressionStream = /CompressionStream/.test(txt);
      rec.usesTextEncoder       = /TextEncoder/.test(txt);
      rec.hasApiFpjsIo          = /api\.fpjs\.io/.test(txt);
    }
  } catch {}
  if (isFp) fpjsHits.push(rec);
  else jsHits.push(rec);
});

await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 45_000 });
await new Promise((r) => setTimeout(r, 3_000));
await close();

console.log(`\n→ ${jsHits.length} non-FPJS JS chunks loaded`);
console.log(`→ ${fpjsHits.length} fpjs.io / fpjscdn.net responses\n`);

if (fpjsHits.length === 0) {
  console.log('✗ no FPJS bundle detected. Confirm the page actually loads /fpjs and is online.');
  process.exit(1);
}

console.log('─── FPJS BUNDLE(S) ───');
for (const h of fpjsHits) {
  console.log(`  ${h.url}`);
  console.log(`    status=${h.status}  bytes=${h.bytes}  sha256-16=${h.sha256}`);
  if (h.version)        console.log(`    version=${h.version}`);
  if (h.publicKey)      console.log(`    publicKey=${h.publicKey}`);
  if (h.usesCompressionStream != null) {
    console.log(`    chokepoints: CompressionStream=${h.usesCompressionStream}  ` +
                `TextEncoder=${h.usesTextEncoder}  api.fpjs.io=${h.hasApiFpjsIo}`);
  }
  console.log();
}

const bundle = fpjsHits.find((h) => h.usesCompressionStream);
if (bundle) {
  console.log(`✓ main bundle: ${bundle.url}`);
  console.log(`  use this URL in init-script route patches`);
} else {
  console.log('⚠ no chunk uses CompressionStream — bundle may have rotated to a new chokepoint');
}
