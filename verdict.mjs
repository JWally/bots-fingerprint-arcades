#!/usr/bin/env node
/**
 * Single-shot FPJS verdict capture against arcades.click/fpjs.
 *
 * Loads the page once, intercepts the merchant-proxy /api/fpjs/event
 * response (which is the full Smart Signals payload from api.fpjs.io),
 * prints a one-line summary, saves the raw JSON to ./results/.
 *
 * Use as the oracle. Every tamper/bypass run boils down to "did this
 * change the verdict that verdict.mjs would print?"
 *
 * Usage:
 *   node verdict.mjs                       # headless, no proxy
 *   node verdict.mjs --headed
 *   node verdict.mjs --target https://...  # override default target
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
const OUT = path.join(RESULTS, `verdict-${STAMP}.json`);

console.log(`→ launching real Chrome (set FPJS_CHROMIUM=1 for bundled chromium)`);
const { ctx, close } = await launchFor('verdict');
const page = await ctx.newPage();

let event = null;
const waitForEvent = new Promise((resolve) => {
  page.on('response', async (res) => {
    if (res.url().includes('/api/fpjs/event')) {
      try { resolve(JSON.parse(await res.text())); }
      catch { resolve(null); }
    }
  });
  setTimeout(() => resolve(null), 30_000);
});

console.log(`→ visiting ${TARGET}`);
await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 45_000 });
event = await waitForEvent;
await close();

if (!event) {
  console.error('ERROR: no /api/fpjs/event captured');
  process.exit(1);
}
fs.writeFileSync(OUT, JSON.stringify(event, null, 2));
console.log(`✓ wrote ${OUT}`);

const p = event.products ?? {};
console.log('\n=== FPJS VERDICT ===');
console.log('  visitor_id:    ', p.identification?.data?.visitorId);
console.log('  confidence:    ', p.identification?.data?.confidence?.score);
console.log('  suspectScore:  ', p.suspectScore?.data?.result);
console.log('  bot.result:    ', p.botd?.data?.bot?.result);
console.log('  bot.type:      ', p.botd?.data?.bot?.type ?? '—');
console.log('  vpn.result:    ', p.vpn?.data?.result, '(' + p.vpn?.data?.confidence + ')');
console.log('  vpn.methods:   ', JSON.stringify(p.vpn?.data?.methods));
console.log('  proxy.result:  ', p.proxy?.data?.result);
console.log('  tampering:     ', p.tampering?.data?.result,
  '(anomaly=' + p.tampering?.data?.anomalyScore + ' ml=' + p.tampering?.data?.mlScore + ')');
console.log('  incognito:     ', p.incognito?.data?.result);
console.log('  virtualMachine:', p.virtualMachine?.data?.result);
console.log('  ip:            ', p.ipInfo?.data?.v4?.address);
console.log('  ip.country:    ', p.ipInfo?.data?.v4?.geolocation?.country?.code);
console.log('  ip.asn:        ', p.ipInfo?.data?.v4?.asn?.asn, p.ipInfo?.data?.v4?.asn?.name);
