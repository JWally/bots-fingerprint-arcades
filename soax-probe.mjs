#!/usr/bin/env node
/**
 * SOAX residential proxy probe — does using a residential exit IP
 * flip fpjs's `vpn.osMismatch` from true → false?
 *
 * If yes, the bypass story is dramatically simpler: pair a SOAX
 * residential session with a UA matching the exit region/OS, no need
 * to wrap canvas/audio at source. The 12-point IP-driven floor
 * disappears.
 *
 * Reads creds from ~/Dev/soax.txt (RESIDENTIAL line).
 *
 * Usage:
 *   node soax-probe.mjs                       # default: residential, real Chrome UA
 *   node soax-probe.mjs --pool mobile         # use the MOBILE line instead
 *   node soax-probe.mjs --no-proxy            # control run, no proxy (for diff)
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { chromium } from 'playwright';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.join(__dirname, 'results');
fs.mkdirSync(RESULTS, { recursive: true });

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(`--${n}`);
const val = (n, d) => {
  const i = argv.indexOf(`--${n}`);
  return i !== -1 && i + 1 < argv.length ? argv[i + 1] : d;
};

const POOL = val('pool', 'residential').toUpperCase();
const NO_PROXY = flag('no-proxy');
const TARGET = val('target', 'https://arcades.click/fpjs');
const STAMP = new Date().toISOString().replace(/[:.]/g, '-');
const OUT = path.join(RESULTS, `soax-probe-${POOL.toLowerCase()}-${STAMP}.json`);

function readSoax() {
  const file = path.join(os.homedir(), 'Dev', 'soax.txt');
  if (!fs.existsSync(file)) throw new Error(`SOAX creds not found at ${file}`);
  const txt = fs.readFileSync(file, 'utf8');
  const line = txt.split('\n').find((l) => l.startsWith(POOL + ':'));
  if (!line) throw new Error(`pool "${POOL}" not in ${file} (looking for line starting with "${POOL}:")`);
  // Extract -x USER:PASS@HOST:PORT
  const m = line.match(/-x\s+([^\s:]+):([^\s@]+)@([^\s:]+):(\d+)/);
  if (!m) throw new Error(`could not parse SOAX line: ${line.slice(0, 50)}...`);
  return { user: m[1], pass: m[2], host: m[3], port: parseInt(m[4], 10) };
}

let proxy = null;
let creds = null;
if (!NO_PROXY) {
  creds = readSoax();
  proxy = {
    server: `http://${creds.host}:${creds.port}`,
    username: creds.user,
    password: creds.pass,
  };
  console.log(`→ SOAX ${POOL} via http://${creds.host}:${creds.port} (user=${creds.user.slice(0, 30)}…)`);
}

console.log(`→ launching real Chrome${proxy ? ' through SOAX' : ' direct'}`);
const browser = await chromium.launch({
  channel: 'chrome',
  headless: false,
  proxy: proxy ?? undefined,
  args: ['--disable-blink-features=AutomationControlled'],
});
const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
const page = await ctx.newPage();

// First confirm what IP we look like to the world via SOAX's own checker
let exitInfo = null;
try {
  await page.goto('https://checker.soax.com/api/ipinfo', { waitUntil: 'load', timeout: 30_000 });
  exitInfo = JSON.parse(await page.evaluate(() => document.body.innerText));
  console.log(`→ exit IP: ${exitInfo?.ip}  geo: ${exitInfo?.country_code || '?'} / ${exitInfo?.city || '?'}  ASN: ${exitInfo?.asn?.number || '?'} ${exitInfo?.asn?.name || '?'}`);
} catch (e) {
  console.log(`⚠ exit-IP probe failed: ${e.message}`);
}

let event = null;
const waitForEvent = new Promise((resolve) => {
  page.on('response', async (res) => {
    if (res.url().includes('/api/fpjs/event')) {
      try { resolve(JSON.parse(await res.text())); }
      catch { resolve(null); }
    }
  });
  setTimeout(() => resolve(null), 45_000);
});

console.log(`→ visiting ${TARGET}`);
try {
  await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 60_000 });
} catch (e) {
  console.log(`⚠ nav: ${e.message}`);
}
event = await waitForEvent;
await browser.close();

if (!event) {
  console.error('ERROR: no /api/fpjs/event captured');
  process.exit(1);
}
fs.writeFileSync(OUT, JSON.stringify({ exitInfo, event }, null, 2));
console.log(`✓ wrote ${OUT}`);

const p = event.products ?? {};
console.log('\n=== FPJS VERDICT ===');
console.log('  visitor_id:    ', p.identification?.data?.visitorId);
console.log('  suspectScore:  ', p.suspectScore?.data?.result);
console.log('  bot.result:    ', p.botd?.data?.bot?.result);
console.log('  vpn.result:    ', p.vpn?.data?.result, '(' + p.vpn?.data?.confidence + ')');
console.log('  vpn.methods:   ', JSON.stringify(p.vpn?.data?.methods));
console.log('  proxy.result:  ', p.proxy?.data?.result, '(' + p.proxy?.data?.confidence + ')');
console.log('  tampering:     ', p.tampering?.data?.result, '(aml=' + p.tampering?.data?.anomalyScore + ' ml=' + p.tampering?.data?.mlScore + ')');
console.log('  ip:            ', p.ipInfo?.data?.v4?.address);
console.log('  ip.country:    ', p.ipInfo?.data?.v4?.geolocation?.country?.code);
console.log('  ip.asn:        ', p.ipInfo?.data?.v4?.asn?.asn, p.ipInfo?.data?.v4?.asn?.name);
console.log('  ip.type:       ', p.ipInfo?.data?.v4?.asn?.type);
console.log('  datacenter:    ', p.ipInfo?.data?.v4?.datacenter?.result);

const before = 'osMismatch=true (baseline pre-SOAX)';
const after = p.vpn?.data?.methods?.osMismatch
  ? 'osMismatch=true (SOAX did NOT flip it)'
  : 'osMismatch=false ★ (SOAX FLIPPED IT)';
console.log(`\n${before} → ${after}`);
