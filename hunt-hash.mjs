#!/usr/bin/env node
/**
 * Hunt for FPJS's pre-serialization integrity hash.
 *
 * Hypothesis: Stage B's mlScore=1.0 tampering signal means fpjs computes
 * a content-digest BEFORE CompressionStream, includes it either as one
 * of the sN slots OR as bytes outside the JSON, then the server
 * verifies. To find it:
 *
 *   1. Capture two BASELINE plaintexts back-to-back. Diff to identify
 *      deterministic-vs-random slots.
 *   2. Capture the WIRE BODY (encrypted POST bytes) for each run.
 *      Compare lengths and prefixes — if there's extra bytes that don't
 *      scale with plaintext length, the digest lives outside JSON.
 *   3. Capture a MUTATED plaintext (rewrite s101 only). Compare the
 *      assembled object against baseline-2. Any slot that DIFFERS
 *      between baseline-2 and mutated despite us only touching s101 is
 *      a derived hash whose input includes s101.
 *
 * Output: per-slot stability map + delta map per mutation.
 *
 * Usage:  node hunt-hash.mjs
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { launchFor } from './_launch.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.join(__dirname, 'results');
fs.mkdirSync(RESULTS, { recursive: true });

const TARGET = 'https://arcades.click/fpjs';
const STAMP = new Date().toISOString().replace(/[:.]/g, '-');

// Mutations to try, one at a time
const MUTATIONS = [
  { name: 'baseline_1',  apply: `/* no mutation */` },
  { name: 'baseline_2',  apply: `/* no mutation */` },
  { name: 'mut_s101_UA', apply: `if (obj.s101) obj.s101.v = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';` },
  { name: 'mut_s15_plat', apply: `if (obj.s15)  obj.s15.v  = 'MacIntel';` },
  { name: 'mut_s4_cores', apply: `if (obj.s4)   obj.s4.v   = 4;` },
  { name: 'mut_s7_mem',   apply: `if (obj.s7)   obj.s7.v   = 4;` },
  { name: 'mut_s9_tz',    apply: `if (obj.s9)   obj.s9.v   = 'Europe/London';` },
];

function buildInit(applyExpr) {
  return `(() => {
    if (window.__hunt) return; window.__hunt = true;
    window.__capturedPlain = null;
    window.__capturedWire  = null;

    // 1. Capture plaintext via the CompressionStream chokepoint.
    if (typeof CompressionStream !== 'undefined') {
      const Orig = CompressionStream;
      const tagged = new WeakSet();
      self.CompressionStream = function (f) { const cs = new Orig(f); tagged.add(cs.writable); return cs; };
      self.CompressionStream.prototype = Orig.prototype;
      const origGW = WritableStream.prototype.getWriter;
      WritableStream.prototype.getWriter = function () {
        const w = origGW.call(this);
        if (!tagged.has(this)) return w;
        const ow = w.write.bind(w);
        w.write = function (chunk) {
          try {
            let text;
            if (typeof chunk === 'string') text = chunk;
            else if (chunk && ArrayBuffer.isView(chunk)) text = new TextDecoder().decode(chunk);
            else if (chunk instanceof ArrayBuffer) text = new TextDecoder().decode(new Uint8Array(chunk));
            if (text && text.startsWith('{"c":') && text.length > 1000) {
              const obj = JSON.parse(text);
              ${applyExpr}
              const mutated = JSON.stringify(obj);
              window.__capturedPlain = mutated;
              return ow(new TextEncoder().encode(mutated));
            }
          } catch (e) { window.__huntErr = String(e.message); }
          return ow(chunk);
        };
        return w;
      };
    }

    // 2. Capture the wire body fpjs actually POSTs (after deflate + cipher).
    const origFetch = fetch;
    self.fetch = function (...args) {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url;
      const init = args[1];
      if (/api\\.fpjs\\.io/.test(url || '') && init?.body) {
        const body = init.body;
        let bytes;
        if (body instanceof ArrayBuffer) bytes = new Uint8Array(body);
        else if (ArrayBuffer.isView(body)) bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
        if (bytes && !window.__capturedWire) {
          window.__capturedWire = {
            len: bytes.length,
            hex_head: Array.from(bytes.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(''),
            hex_tail: Array.from(bytes.slice(-32)).map(b => b.toString(16).padStart(2, '0')).join(''),
            url: url,
          };
        }
      }
      return origFetch.apply(this, args);
    };
  })();`;
}

async function captureOne(m) {
  process.env.FPJS_NO_PERSIST = '1';
  const { ctx, close } = await launchFor('hunt-' + m.name);
  await ctx.addInitScript({ content: buildInit(m.apply) });
  const page = await ctx.newPage();

  let verdict = null;
  page.on('response', async (r) => {
    if (r.url().includes('/api/fpjs/event')) {
      try { verdict = JSON.parse(await r.text()); } catch {}
    }
  });

  await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 45_000 });
  await new Promise((r) => setTimeout(r, 6_000));
  const plain = await page.evaluate(() => window.__capturedPlain);
  const wire  = await page.evaluate(() => window.__capturedWire);
  const err   = await page.evaluate(() => window.__huntErr || null);
  await close();

  let parsed = null;
  if (plain) { try { parsed = JSON.parse(plain); } catch {} }
  return { name: m.name, plain, parsed, wire, err, verdict };
}

const captures = [];
for (const m of MUTATIONS) {
  process.stdout.write(`→ ${m.name.padEnd(20)} `);
  const c = await captureOne(m);
  captures.push(c);
  const v = c.verdict?.products;
  const tamp = v?.tampering?.data;
  console.log(`plain=${c.plain?.length}B  wire=${c.wire?.len}B  ` +
              `score=${v?.suspectScore?.data?.result}  ` +
              `tamper=${tamp?.result}/ml=${tamp?.mlScore?.toFixed(3)}`);
  if (c.err) console.log(`   err: ${c.err}`);
}

// Save raw captures for offline analysis
const dump = path.join(RESULTS, `hunt-hash-${STAMP}.json`);
fs.writeFileSync(dump, JSON.stringify(captures.map((c) => ({
  name: c.name, plain: c.plain, wire: c.wire,
  verdict_snapshot: c.verdict ? {
    suspectScore: c.verdict.products?.suspectScore?.data?.result,
    visitorId: c.verdict.products?.identification?.data?.visitorId,
    tampering: c.verdict.products?.tampering?.data,
  } : null,
})), null, 2));
console.log(`\nraw: ${dump}`);

// ── Analysis ──
const base1 = captures.find((c) => c.name === 'baseline_1');
const base2 = captures.find((c) => c.name === 'baseline_2');
if (!base1?.parsed || !base2?.parsed) {
  console.error('\nbaseline capture failed; cannot analyze');
  process.exit(1);
}

// (a) deterministic vs random slots across two baselines
const slotKeys = new Set([...Object.keys(base1.parsed), ...Object.keys(base2.parsed)]);
const stable = [], unstable = [];
for (const k of slotKeys) {
  if (!/^s\d+$/.test(k)) continue;
  const a = JSON.stringify(base1.parsed[k]);
  const b = JSON.stringify(base2.parsed[k]);
  (a === b ? stable : unstable).push(k);
}
console.log(`\n── BASELINE STABILITY ──`);
console.log(`stable across two runs: ${stable.length} slots`);
console.log(`unstable (random/timestamp): ${unstable.length} slots → ${unstable.sort((a,b) => parseInt(a.slice(1))-parseInt(b.slice(1))).join(', ')}`);

// (b) wire body comparison: did length change, did head/tail change?
console.log(`\n── WIRE BODY DELTAS ──`);
const baseWire = base1.wire;
console.log(`baseline_1 wire: ${baseWire.len}B  head=${baseWire.hex_head}  tail=${baseWire.hex_tail}`);
for (const c of captures.slice(1)) {
  if (!c.wire) { console.log(`${c.name}: no wire captured`); continue; }
  const dLen = c.wire.len - baseWire.len;
  const sameHead = c.wire.hex_head === baseWire.hex_head;
  const sameTail = c.wire.hex_tail === baseWire.hex_tail;
  console.log(`${c.name.padEnd(20)} ${c.wire.len}B  Δ=${dLen >= 0 ? '+' : ''}${dLen}B  ` +
              `head${sameHead ? '=' : '≠'}  tail${sameTail ? '=' : '≠'}`);
}

// (c) per-mutation slot-delta map: for each mutation, which OTHER slots changed
//     vs baseline_2? Slots changed despite us only touching one input are
//     either downstream digests OR slots that fpjs derives differently because
//     of our mutation's side-effect on its collector.
console.log(`\n── SLOT DELTAS (mutation vs baseline_2; deterministic slots only) ──`);
for (const c of captures.filter((x) => x.name.startsWith('mut_'))) {
  if (!c.parsed) { console.log(`${c.name}: no plain captured`); continue; }
  const baseObj = base2.parsed;
  const mutObj = c.parsed;
  const diffs = [];
  for (const k of slotKeys) {
    if (!/^s\d+$/.test(k)) continue;
    if (unstable.includes(k)) continue;  // ignore naturally random slots
    const bv = JSON.stringify(baseObj[k]);
    const mv = JSON.stringify(mutObj[k]);
    if (bv !== mv) diffs.push({ k, base: bv, mut: mv });
  }
  console.log(`\n${c.name}: ${diffs.length} stable slots differ`);
  for (const d of diffs) {
    const bs = (d.base || 'undefined').slice(0, 30);
    const ms = (d.mut  || 'undefined').slice(0, 30);
    console.log(`  ${d.k.padEnd(7)} base=${bs.padEnd(30)} mut=${ms}`);
  }
}

console.log(`\n── DONE ──`);
console.log(`If a mutation changes ONE slot we wrote AND no other stable slot, the hash is OUTSIDE the JSON.`);
console.log(`If a mutation changes ONE slot we wrote AND some other stable slot Y, slot Y is a digest of (subset including) what we wrote.`);
console.log(`If wire body Δ ≈ plain body Δ for every mutation, the cipher operates on plaintext only (no external signature).`);
console.log(`If wire body Δ > plain body Δ consistently, there's a per-payload signature in the body bytes.`);
