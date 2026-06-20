#!/usr/bin/env node
/**
 * 3-phase bisect on FPJS's plaintext payload. Mutates ONE slot at a
 * time (Phase A), then small stacks (Phase B), then high-entropy
 * probes (Phase C), each via the CompressionStream chokepoint MITM.
 * Records visitorId, confidence, suspectScore, tampering for each.
 *
 * Use this to figure out which slot moves the verdict before designing
 * your bypass lie-set.
 *
 *   Phase A — single-slot variant: did vid flip? did score move?
 *   Phase B — small stacks of low-weight slots: do they cross a threshold?
 *   Phase C — high-entropy probes (fonts, Navigator.prototype order)
 *
 * Usage:  node bisect.mjs
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { launchFor } from './_launch.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.join(__dirname, 'results');
fs.mkdirSync(RESULTS, { recursive: true });

const TARGET = 'https://arcades.click/fpjs';
const STAMP = new Date().toISOString().replace(/[:.]/g, '-');
const OUT = path.join(RESULTS, `bisect-${STAMP}.json`);

// Reference profile applied to every run including the reference itself
// — frozen so the only variable between runs is the per-variant `extra`.
const REF = {
  s4: 8, s7: 8, s27: 'Google Inc.',
  webglVendor: 'Google Inc. (Intel)',
  webglRenderer: 'ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)',
  s17: { winding: true, geometry: 'a1b2c3d4e5f67890aabbccddeeff1122', text: 'fedcba0987654321ffeeddccbbaa9988' },
  s21: 124.04347527516074,
};
const CLEAN_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.7499.4 Safari/537.36';

function webglDict(vendor, renderer, v2 = false) {
  return {
    version: v2 ? 'WebGL 2.0 (OpenGL ES 3.0 Chromium)' : 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
    vendor: 'WebKit', vendorUnmasked: vendor, renderer: 'WebKit WebGL', rendererUnmasked: renderer,
  };
}

const BASE_APPLY = `
  if (obj.s101) obj.s101.v = ${JSON.stringify(CLEAN_UA)};
  if (obj.s58)  obj.s58.v  = { b: [{b:'Google Chrome',v:'143'},{b:'Chromium',v:'143'},{b:'Not=A?Brand',v:'24'}], m: false, p: 'Linux' };
  if (obj.s4)  obj.s4.v  = ${REF.s4};
  if (obj.s7)  obj.s7.v  = ${REF.s7};
  if (obj.s27) obj.s27.v = ${JSON.stringify(REF.s27)};
  if (obj.s74) obj.s74.v = ${JSON.stringify(webglDict(REF.webglVendor, REF.webglRenderer, false))};
  if (obj.s75) obj.s75.v = ${JSON.stringify(webglDict(REF.webglVendor, REF.webglRenderer, true))};
  if (obj.s17) obj.s17.v = ${JSON.stringify(REF.s17)};
  if (obj.s21) obj.s21.v = ${REF.s21};
`;

const ALT = {
  canvas2: { winding: true, geometry: crypto.randomBytes(16).toString('hex'), text: crypto.randomBytes(16).toString('hex') },
  webglAMD: { v: 'Google Inc. (AMD)', r: 'ANGLE (AMD, Mesa AMD Radeon RX 580 Series (POLARIS10, DRM 3.41.0), OpenGL 4.6)' },
  webglNV:  { v: 'Google Inc. (NVIDIA)', r: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Ti, OpenGL 4.6)' },
  UA144:    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.7499.4 Safari/537.36',
};

const VARIANTS = [
  { phase: 'A', name: 'reference_1', extra: `` },
  { phase: 'A', name: 'reference_2', extra: `` },  // sanity: is vid stable run-to-run?

  // Phase A — single slot, does it flip?
  { phase: 'A', name: 's4_cores_16',      extra: `if (obj.s4)  obj.s4.v  = 16;` },
  { phase: 'A', name: 's4_cores_24',      extra: `if (obj.s4)  obj.s4.v  = 24;` },
  { phase: 'A', name: 's7_mem_16',        extra: `if (obj.s7)  obj.s7.v  = 16;` },
  { phase: 'A', name: 's7_mem_4',         extra: `if (obj.s7)  obj.s7.v  = 4;` },
  { phase: 'A', name: 's17_canvas_new',   extra: `if (obj.s17) obj.s17.v = ${JSON.stringify(ALT.canvas2)};` },
  { phase: 'A', name: 's21_audio_shift',  extra: `if (obj.s21) obj.s21.v = 122.88;` },
  { phase: 'A', name: 's27_vendor_Mesa',  extra: `if (obj.s27) obj.s27.v = 'Mesa';` },
  { phase: 'A', name: 's74_75_AMD',       extra: `
      if (obj.s74) obj.s74.v = ${JSON.stringify(webglDict(ALT.webglAMD.v, ALT.webglAMD.r, false))};
      if (obj.s75) obj.s75.v = ${JSON.stringify(webglDict(ALT.webglAMD.v, ALT.webglAMD.r, true))};
  `},
  { phase: 'A', name: 's74_75_NVIDIA',    extra: `
      if (obj.s74) obj.s74.v = ${JSON.stringify(webglDict(ALT.webglNV.v, ALT.webglNV.r, false))};
      if (obj.s75) obj.s75.v = ${JSON.stringify(webglDict(ALT.webglNV.v, ALT.webglNV.r, true))};
  `},
  { phase: 'A', name: 's101_ua_144',      extra: `if (obj.s101) obj.s101.v = ${JSON.stringify(ALT.UA144)};` },
  { phase: 'A', name: 's3_colordepth_32', extra: `if (obj.s3)  obj.s3.v  = 32;` },
  { phase: 'A', name: 's5_screen_1440',   extra: `if (obj.s5)  obj.s5.v  = [1440, 900];` },
  { phase: 'A', name: 's20_fonts_many',   extra: `if (obj.s20) obj.s20.v = ["Arial","Helvetica","Times New Roman","Courier","Verdana","Georgia","Comic Sans MS"];` },
  { phase: 'A', name: 's94_uuid_new',     extra: `if (obj.s94) obj.s94.v = { u: '99999999-8888-7777-6666-555555555555', e: [], s: [] };` },
  { phase: 'A', name: 's154_codec_diff',  extra: `if (obj.s154 && obj.s154.v) { obj.s154.v.wvp = true; obj.s154.v.pr = true; }` },
  { phase: 'A', name: 's166_proto_reverse', extra: `if (obj.s166 && obj.s166.v && Array.isArray(obj.s166.v.p)) { obj.s166.v.p.reverse(); }` },

  // Phase B — cumulative low-weight
  { phase: 'B', name: 'B_canvas_audio',   extra: `
      if (obj.s17) obj.s17.v = ${JSON.stringify(ALT.canvas2)};
      if (obj.s21) obj.s21.v = 122.88;
  `},
  { phase: 'B', name: 'B_3_low_weight',   extra: `
      if (obj.s17) obj.s17.v = ${JSON.stringify(ALT.canvas2)};
      if (obj.s21) obj.s21.v = 122.88;
      if (obj.s87 && obj.s87.v) obj.s87.v.b = 'rgb(250, 250, 250)';
  `},
  { phase: 'B', name: 'B_hardware_plus_low', extra: `
      if (obj.s7)  obj.s7.v  = 16;
      if (obj.s17) obj.s17.v = ${JSON.stringify(ALT.canvas2)};
      if (obj.s21) obj.s21.v = 122.88;
  `},

  // Phase C — specific high-entropy probes
  { phase: 'C', name: 'C_fonts_empty',    extra: `if (obj.s20) obj.s20.v = [];` },
  { phase: 'C', name: 'C_fonts_long',     extra: `if (obj.s20) obj.s20.v = ["Arial","Helvetica","Times New Roman","Courier New","Verdana","Georgia","Palatino","Garamond","Bookman","Comic Sans MS","Trebuchet MS","Impact","Lucida Console","Tahoma","Symbol"];` },
  { phase: 'C', name: 'C_nav_shrink',     extra: `if (obj.s166 && obj.s166.v) { obj.s166.v.l = 60; obj.s166.v.p = obj.s166.v.p.slice(0, 1); }` },
  { phase: 'C', name: 'C_nav_length',     extra: `if (obj.s166 && obj.s166.v) obj.s166.v.l = 95;` },
];

function buildInit(extra) {
  return `(() => {
    if (window.__m) return; window.__m = true;
    if (typeof CompressionStream === 'undefined') return;
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
            ${BASE_APPLY}
            ${extra}
            return ow(new TextEncoder().encode(JSON.stringify(obj)));
          }
        } catch {}
        return ow(chunk);
      };
      return w;
    };
  })();`;
}

async function run(v) {
  process.env.FPJS_NO_PERSIST = '1';
  const { ctx, close } = await launchFor('bisect-' + v.name);
  await ctx.addInitScript({ content: buildInit(v.extra) });
  const page = await ctx.newPage();
  let snap = {};
  page.on('response', async (r) => {
    if (r.url().includes('/api/fpjs/event')) {
      try {
        const b = JSON.parse(await r.text());
        snap = {
          vid: b.products?.identification?.data?.visitorId,
          score: b.products?.suspectScore?.data?.result,
          found: b.products?.identification?.data?.visitorFound,
          conf: b.products?.identification?.data?.confidence?.score,
          tamp: b.products?.tampering?.data?.result,
          tml: b.products?.tampering?.data?.mlScore,
        };
      } catch {}
    }
  });
  try {
    await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 45_000 });
    await new Promise((r) => setTimeout(r, 4_500));
  } catch {}
  await close();
  return { phase: v.phase, name: v.name, ...snap };
}

const results = [];
for (const v of VARIANTS) {
  process.stdout.write(`[${v.phase}] ${v.name.padEnd(28)} ... `);
  const r = await run(v);
  results.push(r);
  console.log(`vid=${r.vid}  conf=${r.conf}  score=${r.score}  tamp=${r.tamp}/${(r.tml ?? 0).toFixed(3)}`);
}

const refVid = results.find((r) => r.name === 'reference_1')?.vid;

console.log('\n=== PHASE A: single-slot weight map ===');
console.log(`reference vid: ${refVid}`);
for (const r of results.filter((x) => x.phase === 'A' && x.name !== 'reference_1')) {
  const flip = r.vid !== refVid ? 'FLIP' : 'same';
  console.log(`  ${r.name.padEnd(28)} ${flip.padEnd(5)} vid=${r.vid}  conf=${r.conf}  ${r.tamp ? 'TAMPER' : ''}`);
}
console.log('\n=== PHASE B: cumulative threshold ===');
for (const r of results.filter((x) => x.phase === 'B')) {
  const flip = r.vid !== refVid ? 'FLIP' : 'same';
  console.log(`  ${r.name.padEnd(28)} ${flip.padEnd(5)} vid=${r.vid}  conf=${r.conf}`);
}
console.log('\n=== PHASE C: specific high-entropy ===');
for (const r of results.filter((x) => x.phase === 'C')) {
  const flip = r.vid !== refVid ? 'FLIP' : 'same';
  console.log(`  ${r.name.padEnd(28)} ${flip.padEnd(5)} vid=${r.vid}  conf=${r.conf}`);
}

fs.writeFileSync(OUT, JSON.stringify({ refVid, results }, null, 2));
console.log(`\nfull: ${OUT}`);
