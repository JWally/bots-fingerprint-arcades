#!/usr/bin/env node
/**
 * FPJS verdict bypass — the headliner.
 *
 * Two approaches are stacked here:
 *
 *   A. PROTOTYPE-LAYER LIES (WeakMap toString preserved).
 *      Spoofs navigator/screen/UA-CH/WebGL at the JS-API layer before
 *      fpjs reads. Defeats the static slot reads (s101 UA, s58 UA-CH,
 *      s74/75 WebGL, s4/7 hardware). fpjs's own toString sweep over the
 *      patched accessors sees `[native code]` because we forge it via
 *      a WeakMap that maps wrapper-fn → cached `[native code]` string.
 *
 *   B. CHOKEPOINT PAYLOAD MUTATION (CompressionStream + WeakSet).
 *      Replaces the assembled plaintext at the serialization boundary
 *      via a WeakSet-tagged write hook. fpjs runs every collector for
 *      real, sees the real machine; we then surgically rewrite specific
 *      sN slots before deflate-raw runs. The cipher, the wire format,
 *      and the suspect-score model all run untouched on our spoofed
 *      data. Strictly more powerful than (A) because fpjs has no
 *      client-side detector for this — nothing the browser exposes can
 *      tell a wrapped CompressionStream apart from a real one.
 *
 * Goal: flip arcades.click/fpjs verdict from VPN=true (osMismatch=true)
 * → VPN=false. Strategy: claim a "clean Mac Chrome" identity end to
 * end. fpjs's osMismatch detector compares the UA-claimed OS to its
 * server-side network/IP signals; making the UA + UA-CH + platform +
 * userAgentData all CONSISTENTLY claim macOS lines them up with the
 * server's expectation for a typical AT&T residential IP.
 *
 * Usage:
 *   node bypass.mjs                       # default cascade
 *   node bypass.mjs --stage A             # just prototype lies
 *   node bypass.mjs --stage B             # just chokepoint mutation
 *   node bypass.mjs --stage both          # default
 *   node bypass.mjs --target https://...
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
const STAGE = val('stage', 'both');
const STAMP = new Date().toISOString().replace(/[:.]/g, '-');
const OUT = path.join(RESULTS, `bypass-${STAMP}.json`);

// Target identity: Mac Chrome 131 on macOS 15
const FAKE_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const FAKE_PLATFORM = 'MacIntel';

// ── Stage A: prototype-layer lies (WeakMap toString preserved) ──
const STAGE_A = `(() => {
  if (window.__bypassA) return;
  window.__bypassA = true;

  const lyingMap = new WeakMap();
  const _origFnToString = Function.prototype.toString;
  Function.prototype.toString = function () {
    if (lyingMap.has(this)) return lyingMap.get(this);
    return _origFnToString.call(this);
  };
  lyingMap.set(Function.prototype.toString, 'function toString() { [native code] }');

  const lieAsNative = (fn, name) => {
    lyingMap.set(fn, 'function ' + (name || 'get') + '() { [native code] }');
    return fn;
  };
  const def = (host, prop, value) => {
    try {
      const g = lieAsNative(function () { return value; }, 'get ' + prop);
      Object.defineProperty(host, prop, { get: g, configurable: true });
    } catch {}
  };

  const FAKE_UA = ${JSON.stringify(FAKE_UA)};
  def(Navigator.prototype, 'userAgent', FAKE_UA);
  def(Navigator.prototype, 'appVersion', FAKE_UA.replace('Mozilla/', ''));
  def(Navigator.prototype, 'platform', 'MacIntel');
  def(Navigator.prototype, 'vendor', 'Google Inc.');
  def(Navigator.prototype, 'oscpu', undefined);

  // UA-CH consistent with Mac Chrome
  const uaData = {
    brands: [
      { brand: 'Not_A Brand', version: '8' },
      { brand: 'Chromium', version: '131' },
      { brand: 'Google Chrome', version: '131' },
    ],
    mobile: false,
    platform: 'macOS',
    getHighEntropyValues: lieAsNative(function () {
      return Promise.resolve({
        architecture: 'arm', bitness: '64',
        brands: this.brands, fullVersionList: this.brands,
        mobile: false, model: '', platform: 'macOS',
        platformVersion: '15.0.0', uaFullVersion: '131.0.6778.205', wow64: false,
      });
    }, 'getHighEntropyValues'),
    toJSON: lieAsNative(function () { return { brands: this.brands, mobile: this.mobile, platform: this.platform }; }, 'toJSON'),
  };
  def(Navigator.prototype, 'userAgentData', uaData);

  // hardware consistent with a typical M-series Mac
  def(Navigator.prototype, 'hardwareConcurrency', 10);
  def(Navigator.prototype, 'deviceMemory', 8);
  def(Navigator.prototype, 'maxTouchPoints', 0);
  def(Navigator.prototype, 'pdfViewerEnabled', true);

  // WebGL renderer string — Apple
  function wrapGetParameter(proto) {
    if (!proto || !proto.getParameter) return;
    const orig = proto.getParameter;
    const w = function (param) {
      if (param === 37446) return 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)';
      if (param === 37445) return 'Google Inc. (Apple)';
      if (param === 7937)  return 'WebKit WebGL';
      if (param === 7936)  return 'WebKit';
      return orig.call(this, param);
    };
    lieAsNative(w, 'getParameter');
    proto.getParameter = w;
  }
  if (typeof WebGLRenderingContext !== 'undefined') wrapGetParameter(WebGLRenderingContext.prototype);
  if (typeof WebGL2RenderingContext !== 'undefined') wrapGetParameter(WebGL2RenderingContext.prototype);

  // also lie about timezone so VPN.timezoneMismatch stays false
  // (Dallas user → America/Chicago; leave as-is. If you're elsewhere, override here.)

  console.log('[bypass:A] prototype lies installed');
})();`;

// ── Stage B: chokepoint plaintext mutation (CompressionStream + WeakSet) ──
//
// This is the BIG hammer: rewrites obj.sN slots in the serialized JSON
// right before deflate-raw + cipher + POST. Done in the same world as
// the bundle, after fpjs has fully assembled the payload, so the
// rewrite reflects "fpjs ran everything for real, then the bytes got
// edited at the door." There's no client-side detector for this.
const STAGE_B = `(() => {
  if (window.__bypassB) return;
  window.__bypassB = true;

  if (typeof CompressionStream === 'undefined') return;

  // Lies to apply to the assembled object. Slot meanings from FPJS.md §3.2.
  const apply = (obj) => {
    const UA = ${JSON.stringify(FAKE_UA)};
    if (obj.s101) obj.s101.v = UA;                               // navigator.userAgent
    if (obj.s103) obj.s103.v = UA.replace('Mozilla/', '');       // navigator.appVersion
    if (obj.s15)  obj.s15.v  = 'MacIntel';                       // navigator.platform
    if (obj.s4)   obj.s4.v   = 10;                               // hardwareConcurrency
    if (obj.s7)   obj.s7.v   = 8;                                // deviceMemory
    if (obj.s27)  obj.s27.v  = 'Google Inc. (Apple)';            // webgl vendor unmasked
    if (obj.s58)  obj.s58.v  = {                                 // userAgentData
      b: [
        { b: 'Not_A Brand', v: '8' },
        { b: 'Chromium', v: '131' },
        { b: 'Google Chrome', v: '131' },
      ],
      m: false, p: 'macOS',
    };
    if (obj.s74)  obj.s74.v  = {                                 // WebGL1 params
      version: 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
      vendor: 'WebKit', vendorUnmasked: 'Google Inc. (Apple)',
      renderer: 'WebKit WebGL',
      rendererUnmasked: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)',
    };
    if (obj.s75)  obj.s75.v  = {                                 // WebGL2 hashes — proper md5 length (32 hex chars)
      contextAttributes: '6b1ed336830d2bc96442a9d76373252a',
      parameters: '57a2cddb99538d50a013818c1f0f6b3b',
    };
    if (obj.s103) obj.s103.v = UA.replace('Mozilla/', '');       // navigator.appVersion
    if (obj.s145) {                                              // Navigator-API list — strip Linux-only entries if present
      // (no-op for now; keep here as a hook if osMismatch persists)
    }
  };

  const Orig = CompressionStream;
  const tagged = new WeakSet();
  self.CompressionStream = function (format) {
    const cs = new Orig(format);
    tagged.add(cs.writable);
    return cs;
  };
  self.CompressionStream.prototype = Orig.prototype;

  const origGetWriter = WritableStream.prototype.getWriter;
  WritableStream.prototype.getWriter = function () {
    const w = origGetWriter.call(this);
    if (!tagged.has(this)) return w;
    const ow = w.write.bind(w);
    w.write = function (chunk) {
      try {
        let text;
        if (typeof chunk === 'string') text = chunk;
        else if (chunk && ArrayBuffer.isView(chunk)) text = new TextDecoder().decode(chunk);
        else if (chunk instanceof ArrayBuffer) text = new TextDecoder().decode(new Uint8Array(chunk));
        // fpjs payload shape: starts with {"c":"<pubkey>"...
        if (text && text.startsWith('{"c":') && text.length > 1000) {
          const obj = JSON.parse(text);
          apply(obj);
          const mutated = new TextEncoder().encode(JSON.stringify(obj));
          window.__bypassBApplied = true;
          return ow(mutated);
        }
      } catch (e) { window.__bypassBErr = String(e.message); }
      return ow(chunk);
    };
    return w;
  };
  console.log('[bypass:B] chokepoint mutation installed');
})();`;

async function runStage(stages) {
  // Each stage gets its own ephemeral profile so prior IDB/cookies don't
  // make fpjs flag this as a returning-visitor on the second+ run.
  process.env.FPJS_NO_PERSIST = '1';
  // When either lie stage is active, ALSO spoof the HTTP UA header.
  // Without this, fpjs's server reads the real Chrome HTTP UA and
  // browserDetails.os stays "Linux" regardless of slot mutations.
  const ua = stages.length > 0 ? FAKE_UA : undefined;
  const { ctx, close } = await launchFor('bypass-' + (stages.join('') || 'baseline'),
                                          ua ? { userAgent: ua } : {});
  if (stages.includes('A')) await ctx.addInitScript({ content: STAGE_A });
  if (stages.includes('B')) await ctx.addInitScript({ content: STAGE_B });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (/bypass/.test(m.text())) console.log(`  [browser] ${m.text()}`); });

  let verdict = null;
  page.on('response', async (r) => {
    if (r.url().includes('/api/fpjs/event')) {
      try { verdict = JSON.parse(await r.text()); } catch {}
    }
  });

  await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 45_000 });
  await new Promise((r) => setTimeout(r, 6_000));
  const applied = await page.evaluate(() => ({ B: !!window.__bypassBApplied, err: window.__bypassBErr }));
  await close();
  return { stages, verdict, applied };
}

function snap(v) {
  if (!v?.products) return null;
  const g = (p) => p.split('.').reduce((o, k) => (o == null ? null : o[k]), v.products);
  return {
    suspect: g('suspectScore.data.result'),
    bot: g('botd.data.bot.result'),
    bot_type: g('botd.data.bot.type'),
    vpn: g('vpn.data.result'),
    vpn_conf: g('vpn.data.confidence'),
    vpn_methods: g('vpn.data.methods'),
    proxy: g('proxy.data.result'),
    tampering: g('tampering.data.result'),
    tampering_aml: g('tampering.data.anomalyScore'),
    tampering_ml: g('tampering.data.mlScore'),
    visitorId: g('identification.data.visitorId'),
  };
}

const plan = STAGE === 'A' ? [['baseline', []], ['A only', ['A']]]
           : STAGE === 'B' ? [['baseline', []], ['B only', ['B']]]
           : /* both */      [['baseline', []], ['A only', ['A']], ['B only', ['B']], ['A + B', ['A', 'B']]];

const results = [];
for (const [label, stages] of plan) {
  console.log(`\n→ ${label}  (stages: ${stages.join('+') || 'none'})`);
  const r = await runStage(stages);
  const s = snap(r.verdict);
  results.push({ label, stages, ...r, snap: s });
  if (s) {
    console.log(`   suspect=${s.suspect}  bot=${s.bot}  vpn=${s.vpn}(${s.vpn_conf})  ` +
                `osMismatch=${s.vpn_methods?.osMismatch}  tamper=${s.tampering}(aml=${s.tampering_aml})`);
    if (stages.includes('B')) console.log(`   stage-B applied=${r.applied.B}  err=${r.applied.err ?? 'none'}`);
  } else {
    console.log(`   NO VERDICT`);
  }
}

fs.writeFileSync(OUT, JSON.stringify({
  target: TARGET, ts: new Date().toISOString(),
  results: results.map((r) => ({ ...r, verdict: r.verdict ? '[saved]' : null })),
  verdicts: results.map((r) => ({ label: r.label, verdict: r.verdict })),
}, null, 2));

console.log('\n─── BYPASS LADDER ───');
const W = (s, n) => String(s ?? '').padEnd(n);
console.log(W('stage', 14), W('suspect', 8), W('bot', 14), W('vpn', 8),
            W('osMismatch', 12), W('tamper', 10), 'visitorId');
console.log('─'.repeat(110));
for (const r of results) {
  const s = r.snap;
  console.log(W(r.label, 14), W(s?.suspect, 8), W(s?.bot, 14),
              W(s?.vpn, 8), W(s?.vpn_methods?.osMismatch, 12),
              W(s?.tampering + '/' + s?.tampering_aml, 10),
              (s?.visitorId || '').slice(0, 20));
}
console.log(`\nfull: ${OUT}`);

// Win condition
const last = results[results.length - 1].snap;
if (last && last.vpn === false && last.tampering === false && (last.suspect ?? 100) < 10) {
  console.log('\n★ BYPASS SUCCEEDED — verdict is clean ★');
}
