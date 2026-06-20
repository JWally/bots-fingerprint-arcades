#!/usr/bin/env node
/**
 * Confirmation: when does the ML cross-signal detector fire?
 *
 * Hypothesis (from hunt-hash.mjs): mlScore = 0 for single-slot
 * mutations; jumps to ~1.0 only when we mutate MULTIPLE slots together
 * in a way that contradicts the unmutated canvas/audio/font signals.
 *
 * Runs a ladder of progressively-more-coordinated lies via the
 * CompressionStream chokepoint:
 *   step 0: baseline (no mutation)
 *   step 1: s101 only — UA → Mac UA
 *   step 2: s101 + s58 — UA + UA-CH both → Mac
 *   step 3: s101 + s58 + s15 — UA + UA-CH + platform → Mac
 *   step 4: + s74 + s75 — also WebGL → Apple
 *
 * Expected: ml stays 0 until step 3 or 4 when fpjs ML starts to see
 * "claims Mac but canvas/audio still say Linux."
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { launchFor, applyFullUASpoof, UA_PROFILES, APPLE_WEBGL_INIT } from './_launch.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.join(__dirname, 'results');
fs.mkdirSync(RESULTS, { recursive: true });

const TARGET = 'https://arcades.click/fpjs';
const STAMP = new Date().toISOString().replace(/[:.]/g, '-');

const MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const MAC_UA_CH = {
  b: [
    { b: 'Not_A Brand', v: '8' },
    { b: 'Chromium', v: '131' },
    { b: 'Google Chrome', v: '131' },
  ],
  m: false, p: 'macOS',
};
const APPLE_WEBGL = {
  version: 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
  vendor: 'WebKit', vendorUnmasked: 'Google Inc. (Apple)',
  renderer: 'WebKit WebGL',
  rendererUnmasked: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)',
};
const APPLE_WEBGL2 = {
  contextAttributes: '6b1ed336830d2bc96442a9d76373252a',
  parameters: '57a2cddb99538d50a013818c1f0f6b3b',
};

const STEPS = [
  { n: 0,   name: 'baseline',              slots: 'none',                    httpUA: null,    apply: `/* no mutation */` },
  { n: 1,   name: 's101_only',             slots: 's101',                    httpUA: null,    apply: `if (obj.s101) obj.s101.v = ${JSON.stringify(MAC_UA)};` },
  { n: 2,   name: 's101_s58',              slots: 's101+s58',                httpUA: null,    apply: `if (obj.s101) obj.s101.v = ${JSON.stringify(MAC_UA)}; if (obj.s58) obj.s58.v = ${JSON.stringify(MAC_UA_CH)};` },
  { n: 3,   name: 's101_s58_s15',          slots: 's101+s58+s15',            httpUA: null,    apply: `if (obj.s101) obj.s101.v = ${JSON.stringify(MAC_UA)}; if (obj.s58) obj.s58.v = ${JSON.stringify(MAC_UA_CH)}; if (obj.s15) obj.s15.v = 'MacIntel';` },
  { n: 3.5, name: 's101_s58_s15_s103',     slots: 's101+s58+s15+s103',       httpUA: null,    apply: `
      if (obj.s101) obj.s101.v = ${JSON.stringify(MAC_UA)};
      if (obj.s58)  obj.s58.v  = ${JSON.stringify(MAC_UA_CH)};
      if (obj.s15)  obj.s15.v  = 'MacIntel';
      if (obj.s103) obj.s103.v = ${JSON.stringify(MAC_UA.replace('Mozilla/', ''))};
  `},
  { n: 4,   name: 's101_s58_s15_s74_s75',  slots: 's101+s58+s15+s103+s74+s75', httpUA: null,  apply: `
      if (obj.s101) obj.s101.v = ${JSON.stringify(MAC_UA)};
      if (obj.s58)  obj.s58.v  = ${JSON.stringify(MAC_UA_CH)};
      if (obj.s15)  obj.s15.v  = 'MacIntel';
      if (obj.s103) obj.s103.v = ${JSON.stringify(MAC_UA.replace('Mozilla/', ''))};
      if (obj.s74)  obj.s74.v  = ${JSON.stringify(APPLE_WEBGL)};
      if (obj.s75)  obj.s75.v  = ${JSON.stringify(APPLE_WEBGL2)};
  `},
  // The real test: also override the HTTP User-Agent header that Chrome sends.
  // Without this, fpjs server reads HTTP UA and reports browserDetails.os="Linux"
  // regardless of slot mutations.
  { n: 5,   name: 'step4 + HTTP_UA_override', slots: 'all of step 4 + HTTP UA (ctx)', httpUA: MAC_UA, cdpUA: false, webglWrap: false, apply: `
      if (obj.s101) obj.s101.v = ${JSON.stringify(MAC_UA)};
      if (obj.s58)  obj.s58.v  = ${JSON.stringify(MAC_UA_CH)};
      if (obj.s15)  obj.s15.v  = 'MacIntel';
      if (obj.s103) obj.s103.v = ${JSON.stringify(MAC_UA.replace('Mozilla/', ''))};
      if (obj.s74)  obj.s74.v  = ${JSON.stringify(APPLE_WEBGL)};
      if (obj.s75)  obj.s75.v  = ${JSON.stringify(APPLE_WEBGL2)};
  `},
  // Step 6: add CDP setUserAgentOverride with userAgentMetadata — this
  // overrides the Sec-CH-UA-* headers + navigator.userAgentData that
  // Playwright's userAgent option leaves untouched.
  { n: 6,   name: 'step5 + CDP_UA_CH',     slots: 'step 5 + Sec-CH-UA-* via CDP',  httpUA: null, cdpUA: true, webglWrap: false, apply: `
      if (obj.s101) obj.s101.v = ${JSON.stringify(MAC_UA)};
      if (obj.s58)  obj.s58.v  = ${JSON.stringify(MAC_UA_CH)};
      if (obj.s15)  obj.s15.v  = 'MacIntel';
      if (obj.s103) obj.s103.v = ${JSON.stringify(MAC_UA.replace('Mozilla/', ''))};
      if (obj.s74)  obj.s74.v  = ${JSON.stringify(APPLE_WEBGL)};
      if (obj.s75)  obj.s75.v  = ${JSON.stringify(APPLE_WEBGL2)};
  `},
  // Step 7: also wrap WebGL.getParameter at the JS layer. fpjs's
  // virtualMachine detector reads the live WebGL renderer string from
  // the canvas context, not just from our payload slots, so the
  // payload-side s74/s75 lies aren't enough on their own.
  { n: 7,   name: 'step6 + WebGL_wrap',    slots: 'step 6 + JS WebGL.getParameter', httpUA: null, cdpUA: true, webglWrap: true, apply: `
      if (obj.s101) obj.s101.v = ${JSON.stringify(MAC_UA)};
      if (obj.s58)  obj.s58.v  = ${JSON.stringify(MAC_UA_CH)};
      if (obj.s15)  obj.s15.v  = 'MacIntel';
      if (obj.s103) obj.s103.v = ${JSON.stringify(MAC_UA.replace('Mozilla/', ''))};
      if (obj.s74)  obj.s74.v  = ${JSON.stringify(APPLE_WEBGL)};
      if (obj.s75)  obj.s75.v  = ${JSON.stringify(APPLE_WEBGL2)};
  `},
];

function buildInit(apply) {
  return `(() => {
    if (window.__c) return; window.__c = true;
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
            ${apply}
            return ow(new TextEncoder().encode(JSON.stringify(obj)));
          }
        } catch {}
        return ow(chunk);
      };
      return w;
    };
  })();`;
}

async function runStep(s) {
  process.env.FPJS_NO_PERSIST = '1';
  const launchOpts = s.httpUA ? { userAgent: s.httpUA } : {};
  const { ctx, close } = await launchFor('confirm-ua-' + s.name, launchOpts);
  await ctx.addInitScript({ content: buildInit(s.apply) });
  if (s.webglWrap) await ctx.addInitScript({ content: APPLE_WEBGL_INIT });
  const page = await ctx.newPage();
  if (s.cdpUA) {
    const profile = UA_PROFILES.mac_chrome_131;
    await applyFullUASpoof(page, profile.ua, profile.metadata);
  }
  let v = null;
  page.on('response', async (r) => {
    if (r.url().includes('/api/fpjs/event')) {
      try { v = JSON.parse(await r.text()); } catch {}
    }
  });
  try {
    await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 45_000 });
    await new Promise((r) => setTimeout(r, 6_000));
  } catch {}
  await close();
  const p = v?.products ?? {};
  return {
    step: s.n,
    name: s.name,
    slots_mutated: s.slots,
    httpUA: s.httpUA ? s.httpUA.slice(0, 40) + '…' : null,
    suspectScore: p.suspectScore?.data?.result,
    bot: p.botd?.data?.bot?.result,
    vpn: p.vpn?.data?.result,
    vpn_osMismatch: p.vpn?.data?.methods?.osMismatch,
    tampering_result: p.tampering?.data?.result,
    tampering_anomaly: p.tampering?.data?.anomalyScore,
    tampering_ml: p.tampering?.data?.mlScore,
    server_os: p.identification?.data?.browserDetails?.os,
    server_ua_head: p.identification?.data?.browserDetails?.userAgent?.slice(0, 40),
    server_vm: p.virtualMachine?.data?.result,
    visitorId: p.identification?.data?.visitorId,
  };
}

const results = [];
for (const s of STEPS) {
  process.stdout.write(`[step ${s.n}] ${s.slots.padEnd(28)} `);
  const r = await runStep(s);
  results.push(r);
  console.log(`score=${String(r.suspectScore).padEnd(3)}  bot=${r.bot}  osMismatch=${r.vpn_osMismatch}  tamper=${r.tampering_result}  aml=${(r.tampering_anomaly ?? 0).toFixed(3)}  ml=${(r.tampering_ml ?? 0).toFixed(3)}`);
}

const out = path.join(RESULTS, `confirm-ua-${STAMP}.json`);
fs.writeFileSync(out, JSON.stringify(results, null, 2));
console.log(`\nfull: ${out}\n`);

console.log('─── LADDER ───');
const W = (s, n) => String(s ?? '').padEnd(n);
console.log(W('slots mutated', 40), W('score', 7), W('osMM', 6), W('aml', 6), W('vm', 6), W('server.os', 12), 'server.ua (head)');
console.log('─'.repeat(130));
for (const r of results) {
  console.log(W(r.slots_mutated, 40), W(r.suspectScore, 7),
              W(r.vpn_osMismatch, 6),
              W((r.tampering_anomaly ?? 0).toFixed(2), 6),
              W(r.server_vm, 6),
              W(r.server_os, 12),
              (r.server_ua_head || ''));
}

const mlSpike = results.findIndex((r) => (r.tampering_ml ?? 0) > 0.1);
if (mlSpike === -1) {
  console.log('\n✓ ml stayed 0 across all steps — even the 5-slot coordinated Mac claim slipped past ML this run.');
} else {
  console.log(`\n⚠ ml first spiked at step ${results[mlSpike].step} (${results[mlSpike].slots_mutated})`);
  console.log('  → that step\'s coordination is the trigger threshold for this detector.');
}
