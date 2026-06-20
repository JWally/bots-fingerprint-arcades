#!/usr/bin/env node
/**
 * Empirical resolution: does fpjs use SURFACE cross-checks (UA matches
 * UA-CH matches platform etc.) OR does it ALSO independently validate
 * canvas/audio/font hashes against an OS-conditional reference?
 *
 * Three runs against arcades.click/fpjs:
 *
 *   STEP 0 — baseline (no overrides). Control.
 *
 *   STEP 1 — FULL surface Windows lockdown.
 *     - HTTP User-Agent header → Win Chrome 131 (Playwright userAgent)
 *     - CDP setUserAgentOverride with Windows userAgentMetadata
 *       (Sec-CH-UA-Platform, Sec-CH-UA-Arch, etc.)
 *     - Init script: navigator.platform → "Win32",
 *                    navigator.userAgentData → Windows brands+platform,
 *                    Navigator.prototype.userAgent → Win UA (defensive)
 *     - Chokepoint mutation: s101, s58, s15, s103 → Win values
 *     - LEAVES UNTOUCHED: canvas (s17), audio (s21), font metrics (s51),
 *       WebGL (s74, s75, s76)
 *     - In-page assert: navigator.platform === "Win32",
 *                       navigator.userAgentData.platform === "Windows",
 *                       navigator.userAgent.includes("Windows")
 *     - Outcome decides surface-vs-deeper question:
 *       · score ≤ baseline + small noise → surface checks were the gate
 *       · score still jumps → fpjs uses deeper hash/rendering validation
 *
 *   STEP 2 — STEP 1 + tamper s17 canvas hash to a random md5.
 *     - If step 1 was clean and step 2 caught: fpjs validates the canvas
 *       hash independently. Almost certainly population sampling or
 *       reference-set lookup (the hash space is enormous; hardcoded
 *       constants couldn't cover it).
 *     - If step 1 was already caught: this step is uninformative.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { launchFor, applyFullUASpoof, UA_PROFILES } from './_launch.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.join(__dirname, 'results');
fs.mkdirSync(RESULTS, { recursive: true });

const TARGET = 'https://arcades.click/fpjs';
const STAMP = new Date().toISOString().replace(/[:.]/g, '-');

const WIN = UA_PROFILES.win_chrome_131;
const WIN_UA_CH_PAYLOAD = {
  b: WIN.metadata.brands.map(({ brand, version }) => ({ b: brand, v: version })),
  m: false,
  p: 'Windows',
};

// Init script: defensively override JS-side surface APIs that CDP doesn't cover.
// Uses WeakMap-toString preservation so navigator.platform getter still tostrings
// as `[native code]` (defeats fpjs slot s148).
const JS_SURFACE_LOCKDOWN = `(() => {
  if (window.__winLock) return; window.__winLock = true;

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

  def(Navigator.prototype, 'platform', 'Win32');
  def(Navigator.prototype, 'oscpu', undefined);

  // Rebuild navigator.userAgentData since CDP setUserAgentOverride doesn't
  // populate it.
  const brands = ${JSON.stringify(WIN.metadata.brands)};
  const fakeUaData = {
    brands,
    mobile: false,
    platform: 'Windows',
    getHighEntropyValues: lieAsNative(async () => ({
      architecture: 'x86',
      bitness: '64',
      brands,
      fullVersionList: brands,
      mobile: false,
      model: '',
      platform: 'Windows',
      platformVersion: '15.0.0',
      uaFullVersion: '131.0.6778.205',
      wow64: false,
    }), 'getHighEntropyValues'),
    toJSON: lieAsNative(() => ({ brands, mobile: false, platform: 'Windows' }), 'toJSON'),
  };
  def(Navigator.prototype, 'userAgentData', fakeUaData);
})();`;

// Chokepoint payload mutation — rewrites s101/s58/s15/s103 only.
// LEAVES CANVAS/AUDIO/FONT/WEBGL HASHES UNTOUCHED. That's the point.
function payloadMutationInit(extraSlot) {
  return `(() => {
    if (window.__plain) return; window.__plain = true;
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
            if (obj.s101) obj.s101.v = ${JSON.stringify(WIN.ua)};
            if (obj.s103) obj.s103.v = ${JSON.stringify(WIN.ua.replace('Mozilla/', ''))};
            if (obj.s15)  obj.s15.v  = 'Win32';
            if (obj.s58)  obj.s58.v  = ${JSON.stringify(WIN_UA_CH_PAYLOAD)};
            ${extraSlot}
            return ow(new TextEncoder().encode(JSON.stringify(obj)));
          }
        } catch {}
        return ow(chunk);
      };
      return w;
    };
  })();`;
}

const FAKE_CANVAS_HASH = {
  winding: true,
  geometry: crypto.randomBytes(16).toString('hex'),
  text: crypto.randomBytes(16).toString('hex'),
};

// Plausible Windows-NVIDIA WebGL renderer strings (so steps 3+ can claim
// a CONSISTENT Windows identity all the way down to the WebGL slot, not
// just surface UA).
const WIN_WEBGL = {
  version: 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
  vendor: 'WebKit',
  vendorUnmasked: 'Google Inc. (NVIDIA)',
  renderer: 'WebKit WebGL',
  rendererUnmasked: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Ti Direct3D11 vs_5_0 ps_5_0, D3D11)',
};
const WIN_WEBGL2 = WIN_WEBGL;
const WIN_WEBGL_HASHES = {
  contextAttributes: crypto.randomBytes(16).toString('hex'),
  parameters: crypto.randomBytes(16).toString('hex'),
};
const WIN_WEBGL_SUMMARY = crypto.randomBytes(16).toString('hex');

const WEBGL_ALIGN_MUTATION = `
  if (obj.s27) obj.s27.v = 'Google Inc. (NVIDIA)';
  if (obj.s74) obj.s74.v = ${JSON.stringify(WIN_WEBGL)};
  if (obj.s75) obj.s75.v = ${JSON.stringify(WIN_WEBGL_HASHES)};
  if (obj.s76) obj.s76.v = ${JSON.stringify(WIN_WEBGL_SUMMARY)};
`;

const STEPS = [
  {
    n: 0, name: 'baseline',
    httpUA: null, cdpUA: false, jsLock: false, mutate: '',
    info: 'control — no overrides at all',
  },
  {
    n: 1, name: 'surface_win_lockdown',
    httpUA: WIN.ua, cdpUA: true, jsLock: true, mutate: '',
    info: 'HTTP UA + CDP UA-CH + JS platform/userAgentData → Windows. Canvas/audio/fonts/WebGL untouched.',
  },
  {
    n: 2, name: 'surface_win_lockdown_plus_canvas_tamper',
    httpUA: WIN.ua, cdpUA: true, jsLock: true,
    mutate: `if (obj.s17) obj.s17.v = ${JSON.stringify(FAKE_CANVAS_HASH)};`,
    info: 'Step 1 + tamper s17 canvas hash to random md5. Tests independent canvas validation.',
  },
  {
    n: 3, name: 'win_full_surface_plus_webgl_align',
    httpUA: WIN.ua, cdpUA: true, jsLock: true,
    mutate: WEBGL_ALIGN_MUTATION,
    info: 'Step 1 + also align s74/s75/s76 (WebGL) to Win-NVIDIA. Canvas/audio STILL untouched. ' +
          'If this clears, fpjs only checks WebGL slot consistency, not raw canvas/audio. ' +
          'If still caught, deeper validation exists.',
  },
  {
    n: 4, name: 'win_full_plus_webgl_align_plus_canvas_tamper',
    httpUA: WIN.ua, cdpUA: true, jsLock: true,
    mutate: WEBGL_ALIGN_MUTATION +
            `\n      if (obj.s17) obj.s17.v = ${JSON.stringify(FAKE_CANVAS_HASH)};`,
    info: 'Step 3 + tamper s17 canvas hash. If step 3 was clean and this is caught: ' +
          'canvas hash IS independently validated. Decisive on the population-sampling question.',
  },
  // ── ISOLATING TESTS — stay on the actual OS (Linux), no UA spoof ──
  // These remove the TLS/HTTP-layer noise so we can see if canvas/audio
  // hashes are independently validated within an OS-consistent identity.
  {
    n: 5, name: 'linux_baseline_with_payload_hook',
    httpUA: null, cdpUA: false, jsLock: false,
    mutate: '/* hook installed but no payload mutation */',
    info: 'Linux baseline with the CompressionStream hook installed but no mutation. Control for step 6.',
  },
  {
    n: 6, name: 'linux_baseline_plus_canvas_tamper',
    httpUA: null, cdpUA: false, jsLock: false,
    mutate: `if (obj.s17) obj.s17.v = ${JSON.stringify(FAKE_CANVAS_HASH)};`,
    info: 'Linux baseline + tamper s17 canvas to random md5. Stays OS-consistent. ' +
          'If score moves vs step 5, fpjs validates canvas hash even within consistent OS claims.',
  },
  {
    n: 7, name: 'linux_baseline_plus_webgl_tamper',
    httpUA: null, cdpUA: false, jsLock: false,
    mutate: `if (obj.s74) obj.s74.v = ${JSON.stringify({...WIN_WEBGL, vendorUnmasked: 'Some Unknown Vendor', rendererUnmasked: 'Totally Fake GPU 9000'})}; if (obj.s75) obj.s75.v = ${JSON.stringify(WIN_WEBGL_HASHES)}; if (obj.s76) obj.s76.v = ${JSON.stringify(WIN_WEBGL_SUMMARY)};`,
    info: 'Linux baseline + tamper WebGL slots to random values. If caught, WebGL is validated.',
  },
  {
    n: 8, name: 'linux_baseline_plus_audio_tamper',
    httpUA: null, cdpUA: false, jsLock: false,
    mutate: `if (obj.s21) obj.s21.v = 99.99999;`,
    info: 'Linux baseline + tamper audio sum to obvious non-Mesa-Linux value. If caught, audio is validated.',
  },
];

async function runStep(s) {
  process.env.FPJS_NO_PERSIST = '1';
  const launchOpts = s.httpUA ? { userAgent: s.httpUA } : {};
  const { ctx, close } = await launchFor('winlock-' + s.name, launchOpts);

  if (s.jsLock)      await ctx.addInitScript({ content: JS_SURFACE_LOCKDOWN });
  if (s.mutate !== undefined && (s.jsLock || s.mutate)) {
    // Always install payload mutation when in lockdown mode (so s101 etc. align)
    await ctx.addInitScript({ content: payloadMutationInit(s.mutate || '') });
  }

  const page = await ctx.newPage();
  if (s.cdpUA) await applyFullUASpoof(page, WIN.ua, WIN.metadata);

  // After overrides, check what fpjs WILL see when it reads the JS surface.
  let surfaceCheck = null;
  let v = null;
  page.on('response', async (r) => {
    if (r.url().includes('/api/fpjs/event')) {
      try { v = JSON.parse(await r.text()); } catch {}
    }
  });

  try {
    await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 45_000 });
    // Grab what fpjs would have seen on the JS surface
    surfaceCheck = await page.evaluate(async () => ({
      ua: navigator.userAgent,
      platform: navigator.platform,
      uaData_platform: navigator.userAgentData?.platform,
      uaData_brands: navigator.userAgentData?.brands?.map((b) => b.brand + '/' + b.version).join(','),
      uaData_HE_platform: navigator.userAgentData?.getHighEntropyValues
        ? (await navigator.userAgentData.getHighEntropyValues(['platform', 'architecture'])).platform
        : null,
    })).catch(() => null);
    await new Promise((r) => setTimeout(r, 6_000));
  } catch (e) {
    console.error('  nav:', e.message);
  }
  await close();
  const p = v?.products ?? {};
  return {
    step: s.n, name: s.name, info: s.info,
    surface_seen_by_fpjs: surfaceCheck,
    suspectScore: p.suspectScore?.data?.result,
    bot: p.botd?.data?.bot?.result,
    vpn: p.vpn?.data?.result,
    vpn_osMismatch: p.vpn?.data?.methods?.osMismatch,
    tampering: p.tampering?.data?.result,
    tampering_anomaly: p.tampering?.data?.anomalyScore,
    tampering_ml: p.tampering?.data?.mlScore,
    server_os: p.identification?.data?.browserDetails?.os,
    server_ua_head: p.identification?.data?.browserDetails?.userAgent?.slice(0, 50),
    server_vm: p.virtualMachine?.data?.result,
    visitorId: p.identification?.data?.visitorId,
  };
}

const results = [];
for (const s of STEPS) {
  console.log(`\n[step ${s.n}] ${s.name}`);
  console.log(`   ${s.info}`);
  const r = await runStep(s);
  results.push(r);
  console.log(`   ─ surface seen by fpjs:`);
  console.log(`       platform        =`, r.surface_seen_by_fpjs?.platform);
  console.log(`       uaData.platform =`, r.surface_seen_by_fpjs?.uaData_platform);
  console.log(`       uaData_HE.plat  =`, r.surface_seen_by_fpjs?.uaData_HE_platform);
  console.log(`       UA              =`, r.surface_seen_by_fpjs?.ua?.slice(0, 70));
  console.log(`   ─ verdict:`);
  console.log(`       score=${r.suspectScore}  bot=${r.bot}  osMismatch=${r.vpn_osMismatch}  vm=${r.server_vm}`);
  console.log(`       tamper=${r.tampering}  aml=${(r.tampering_anomaly ?? 0).toFixed(2)}  ml=${(r.tampering_ml ?? 0).toFixed(2)}`);
  console.log(`       server.os=${r.server_os}  server.ua_head=${r.server_ua_head}`);
}

const out = path.join(RESULTS, `win-lockdown-${STAMP}.json`);
fs.writeFileSync(out, JSON.stringify(results, null, 2));
console.log(`\nfull: ${out}\n`);

// ── Verdict on the surface-vs-deeper question ──
console.log('─── VERDICT ───\n');
const base = results[0];
const lock = results[1];
const canv = results[2];

const lockClean = lock.tampering === false && (lock.suspectScore ?? 100) <= (base.suspectScore ?? 0) + 4;

if (lockClean) {
  console.log('★ STEP 1 LANDED CLEAN (within noise of baseline).');
  console.log('  → fpjs gate at this layer is SURFACE-CROSS-CHECKS only.');
  console.log('  → A consistent UA/UA-CH/platform chain passes the surface tests.\n');

  if (canv.tampering || (canv.suspectScore ?? 0) > (lock.suspectScore ?? 0) + 4) {
    console.log('★ STEP 2 GOT CAUGHT after tampering canvas hash.');
    console.log('  → fpjs DOES independently validate the canvas hash.');
    console.log('  → Mechanism is either:');
    console.log('      (a) population sampling: claimed-OS-conditional hash distribution');
    console.log('      (b) hardcoded invariants: specific canvas hash patterns per OS');
    console.log('      (c) cross-run consistency: visitor-id locked canvas hash');
    console.log(`  → Score delta from canvas tamper: ${(canv.suspectScore ?? 0) - (lock.suspectScore ?? 0)} pts`);
  } else {
    console.log('  STEP 2 also passed. fpjs is not validating canvas hash independently here.');
    console.log('  Either the canvas hash space is unverified, or the random hash happened to');
    console.log('  fall in distribution by chance.');
  }
} else {
  console.log('✗ STEP 1 GOT CAUGHT.');
  console.log('  → Surface lockdown was insufficient. Something we didn\'t cover is leaking.');
  console.log(`  → Score: ${lock.suspectScore} vs baseline ${base.suspectScore}`);
  console.log(`  → tampering=${lock.tampering}/aml=${lock.tampering_anomaly}, vm=${lock.server_vm}`);
  console.log('  → Cannot conclude on canvas-validation question until surface is clean.');
  console.log('  → Re-check the in-page surface assertions printed above for what fpjs actually sees.');
}
