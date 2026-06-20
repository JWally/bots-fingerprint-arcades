#!/usr/bin/env node
/**
 * FPJS value-tampering harness. Iterates ~11 variants of lies installed
 * via prototype-getter overrides BEFORE the fpjs bundle runs, captures
 * the live /api/fpjs/event verdict for each variant, diffs vs baseline.
 *
 * Every override is wrapped in a WeakMap-backed toString forgery so
 * `String(navigator.userAgent)` and `String(Object.getOwnPropertyDescriptor
 * (Navigator.prototype, 'userAgent').get)` still return `function …()
 * { [native code] }`. Without this, fpjs slot s148 catches the lie.
 *
 * Pattern is intentional: this is the JS-PROTOTYPE-LAYER tamper. The
 * sister attack — mutating the assembled plaintext at the
 * CompressionStream chokepoint — is what `bypass.mjs` uses. Use this
 * one when you want fpjs to NOTICE the lie (e.g. you're testing the
 * detector); use bypass.mjs when you want fpjs to be FED bad data
 * without realizing.
 *
 * Usage:
 *   node tamper.mjs                     # arcades.click/fpjs
 *   node tamper.mjs --target https://...
 *   node tamper.mjs --only variant_name # run just one variant
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
const ONLY = val('only', null);
const STAMP = new Date().toISOString().replace(/[:.]/g, '-');
const OUT = path.join(RESULTS, `tamper-${STAMP}.json`);

// Shared WeakMap-toString forgery prelude — included in every lie-injected variant.
const TOSTRING_FORGERY = `
  if (!window.__lyingMap) {
    window.__lyingMap = new WeakMap();
    const _origFnToString = Function.prototype.toString;
    Function.prototype.toString = function () {
      if (window.__lyingMap.has(this)) return window.__lyingMap.get(this);
      return _origFnToString.call(this);
    };
    // forge the wrapper itself: String(Function.prototype.toString) → [native code]
    window.__lyingMap.set(Function.prototype.toString, 'function toString() { [native code] }');
  }
  // helper used in every variant
  window.__lieAsNative = function (fn, name) {
    window.__lyingMap.set(fn, 'function ' + (name || 'get') + '() { [native code] }');
    return fn;
  };
  window.__defineNativeGetter = function (host, prop, value) {
    try {
      const getter = window.__lieAsNative(function () { return value; }, 'get ' + prop);
      Object.defineProperty(host, prop, { get: getter, configurable: true });
    } catch (_) {}
  };
`;

const VARIANTS = [
  { name: 'baseline', description: 'control for this run', inject: `/* nothing */` },

  {
    name: 'ua_strip_headless',
    description: 'remove HeadlessChrome from navigator.userAgent (should DROP botd)',
    inject: `
      ${TOSTRING_FORGERY}
      const real = navigator.userAgent;
      const fixed = real.replace(/HeadlessChrome/g, 'Chrome');
      window.__defineNativeGetter(Navigator.prototype, 'userAgent', fixed);
    `,
  },

  {
    name: 'plugins_forgery',
    description: 'inject fake navigator.plugins (Flash/Silverlight — decade-old tells)',
    inject: `
      ${TOSTRING_FORGERY}
      const fake = [
        { name: 'Shockwave Flash', description: 'Shockwave Flash 32.0 r0', filename: 'libpepflashplayer.so', length: 1 },
        { name: 'Microsoft Silverlight', description: 'Silverlight 5.1', filename: 'silverlight.dll', length: 1 },
        { name: 'Java Applet Plug-in', description: 'Java(TM)', filename: 'javaplugin.dll', length: 1 },
      ];
      window.__defineNativeGetter(Navigator.prototype, 'plugins', fake);
    `,
  },

  {
    name: 'webgl_swiftshader',
    description: 'claim software renderer (SwiftShader + llvmpipe) — should up VM/sandbox tell',
    inject: `
      ${TOSTRING_FORGERY}
      const SWIFT = { 37445: 'Google Inc. (Google)', 37446: 'ANGLE (Google, SwiftShader Device (Subzero), SwiftShader driver)' };
      function hook(proto) {
        const orig = proto.getParameter;
        const wrapped = function (p) { return p in SWIFT ? SWIFT[p] : orig.call(this, p); };
        window.__lieAsNative(wrapped, 'getParameter');
        proto.getParameter = wrapped;
      }
      if (typeof WebGLRenderingContext !== 'undefined') hook(WebGLRenderingContext.prototype);
      if (typeof WebGL2RenderingContext !== 'undefined') hook(WebGL2RenderingContext.prototype);
    `,
  },

  {
    name: 'permissions_all_granted',
    description: 'override navigator.permissions.query to always return granted',
    inject: `
      ${TOSTRING_FORGERY}
      if (navigator.permissions && navigator.permissions.query) {
        const wrapped = async function () {
          return { state: 'granted', status: 'granted', onchange: null,
                   addEventListener: () => {}, removeEventListener: () => {} };
        };
        window.__lieAsNative(wrapped, 'query');
        navigator.permissions.query = wrapped;
      }
    `,
  },

  {
    name: 'uadata_vs_ua_mismatch',
    description: 'UA-CH claims Edge/Windows, UA string says Chrome/Linux — inter-source mismatch',
    inject: `
      ${TOSTRING_FORGERY}
      const fake = {
        brands: [
          { brand: 'Microsoft Edge', version: '121' },
          { brand: 'Not A(Brand', version: '24' },
          { brand: 'Chromium', version: '121' },
        ],
        mobile: false,
        platform: 'Windows',
        getHighEntropyValues: window.__lieAsNative(async () => ({
          architecture: 'x86', bitness: '64',
          brands: fake.brands, mobile: false, model: '',
          platform: 'Windows', platformVersion: '14.0.0',
          uaFullVersion: '121.0.2277.112',
        }), 'getHighEntropyValues'),
        toJSON: window.__lieAsNative(() => ({ brands: fake.brands, mobile: false, platform: 'Windows' }), 'toJSON'),
      };
      window.__defineNativeGetter(Navigator.prototype, 'userAgentData', fake);
    `,
  },

  {
    name: 'screen_mobile_desktop_ua',
    description: '320×480 screen with desktop Linux Chrome UA — form-factor mismatch',
    inject: `
      ${TOSTRING_FORGERY}
      window.__defineNativeGetter(Screen.prototype, 'width', 320);
      window.__defineNativeGetter(Screen.prototype, 'height', 480);
      window.__defineNativeGetter(Screen.prototype, 'availWidth', 320);
      window.__defineNativeGetter(Screen.prototype, 'availHeight', 480);
    `,
  },

  {
    name: 'empty_languages',
    description: 'navigator.languages is empty array, .language is ""',
    inject: `
      ${TOSTRING_FORGERY}
      window.__defineNativeGetter(Navigator.prototype, 'languages', Object.freeze([]));
      window.__defineNativeGetter(Navigator.prototype, 'language', '');
    `,
  },

  {
    name: 'touchpoints_desktop_contradiction',
    description: 'maxTouchPoints=10 on desktop Chrome — touch device + desktop UA mismatch',
    inject: `
      ${TOSTRING_FORGERY}
      window.__defineNativeGetter(Navigator.prototype, 'maxTouchPoints', 10);
    `,
  },

  {
    name: 'mediadevices_empty',
    description: 'mediaDevices.enumerateDevices returns []',
    inject: `
      ${TOSTRING_FORGERY}
      if (navigator.mediaDevices) {
        const wrapped = async function () { return []; };
        window.__lieAsNative(wrapped, 'enumerateDevices');
        navigator.mediaDevices.enumerateDevices = wrapped;
      }
    `,
  },

  {
    name: 'mac_safari_stack',
    description: 'Safari-on-Mac UA + hardware + plugins + screen mobile + permissions + Europe/London tz',
    inject: `
      ${TOSTRING_FORGERY}
      const FAKE_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15';
      window.__defineNativeGetter(Navigator.prototype, 'userAgent', FAKE_UA);
      window.__defineNativeGetter(Navigator.prototype, 'platform', 'MacIntel');
      window.__defineNativeGetter(Navigator.prototype, 'vendor', 'Apple Computer, Inc.');
      window.__defineNativeGetter(Navigator.prototype, 'hardwareConcurrency', 128);
      window.__defineNativeGetter(Navigator.prototype, 'deviceMemory', 64);
      window.__defineNativeGetter(Navigator.prototype, 'maxTouchPoints', 10);
      window.__defineNativeGetter(Navigator.prototype, 'plugins',
        [{ name: 'Shockwave Flash', filename: 'libpepflashplayer.so', length: 1 }]);
      window.__defineNativeGetter(Screen.prototype, 'width', 320);
      window.__defineNativeGetter(Screen.prototype, 'height', 480);
      const origResolved = Intl.DateTimeFormat.prototype.resolvedOptions;
      const wrappedR = function () { const o = origResolved.call(this); o.timeZone = 'Europe/London'; return o; };
      window.__lieAsNative(wrappedR, 'resolvedOptions');
      Intl.DateTimeFormat.prototype.resolvedOptions = wrappedR;
      if (navigator.permissions && navigator.permissions.query) {
        const wrappedQ = async () => ({ state: 'granted', status: 'granted', onchange: null,
                                        addEventListener: () => {}, removeEventListener: () => {} });
        window.__lieAsNative(wrappedQ, 'query');
        navigator.permissions.query = wrappedQ;
      }
    `,
  },

  {
    name: 'platform_to_win32',
    description: 'navigator.platform → Win32 (does fpjs catch UA/platform mismatch?)',
    inject: `
      ${TOSTRING_FORGERY}
      window.__defineNativeGetter(Navigator.prototype, 'platform', 'Win32');
    `,
  },
];

async function runVariant(variant) {
  // Per-variant ephemeral profile so IDB visitor_id (s94) doesn't carry state
  // between variants. Tradeoff: vid jumps every run, but the SCORE comparison
  // (the thing we actually care about) is clean.
  process.env.FPJS_NO_PERSIST = '1';
  const { ctx, close } = await launchFor('tamper-' + variant.name);
  if (variant.inject && variant.inject.trim() !== '/* nothing */') {
    await ctx.addInitScript({ content: variant.inject });
  }
  const page = await ctx.newPage();
  let resp = null;
  page.on('response', async (r) => {
    if (r.url().includes('/api/fpjs/event')) {
      try { resp = { status: r.status(), body: await r.text() }; } catch {}
    }
  });
  try {
    await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 45_000 });
    await new Promise((r) => setTimeout(r, 6_000));
  } catch (e) { console.error(`  nav: ${e.message}`); }
  await close();
  let parsed = null;
  if (resp?.body) { try { parsed = JSON.parse(resp.body); } catch { parsed = { _raw: resp.body }; } }
  return { variant: variant.name, description: variant.description, response: parsed };
}

function snapshot(r) {
  if (!r || !r.products) return null;
  const g = (p) => p.split('.').reduce((o, k) => (o == null ? null : o[k]), r.products);
  return {
    suspectScore: g('suspectScore.data.result'),
    botd_result: g('botd.data.bot.result'),
    botd_type: g('botd.data.bot.type'),
    vpn_result: g('vpn.data.result'),
    vpn_confidence: g('vpn.data.confidence'),
    vpn_tzMismatch: g('vpn.data.methods.timezoneMismatch'),
    vpn_osMismatch: g('vpn.data.methods.osMismatch'),
    vpn_publicVPN: g('vpn.data.methods.publicVPN'),
    proxy_result: g('proxy.data.result'),
    incognito: g('incognito.data.result'),
    devTools: g('developerTools.data.result'),
    tampering_result: g('tampering.data.result'),
    tampering_anomaly: g('tampering.data.anomalyScore'),
    tampering_ml: g('tampering.data.mlScore'),
    tampering_antidetect: g('tampering.data.antiDetectBrowser'),
    vm_result: g('virtualMachine.data.result'),
    emulator_result: g('emulator.data.result'),
    privacySettings: g('privacySettings.data.result'),
    highActivity: g('highActivity.data.result'),
    mitm_result: g('mitmAttack.data.result'),
    tor_result: g('tor.data.result'),
    visitorId: g('identification.data.visitorId'),
    confidence: g('identification.data.confidence.score'),
  };
}

function diff(a, b) {
  if (!a || !b) return { _missing: true };
  const d = {};
  for (const k of Object.keys(a)) {
    if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) d[k] = { baseline: a[k], after: b[k] };
  }
  return d;
}

const results = [];
const toRun = ONLY ? VARIANTS.filter((v) => v.name === ONLY || v.name === 'baseline') : VARIANTS;
for (const v of toRun) {
  console.log(`→ ${v.name.padEnd(32)} ${v.description}`);
  const r = await runVariant(v);
  const s = snapshot(r.response);
  results.push({ ...r, snapshot: s });
  if (s) {
    console.log(`   suspect=${s.suspectScore}  bot=${s.botd_result}${s.botd_type ? '/' + s.botd_type : ''}  ` +
                `tamper=${s.tampering_result}/aml=${s.tampering_anomaly}  vpn=${s.vpn_result}/${s.vpn_confidence}`);
  } else {
    console.log(`   NO RESPONSE`);
  }
}
const base = results.find((r) => r.variant === 'baseline')?.snapshot;
const diffs = {};
for (const r of results) {
  if (r.variant === 'baseline') continue;
  diffs[r.variant] = {
    description: r.description,
    scoreDelta: (r.snapshot?.suspectScore ?? 0) - (base?.suspectScore ?? 0),
    flipped: diff(base, r.snapshot),
  };
}
fs.writeFileSync(OUT, JSON.stringify({
  target: TARGET, ts: new Date().toISOString(),
  baseline: base, variantResults: results, diffMap: diffs,
}, null, 2));

console.log('\n─── DIFF MAP ───');
const W = (s, n) => String(s ?? '').padEnd(n);
console.log(W('variant', 32), W('score', 7), W('Δ', 5), 'flipped signals');
console.log('─'.repeat(100));
console.log(W('baseline', 32), W(base?.suspectScore, 7), W('—', 5), '(reference)');
for (const r of results) {
  if (r.variant === 'baseline') continue;
  const d = diffs[r.variant];
  const flips = Object.keys(d.flipped).filter((k) => !['visitorId', 'confidence'].includes(k)).join(', ');
  const sign = d.scoreDelta > 0 ? '+' : '';
  console.log(W(r.variant, 32), W(r.snapshot?.suspectScore, 7), W(sign + d.scoreDelta, 5), flips);
}
console.log(`\nfull: ${OUT}`);
