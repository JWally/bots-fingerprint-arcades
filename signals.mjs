#!/usr/bin/env node
/**
 * Print the bundled slot dictionary: maps FPJS v4 `sN` slot IDs to
 * their reverse-engineered semantic meaning. Source: FPJS.md §3.2,
 * derived from the CompressionStream chokepoint dump of the assembled
 * plaintext payload (138 slots observed).
 *
 * Usage:
 *   node signals.mjs                          # print the full dictionary
 *   node signals.mjs ./results/mitm-*-plaintext.json
 *                                              # annotate a captured payload
 *                                              # with names + types
 */

import fs from 'fs';
import path from 'path';

// Slot dictionary — high-confidence mappings from FPJS.md §3.2.
// Empty entry = observed-but-unmapped, marked '?'.
const DICT = {
  s1: '? (-1 here)',
  s2: 'navigator.languages',
  s3: 'screen.colorDepth',
  s4: 'navigator.hardwareConcurrency',
  s5: 'screen [h, w]',
  s6: 'screen avail rect [availLeft, availTop, w, h]',
  s7: 'navigator.deviceMemory',
  s9: 'timezone (IANA)',
  s10: 'cookies enabled',
  s11: 'sessionStorage enabled',
  s12: 'localStorage enabled',
  s13: 'indexedDB enabled (false = incognito tell)',
  s14: 'navigator.storage.estimate() quota/usage',
  s15: 'navigator.platform',
  s16: 'navigator.plugins (array)',
  s17: '★ canvas fingerprint {winding, geometry md5, text md5}',
  s19: 'touch capability {maxTouchPoints, touchEvent, touchStart}',
  s20: 'font probe (list of detected fonts)',
  s21: '★ audio fingerprint (OfflineAudioContext sum)',
  s22: '? numeric',
  s23: '? (-3 = skipped on this run)',
  s24: '? numeric',
  s27: 'WebGL vendor unmasked',
  s28: '? array',
  s29: 'timestamp (some persistent ID epoch)',
  s30: '? null',
  s32: '? bool',
  s33: '? bool',
  s36: '? null',
  s37: 'color gamut ("srgb" | "p3" | "rec2020")',
  s38: 'HDR? numeric',
  s39: 'wide gamut? bool',
  s40: 'inverted colors? bool',
  s41: '? null',
  s42: 'forced colors numeric',
  s43: 'prefers-reduced-motion? bool',
  s44: 'prefers-reduced-transparency? bool',
  s45: '★ timezone consistency probe (two timestamps 5h apart)',
  s46: '? md5 hash (some signal)',
  s48: '★ Math constants fingerprint (sin/cos/tan/log)',
  s49: '★ float-precision quirks ([0.0999..., 0.1000...])',
  s50: 'timing granularity (ns?)',
  s51: 'font generic-family metrics {default, apple, serif, sans, mono}',
  s52: '? null (-2)',
  s55: '? null (-1)',
  s56: '★ handshake token echo (96-char base64 sealed_box from GET)',
  s57: '? = 1',
  s58: 'navigator.userAgentData.{brands, mobile, platform}',
  s59: '? bool',
  s60: '? bool',
  s61: '? bool',
  s62: '? bool',
  s63: '? bool',
  s64: '? bool',
  s65: '? bool',
  s66: '? null',
  s68: '? bool',
  s69: 'window.history stack shape',
  s70: '? (-4)',
  s71: 'origin info {window, location, ancestors}',
  s72: '? bool',
  s74: '★ WebGL params unmasked {version, vendor, vendorUnmasked, renderer, rendererUnmasked}',
  s75: '★ WebGL attrs + params hashes {contextAttributes md5, parameters md5}',
  s76: '★ WebGL2 summary hash',
  s79: 'font-file probe (via /default.ini)',
  s80: '? bool',
  s81: '? = 255',
  s82: 'primary language',
  s83: 'language list',
  s84: 'viewport {w, h}',
  s85: '? null',
  s86: '? null',
  s87: '★ system CSS colors (dark/light theme fingerprint)',
  s89: 'navigator.vendor',
  s91: '? bool',
  s92: 'DOM element bounding rect (some probe element)',
  s93: 'DOM bounding rect (<body>?)',
  s94: '★ IndexedDB persistent visitor ID {u: uuid, e: [], s: []}',
  s95: '? null',
  s96: '? null',
  s97: '? null',
  s98: '? bool',
  s99: '? bool',
  s101: '★ full userAgent',
  s102: 'window.chrome present?',
  s103: 'navigator.appVersion',
  s104: '? numeric',
  s106: 'window.chrome.runtime? bool',
  s117: '? numeric',
  s118: '? bool',
  s119: '★ thrown-error stack format ("TypeError: …\\n    at GW …")',
  s120: '? bool',
  s123: 'navigator.productSub',
  s130: 'function toString output array',
  s131: '? array',
  s132: 'function-toString-fingerprint (e.g. close().toString())',
  s133: '? string ("[object External]")',
  s135: '? numeric',
  s136: '? bool',
  s139: '? bool',
  s142: '? bool',
  s144: '? null (-2)',
  s145: 'Navigator-API availability list (~50 method names)',
  s146: '? bool',
  s148: '★ Function.prototype.bind.toString() — patches caught here',
  s149: '? null',
  s150: 'window.{outer,inner}{Width,Height}',
  s151: '? null',
  s152: '? = 2',
  s153: '? = true',
  s154: 'webdriver-framework flags {wv, wvp, pr, ck, pt, fp}',
  s155: '? {}',
  s156: 'global prototype chain quirks (e.g. ["Iterator"])',
  s157: '★ named-bot-framework probes {awesomium, cef, phantom, selenium, …}',
  s158: '? bool',
  s159: '? bool',
  s160: '? null (-2)',
  s162: '? bool',
  s163: '? bool',
  s165: '★ isTrusted probe (dispatch synthetic click, read event.isTrusted)',
  s166: '★ Navigator.prototype property enumeration {l: count, p: [{i, n}, …]}',
  s167: '? null (-3)',
  s200: 'performance.now() at collection start',
  s201: '? bool',
  s202: 'document language',
  s203: '★ CSS calc() subpixel result ("calc(0.207912px)")',
  s204: '? bool',
  s205: '? = "c:"',
  s206: '? null',
  s207: '? bool',
  s209: '★ Math precision: sin/cos/tan hashed {s: [...], p: [...]}',
  s210: '? null',
  s211: 'Intl.* resolver state counts',
  s212: '? bool',
  s213: '? null',
  s214: '? = 960 (timing metric)',
  s215: '★ ~40 feature-detection booleans {cc, cg, eai, eaie, ecb, ecp, …}',
};

const argv = process.argv.slice(2);

if (argv.length === 0) {
  // Print the dictionary.
  console.log(`FPJS v4 slot dictionary — ${Object.keys(DICT).length} mappings`);
  console.log('Stars (★) mark high-signal slots referenced in FPJS.md §3.\n');
  for (const k of Object.keys(DICT).sort((a, b) => parseInt(a.slice(1)) - parseInt(b.slice(1)))) {
    console.log(`  ${k.padEnd(7)} ${DICT[k]}`);
  }
  process.exit(0);
}

const file = argv[0];
if (!fs.existsSync(file)) {
  console.error(`file not found: ${file}`);
  process.exit(1);
}
const raw = fs.readFileSync(file, 'utf8');
let obj;
try { obj = JSON.parse(raw); }
catch (e) { console.error(`not valid JSON: ${e.message}`); process.exit(1); }

console.log(`annotated payload from ${path.basename(file)}\n`);
console.log('slot'.padEnd(7), 'meaning'.padEnd(50), 'status', 'value');
console.log('─'.repeat(140));

const slotKeys = Object.keys(obj).filter((k) => /^s\d+$/.test(k))
                       .sort((a, b) => parseInt(a.slice(1)) - parseInt(b.slice(1)));
for (const k of slotKeys) {
  const entry = obj[k];
  const status = entry?.s;
  const value = entry?.v;
  const meaning = DICT[k] || '?';
  const valStr = value === null ? 'null'
    : typeof value === 'object' ? JSON.stringify(value).slice(0, 80)
    : String(value).slice(0, 80);
  console.log(k.padEnd(7), meaning.slice(0, 48).padEnd(50), String(status ?? '?').padEnd(6), valStr);
}

const unmapped = slotKeys.filter((k) => !DICT[k]);
if (unmapped.length) {
  console.log(`\n${unmapped.length} unmapped slots: ${unmapped.join(', ')}`);
  console.log('(add to DICT in signals.mjs as you reverse them)');
}
