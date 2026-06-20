#!/usr/bin/env node
/**
 * Diff two saved verdict JSONs slot-by-slot. Useful for confirming a
 * tamper run actually moved something fpjs observed.
 *
 * Usage:
 *   node diff.mjs ./results/verdict-A.json ./results/verdict-B.json
 *   node diff.mjs   (uses the two latest verdict-*.json by mtime)
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.join(__dirname, 'results');

let [a, b] = process.argv.slice(2);
if (!a || !b) {
  const files = fs.readdirSync(RESULTS)
    .filter((f) => /^verdict-.*\.json$/.test(f))
    .map((f) => ({ f, m: fs.statSync(path.join(RESULTS, f)).mtimeMs }))
    .sort((x, y) => y.m - x.m);
  if (files.length < 2) {
    console.error('Need two verdict JSONs. Pass paths or run verdict.mjs twice first.');
    process.exit(1);
  }
  [b, a] = [files[0].f, files[1].f].map((f) => path.join(RESULTS, f));
  console.log(`(using latest two: ${path.basename(a)} → ${path.basename(b)})\n`);
}

const A = JSON.parse(fs.readFileSync(a, 'utf8'));
const B = JSON.parse(fs.readFileSync(b, 'utf8'));

function flat(obj, prefix = '') {
  const out = {};
  for (const k of Object.keys(obj || {})) {
    const v = obj[k];
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) Object.assign(out, flat(v, key));
    else out[key] = v;
  }
  return out;
}
const flatA = flat(A);
const flatB = flat(B);
const allKeys = new Set([...Object.keys(flatA), ...Object.keys(flatB)]);

const diffs = [];
for (const k of allKeys) {
  const va = JSON.stringify(flatA[k]);
  const vb = JSON.stringify(flatB[k]);
  if (va !== vb) diffs.push({ key: k, a: flatA[k], b: flatB[k] });
}

// Show the meta first, then the products diffs sorted
diffs.sort((x, y) => x.key.localeCompare(y.key));

console.log(`A: ${path.basename(a)}`);
console.log(`B: ${path.basename(b)}`);
console.log(`\n${diffs.length} differing fields\n`);
console.log('field'.padEnd(70), 'A'.padEnd(30), 'B');
console.log('─'.repeat(140));
for (const d of diffs) {
  const va = JSON.stringify(d.a) ?? 'undefined';
  const vb = JSON.stringify(d.b) ?? 'undefined';
  console.log(d.key.padEnd(70), va.slice(0, 28).padEnd(30), vb.slice(0, 60));
}
