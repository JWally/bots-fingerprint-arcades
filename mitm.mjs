#!/usr/bin/env node
/**
 * FPJS chokepoint MITM. Captures the plaintext fingerprint payload
 * BEFORE encryption + wire transmission.
 *
 * Pipeline (fpjs v4):
 *   buildPayload() → JSON.stringify → TextEncoder.encode →
 *   CompressionStream('deflate-raw').writable.getWriter().write(bytes)
 *   → (read compressed output) → customCipher(...) → fetch(POST body)
 *
 * Hook strategy (installed at document-start, before any page script):
 *   1. JSON.stringify     — catches the assembled object early
 *   2. TextEncoder.encode — catches strings the bundle skips JSON for
 *   3. CompressionStream  — the gold one: replace ctor, tag .writable
 *                           in a WeakSet, wrap WritableStream.prototype.
 *                           getWriter so the writer for that stream gets
 *                           .write monkey-patched to log/save the chunk.
 *   4. fetch              — catches the encrypted body shape on the wire.
 *
 * The WeakSet trick is intentional: it identifies streams created by the
 * patched ctor without storing a strong ref (no leaks, no enumeration
 * surface for the bundle to inspect). Function.prototype.toString stays
 * untouched, so a `String(JSON.stringify)` check returns the real
 * `[native code]` since we only swapped the binding, not the body.
 *
 * Usage:
 *   node mitm.mjs                                # arcades.click/fpjs
 *   node mitm.mjs --target https://...
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
const OUT = path.join(RESULTS, `mitm-${STAMP}.json`);

// Note: must be a string for addInitScript({ content }). Keep self-contained.
const INIT = `(() => {
  if (window.__plainInstalled) return;
  window.__plainInstalled = true;
  window.__plainLog = [];

  // 1. JSON.stringify — catches any object-shaped payload before it becomes bytes.
  const origStringify = JSON.stringify;
  JSON.stringify = function (...args) {
    const out = origStringify.apply(this, args);
    if (typeof out === 'string' && out.length >= 500) {
      const fpShape = /canvas|webgl|audio|fonts|userAgent|plugins|screen|timezone|fingerprint|visitor|"s\\d+":/i;
      window.__plainLog.push({
        kind: 'json.stringify',
        t: performance.now(),
        len: out.length,
        preview: out.slice(0, 400),
        full: fpShape.test(out.slice(0, 4000)) ? out : null,
      });
    }
    return out;
  };

  // 2. TextEncoder.encode — final string→bytes step before most ciphers.
  if (typeof TextEncoder !== 'undefined') {
    const origEncode = TextEncoder.prototype.encode;
    TextEncoder.prototype.encode = function (s) {
      if (typeof s === 'string' && s.length >= 500) {
        const fpShape = /canvas|webgl|audio|fonts|userAgent|plugins|screen|timezone|fingerprint|visitor|"s\\d+":/i;
        window.__plainLog.push({
          kind: 'textencoder.encode',
          t: performance.now(),
          len: s.length,
          preview: s.slice(0, 400),
          full: fpShape.test(s.slice(0, 4000)) ? s : null,
        });
      }
      return origEncode.call(this, s);
    };
  }

  // 3. CompressionStream chokepoint (THE GOLD HOOK).
  //    WeakSet tags streams created by the wrapped ctor; getWriter
  //    checks membership and only wraps .write on those streams.
  if (typeof CompressionStream !== 'undefined' &&
      typeof WritableStreamDefaultWriter !== 'undefined') {
    const origCS = CompressionStream;
    const wrappedStreams = new WeakSet();
    self.CompressionStream = function (format) {
      const cs = new origCS(format);
      wrappedStreams.add(cs.writable);
      return cs;
    };
    self.CompressionStream.prototype = origCS.prototype;

    const origGetWriter = WritableStream.prototype.getWriter;
    WritableStream.prototype.getWriter = function () {
      const w = origGetWriter.call(this);
      if (wrappedStreams.has(this)) {
        const origWrite = w.write.bind(w);
        w.write = function (chunk) {
          try {
            let text;
            if (typeof chunk === 'string') text = chunk;
            else if (chunk && ArrayBuffer.isView(chunk)) {
              text = new TextDecoder('utf-8', { fatal: false }).decode(chunk);
            } else if (chunk instanceof ArrayBuffer) {
              text = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(chunk));
            }
            if (text && text.length > 0) {
              window.__plainLog.push({
                kind: 'compression.write',
                t: performance.now(),
                len: text.length,
                preview: text.slice(0, 400),
                full: text,
              });
            }
          } catch {}
          return origWrite(chunk);
        };
      }
      return w;
    };
  }

  // 4. fetch — catches the encrypted body shape on the wire (validates
  //    that what we see in (3) is what's being compressed and POSTed).
  const origFetch = fetch;
  self.fetch = function (...args) {
    const url = typeof args[0] === 'string' ? args[0] : args[0]?.url;
    const init = args[1];
    if (/api\\.fpjs\\.io/.test(url || '') && init?.body) {
      const body = init.body;
      let preview;
      if (typeof body === 'string') preview = body.slice(0, 200);
      else if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
        const u8 = body instanceof ArrayBuffer ? new Uint8Array(body)
          : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
        preview = Array.from(u8.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('');
      }
      window.__plainLog.push({
        kind: 'fetch-body',
        t: performance.now(),
        url,
        bodyType: body?.constructor?.name,
        bodyBytes: body?.byteLength ?? body?.length ?? -1,
        preview,
      });
    }
    return origFetch.apply(this, args);
  };
})();`;

const { ctx, close } = await launchFor('mitm');
await ctx.addInitScript({ content: INIT });

const page = await ctx.newPage();

let verdict = null;
page.on('response', async (res) => {
  if (res.url().includes('/api/fpjs/event')) {
    try { verdict = JSON.parse(await res.text()); } catch {}
  }
});

console.log(`→ visiting ${TARGET}`);
await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 45_000 });
await new Promise((r) => setTimeout(r, 6_000));

const log = await page.evaluate(() => window.__plainLog ?? []);
await close();

log.sort((a, b) => a.t - b.t);
console.log(`\n→ captured ${log.length} chokepoint events\n`);

// Print timeline
for (const e of log) {
  if (e.kind === 'fetch-body') {
    console.log(`[${e.t.toFixed(0).padStart(6)}ms] fetch-body  ${e.url}`);
    console.log(`                bodyType=${e.bodyType} bytes=${e.bodyBytes}  hex=${e.preview}`);
    continue;
  }
  const flag = e.full ? ' ★ FULL SAVED' : '';
  console.log(`[${e.t.toFixed(0).padStart(6)}ms] ${e.kind.padEnd(20)} ${e.len} chars${flag}`);
  if (e.full == null) {
    console.log(`                preview: ${e.preview.replace(/\s+/g, ' ').slice(0, 160)}`);
  }
}

// Save the gold: the longest CompressionStream.write capture is the
// fingerprint plaintext.
const candidates = log.filter((e) => e.full && e.kind === 'compression.write');
candidates.sort((a, b) => b.len - a.len);
const winner = candidates[0];
if (winner) {
  const plain = path.join(RESULTS, `mitm-${STAMP}-plaintext.json`);
  let pretty;
  try { pretty = JSON.stringify(JSON.parse(winner.full), null, 2); }
  catch { pretty = winner.full; }
  fs.writeFileSync(plain, pretty);
  console.log(`\n✓ plaintext payload (${winner.len} chars) saved to ${plain}`);
}

fs.writeFileSync(OUT, JSON.stringify({
  target: TARGET,
  ts: new Date().toISOString(),
  log: log.map((e) => ({ ...e, full: e.full ? `(saved, ${e.len} chars)` : null })),
  verdict,
}, null, 2));
console.log(`✓ event log saved to ${OUT}`);

if (verdict) {
  const p = verdict.products ?? {};
  console.log('\n=== VERDICT ON THIS RUN ===');
  console.log('  suspectScore  =', p.suspectScore?.data?.result);
  console.log('  bot           =', p.botd?.data?.bot?.result, p.botd?.data?.bot?.type ?? '');
  console.log('  vpn           =', p.vpn?.data?.result, JSON.stringify(p.vpn?.data?.methods));
  console.log('  tampering     =', p.tampering?.data?.result,
              'anomaly=' + p.tampering?.data?.anomalyScore + ' ml=' + p.tampering?.data?.mlScore);
}
