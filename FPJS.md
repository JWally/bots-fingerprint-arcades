# FingerprintJS v4 — Reverse-Engineering Writeup

Companion to [README.md](README.md). Target: `https://arcades.click/fpjs`
(an arcades.click demo page that loads `https://fpjscdn.net/v4/<publicKey>`
and surfaces the full Smart Signals verdict to the client via the
merchant proxy at `/api/fpjs/event`).

The arcades.click setup is a **white-box oracle**: every bypass attempt
is immediately visible in the rendered verdict. That's the bonus this
harness exploits — you don't need the merchant's secret API key to
score your own tamper attempts; the page shows the verdict.

This writeup is the third in a series:

- `~/Dev/bots-x-castle/X.Castle.md` — Castle.io's per-field cipher and
  prototype-layer tamper. Castle has **no plaintext chokepoint**
  observable client-side; every field is ciphered individually before
  the encoder ever sees a structured object.
- `~/Dev/bots-datadome/DataDome.md` — DataDome's XOR-keystream cipher
  and the `v(n,t)` collector chokepoint. DataDome **does** route every
  signal through a single TLV-encoder function, which is the
  bundle-patch site.
- **This document** — fpjs v4's `CompressionStream`-anchored pipeline,
  which exposes a chokepoint *upstream* of the cipher (the plaintext
  passes through `WritableStreamDefaultWriter.write` on a stream
  created by `new CompressionStream('deflate-raw')`). This is the
  single most exploitable chokepoint of the three vendors.

---

## 1. TL;DR

- Fpjs v4 talks to `api.fpjs.io` over a **two-request handshake**: a
  GET returns a 72-byte ephemeral key blob, then a POST ships a
  deflate-compressed-and-encrypted fingerprint payload.
- The payload is JSON but uses **numeric slot IDs** (`s1`, `s2`, …,
  `s215`) instead of semantic keys, raising the cost of "what does
  this signal mean" even after plaintext capture.
- Cryptography is pure-JS (no `crypto.subtle`). The pipeline is roughly
  `buildObject → JSON.stringify → TextEncoder.encode →
  CompressionStream('deflate-raw') → customCipher → fetch(ArrayBuffer)`.
- **Hooking `CompressionStream.writable.getWriter().write` captures
  the entire plaintext before encryption.** The hook uses a `WeakSet`
  to tag streams created by the wrapped constructor — no leaks, no
  enumeration surface, no global-scope side channel. `Function.proto-
  type.toString` is left untouched (only specific accessor wrappers
  get cached `[native code]` strings via a `WeakMap`).
- Suspect-score is driven primarily by `osMismatch` (server-side OS
  inference vs claimed UA) and the named-bot-framework probes (slot
  `s157`). The chokepoint mutation in `bypass.mjs` neutralizes both
  by rewriting `s101` / `s103` / `s15` / `s58` consistently with the
  spoofed OS, without touching the actual JS APIs the browser exposes
  (so fpjs's lie-scanners over Navigator / WebGL prototype getters
  see nothing).

---

## 2. Wire Protocol

### 2.1 Handshake GET

```
GET https://api.fpjs.io/<rotating-path>?q=<publicKey>
```

- No body, no special headers beyond `Accept: */*`.
- Path segment rotates per bundle version (e.g. `xridvya/qAo6p`).
  Makes path-based blocking marginally harder than a stable
  `/v1/handshake`.
- Response is 96 bytes of base64 (~72 bytes decoded). 72 bytes is the
  exact size of a libsodium `crypto_box_seal` output (32-byte
  ephemeral pubkey + 24-byte nonce + 16-byte MAC). The client stores
  this and echoes it back inside the payload as slot `s56`.

### 2.2 Fingerprint POST

```
POST https://api.fpjs.io/?ci=js/4.0.3&q=<publicKey>
Content-Type: text/plain          ← intentional disguise; body is binary
Body: ~3KB ArrayBuffer, high-entropy, no gzip/deflate/brotli magic
```

`Content-Type: text/plain` for a binary encrypted blob is a
covertness move. On corporate proxies that log by content-type, fpjs's
POST blends with analytics beacons rather than a binary blob that
might get flagged.

Pipeline (reverse-engineered, every stage verified by hooking):

```
buildFingerprintObject()                    # all 138 signal slots assembled
  → JSON.stringify(obj)                      # ~9KB string
  → TextEncoder.encode(str)                  # Uint8Array
  → CompressionStream('deflate-raw').writable.write(bytes)
  → (read compressed output via reader)
  → customCipher(compressed, keyFromHandshake)   # pure-JS, XOR-derived
  → fetch(url, { method:'POST', body: encryptedArrayBuffer })
```

### 2.3 POST Response

```json
{
  "version": "4",
  "event_id": "1776446246059.toCkPH",
  "sealed_result": null,
  "visitor_id": "Yvb01Gc5NQllpQoZRg8K",
  "suspect_score": 4,
  "internal": "VlljW…(base64, ~280 bytes)…"
}
```

`visitor_id`, `event_id`, and `suspect_score` are client-visible. The
`internal` field is an encrypted handle the merchant's Server API uses
to fetch the full Smart Signals payload server-side. Clients can't
decrypt it.

Arcades.click then proxies the merchant Server API call through its
own `/api/fpjs/event` route, which returns the full Smart Signals JSON
(this is the response `verdict.mjs` captures and `tamper.mjs` /
`bypass.mjs` use as the oracle).

---

## 3. Plaintext Payload

Captured by hooking `WritableStreamDefaultWriter.prototype.write` on
the `CompressionStream('deflate-raw')` instance fpjs creates just
before the fetch. The exact string fed into the compressor.

### 3.1 Envelope (non-slot keys)

```json
{
  "c":  "<publicKey>",                       // client / public API key
  "m":  "e",                                 // mode ("e" = encrypted?)
  "mo": ["cm"],                              // modules
  "sc": { "u": "https://fpjscdn.net/v4/<publicKey>" },  // self-ref
  "ii": [],                                  // integration identifier
  "gt": 1,                                   // ?
  "ab": { "noop": "a", "fp": "h" },          // A/B flags
  "lr": []                                   // ?
}
```

### 3.2 Slot IDs → semantic meaning

138 slots observed (`s1..s215`, sparse). High-signal mappings:

| Slot | Meaning | Notes |
|------|---------|-------|
| s2 | navigator.languages | array of arrays |
| s3 | screen.colorDepth | typically 24 |
| s4 | navigator.hardwareConcurrency | |
| s5 | screen [h, w] | |
| s7 | navigator.deviceMemory | |
| s9 | timezone (IANA) | |
| s15 | navigator.platform | |
| **s17** | **canvas fingerprint** | `{winding, geometry md5, text md5}` |
| s19 | touch capability | `{maxTouchPoints, touchEvent, touchStart}` |
| s20 | font probe | list of detected fonts |
| **s21** | **audio fingerprint** | `OfflineAudioContext` sum |
| s27 | WebGL vendor unmasked | |
| **s45** | **timezone consistency probe** | two timestamps 5h apart |
| **s48** | **Math constants fingerprint** | sin/cos/etc with specific inputs |
| **s49** | **float-precision quirks** | `[0.0999..., 0.1000...]` |
| **s56** | **handshake token echo** | 96-char base64 from §2.1 |
| s58 | navigator.userAgentData | `{brands, mobile, platform}` |
| **s74** | **WebGL params unmasked** | full renderer dict |
| **s75** | **WebGL attrs + params hashes** | |
| **s87** | **system CSS colors** | dark/light theme fingerprint |
| **s94** | **IndexedDB persistent visitor ID** | UUID, survives cookie clears |
| **s101** | **full userAgent** | |
| **s119** | **thrown-error stack format** | `"TypeError: …\n    at GW (…)"` — engine fingerprint |
| s145 | Navigator-API availability list | ~50 method names |
| s148 | `Function.prototype.bind.toString()` | **tamper-detection chokepoint** |
| s154 | webdriver-framework flags | `{wv, wvp, pr, ck, pt, fp}` |
| **s157** | **named-bot-framework probes** | `{awesomium, cef, phantom, selenium, …}` |
| **s165** | **isTrusted probe** | synthetic click, read `event.isTrusted` |
| **s166** | **Navigator.prototype property enumeration** | count + index/name pairs |
| **s203** | **CSS `calc()` subpixel result** | `"calc(0.207912px)"` — engine math precision |
| **s209** | **Math precision sin/cos/tan hashed** | |
| **s215** | **~40 feature-detection booleans** | dense API matrix |

Full mappings: see `signals.mjs` (it's the source of truth and the
annotator for captured `mitm-*-plaintext.json`).

---

## 4. Chokepoints — Why The `WeakSet` + `CompressionStream` Pattern Wins

This is the meat. Three observations:

### 4.1 The serialization pipeline has one stream-shaped seam

Fpjs uses `new CompressionStream('deflate-raw')` as the final
Web-API-level step before its custom pure-JS cipher. This means:

- The plaintext (JSON string → Uint8Array via `TextEncoder.encode`)
  passes through `WritableStreamDefaultWriter.prototype.write` on
  the stream's `.writable`.
- That write happens **after** every collector has run and the object
  is fully assembled.
- That write happens **before** any cipher operation. No XOR, no
  cipher state, no opaque bytes. Just the JSON string in `Uint8Array`
  form.

### 4.2 The WeakSet identity trick

You can't just monkey-patch `WritableStreamDefaultWriter.prototype.write`
globally — every stream in every page would log, you'd lose all
attribution, and the bundle would notice the perf impact. Instead:

```js
const Orig = CompressionStream;
const tagged = new WeakSet();
self.CompressionStream = function (format) {
  const cs = new Orig(format);
  tagged.add(cs.writable);          // ← mark this stream
  return cs;
};
self.CompressionStream.prototype = Orig.prototype;

const origGetWriter = WritableStream.prototype.getWriter;
WritableStream.prototype.getWriter = function () {
  const w = origGetWriter.call(this);
  if (tagged.has(this)) {           // ← only wrap if WE made this stream
    const origWrite = w.write.bind(w);
    w.write = function (chunk) {
      // chunk is the plaintext Uint8Array — log/save/mutate, then pass through
      return origWrite(chunk);
    };
  }
  return w;
};
```

Why `WeakSet` specifically:

- **No strong refs**: streams get GC'd normally; no leak.
- **No enumeration**: a `WeakSet` has no `forEach`, no `size`, no
  way for the bundle to discover wrapped streams short of holding
  the stream object itself and calling `.has()` (which it doesn't).
- **No global side channel**: no extra property on the stream, no
  hidden symbol, no toString change. The stream is byte-identical to
  a real one from any inspection vector the bundle has.

A `Map` or plain object would expose either enumeration (object) or
strong refs + a missing-key fallback (Map's `.get(stream)` returning
undefined needs a wrapper). `WeakSet` is the cleanest fit.

### 4.3 The WeakMap toString preservation

Fpjs reads `Function.prototype.bind.toString()` (slot `s148`) and
`function close() { [native code] }` (slot `s132`) as anti-tamper
probes. If you wrap `getParameter` on `WebGLRenderingContext.prototype`
with a regular function, `String(wrapped)` returns
`"function (param) { ... }"` — caught.

Defense:

```js
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
```

Now `String(wrapped)` returns the cached `[native code]` string for
every function we've registered. `String(JSON.stringify)` and any
function we *didn't* wrap returns the real V8 output unchanged. The
`WeakMap` mirrors the same identity-tagging trick as the `WeakSet`:
non-enumerable, GC-safe, no enumeration surface.

This is the chokepoint of chokepoints: one wrapped `toString`, one
`WeakMap`, and every subsequent lie can be marked native at no
per-lie cost.

### 4.4 What about the other chokepoints?

`mitm.mjs` also installs hooks on `JSON.stringify`, `TextEncoder.encode`,
and `fetch`. These are weaker:

- **`JSON.stringify`** fires on every large object the page builds —
  React, the fpjs payload, console logs. High noise floor; we filter
  by content shape (`/canvas|webgl|fingerprint|"s\d+":/`).
- **`TextEncoder.encode`** is downstream of `JSON.stringify` for the
  fpjs path. Useful only if fpjs ever skips JSON for a payload
  (currently doesn't).
- **`fetch`** is downstream of the cipher. Body is opaque bytes; only
  useful for confirming the POST shape and size.

The `CompressionStream` write is the only one with plaintext + low
noise + before-cipher position. It's the win.

---

## 5. Two Attack Stages, Stackable

### Stage A — prototype-getter lies (the JS-API layer)

Spoof what fpjs reads when it asks the browser:
`navigator.userAgent`, `Navigator.prototype.webdriver`,
`WebGLRenderingContext.prototype.getParameter(37446)`, etc. Every
wrapper goes through `lieAsNative()` so `s148` doesn't catch us.

Power: defeats every static read by the collector.

Limit: fpjs's score is partly server-side. Lying about `userAgent`
client-side doesn't change what the server sees in the request
headers or the IP-class lookup. `osMismatch=true` still fires if your
ASN looks like a residential ISP but your UA claims Linux server.

### Stage B — chokepoint plaintext mutation (the SERIALIZATION layer)

After fpjs runs every real collector against the real browser,
intercept the assembled JSON in the `CompressionStream` write hook
and rewrite specific slots:

```js
if (text.startsWith('{"c":') && text.length > 1000) {
  const obj = JSON.parse(text);
  if (obj.s101) obj.s101.v = FAKE_UA;          // userAgent
  if (obj.s15)  obj.s15.v  = 'MacIntel';        // platform
  if (obj.s58)  obj.s58.v  = { b: […], m: false, p: 'macOS' };  // UA-CH
  if (obj.s74)  obj.s74.v  = { …apple_webgl }; // WebGL
  return origWrite(new TextEncoder().encode(JSON.stringify(obj)));
}
```

Power: the **server sees our spoofed data**, signed with the real
cipher (the cipher runs untouched on our edited bytes), with a real
ephemeral handshake key, indistinguishable from a real client whose
browser actually had those values. The only client-side detector
that *could* catch this would need to verify post-serialization
byte equality against a pre-serialization snapshot — fpjs has no such
detector, because there's nothing on the client side that *needs* it
(the cipher already authenticates everything downstream).

Limit: any signal fpjs's server derives from request metadata
(IP-class, ASN, TLS fingerprint, Cloudflare-injected headers) is
outside our reach. To go fully clean you'd combine Stage B with a
real residential proxy.

### Why stack them?

Sometimes a fpjs detector reads the same signal twice — once via the
prototype getter (Stage A catches it), once via a side-channel like
`Intl.DateTimeFormat.resolvedOptions().timeZone` (Stage A catches it
only if you also wrap `Intl`) or via something we forgot to wrap.
Stage B is the safety net: even if Stage A missed a read, Stage B
overwrites the final slot value before it ships.

The cascade in `bypass.mjs` runs all four configurations (no lies,
A only, B only, A+B) so you can see exactly which stage moved which
signal.

---

## 6. Comparison vs Castle and DataDome

| Property | Castle | DataDome | **FPJS** |
|---|---|---|---|
| Crypto | per-field bit-mix cipher (`tt()`) | XOR keystream (Marsaglia-xorshift seeded from `Date.now() >> 3`) | pure-JS XOR over deflate-raw output |
| Plaintext chokepoint | none (each field ciphered standalone before assembly) | `v(n,t)` collector entry | `CompressionStream.write` |
| WebRTC | no | yes (signal `wr_*`) | no |
| SubtleCrypto | no | no | no |
| Wire shape | `request_token` (base64 in body of POST /1.1/onboarding/task.json) | encoded jspl param in POST to api-js.datadome.co | binary POST to api.fpjs.io with `text/plain` |
| Anti-tamper at client | `Function.prototype.toString` sweep | Object.prototype getter checks + cookie HMAC | `s148` toString probe + `s157` framework probes |
| Verdict visible client-side | no (need merchant secret to call /v1/filter) | partly (cookie + HTTP status; full only via /js/) | **yes** (via `/api/fpjs/event` on arcades.click) |
| Bypass attack class | per-field tamper via prototype lies | network-level (clean SOAX mobile) + signal lies | prototype lies + chokepoint payload rewrite |
| Easiest attack | tamper.mjs lies the prototype (Castle ciphers them as-is) | residential IP + signed-envelope bypass | **stage B chokepoint mutation** (no detection surface) |

FPJS's design is structurally the most attacker-friendly of the three
because (a) it uses a standard Web API at the serialization seam
where any extension can hook (b) it surfaces the full verdict to the
client (the merchant has no secret-key-protected detail; if the
merchant wants confidentiality they have to round-trip the
`internal` token server-side, which arcades.click doesn't bother
with because the demo's point is showing the verdict). Castle is
hardest of the three because it never assembles a structured
plaintext anywhere observable.

---

## 7. Cross-layer consistency — the actual gate

Everything in §4–6 is about *capturing and rewriting the payload*. But
empirically (this session, 2026-05-23, ~30 runs against arcades.click/
fpjs), the chokepoint mutation by itself isn't what gets caught. The
gate that traps every multi-layer spoof attempt is fpjs's
**cross-layer consistency check**.

### 7.1 We can spoof anything; the server only needs one disagreement

This is the entire game in one sentence: **we can lie about anything
the JS engine exposes — every value goes where we tell it. fpjs's
server doesn't need to know what's true. It just needs to find one
axis that doesn't agree with the others.**

You have to maintain a coherent lie across **every** axis they read.
They have to find **one** axis that doesn't fit. Asymmetric in their
favor.

### 7.2 Three layers, ranked by spoofability

| Layer | Examples | Can we spoof from Playwright/CDP? |
|---|---|---|
| **JS application** | navigator.*, canvas/audio/WebGL hashes, fonts, screen, plugins, Math, userAgentData | ✓ Every value, with effort |
| **HTTP application** | User-Agent header, Sec-CH-UA-* headers, Accept-Language | ✓ Via `chromium.launch({channel:'chrome'})` + `Network.setUserAgentOverride` w/ userAgentMetadata |
| **Network / connection** | JA3/JA4 TLS fingerprint, HTTP/2 SETTINGS frame, header order/casing, TCP options, MSS | ✗ **No.** Baked into Chrome's network stack below the CDP surface. |

The third layer is what closed every Mac/Win impersonation attempt
in this session. TLS ClientHello + HTTP/2 SETTINGS emit before any
JS runs, before any extension hooks fire, before CDP can override
anything. Chrome on Linux sends *measurably* different TLS handshake
parameters than Chrome on Windows: different optional extensions
present/absent, different cipher suite order, different ALPN entries,
different session-resumption defaults. fpjs's server captures the JA3/
JA4 of the actual connection, compares to the OS claim in HTTP and
JS layers, and lights up `anomalyScore=1.0` and `vm.result=true`
before payload-layer validation even matters.

### 7.3 Empirical confirmation

The decisive run (`win-lockdown.mjs` step 1, 2026-05-23):

| Surface | Value seen by fpjs |
|---|---|
| `navigator.userAgent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) … Chrome/131…` (we set) |
| `navigator.platform` | `Win32` (we set via prototype override) |
| `navigator.userAgentData.platform` | `Windows` (we set via prototype override) |
| `navigator.userAgentData.getHighEntropyValues().platform` | `Windows` (we set) |
| HTTP `User-Agent` header | `Mozilla/5.0 (Windows NT 10.0…)` (we set via Playwright `userAgent` option) |
| HTTP `Sec-CH-UA-Platform` header | `Windows` (we set via CDP `Network.setUserAgentOverride` with `userAgentMetadata`) |
| `server_os` in fpjs response | `Windows` ← server believed our HTTP+JS claim |
| `tampering.result` | **`true`** |
| `tampering.anomalyScore` | **`1.00`** |
| `virtualMachine.result` | **`true`** |
| `suspectScore` | 52 (baseline was 22) |

The above is *every layer fpjs reads via JS or HTTP*, all aligned to
Windows. The 30-point penalty came from connection-layer signals
(JA3 of real Linux Chrome 148 + HTTP/2 SETTINGS) that fpjs's server
caught directly against the claimed Windows OS.

### 7.4 What fpjs can prove about your OS from each signal class

Question often asked: "can they tell I'm on Windows from math hashes
alone?" Answer per signal class (ranked):

| Signal | Strength as OS oracle | Why |
|---|---|---|
| **WebGL renderer string** | ★★★★★ Near-deterministic | ANGLE+D3D11 → Win only; ANGLE+Metal → Mac only; Mesa → Linux only. Driver/API is OS-pinned. |
| **Sec-CH-UA-Platform header** | ★★★★★ Direct OS marker | Chrome sends this from the real OS unless CDP overrides it |
| **JA3/JA4 TLS fingerprint** | ★★★★ Strong | Chrome's TLS params vary measurably by OS build. Can't spoof from inside Chrome. |
| **Canvas pixel md5** | ★★★★ Strong | Font rasterizer is OS-specific (FreeType/DirectWrite/CoreText). md5 distributions are OS-correlated. |
| **Font enumeration** | ★★★★ Strong | Windows: Segoe UI/Calibri/Cambria. Mac: SF Pro/Helvetica Neue. Linux: DejaVu/Liberation. |
| **HTTP/2 SETTINGS frame** | ★★★ Medium-strong | Browser-version + OS combos have stable H2 client params |
| **Audio sum** | ★★★ Medium | OfflineAudioContext DSP varies subtly by OS via SIMD intrinsics |
| **Math precision (s48, s209)** | ★★ Weak | V8 normalizes most transcendental output via fdlibm. Cross-OS deltas are small. |

From WebGL renderer alone, fpjs can prove/disprove your OS with
~99% confidence. Add canvas + fonts + JA4 and it's effectively
certain. Math hashes alone — no. They're a confirmation signal, not a
primary one.

### 7.5 The asymmetry, server-side (what fpjs's anomaly detector is
approximately doing)

```
expected_axes = inferOSFromSignals(payload + headers + connection)
claimed_os    = parseUA(http_user_agent)

inconsistency = 0
for each axis:
    if expected_axes[axis] != axis_value_consistent_with(claimed_os):
        inconsistency += weight[axis]

if inconsistency > threshold:
    tampering.result = true
    tampering.anomalyScore = min(inconsistency / max_inconsistency, 1.0)
```

Per-axis weights matter — JA4-vs-UA disagreement is weighted heavily
because TLS-layer lies are hard to fake coincidentally. Canvas-hash-
vs-claimed-OS is weighted moderately (hash space is large enough that
random collisions happen). Math-precision-vs-claimed-OS is weighted
low because V8 normalizes it.

### 7.6 The two practical regimes for a bot operator

There are **only two** workable regimes given fpjs's cross-layer
check:

**Regime 1 — Stay native.** Don't lie about the OS at all. Spoof only
individual fields that make sense (cores=4 vs 32 dropped 6 points
cleanly in our `hunt-hash.mjs`). Score floor: the natural baseline
for your real `(OS, IP, browser)` combo. For our test machine
(Linux + AT&T residential + Chrome 148): **22**. For the user's real
Firefox on same IP: **4** (because Firefox has no `HeadlessChrome`
tell and a real font stack). Cheap, durable.

**Regime 2 — Full impersonation.** Build a complete fake stack:
   - Real or emulated Windows Chrome at the JS+HTTP layer (Playwright
     real Chrome works for JS/HTTP)
   - Custom TLS client like `curl-impersonate` to forge JA3/JA4
   - Custom HTTP/2 client to forge SETTINGS frame + header order
   - Pre-recorded library of (Win, hardware) canvas md5s, audio sums,
     font metrics, WebGL renderer strings to swap in via the
     chokepoint mutation
   - Maintain this stack as Chrome releases drift the fingerprints
     every 6 weeks

   Hours-to-days of work per identity, brittle, requires a constant
   integration with fingerprint-reference data sources. Effectively
   you're rebuilding Chrome.

**There is no middle path that defeats the cross-layer consistency
check from inside a stock Chrome process.** That's exactly fpjs's
intended deterrence — they can't make spoofing impossible, but they
make it expensive enough that operators go target someone with a
lower fence.

### 7.7 Three vendors, three different bets

Castle, DataDome, and fpjs are betting on *different things being
expensive*:

- **Castle's bet:** capturing the plaintext is expensive — per-field
  cipher, no chokepoint, attackers have to reverse the bundle.
- **DataDome's bet:** getting into the collector realm is expensive
  — Worker, signed envelope, attackers have to navigate sandboxes.
- **fpjs's bet:** **forging convincingly across layers is expensive**
  — TLS, HTTP/2, headers, JS, payload all must agree, attackers
  have to rebuild Chrome.

Castle's bet has been broken (`bots-x-castle` decrypts tokens with
`tv()`); DataDome's bet has been broken under controlled conditions
(`bots-datadome` bypass via clean mobile IP + chokepoint patch); fpjs's
bet remains *practically* unbroken from stock Chrome — not because
it's mathematically impossible to spoof, but because spoofing every
layer simultaneously requires rebuilding the bottom of the network
stack outside Chrome's process. Different lever, harder to break.

---

## 8. Detection ideas for fpjs (defensive notes)

If you're on fpjs's side and want to close the chokepoint mutation
attack class:

1. **Bytecode-native serialization.** Skip `JSON.stringify` and
   `CompressionStream`. Walk the assembled object with a small VM
   and produce the encoded bytes directly. Cost: ~50-100 ops for a
   minimal JSON walker. Result: there's no Web API at the seam to
   wrap.
2. **Pre-serialization signature.** Hash the assembled object with a
   pure-JS hash function (FNV, MurmurHash) before handing it to
   `JSON.stringify`, ship the hash alongside the encrypted body. A
   chokepoint attacker who mutates after `JSON.stringify` produces a
   payload whose decrypted content won't match the hash. Cost: ~50
   lines and a server-side check.
3. **Streams realm pinning.** Grab `CompressionStream` from a fresh
   iframe's contentWindow at bundle load, store the reference, use
   only that ref. An attacker who only wraps `window.CompressionStream`
   in the main realm gets nothing — the bundle's compression uses an
   unrelated ref the attacker never touched. Cost: 1 hidden iframe.

(1) is the durable fix. (3) is the cheapest immediate win.

A hardened SDK can do (3)-flavored isolation for `crypto.subtle` via a
pristine-iframe pattern — the same trick applies to compression.

---

## 8. Methodology — How to reproduce every claim here

```bash
# 1. Confirm the bundle is what we say:
npm run recon
# → reports https://fpjscdn.net/v4/<publicKey> with version=4.0.3

# 2. Dump the plaintext payload:
npm run mitm
# → ./results/mitm-XXX-plaintext.json (138 sN slots)

# 3. Annotate the plaintext with names:
node signals.mjs ./results/mitm-XXX-plaintext.json
# → ~100 slots semantically labeled

# 4. Get the baseline verdict:
npm run verdict
# → ./results/verdict-XXX.json — note suspectScore + vpn.methods.osMismatch

# 5. Variant tamper matrix:
npm run tamper
# → ./results/tamper-XXX.json — see which lies fpjs catches

# 6. Bisect for score-driving signals:
npm run bisect
# → identifies which sN flips visitor_id and which moves suspectScore

# 7. Bypass:
npm run bypass
# → cascade: baseline → A → B → A+B
# → "★ BYPASS SUCCEEDED — verdict is clean ★" when (vpn=false, tamper=false, suspect<10)

# 8. Verify what moved:
npm run diff
# → diffs the two latest verdict JSONs slot-by-slot
```

If you don't see the bypass succeed on your first run, run
`bisect.mjs` to see which slots are score-relevant given your
specific IP/ASN, then add those slots to the `apply(obj)` block in
`bypass.mjs` stage B.

---

## Appendix A — Source artifacts

This harness consolidates work that was previously scattered across:

- An earlier internal writeup — this document supersedes it for
  arcades.click / chokepoint patterns.
- `~/Dev/FPJS-Delta-Analysis.md` — slot-level deltas across
  browser/OS combinations.
- An earlier internal `fpjs-plaintext-dump.mjs` script, from which
  the `CompressionStream`+`WeakSet` pattern is ported here.
- `~/Dev/tmp/fpjs-*.mjs` — 16 experimental scripts including the
  three-phase bisection, the believable-spoof iterator, the
  Dallas-tumble (IP-aware), the SOAX-proxy verdict bot. Most of the
  attack patterns above were prototyped here first.

If you find a chokepoint not listed in §4, add it to `mitm.mjs`, run
`mitm.mjs` to confirm the new hook fires, then propagate to
`bypass.mjs` if it's serialization-stage.
