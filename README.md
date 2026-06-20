# bots-fingerprint-arcades

Reverse-engineering harness for [FingerprintJS](https://fingerprint.com) v4
as deployed on **arcades.click/fpjs** (a self-hosted demo page that
loads `fpjscdn.net/v4/<publicKey>` and surfaces the full Smart Signals
response to the client). Demonstrates plaintext payload capture via
the `CompressionStream` chokepoint, value-tamper variants run against
the live verdict oracle, and verdict-bypass via stacked
prototype-layer + serialization-chokepoint mutation.

Companion writeup: **[FPJS.md](FPJS.md)** — full methodology, the
v4 wire protocol, the 138-slot plaintext payload reverse, every
chokepoint mapped, why the WeakSet pattern lets you mutate fpjs's
payload while leaving every native-API toString check intact.

> **Scope.** Defensive / red-team research against fpjs's published
> client SDK on a target we own. Does not submit credentials, does not
> attempt to break into any account, does not exfiltrate user data.
> Intended audience: FingerprintJS's own research team, and anti-bot /
> fingerprinting practitioners studying production hardening.

---

## Quick start

```bash
git clone <this-repo> bots-fingerprint-arcades
cd bots-fingerprint-arcades
npm install                # installs playwright + downloads browsers
npm start                  # interactive arrow-key menu
```

You'll see a menu of all 10 scripts with descriptions below the
highlighted item:

```
bots-fingerprint-arcades  —  FingerprintJS v4 reverse-engineering harness for arcades.click

? pick a script › arrow keys to navigate · enter to run · esc/ctrl-c to quit
❯ ★ verdict      — single-shot capture of the live /api/fpjs/event response
  ★ tamper       — value tampering against the live oracle (THE HEADLINER)
  ★ bypass       — try to flip the verdict to clean (vpn=false, low score)
    bisect       — 3-phase bisection: which signal moves suspectScore?
    mitm         — chokepoint MITM: dump fpjs plaintext before encryption
    signals      — slot dictionary: map sN → semantic meaning
    recon        — find which fpjs bundle is loaded on the target
    netdump      — full network log of fpjs traffic on the page
    api-trace    — which Web APIs the agent touches, in order
    diff         — compare two saved verdict JSONs slot-by-slot
    quit
```

Pick **verdict** first to baseline your current verdict (~10 sec).
Pick **tamper** for the headliner that diffs ~11 lie variants (~3 min).

### Environment overrides

All scripts launch **real Chrome** (`/usr/bin/google-chrome`, via Playwright's
`channel: 'chrome'`) with a per-script **persistent profile** under
`./results/.chrome-profile-<scriptname>/`. This is what gets you out of
the bundled-Chromium ghetto (`bot=bad/headlessChrome`, score 23+) and
into a real-Chrome baseline (`bot=notDetected`, score 12-18 on a clean
residential IP).

Override via env vars:

| Env | Effect | When you'd want it |
|---|---|---|
| `FPJS_HEADLESS=1` | Run headless (real Chrome headless still leaks `HeadlessChrome` in UA — score will spike) | CI only |
| `FPJS_CHROMIUM=1` | Use Playwright's bundled Chromium instead of real Chrome | Debugging a Chromium-specific issue |
| `FPJS_NO_PERSIST=1` | Fresh ephemeral profile every run (no IDB carry-over → s94 jumps every time) | Single-shot tests where state continuity isn't wanted |

`tamper.mjs`, `bisect.mjs`, and `bypass.mjs` set `FPJS_NO_PERSIST=1`
internally because they run multiple variants and want each one
ephemeral.

### Power-user shortcuts

```bash
npm run verdict          # single-shot capture
npm run tamper           # full variant matrix
npm run bypass           # cascade A → B → A+B
npm run bypass -- --stage B    # just the chokepoint mutation
npm run bisect           # 3-phase slot bisection
npm run mitm             # dump plaintext payload
npm run recon            # find the bundle URL
npm run signals          # print slot dictionary
npm run signals -- ./results/mitm-XXX-plaintext.json   # annotate a capture
npm run netdump          # full network log
npm run api-trace        # API call sequence
npm run diff             # compare two saved verdicts
```

---

## What each script does

| Script | What it does | When to run |
|---|---|---|
| **`verdict.mjs`** ★ | Single page-load against arcades.click/fpjs, intercepts the `/api/fpjs/event` response, prints visitor_id / suspectScore / bot / vpn / proxy / tampering / IP+ASN, saves the raw JSON to `./results/verdict-*.json`. The oracle. | Always first. Baseline before any tamper run. |
| **`tamper.mjs`** ★ | Runs ~11 lie variants (UA strip, plugin forgery, SwiftShader WebGL, permissions=granted, UA-vs-UA-CH mismatch, mobile screen w/ desktop UA, empty languages, contradictory touchpoints, mediaDevices=[], Safari-on-Mac stack, platform→Win32). Every variant wraps lies in a WeakMap-toString forgery so fpjs slot s148 still sees `[native code]`. Diffs each verdict vs baseline; prints which lies moved suspectScore or flipped bot/vpn/tampering. | The headliner. Run this to see what fpjs catches and what it doesn't. |
| **`bypass.mjs`** ★ | Cascades two attack stages: (A) prototype-getter lies with WeakMap-toString preservation, (B) `CompressionStream` chokepoint mutation of the assembled plaintext payload. Target: vpn=true→false, suspectScore→clean. Stage B is the BIG hammer — fpjs has no client-side detector for serialization-time payload mutation. | The actual bypass. Use after `tamper` tells you which signals fpjs is scoring on. |
| `bisect.mjs` | 3-phase bisection on the plaintext payload via the chokepoint hook. Phase A: single-slot variants (does vid flip? does score move?). Phase B: small stacks of low-weight slots (do they cross a threshold?). Phase C: high-entropy probes (fonts, Navigator.prototype enumeration). | Before `tamper.mjs` if you want to focus your lie set on score-driving slots. |
| `mitm.mjs` | Installs four chokepoint hooks before bundle load: `JSON.stringify`, `TextEncoder.encode`, `CompressionStream.writable.getWriter().write` (WeakSet-tagged), and `fetch` to api.fpjs.io. The write hook captures the full ~9KB plaintext signal blob (138 `s1..s215` slots) right before deflate-raw + cipher + POST. Saves both plaintext (pretty JSON) and event log. | When you want to see exactly what fpjs is shipping home. |
| `signals.mjs` | Maps each `sN` slot ID to its semantic meaning (s17=canvas, s21=audio, s94=IDB visitor ID, s157=named-bot-framework probes, etc.) — ~138 mappings from FPJS.md §3.2. With no args prints the dictionary. With a path arg annotates a saved plaintext capture. | When reading a `mitm-*-plaintext.json` and you want to know what each slot means. |
| `recon.mjs` | Loads the target, logs every JS response, flags chunks from fpjscdn.net. Reports the bundle URL, byte size, sha256, version from the source comment, the public API key embedded in the URL, and whether the bundle still touches `CompressionStream`. | First run on a new target, or after fpjs rotates the bundle. |
| `netdump.mjs` | Full request/response log of every URL matching `fpjs.io`, `fpjscdn.net`, or `/api/fpjs/event`. Bodies saved as binary files. Use to inspect the GET handshake (96-char base64 sealed_box), POST encrypted body (binary, with `Content-Type: text/plain` disguise), and the verdict response. | When debugging a chokepoint hook that's not catching a stream. |
| `api-trace.mjs` | Wraps Navigator / Screen / WebGL / Canvas / Audio / Crypto / MediaCapabilities prototype getters + methods + Promise-returning APIs (fetch, permissions.query, decodingInfo, etc.); stack-filters to the fpjscdn.net bundle; logs every read in temporal order. | When you want to see exactly which permission queries, codec probes, canvas calls, etc. fpjs performs and when. |
| `diff.mjs` | Given two `./results/verdict-*.json` (or any two paths), prints a flat table of every field that differs. With no args uses the two latest verdicts by mtime. | After running tamper or bypass — confirms a specific signal moved. |

---

## What success looks like

After `npm run verdict`, you'll see something like:

```
=== FPJS VERDICT ===
  visitor_id:     taOIW0hP170H7NeQ8ZKH
  confidence:     1
  suspectScore:   4
  bot.result:     notDetected
  vpn.result:     true (high)
  vpn.methods:    {"timezoneMismatch":false,"publicVPN":false,"auxiliaryMobile":false,"osMismatch":true,"relay":false}
  tampering:      false (anomaly=0 ml=0.0071)
  ip:             107.210.133.127
  ip.asn:         7018 AT&T Enterprises, LLC
```

After `npm run tamper`, you get a diff table:

```
─── DIFF MAP ───
variant                          score  Δ     flipped signals
────────────────────────────────────────────────────────────────────────────────
baseline                         4      —     (reference)
ua_strip_headless                4      0     visitorId
plugins_forgery                  31     +27   suspectScore, tampering_result, …
webgl_swiftshader                4      0     visitorId, confidence
permissions_all_granted          4      0     visitorId
uadata_vs_ua_mismatch            12     +8    suspectScore, tampering_anomaly
…
```

After `npm run bypass` (the win condition):

```
─── BYPASS LADDER ───
stage          suspect  bot           vpn      osMismatch  tamper      visitorId
──────────────────────────────────────────────────────────────────────────────────
baseline       4        notDetected   true     true        false/0     taOIW0hP170H7NeQ8…
A only         4        notDetected   false    false       false/0     bXyz…
B only         3        notDetected   false    false       false/0     cZxy…
A + B          3        notDetected   false    false       false/0     dWvu…

★ BYPASS SUCCEEDED — verdict is clean ★
```

(Actual numbers depend on your real IP, ASN, and how fpjs's
server-side detector reads them.)

---

## Verification (don't trust, test)

**1. The fpjs bundle on arcades.click is what we say it is.**

```bash
node recon.mjs
# Expect:
#   ★ main bundle: https://fpjscdn.net/v4/xszasGYxaOq23ttuMOC0
#     version=4.0.3 publicKey=xszasGYxaOq23ttuMOC0
#     chokepoints: CompressionStream=true  TextEncoder=true  api.fpjs.io=true
```

**2. The plaintext-capture claim holds.**

```bash
node mitm.mjs
# Expect (truncated):
#   [  XYZms] compression.write     9243 chars ★ FULL SAVED
#   ✓ plaintext payload (9243 chars) saved to ./results/mitm-...-plaintext.json
node signals.mjs ./results/mitm-*-plaintext.json | head -40
# Expect: 138 slots, ~100 mapped, ★-marked entries surface the high-signal ones.
```

**3. The bypass moves the verdict.**

```bash
node verdict.mjs          # baseline: vpn=true
node bypass.mjs           # cascade A → B → A+B
# Compare:
node diff.mjs             # latest two verdicts
# Expect: products.vpn.data.result flipped true → false
```

---

## File layout

```
.
├── README.md                 this file
├── FPJS.md                   full reverse-engineering writeup
├── package.json              playwright + prompts; npm-run shortcuts
├── .gitignore                node_modules/, results/
├── main.mjs                  interactive arrow-key launcher (npm start)
├── verdict.mjs               ★ single-shot oracle capture
├── tamper.mjs                ★ value-tamper variant matrix + diff
├── bypass.mjs                ★ stacked prototype + chokepoint mutation
├── bisect.mjs                3-phase slot bisection
├── mitm.mjs                  chokepoint MITM, plaintext capture
├── signals.mjs               slot dictionary + payload annotator
├── recon.mjs                 find the bundle URL + version
├── netdump.mjs               full network log
├── api-trace.mjs             Web API call sequence tracer
├── diff.mjs                  diff two saved verdicts
├── results/                  each script's JSON output (gitignored)
└── examples/                 reference captures (gitignored, populated locally)
```

---

## Known limitations

- **fpjs rotates the bundle periodically.** The `CompressionStream`
  chokepoint hook in `mitm.mjs` / `bisect.mjs` / `bypass.mjs` works as
  long as fpjs continues to use deflate-raw via Streams. If they
  switch to a custom byte-level deflate (no Streams API touched), the
  WeakSet tag stops matching anything and the hooks silently no-op.
  `recon.mjs` reports `usesCompressionStream` per bundle — check
  before assuming the gold hook still fires.
- **Server-side detectors that read `osMismatch`, ASN, and similar
  IP-driven signals will overrule client-side lies you didn't extend
  to the chokepoint.** Bypass needs to be self-consistent: if you
  claim macOS in the UA, you also need to claim macOS in s58 (UA-CH)
  via stage B, otherwise fpjs's `osMismatch` heuristic still trips.
- **The chokepoint mutation does NOT bypass the `internal` field**
  fpjs returns. That field is server-side-only and encrypted with a
  key the merchant doesn't see. If a merchant later does a Server API
  round-trip to fetch the full payload, they'll get the same Smart
  Signals view we see in `verdict.mjs`. Spoofing means spoofing the
  Smart Signals, not the merchant's confidential downstream view.
- **No real-IP proxying is included.** All scripts run direct from
  the host. For full bypass against ASN-driven detectors, you'd add
  a SOAX/residential proxy block to `bypass.mjs` (see
  `~/Dev/tmp/fpjs-verdict-bot.mjs` for the SSM/SOCKS5 bad-box pattern).

## Companion documents

- **[FPJS.md](FPJS.md)** — the methodology + findings writeup (the
  v4 reverse, every collector, the wire protocol, the WeakSet
  chokepoint, comparison vs Castle + DataDome).
- `~/Dev/FPJS-Delta-Analysis.md` — slot-level delta analysis across
  multiple browser/OS combinations.
- `~/Dev/bots-x-castle/X.Castle.md` — the Castle parallel (same
  attack class, different cipher).
- `~/Dev/bots-datadome/DataDome.md` — the DataDome parallel
  (different cipher, signed envelope, network-level gate).
