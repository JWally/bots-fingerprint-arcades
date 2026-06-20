#!/usr/bin/env node
/**
 * FPJS deep API-call tracer. Same approach as botbuster-api-trace.mjs:
 * route-intercept the fpjs agent bundle, prepend a document-start wrap
 * of Promise-returning APIs + addEventListener + timers + blob/worker/
 * postMessage instrumentation; also context.addInitScript so the
 * outer page (arcades.click/fpjs) is instrumented too.
 *
 * Then navigate to /fpjs, let fp.get({ extendedResult: true }) finish,
 * and dump what the fpjs agent actually hit — for direct comparison
 * against a reference integrity trace.
 */

import { launchFor } from './_launch.mjs';

const TARGET = 'https://arcades.click/fpjs';

const INIT = `(() => {
  if (window.__apiLogInstalled) return;
  window.__apiLogInstalled = true;
  window.__apiLog = [];
  window.__eventSubs = [];
  window.__timers = [];
  window.__blobsCreated = [];
  window.__iframeSrcs = [];
  window.__messagesRx = [];
  window.__messagesTx = [];
  window.__workers = [];
  window.__apiNextId = 1;

  const now = () => performance.now();
  const track = (name) => {
    const id = window.__apiNextId++;
    const entry = { id, name, start: now(), status: 'pending' };
    window.__apiLog.push(entry);
    return entry;
  };

  const wrapPromise = (obj, method, label) => {
    if (!obj || typeof obj[method] !== 'function') return;
    const orig = obj[method];
    obj[method] = function (...args) {
      const entry = track(label + '.' + method);
      let result;
      try { result = orig.apply(this, args); } catch (e) {
        entry.status = 'throw'; entry.end = now(); entry.error = String(e);
        throw e;
      }
      if (result && typeof result.then === 'function') {
        return result.then(
          (v) => { entry.status = 'resolved'; entry.end = now(); return v; },
          (e) => { entry.status = 'rejected'; entry.end = now(); entry.error = String(e); throw e; }
        );
      }
      entry.status = 'sync'; entry.end = now();
      return result;
    };
  };

  // Promise-returning APIs
  if (typeof fetch === 'function') {
    const origFetch = fetch;
    self.fetch = function (...args) {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '(Request)';
      const entry = track('fetch ' + url.slice(0, 150));
      return origFetch.apply(this, args).then(
        (v) => { entry.status = 'resolved'; entry.end = now(); entry.httpStatus = v.status; return v; },
        (e) => { entry.status = 'rejected'; entry.end = now(); entry.error = String(e); throw e; }
      );
    };
  }

  if (typeof XMLHttpRequest === 'function') {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      this.__xhrMeta = { method, url };
      return origOpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function (...args) {
      const entry = track('xhr ' + (this.__xhrMeta?.method || '?') + ' ' + (this.__xhrMeta?.url || '?').slice(0, 100));
      const done = (s) => { entry.status = s; entry.end = now(); };
      this.addEventListener('load', () => done('resolved'));
      this.addEventListener('error', () => done('rejected'));
      this.addEventListener('abort', () => done('aborted'));
      this.addEventListener('timeout', () => done('timeout'));
      return origSend.apply(this, args);
    };
  }

  if (crypto && crypto.subtle) {
    for (const m of ['encrypt','decrypt','sign','verify','digest','generateKey',
                     'importKey','exportKey','deriveKey','deriveBits','wrapKey','unwrapKey']) {
      wrapPromise(crypto.subtle, m, 'crypto.subtle');
    }
  }
  if (navigator.userAgentData) wrapPromise(navigator.userAgentData, 'getHighEntropyValues', 'navigator.userAgentData');
  if (navigator.permissions) wrapPromise(navigator.permissions, 'query', 'navigator.permissions');
  if (navigator.storage) wrapPromise(navigator.storage, 'estimate', 'navigator.storage');
  if (navigator.mediaDevices) wrapPromise(navigator.mediaDevices, 'enumerateDevices', 'navigator.mediaDevices');
  if (navigator.mediaCapabilities) wrapPromise(navigator.mediaCapabilities, 'decodingInfo', 'navigator.mediaCapabilities');
  if (HTMLCanvasElement?.prototype) {
    wrapPromise(HTMLCanvasElement.prototype, 'toBlob', 'canvas');
  }
  if (typeof AudioContext !== 'undefined') wrapPromise(AudioContext.prototype, 'decodeAudioData', 'AudioContext');
  if (typeof OfflineAudioContext !== 'undefined') wrapPromise(OfflineAudioContext.prototype, 'startRendering', 'OfflineAudioContext');
  if (navigator.getBattery) wrapPromise(navigator, 'getBattery', 'navigator');

  // Sync but high-signal: canvas.toDataURL, getContext
  if (HTMLCanvasElement?.prototype) {
    const origTDU = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function (...a) {
      track('canvas.toDataURL').status = 'sync';
      return origTDU.apply(this, a);
    };
    const origGC = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (type, ...a) {
      track('canvas.getContext(' + type + ')').status = 'sync';
      return origGC.apply(this, [type, ...a]);
    };
  }

  // Fonts
  if (document.fonts && FontFaceSet?.prototype) {
    const desc = Object.getOwnPropertyDescriptor(FontFaceSet.prototype, 'ready');
    if (desc && desc.get) {
      const origReady = desc.get;
      Object.defineProperty(document.fonts, 'ready', {
        get() {
          const entry = track('document.fonts.ready');
          const p = origReady.call(this);
          p.then(
            () => { entry.status = 'resolved'; entry.end = now(); },
            (e) => { entry.status = 'rejected'; entry.end = now(); entry.error = String(e); }
          );
          return p;
        },
      });
    }
    wrapPromise(document.fonts, 'load', 'document.fonts');
    wrapPromise(document.fonts, 'check', 'document.fonts');
  }

  // addEventListener
  const origAEL = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, listener, opts) {
    let targetLabel;
    if (this === window) targetLabel = 'window';
    else if (this === document) targetLabel = 'document';
    else if (this === navigator) targetLabel = 'navigator';
    else if (this instanceof MessagePort) targetLabel = 'MessagePort';
    else if (this.nodeName) targetLabel = this.nodeName.toLowerCase();
    else targetLabel = this.constructor?.name || 'EventTarget';
    window.__eventSubs.push({ target: targetLabel, type: String(type), t: now() });
    return origAEL.call(this, type, listener, opts);
  };

  // Timers
  const origSetTimeout = window.setTimeout;
  const origSetInterval = window.setInterval;
  const origClearTimeout = window.clearTimeout;
  window.setTimeout = function (cb, ms, ...args) {
    const entry = { kind: 'timeout', ms: Number(ms) || 0, t: now(), status: 'pending' };
    window.__timers.push(entry);
    const realId = origSetTimeout.call(window, () => {
      entry.status = 'fired'; entry.end = now();
      try { return typeof cb === 'function' ? cb.apply(undefined, args) : eval(String(cb)); } catch (e) { throw e; }
    }, ms);
    entry.realId = realId;
    return realId;
  };
  window.clearTimeout = function (id) {
    const e = window.__timers.find((x) => x.realId === id && x.status === 'pending');
    if (e) { e.status = 'cleared'; e.end = now(); }
    return origClearTimeout.call(window, id);
  };
  window.setInterval = function (cb, ms, ...args) {
    const entry = { kind: 'interval', ms: Number(ms) || 0, t: now(), status: 'pending', fires: 0 };
    window.__timers.push(entry);
    const realId = origSetInterval.call(window, () => { entry.fires++; try { cb.apply(undefined, args); } catch {} }, ms);
    entry.realId = realId;
    return realId;
  };

  // Blob creation + iframe src/srcdoc
  const origCreateBlobURL = URL.createObjectURL;
  URL.createObjectURL = function (obj) {
    const url = origCreateBlobURL.call(this, obj);
    const entry = { url, type: obj?.type || null, size: obj?.size ?? null, t: now() };
    if (obj instanceof Blob && obj.size < 100000) {
      obj.text().then((text) => { entry.preview = text; }).catch(() => {});
    }
    window.__blobsCreated.push(entry);
    return url;
  };

  if (HTMLIFrameElement?.prototype) {
    const desc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
    if (desc?.set) {
      const origSet = desc.set;
      Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
        set(v) { window.__iframeSrcs.push({ src: String(v).slice(0, 200), t: now() }); return origSet.call(this, v); },
        get() { return desc.get.call(this); },
        configurable: true,
      });
    }
    const descDoc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
    if (descDoc?.set) {
      const origSet = descDoc.set;
      Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
        set(v) { window.__iframeSrcs.push({ srcdoc: String(v).slice(0, 400), t: now() }); return origSet.call(this, v); },
        get() { return descDoc.get.call(this); },
        configurable: true,
      });
    }
  }

  // postMessage tx + rx
  if (typeof Window !== 'undefined' && Window.prototype?.postMessage) {
    const origPM = Window.prototype.postMessage;
    Window.prototype.postMessage = function (msg, ...rest) {
      let preview;
      try { preview = typeof msg === 'object' ? JSON.stringify(msg).slice(0, 300) : String(msg).slice(0, 300); } catch { preview = '(unserializable)'; }
      let targetLabel;
      try {
        if (this === window) targetLabel = 'self';
        else if (this === window.parent) targetLabel = 'parent';
        else if (this === window.top) targetLabel = 'top';
        else targetLabel = 'other';
      } catch { targetLabel = 'cross-origin'; }
      window.__messagesTx.push({ t: now(), to: targetLabel, preview });
      return origPM.apply(this, [msg, ...rest]);
    };
  }
  origAEL.call(window, 'message', (e) => {
    let preview;
    try { preview = typeof e.data === 'object' ? JSON.stringify(e.data).slice(0, 300) : String(e.data).slice(0, 300); } catch { preview = '(unserializable)'; }
    window.__messagesRx.push({ t: now(), from: e.origin || '(blank)', preview });
  }, true);

  // Workers
  if (typeof Worker !== 'undefined') {
    const OrigWorker = window.Worker;
    const wrap = function (url, opts) {
      window.__workers.push({ url: String(url).slice(0, 200), t: now() });
      return new OrigWorker(url, opts);
    };
    wrap.prototype = OrigWorker.prototype;
    window.Worker = wrap;
  }
})();`;

(async () => {
  const { ctx, close } = await launchFor('api-trace');
  await ctx.addInitScript({ content: INIT });

  // Intercept the fpjs agent bundle (any path on fpjscdn.net — covers the
  // main agent URL and any sub-scripts it might pull in).
  await ctx.route('**/fpjscdn.net/**', async (route) => {
    const res = await route.fetch();
    const headers = res.headers();
    const ct = headers['content-type'] || '';
    if (!ct.includes('javascript') && !ct.includes('ecmascript')) {
      route.continue();
      return;
    }
    const body = await res.text();
    route.fulfill({
      status: res.status(),
      headers: { ...headers, 'content-type': 'application/javascript' },
      body: INIT + '\n' + body,
    });
  });

  const page = await ctx.newPage();
  await page.goto(TARGET, { waitUntil: 'load', timeout: 45000 });

  // Fpjs.tsx calls fp.get({ extendedResult: true }) after agent.start().
  // Give it time to finish, including the Lambda server-call hop.
  await new Promise((r) => setTimeout(r, 8_000));

  const frames = [];
  for (const f of page.frames()) {
    try {
      const d = await f.evaluate(() => {
        if (!window.__apiLogInstalled) return null;
        return {
          url: location.href,
          apiLog: window.__apiLog,
          eventSubs: window.__eventSubs,
          timers: window.__timers,
          blobs: window.__blobsCreated,
          iframeSrcs: window.__iframeSrcs,
          messagesRx: window.__messagesRx,
          messagesTx: window.__messagesTx,
          workers: window.__workers,
        };
      });
      if (d) frames.push(d);
    } catch {}
  }

  for (const f of frames) {
    console.log(`\n${'='.repeat(78)}\n  ${f.url}\n${'='.repeat(78)}`);

    if (f.apiLog.length) {
      const by = {};
      for (const e of f.apiLog) (by[e.status] ||= []).push(e);
      for (const status of ['pending', 'resolved', 'rejected', 'throw', 'sync']) {
        const arr = by[status];
        if (!arr?.length) continue;
        const counts = {};
        for (const e of arr) counts[e.name] = (counts[e.name] || 0) + 1;
        const pairs = Object.entries(counts)
          .map(([n, c]) => `${n}×${c}`)
          .sort()
          .join(', ');
        console.log(`  [api ${status}] ${pairs}`);
      }
    }

    if (f.eventSubs.length) {
      const counts = {};
      for (const s of f.eventSubs) {
        const k = `${s.target}:${s.type}`;
        counts[k] = (counts[k] || 0) + 1;
      }
      // Distinguish window/document/navigator/specific-element listeners from
      // React's generic per-element DOM event attachment (which is uniform
      // noise: every div gets click/mousedown/etc.). Show the interesting ones.
      const interesting = Object.entries(counts)
        .filter(([k]) => /^(window|document|navigator|MessagePort|RTCPeerConnection|AudioContext|OfflineAudioContext|HTMLVideoElement|Worker|iframe|XMLHttpRequest):/.test(k))
        .sort((a, b) => b[1] - a[1])
        .map(([k, c]) => `${k}×${c}`)
        .join(', ');
      console.log(`  [addEventListener interesting] ${interesting || '(none)'}`);
      // Also show total + top DOM element listeners for comparison density
      console.log(`  [addEventListener total] ${f.eventSubs.length} subscriptions`);
    }

    if (f.timers.length) {
      const pending = f.timers.filter((t) => t.status === 'pending');
      const fired = f.timers.filter((t) => t.status === 'fired');
      const cleared = f.timers.filter((t) => t.status === 'cleared');
      console.log(`  [timers] fired=${fired.length} cleared=${cleared.length} pending=${pending.length}`);
    }

    if (f.blobs.length) {
      console.log(`  [blobs created] ${f.blobs.length}`);
      for (const b of f.blobs.slice(0, 4)) {
        console.log(`    ${b.url}  type=${b.type} size=${b.size}`);
        if (b.preview) {
          const fs = await import('fs');
          const outPath = new URL(`./results/fpjs-blob-${b.url.split('/').pop()}.js`, import.meta.url);
          fs.writeFileSync(outPath, b.preview);
          console.log(`      -> saved to ${outPath.pathname}`);
        }
      }
    }

    if (f.iframeSrcs.length) {
      console.log(`  [iframe.src|srcdoc set] ${f.iframeSrcs.length}`);
    }

    console.log(`  [postMessage tx] count=${f.messagesTx.length}`);
    for (const m of f.messagesTx.slice(0, 4)) console.log(`    -> ${m.to}: ${m.preview}`);
    console.log(`  [postMessage rx] count=${f.messagesRx.length}`);
    for (const m of f.messagesRx.slice(0, 4)) console.log(`    <- ${m.from}: ${m.preview}`);

    if (f.workers.length) {
      console.log(`  [workers] ${f.workers.length}`);
      for (const w of f.workers.slice(0, 5)) console.log(`    ${w.url}`);
    }
  }

  await close();
})();
