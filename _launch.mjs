/**
 * Shared browser-launch helper. Defaults to:
 *   - Real Chrome (channel: 'chrome') — not Playwright's bundled chromium
 *   - --disable-blink-features=AutomationControlled — drops navigator.webdriver
 *   - Persistent profile under ./results/.chrome-profile — defeats incognito=true
 *   - Headed (real Chrome's headless still leaks `HeadlessChrome` in UA)
 *
 * Override via env vars:
 *   FPJS_HEADLESS=1            run headless (degrades cleanliness — only for CI)
 *   FPJS_NO_PERSIST=1          fresh ephemeral profile every time
 *   FPJS_CHROMIUM=1            use bundled Playwright chromium (debug only)
 *
 * Returns: { ctx, browser, close }
 *   ctx: BrowserContext (already created — both modes give you a ctx)
 *   browser: Browser or null (null when launchPersistentContext was used)
 *   close: () => Promise — safe to call regardless of mode
 */

import { chromium } from 'playwright';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function launchFor(label, opts = {}) {
  const useChromium = process.env.FPJS_CHROMIUM === '1';
  const headless    = process.env.FPJS_HEADLESS === '1';
  const noPersist   = process.env.FPJS_NO_PERSIST === '1';
  // FPJS_UA env var or opts.userAgent: Playwright sets BOTH the HTTP
  // User-Agent header AND navigator.userAgent from this single value.
  // Without it, fpjs's server reads the real Chrome UA from the HTTP
  // header and reports browserDetails.os="Linux" regardless of payload
  // mutations.
  const userAgent = opts.userAgent ?? process.env.FPJS_UA ?? undefined;

  const channel = useChromium ? undefined : 'chrome';
  const args    = ['--disable-blink-features=AutomationControlled'];
  const viewport = { width: 1280, height: 800 };
  const ctxOpts = { viewport, ...(userAgent ? { userAgent } : {}) };

  // Persistent profile — one per script label so tamper/bypass/verdict don't
  // share an IDB visitor ID and pollute each other's s94 slot.
  if (!noPersist) {
    const profileDir = path.join(__dirname, 'results', '.chrome-profile-' + (label || 'default'));
    const ctx = await chromium.launchPersistentContext(profileDir, {
      channel, headless, args, ...ctxOpts,
    });
    return {
      ctx,
      browser: null,
      close: () => ctx.close(),
    };
  }

  // Ephemeral — fresh context each time, no profile dir.
  const browser = await chromium.launch({ channel, headless, args });
  const ctx = await browser.newContext(ctxOpts);
  return {
    ctx,
    browser,
    close: async () => { await ctx.close(); await browser.close(); },
  };
}

/**
 * Apply full UA spoof to a page via CDP. Sets HTTP User-Agent,
 * navigator.userAgent, AND the entire UA-CH stack (Sec-CH-UA-*
 * headers + navigator.userAgentData).
 *
 * Must be awaited BEFORE the page navigates.
 */
export async function applyFullUASpoof(page, userAgent, userAgentMetadata) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Network.setUserAgentOverride', { userAgent, userAgentMetadata });
}

/** Pre-built UA-CH metadata for common spoof identities. */
export const UA_PROFILES = {
  mac_chrome_131: {
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    metadata: {
      brands: [
        { brand: 'Not_A Brand', version: '8' },
        { brand: 'Chromium', version: '131' },
        { brand: 'Google Chrome', version: '131' },
      ],
      fullVersion: '131.0.6778.205',
      fullVersionList: [
        { brand: 'Not_A Brand', version: '8.0.0.0' },
        { brand: 'Chromium', version: '131.0.6778.205' },
        { brand: 'Google Chrome', version: '131.0.6778.205' },
      ],
      platform: 'macOS',
      platformVersion: '15.0.0',
      architecture: 'arm',
      model: '',
      mobile: false,
      bitness: '64',
      wow64: false,
    },
  },
  win_chrome_131: {
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    metadata: {
      brands: [
        { brand: 'Not_A Brand', version: '8' },
        { brand: 'Chromium', version: '131' },
        { brand: 'Google Chrome', version: '131' },
      ],
      fullVersion: '131.0.6778.205',
      fullVersionList: [
        { brand: 'Not_A Brand', version: '8.0.0.0' },
        { brand: 'Chromium', version: '131.0.6778.205' },
        { brand: 'Google Chrome', version: '131.0.6778.205' },
      ],
      platform: 'Windows',
      platformVersion: '15.0.0',
      architecture: 'x86',
      model: '',
      mobile: false,
      bitness: '64',
      wow64: false,
    },
  },
};

/** Init-script that wraps WebGL.getParameter to claim an Apple Metal renderer. */
export const APPLE_WEBGL_INIT = `(() => {
  const r = 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)';
  const v = 'Google Inc. (Apple)';
  const lyingMap = new WeakMap();
  const _origFnToString = Function.prototype.toString;
  Function.prototype.toString = function () {
    if (lyingMap.has(this)) return lyingMap.get(this);
    return _origFnToString.call(this);
  };
  lyingMap.set(Function.prototype.toString, 'function toString() { [native code] }');

  function hook(proto, label) {
    if (!proto || !proto.getParameter) return;
    const orig = proto.getParameter;
    const wrapped = function (p) {
      if (p === 37446) return r;             // UNMASKED_RENDERER_WEBGL
      if (p === 37445) return v;             // UNMASKED_VENDOR_WEBGL
      if (p === 7937)  return 'WebKit WebGL';
      if (p === 7936)  return 'WebKit';
      return orig.call(this, p);
    };
    lyingMap.set(wrapped, 'function getParameter() { [native code] }');
    proto.getParameter = wrapped;
  }
  if (typeof WebGLRenderingContext  !== 'undefined') hook(WebGLRenderingContext.prototype,  'WebGL1');
  if (typeof WebGL2RenderingContext !== 'undefined') hook(WebGL2RenderingContext.prototype, 'WebGL2');
})();`;
