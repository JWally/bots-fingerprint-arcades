#!/usr/bin/env node
// Interactive launcher for bots-fingerprint-arcades.
// Arrow-key menu over all scripts; descriptions render below the list.
// Children inherit stdio so live output streams through.

import prompts from 'prompts';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SCRIPTS = [
  {
    file: 'verdict.mjs',
    title: '★ verdict      — single-shot capture of the live /api/fpjs/event response',
    desc:
      'Loads arcades.click/fpjs once, intercepts the /api/fpjs/event response, ' +
      'prints the Smart Signals snapshot (visitorId, bot, vpn, proxy, tampering, ' +
      'suspectScore, ASN), saves the raw JSON. The oracle. Run this first to ' +
      'baseline your current verdict. ~10 sec.',
  },
  {
    file: 'tamper.mjs',
    title: '★ tamper       — value tampering against the live oracle (THE HEADLINER)',
    desc:
      'Runs ~11 lie variants (UA strip, plugin forgery, SwiftShader WebGL, ' +
      'permissions=granted, UA-vs-UA-CH mismatch, mobile screen w/ desktop UA, ' +
      'empty languages, contradictory touchpoints, mediaDevices=[], Safari-on-Mac ' +
      'mega-stack) and diffs each verdict vs baseline. Prints which lies moved ' +
      'suspectScore, flipped bot/vpn/tampering. ~3 min.',
  },
  {
    file: 'bypass.mjs',
    title: '★ bypass       — try to flip the verdict to clean (vpn=false, low score)',
    desc:
      'Iterative bypass: applies the WeakMap-toString-preserving lie set the ' +
      "tamper script identified as score-neutral or score-negative, layers them, " +
      'and re-runs verdict.mjs after each layer. Target: vpn.osMismatch=true → ' +
      'false, suspectScore ≤ 4. Stops when verdict goes clean. ~2-3 min.',
  },
  {
    file: 'bisect.mjs',
    title: '  bisect       — 3-phase bisection: which signal moves suspectScore?',
    desc:
      'Runs ~7 single-signal lies in isolation, then pairs of lies, then triples, ' +
      'logging Δscore each time. Identifies which signal (or interaction) is ' +
      'driving the score, separates "fpjs reads this" from "fpjs scores on this". ' +
      'Useful before tamper.mjs to focus your lie set. ~5 min.',
  },
  {
    file: 'mitm.mjs',
    title: '  mitm         — chokepoint MITM: dump fpjs plaintext before encryption',
    desc:
      'Installs four chokepoint hooks before the bundle loads: JSON.stringify, ' +
      'TextEncoder.encode, CompressionStream.writable.getWriter().write (WeakSet- ' +
      'tagged), and fetch to api.fpjs.io. The write hook captures the full ~9KB ' +
      'plaintext signal blob (138 s1..s215 slots) right before deflate-raw + ' +
      "cipher + POST. Saves both plaintext slots and wire body. ~30 sec.",
  },
  {
    file: 'signals.mjs',
    title: '  signals      — slot dictionary: map sN → semantic meaning',
    desc:
      'Given a captured plaintext payload (from mitm.mjs), maps each sN slot ID ' +
      'to its reverse-engineered semantic name (s17=canvas, s21=audio, s94=IDB ' +
      'visitor ID, s157=named-bot-framework probes, etc.). Bundled dictionary ' +
      'covers ~138 slots from FPJS.md §3.2. Prints a readable table. ~5 sec.',
  },
  {
    file: 'recon.mjs',
    title: '  recon        — find which fpjs bundle is loaded on the target',
    desc:
      'Loads arcades.click/fpjs (or a target you pass via --target), logs every ' +
      'JS response, flags chunks loaded from fpjscdn.net. Reports the bundle URL ' +
      'and version (4.0.3). Run first to confirm fpjs is still deployed. ~20 sec.',
  },
  {
    file: 'netdump.mjs',
    title: '  netdump      — full network log of fpjs traffic on the page',
    desc:
      'Captures every request/response touching fpjscdn.net, api.fpjs.io, or the ' +
      'merchant proxy (/api/fpjs/event). Saves headers, status, bodies (binary as ' +
      "base64). Use to inspect the GET handshake (96-char base64 sealed_box) and " +
      'POST encrypted body shape. ~30 sec.',
  },
  {
    file: 'api-trace.mjs',
    title: '  api-trace    — which Web APIs the agent touches, in order',
    desc:
      'Wraps Navigator/Screen/WebGL/Canvas/Audio/Crypto/MediaCapabilities ' +
      'prototype getters and methods; stack-filters to the fpjscdn.net bundle; ' +
      'logs every read in temporal order. Lets you see exactly which permission ' +
      'queries, codec probes, canvas calls, etc. fpjs performs and when. ~30 sec.',
  },
  {
    file: 'diff.mjs',
    title: '  diff         — compare two saved verdict JSONs slot-by-slot',
    desc:
      'Given two ./results/verdict-*.json files (or arbitrary paths), prints a ' +
      'flat table of every Smart Signal that differs. Useful for proving a ' +
      'tamper variant changed something fpjs observed (or didn\'t). ~2 sec.',
  },
];

function runScript(file) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(__dirname, file)], {
      stdio: 'inherit',
      cwd: __dirname,
    });
    const onSig = () => child.kill('SIGINT');
    process.on('SIGINT', onSig);
    child.on('exit', (code, signal) => {
      process.removeListener('SIGINT', onSig);
      resolve({ code, signal });
    });
  });
}

async function main() {
  console.clear();
  console.log();
  console.log('\x1b[1mbots-fingerprint-arcades\x1b[0m  —  FingerprintJS v4 reverse-engineering harness for arcades.click');
  console.log('\x1b[2mSee README.md for context · FPJS.md for the full writeup\x1b[0m');
  console.log();

  while (true) {
    const { choice } = await prompts({
      type: 'select',
      name: 'choice',
      message: 'pick a script',
      hint: 'arrow keys to navigate · enter to run · esc/ctrl-c to quit',
      choices: [
        ...SCRIPTS.map((s) => ({ title: s.title, description: s.desc, value: s })),
        { title: '  quit', description: 'Exit the launcher.', value: '__quit' },
      ],
      initial: 0,
    });

    if (!choice || choice === '__quit') {
      console.log('\nbye.');
      process.exit(0);
    }

    console.log();
    console.log(`\x1b[36m─── running ${choice.file} ───\x1b[0m\n`);
    const { code, signal } = await runScript(choice.file);
    const status = signal ? `signal ${signal}` : `exit code ${code}`;
    console.log();
    console.log(`\x1b[36m─── ${choice.file} finished (${status}) ───\x1b[0m\n`);

    const { again } = await prompts({
      type: 'confirm',
      name: 'again',
      message: 'back to menu?',
      initial: true,
    });
    if (!again) {
      console.log('bye.');
      process.exit(0);
    }
  }
}

main().catch((e) => {
  console.error('\nlauncher error:', e);
  process.exit(1);
});
