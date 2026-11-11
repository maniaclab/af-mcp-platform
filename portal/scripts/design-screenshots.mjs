// Captures every portal page, per scenario, at desktop and phone widths in
// light and dark, using headless Chromium against the design preview server
// (design-preview.mjs). It builds nothing itself: run the portal build first.
// The pages show EXAMPLE data for design review only.
//
// Usage: node scripts/design-screenshots.mjs --out <dir> [--pages a,b] [--scenarios a,b]
//          [--chrome <path>] [--accent RRGGBB]
// Chromium comes from --chrome, then $CHROME_BIN, then the Playwright cache.
// Files are named <scenario>-<page>-<width>-<theme>.png.

import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { listScenarios, startServer } from './design-preview.mjs';

const DEFAULT_CHROME = join(
  homedir(),
  'Library/Caches/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-mac-arm64/chrome-headless-shell',
);

// page name -> URL path. The public landing page has no name of its own.
const PAGES = {
  home: '/',
  callback: '/callback/',
  overview: '/overview/',
  catalog: '/catalog/',
  identities: '/identities/',
  tokens: '/tokens/',
  usage: '/usage/',
  entitlements: '/entitlements/',
  admin: '/admin/',
};

// Window height is tall so the capture is effectively full-page; a shorter
// virtual-time budget produced unstyled captures.
const VIEWPORTS = [
  { width: 1440, height: 2400 },
  { width: 400, height: 3200 },
];
const THEMES = ['light', 'dark'];
const VIRTUAL_TIME_BUDGET_MS = 20000;
const CAPTURE_TIMEOUT_MS = 120000;
const CONCURRENCY = 4;

function capture(chrome, url, file, { width, height }) {
  // A fresh profile per capture keeps cookies and storage from leaking
  // between the theme/accent overrides of different captures.
  const profile = mkdtempSync(join(tmpdir(), 'design-shot-'));
  const args = [
    '--headless',
    '--disable-gpu',
    '--hide-scrollbars',
    `--virtual-time-budget=${VIRTUAL_TIME_BUDGET_MS}`,
    `--window-size=${width},${height}`,
    `--user-data-dir=${profile}`,
    `--screenshot=${file}`,
    url,
  ];
  return new Promise((resolve, reject) => {
    execFile(chrome, args, { timeout: CAPTURE_TIMEOUT_MS }, (err, _stdout, stderr) => {
      rmSync(profile, { recursive: true, force: true });
      if (err) return reject(new Error(`chrome failed for ${url}: ${err.message}\n${stderr}`));
      if (!existsSync(file)) return reject(new Error(`chrome wrote no file for ${url}`));
      resolve();
    });
  });
}

/** Runs async *tasks* (functions) with at most *limit* in flight; rejects on the first failure. */
async function runPool(tasks, limit) {
  const queue = [...tasks];
  const worker = async () => {
    while (queue.length > 0) await queue.shift()();
  };
  await Promise.all(Array.from({ length: limit }, worker));
}

function splitList(value, allowed, label) {
  if (!value) return allowed;
  const picked = value.split(',').map((s) => s.trim());
  const unknown = picked.filter((p) => !allowed.includes(p));
  if (unknown.length > 0) {
    throw new Error(`unknown ${label}: ${unknown.join(', ')} (have: ${allowed.join(', ')})`);
  }
  return picked;
}

async function main() {
  const { values } = parseArgs({
    options: {
      out: { type: 'string' },
      pages: { type: 'string' },
      scenarios: { type: 'string' },
      chrome: { type: 'string' },
      accent: { type: 'string' },
    },
  });
  if (!values.out) throw new Error('--out <dir> is required');
  const chrome = values.chrome ?? process.env.CHROME_BIN ?? DEFAULT_CHROME;
  if (!existsSync(chrome)) {
    throw new Error(
      `headless Chromium not found at ${chrome}; pass --chrome <path> or set CHROME_BIN`,
    );
  }
  const pages = splitList(values.pages, Object.keys(PAGES), 'page');
  const scenarios = splitList(values.scenarios, listScenarios(), 'scenario');
  const outDir = values.out;
  mkdirSync(outDir, { recursive: true });

  for (const scenario of scenarios) {
    const { server, url } = await startServer({ scenario });
    try {
      const tasks = [];
      for (const page of pages) {
        for (const viewport of VIEWPORTS) {
          for (const theme of THEMES) {
            const query = `?theme=${theme}${values.accent ? `&accent=${values.accent}` : ''}`;
            const file = join(outDir, `${scenario}-${page}-${viewport.width}-${theme}.png`);
            tasks.push(async () => {
              await capture(chrome, `${url}${PAGES[page]}${query}`, file, viewport);
              console.log(file);
            });
          }
        }
      }
      await runPool(tasks, CONCURRENCY);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exitCode = 1;
  });
}
