// Design preview server: serves the built portal (portal/dist) together with
// fixture answers for the broker API, so every signed-in page can be looked at
// (and screenshotted) with realistic data and no broker, Keycloak or login.
//
// ALL DATA HERE IS EXAMPLE DATA FOR DESIGN REVIEW ONLY. It is fictional and
// must never be mistaken for, or pointed at, a real deployment.
//
// This server never runs in production, so Content-Security-Policy is not a
// concern: it deliberately strips the CSP <meta> tag Astro emits into every
// page, otherwise the inline theme script injected below would be blocked.
//
// Usage: node scripts/design-preview.mjs [--port N] [--scenario healthy|problems] [--accent RRGGBB]
//
// Per-request overrides, usable from the URL alone:
//   ?theme=light|dark  stored under the portal's theme key by an injected inline script
//   ?accent=RRGGBB     remembered in a cookie, which /config.json turns into branding.accentColor
//                      (the config request carries no query string of its own); an empty
//                      value (?accent=) clears it.
//
// Fixtures live in design-preview-fixtures/<scenario>/<endpoint>.json, where
// <endpoint> is the /v1 path with "/" replaced by "-" (/v1/x509/proxy/status
// -> x509-proxy-status.json). Time-dependent values are written as
// placeholders so statuses such as "expires in 3 days" stay true whenever the
// preview runs:
//   "@iso+3d"  ISO-8601 timestamp, now + 3 days   (units: s, m, h, d; sign + or -)
//   "@unix-2h" Unix seconds, now - 2 hours
//   "@secs+9h" a duration in seconds (sign applied)
//   "@date-5d" a UTC calendar day, YYYY-MM-DD

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const DIST_DIR = join(HERE, '..', 'dist');
const FIXTURES_DIR = join(HERE, 'design-preview-fixtures');

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};

// Must match THEME_STORAGE_KEY in src/lib/theme.ts. Written before the page's
// own theme init (themeInitScript.js) runs, because this script is the first
// thing in <head>.
const THEME_OVERRIDE_SCRIPT = `<script>(function(){try{var t=new URLSearchParams(location.search).get('theme');if(t==='light'||t==='dark')localStorage.setItem('themeMode',t);}catch(e){}})();</script>`;
const CSP_META = /<meta[^>]*http-equiv=["']content-security-policy["'][^>]*>/gi;

const ACCENT_COOKIE = 'af_preview_accent';
const HEX6 = /^[0-9a-fA-F]{6}$/;

const UNIT_SECONDS = { s: 1, m: 60, h: 3600, d: 86400 };
const PLACEHOLDER = /"@(iso|unix|secs|date)([+-])(\d+)([smhd])"/g;

/** Replaces the time placeholders documented at the top of the file. */
export function expandPlaceholders(text, nowMs = Date.now()) {
  return text.replace(PLACEHOLDER, (_, kind, sign, amount, unit) => {
    const seconds = (sign === '-' ? -1 : 1) * Number(amount) * UNIT_SECONDS[unit];
    const when = new Date(nowMs + seconds * 1000);
    if (kind === 'secs') return String(seconds);
    if (kind === 'unix') return String(Math.floor(when.getTime() / 1000));
    if (kind === 'date') return JSON.stringify(when.toISOString().slice(0, 10));
    return JSON.stringify(when.toISOString().replace(/\.\d{3}Z$/, 'Z'));
  });
}

function readCookie(req, name) {
  const match = (req.headers.cookie ?? '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? match[1] : null;
}

function sendJson(res, status, body) {
  const payload = status === 204 ? '' : JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': CONTENT_TYPES['.json'], 'Cache-Control': 'no-store' });
  res.end(payload);
}

function loadFixture(scenario, name) {
  const file = join(FIXTURES_DIR, scenario, `${name}.json`);
  if (!existsSync(file)) return null;
  return JSON.parse(expandPlaceholders(readFileSync(file, 'utf8')));
}

/** The tools listing for services without their own fixture, derived from the catalog entry. */
function fallbackTools(scenario, service) {
  const entry = loadFixture(scenario, 'catalog')?.servers.find((s) => s.name === service);
  if (!entry) return null;
  const ok = entry.status === 'available';
  const tool = (suffix, action_type, description) => ({
    name: `${service}_${suffix}`,
    description,
    action_type,
    permission: entry.permission ?? '__none__',
  });
  return {
    name: entry.name,
    display_name: entry.display_name,
    description: entry.description,
    status: ok ? 'ok' : 'unavailable',
    status_detail: ok ? 'Ready to use.' : entry.status_detail,
    tools: ok
      ? [
          tool('list_examples', 'read', 'List example items.'),
          tool('update_example', 'state_change', 'Update an example item.'),
        ]
      : [],
  };
}

/** GET /v1/usage?days=N: the fixture holds 30 days; narrow it to the requested window. */
function usageForWindow(usage, days) {
  if (!usage || !Number.isInteger(days) || days <= 0) return usage;
  return { ...usage, window_days: days, by_day: usage.by_day.slice(-days) };
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        resolve({});
      }
    });
  });
}

/** A plausible success body for each mutating call; nothing persists. */
function mutationResponse(method, path, body) {
  const nowMs = Date.now();
  const iso = (offsetS) => new Date(nowMs + offsetS * 1000).toISOString();
  if (method === 'DELETE') return [204, null];
  if (path === '/tokens') {
    const days = body.expires_in_days ?? 30;
    return [
      200,
      {
        token: 'mcp_pat_EXAMPLE0000000000000000000000000000',
        lookup_id: 'EXAMPLE9999',
        created_at: iso(0),
        expires_at: body.never_expires ? null : iso(days * 86400),
        name: body.name ?? 'example-new-token',
        note: body.note ?? null,
        permission_grant: body.permissions ?? null,
      },
    ];
  }
  if (path === '/x509/proxy') {
    return [
      200,
      {
        dn: '/DC=org/DC=example/CN=Example User',
        voms_attributes: ['/atlas/Role=NULL/Capability=NULL'],
        expires_at: iso(43200),
        remaining_seconds: 43200,
      },
    ];
  }
  if (path === '/krb5/ticket' || path === '/krb5/keytab') {
    return [
      200,
      {
        target: 'example',
        principal: 'example-user-1@EXAMPLE.ORG',
        realm: 'EXAMPLE.ORG',
        expires_at: iso(86400),
        remaining_seconds: 86400,
        renew_until: iso(7 * 86400),
        source: 'password_mint',
      },
    ];
  }
  if (path === '/servicex/link') {
    return [200, { target: 'example', expires_at: iso(30 * 86400), remaining_seconds: 30 * 86400 }];
  }
  if (path === '/admin/maintenance') {
    return [
      200,
      {
        enabled: Boolean(body.enabled),
        reason: body.reason ?? null,
        enabled_by: 'example-subject-0001',
        enabled_at: Math.floor(nowMs / 1000),
        enabled_by_unixname: 'example-user-1',
        enabled_by_email: 'example-user-1@example-facility.org',
      },
    ];
  }
  if (path === '/admin/credmon/sync') {
    return [
      200,
      {
        outcome: 'success',
        trigger: 'manual',
        holder: 'example-broker-7d9f-abcde',
        started_at: Math.floor(nowMs / 1000),
        finished_at: Math.floor(nowMs / 1000),
        last_success_at: Math.floor(nowMs / 1000),
        stored: { krb5: 41, x509: 38 },
        not_linked: {},
        skipped_no_posix: {},
        failed: {},
        errors: [],
        errors_truncated: 0,
      },
    ];
  }
  return [200, {}];
}

async function handleApi(req, res, url, scenario) {
  const path = url.pathname.slice('/v1'.length);

  if (req.method !== 'GET') {
    const [status, body] = mutationResponse(req.method, path, await readBody(req));
    return sendJson(res, status, body);
  }

  if (path.startsWith('/oauth/authorize/')) {
    return sendJson(res, 200, { authorize_url: 'https://auth.example-facility.org/authorize' });
  }

  const name = path.replace(/^\//, '').replaceAll('/', '-');
  let body = loadFixture(scenario, name);
  if (name === 'usage') body = usageForWindow(body, Number(url.searchParams.get('days')));
  const toolsMatch = name.match(/^catalog-(.+)-tools$/);
  if (body === null && toolsMatch) body = fallbackTools(scenario, toolsMatch[1]);

  if (body === null) {
    console.warn(`design-preview: no fixture for GET ${url.pathname} (scenario ${scenario})`);
    return sendJson(res, 404, { detail: `no design-preview fixture for ${url.pathname}` });
  }
  return sendJson(res, 200, body);
}

function handleConfig(req, res, defaultAccent) {
  const cookie = readCookie(req, ACCENT_COOKIE);
  const accent = cookie !== null ? cookie : defaultAccent;
  // Empty oidc issuer/clientId puts the portal on its unauthenticated path.
  const config = {
    oidc: { issuer: '', clientId: '', scope: 'openid profile email' },
    brokerOrigin: 'https://mcp.example-facility.org',
    branding: {
      shortName: 'EX / MCP',
      fullName: 'Example MCP Platform',
      facilityName: 'Example Analysis Facility',
      ...(HEX6.test(accent ?? '') ? { accentColor: `#${accent}` } : {}),
    },
  };
  sendJson(res, 200, config);
}

/** Resolves a URL path to a file under dist/, or null; never leaves dist/. */
function resolveStaticFile(pathname) {
  const relative = normalize(decodeURIComponent(pathname)).replace(/^([/\\])+/, '');
  const candidates = [relative, join(relative, 'index.html'), `${relative}.html`];
  for (const candidate of candidates) {
    const file = join(DIST_DIR, candidate);
    if (!file.startsWith(DIST_DIR + sep) && file !== DIST_DIR) return null;
    if (existsSync(file) && extname(file)) return file;
  }
  return null;
}

function serveStatic(req, res, url) {
  const file = resolveStaticFile(url.pathname);
  if (!file) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Not found (is portal/dist built?)');
  }
  const type = CONTENT_TYPES[extname(file)] ?? 'application/octet-stream';
  const headers = { 'Content-Type': type, 'Cache-Control': 'no-store' };

  if (extname(file) !== '.html') {
    res.writeHead(200, headers);
    return res.end(readFileSync(file));
  }

  const accent = url.searchParams.get('accent');
  if (accent !== null) {
    headers['Set-Cookie'] = HEX6.test(accent)
      ? `${ACCENT_COOKIE}=${accent}; Path=/; SameSite=Lax`
      : `${ACCENT_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax`;
  }
  const html = readFileSync(file, 'utf8')
    .replace(CSP_META, '')
    .replace(/<head[^>]*>/i, (head) => head + THEME_OVERRIDE_SCRIPT);
  res.writeHead(200, headers);
  res.end(html);
}

export function listScenarios() {
  return readdirSync(FIXTURES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name);
}

/** Starts the server; resolves to { server, port, url }. port 0 picks a free one. */
export function startServer({ port = 0, scenario = 'healthy', accent = null } = {}) {
  if (!listScenarios().includes(scenario)) {
    throw new Error(`unknown scenario "${scenario}" (have: ${listScenarios().join(', ')})`);
  }
  if (!existsSync(join(DIST_DIR, 'index.html'))) {
    throw new Error(`${DIST_DIR} has no index.html: run \`pixi run -e portal build\` first`);
  }
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const respond = async () => {
      if (url.pathname === '/config.json') return handleConfig(req, res, accent);
      if (url.pathname.startsWith('/v1/')) return handleApi(req, res, url, scenario);
      return serveStatic(req, res, url);
    };
    respond().catch((err) => {
      console.error(`design-preview: ${req.method} ${req.url} failed:`, err);
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const actual = server.address().port;
      resolve({ server, port: actual, url: `http://127.0.0.1:${actual}` });
    });
  });
}

async function main() {
  const { values } = parseArgs({
    options: {
      port: { type: 'string', default: '0' },
      scenario: { type: 'string', default: 'healthy' },
      accent: { type: 'string' },
    },
  });
  const { url } = await startServer({
    port: Number(values.port),
    scenario: values.scenario,
    accent: values.accent ?? null,
  });
  console.log('==============================================================');
  console.log(' DESIGN PREVIEW: serves EXAMPLE data for design review only.');
  console.log(' Everything shown is fictional and not from any real service.');
  console.log('==============================================================');
  console.log(`scenario: ${values.scenario} (available: ${listScenarios().join(', ')})`);
  console.log(`listening on ${url}`);
  console.log('append ?theme=light|dark and ?accent=RRGGBB to any page URL to override');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exitCode = 1;
  });
}
