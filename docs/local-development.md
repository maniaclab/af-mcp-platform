# Local development

You just cloned the repo and you want to load the portal in a browser with
real broker data. This page tells you how.

In production, the portal is its own OAuth client and sends its own
`aud=mcp-gateway` Bearer on every `/v1/*` request (see
[docs/auth.md](auth.md)); the broker validates it directly. Locally, the
checked-in `portal/public/config.json` ships with OIDC turned off (empty
`oidc.issuer`), so `astro dev`'s built-in proxy of `/v1/*` to
`http://localhost:8080` would otherwise send no Bearer at all and every Vue
island would 401. The recommended workflow uses a broker-side bypass to get
past that instead of standing up a real Keycloak locally.

## Prerequisites

- [pixi](https://pixi.sh/) (`curl -fsSL https://pixi.sh/install.sh | bash`)
  — everything Python + Node runs through pixi.
- Nothing else. `pixi run -e portal dev` pulls Node from conda-forge on
  first use.

## The two-terminal workflow

**Terminal 1 — broker on :8080, auth bypassed:**

```bash
pixi run -e bypass broker
```

Starts uvicorn with `--reload`. API is at <http://localhost:8080/docs>. The
`bypass` environment is the one for UI work: it needs no Keycloak, and the
broker returns a fixed dev principal on every request (see "Getting past auth
for UI work" below).

> The broker refuses to boot when `POLICY_FILE` is missing, unreadable or
> grants no permissions, and when `SERVICES_FILE` is missing, unreadable,
> invalid or defines no services; the bypass changes neither. The pixi `dev`
> and `bypass` environments (their `localdev` feature) point them at the
> dev-only policy `broker/src/af_mcp_broker/authorization/policy.yaml` (ATLAS
> AF group names) and the dev registry
> `broker/src/af_mcp_broker/mcp/services.yaml`, so both work out of the box.
> The `broker` environment, which the container image is built from, sets
> neither path: the image's entrypoint would export them over the deployment's
> own configuration. Export `POLICY_FILE=/path/to/policy.yaml` (it needs at
> least one group that maps to a non-empty permission list) and/or
> `SERVICES_FILE=/path/to/services.yaml` first to use your own; an exported
> value wins over the default.
>
> The dev registry holds only services the local modes can satisfy, so it has
> no `auth_type: x509` entry. An x509 service needs an `x509`
> `IDENTITY_PROVIDERS` entry covering it, the voms-token-service
> (`service_url`), the broker signing key (`BROKER_SIGNING_KEY_FILE`) and Vault
> (`VAULT_ADDR`, `VAULT_KV_ROOT`, `VAULT_AUTH_ROLE`) at boot. If you have that
> infrastructure, copy `services.yaml` to a file of your own, add the service
> (see `broker/tests/data/x509-ami-service.yaml` for the entry shape) and
> export `SERVICES_FILE` for it, `IDENTITY_PROVIDERS` with an `x509` entry whose
> `targets` names it (see docs/auth.md), and the settings above.

> `pixi run -e dev broker` is the mode without the bypass. It refuses to start
> unless `OIDC_ISSUER` names a real Keycloak realm (`https://…/realms/…`) and a
> Keycloak admin service account is configured
> (`KEYCLOAK_ADMIN_CLIENT_ID`/`KEYCLOAK_ADMIN_CLIENT_SECRET`): every credential
> type (JWT included, not just PATs) resolves its groups and POSIX identity from
> that account, so a broker with neither it nor the bypass can never
> authenticate anyone — see docs/auth.md's "Operator setup: the Keycloak admin
> service account" for details. Use it only with a real realm to point at.

**Terminal 2 — portal on :4321:**

```bash
pixi run -e portal dev
```

`astro dev` proxies `/v1/*` to the broker automatically (see
`portal/astro.config.mjs`). Open <http://localhost:4321>.

Every fetch the Vue islands make goes through the vite proxy to the broker
you started in terminal 1.

## Uvicorn lifecycle lines

uvicorn's own lifecycle lines (`Started server process`, `Application startup
complete.`, the `--reload` watcher's file-change messages) stay plain text under
`pixi run -e dev broker`, because that task does not pass `--log-config`. They
are what you read while editing code, and the broker's own lines are already
JSON either way. To see them as JSON, as in the image, run
`uvicorn af_mcp_broker.app:app --port 8080 --log-config broker/src/af_mcp_broker/uvicorn_log_config.json`
or `python -m af_mcp_broker`.

## Getting past auth for UI work

At this point the broker will 401 on every `/v1/*` call because no bearer
is being sent. The broker ships a local-dev opt-in that returns a hardcoded
"dev principal" without inspecting the token.

The `bypass` environment (terminal 1 above) sets both env vars as pixi
feature activation:

```bash
pixi run -e bypass broker
```

The activation exports `BROKER_DEV_INSECURE_PRINCIPAL` and `OIDC_ISSUER`; an
`OIDC_ISSUER` already exported in your shell is kept, and so are `POLICY_FILE`
and `SERVICES_FILE`. `BROKER_DEV_INSECURE_PRINCIPAL` is always overwritten
(its JSON value cannot be wrapped in a shell default), so to change the dev
principal, set it with `env` after pixi's activation has run:

```bash
pixi run -e bypass env \
  BROKER_DEV_INSECURE_PRINCIPAL='{"uid":1000,"gid":1000,"unixname":"devuser","email":"dev@localhost","groups":["cms"]}' \
  uvicorn af_mcp_broker.app:app --port 8080 --reload
```

Equivalent long form, without the `bypass` environment:

```bash
# the dev policy (`POLICY_FILE`) grants read_data and friends to atlas; pick a
# different group here if your own POLICY_FILE uses a different mapping
export BROKER_DEV_INSECURE_PRINCIPAL='{"uid":1000,"gid":1000,"unixname":"devuser","email":"dev@localhost","groups":["atlas"]}'
export OIDC_ISSUER=http://localhost:8081/realms/dev
pixi run -e dev broker
```

Note that last form still needs the Keycloak admin service account only when
the bypass is off; with `BROKER_DEV_INSECURE_PRINCIPAL` set it boots as is.

### Viewing the Admin page

The Admin page and `/v1/admin/*` need the principal to be in the group named
by `ADMIN_GROUP`, which is empty by default (nobody is an admin). Export it
before starting the broker, naming a group the dev principal is in:

```bash
ADMIN_GROUP=atlas pixi run -e bypass broker
```

`GET /v1/identities` then reports `"is_admin": true`.

You should see a very loud warning line at startup:

```json
{"message": "AUTH BYPASSED — DO NOT USE IN PRODUCTION",
 "event": "dev_bypass.active",
 "oidc_issuer": "http://localhost:8081/realms/x",
 "unixname": "devuser", "uid": 1000,
 "level": "warning", ...}
```

Every response is stamped with `X-Dev-Bypass: true` and every bypassed
request writes an `event="dev_bypass.used"` log line. Refresh the
portal — the Vue islands now render with the dev principal.

> **Do not use this in production.** The broker will refuse to start
> unless the configured `OIDC_ISSUER` looks local (hostname is
> `localhost`, `127.0.0.1`, `::1`, or ends in `.localhost` / `.local` /
> `.test`). The env var is never set by the Helm chart, containers, or
> CI — it exists exclusively for a developer machine.

### Testing the manual `/tokens` flow locally

The portal's `/tokens` page mints a broker-issued identity PAT (issue maniaclab/af-mcp-platform#144
step 2a) — no Keycloak call happens at mint time, so under the `bypass`
environment the whole mint/list/revoke round trip works exactly as-is:
`keycloak_dependency` returns the dev principal, and `POST /v1/tokens`
generates the PAT locally. There's nothing extra to configure for this part.

The minted PAT only authenticates on `/mcp`, though (see docs/auth.md's
"Where PATs are accepted" — `/v1` stays Keycloak-JWT-only on purpose). Note
that `/mcp`'s auth bypass short-circuits ahead of the PAT/JWT dispatch
entirely (see `mcp/middleware/identity_mw.py`'s `AsgiAuthMiddleware`), so
while `BROKER_DEV_INSECURE_PRINCIPAL` stays set, any bearer you present on
`/mcp` — including the PAT you just minted — is ignored in favor of the dev
principal. To actually exercise the PAT for real, drop out of the bypass
(unset `BROKER_DEV_INSECURE_PRINCIPAL`, point `OIDC_ISSUER` at a real realm)
and set `KEYCLOAK_ADMIN_CLIENT_ID`/`KEYCLOAK_ADMIN_CLIENT_SECRET` (see
docs/auth.md's "Operator setup: the Keycloak admin service account") — every
credential type resolves its groups and POSIX identity from the directory,
so the broker refuses to start without either the bypass or this service
account configured (see the note under "Terminal 1" above).

### Testing broker-issued identity tokens locally

The AF Broker Identity Token (issue maniaclab/af-mcp-platform#162, see docs/auth.md's "AF Broker
Identity Token" section) needs an RS256 signing key on disk. Generate a
throwaway one — never commit it, and never auto-generate keys in
production paths (production keys arrive as SealedSecrets):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out /tmp/broker-signing-key.pem
export BROKER_SIGNING_KEY_FILE=/tmp/broker-signing-key.pem
# the minted `iss` claim; either of these works locally
export BROKER_TOKEN_ISSUER=http://localhost:8080
```

With a `broker-issued` entry in `IDENTITY_PROVIDERS` targeting one of your
backends, `POST /v1/credential` mints a token you can check against the
broker's own JWKS at <http://localhost:8080/.well-known/jwks.json>. Without
the key configured, the broker still boots (the endpoint answers 503) —
unless a `broker-issued` entry exists, in which case it refuses to start.

### Alternative: inject a real token from a live deployment

If you'd rather not run the bypass, copy a real bearer — e.g. from
`sessionStorage` in a deployed portal tab's devtools, or from any other
client that's completed the OIDC dance — and inject it with a browser
extension like
[ModHeader](https://modheader.com/) or
[Requestly](https://requestly.io/) — set
`Authorization: Bearer <token>` for `http://localhost:4321`. The vite
proxy forwards headers to the broker, which validates them normally.
Tokens are short-lived, so this is fine for a spot-check but tedious
for extended UI work.

## Testing the real OIDC flow locally (optional)

The checked-in `portal/public/config.json` ships with an empty `oidc.issuer`,
so by default `astro dev` skips OIDC entirely (see the bypass workflow
above — that's the normal path for UI work). To exercise the real
Authorization Code + PKCE flow against a real Keycloak realm instead, edit
that file locally with your facility's own values (never commit real
values). A facility's values might look like:

```json
{
  "oidc": {
    "issuer": "https://auth.example.org/realms/example",
    "clientId": "mcp-portal",
    "scope": "openid profile email mcp-gateway"
  },
  "brokerOrigin": "http://localhost:8080"
}
```

`http://localhost:4321/callback` is already a registered redirect URI on
that deployment's `mcp-portal` client — a different deployment needs its
own client with `http://localhost:4321/callback` registered as an allowed
redirect URI before this works. You'll still need a broker that accepts the
resulting token — either a real `OIDC_ISSUER`/`OIDC_AUDIENCE` pointed at the
same realm, or continue using the bypass broker (it ignores the Bearer
either way, so this is only useful for exercising the portal's own OIDC
code path, not an end-to-end auth check).

## Talking to a broker on a different port

If your broker is not on the default `localhost:8080`:

```bash
PORTAL_DEV_BROKER_URL=http://127.0.0.1:9000 pixi run -e portal dev
```

`astro.config.mjs` reads `PORTAL_DEV_BROKER_URL` and passes it through as
the vite proxy target.

## Running tests and linters

Broker (Python):

```bash
pixi run -e dev test         # pytest broker/ skills/ -v -n auto (-n 0 to debug serially)
pixi run -e dev lint         # ruff check + format --check
pixi run -e dev typecheck    # mypy broker/src
pixi run -e dev lint-all     # everything CI's lint job runs
```

Portal (Astro + Vue + Tailwind):

```bash
pixi run -e portal test         # vitest
pixi run -e portal astro-check  # astro check (types + templates)
pixi run -e portal lint         # eslint
pixi run -e portal format-check # prettier --check
pixi run -e portal check        # the aggregate CI runs
```

## Previewing every page with example data (design review)

The signed-in pages are empty or error-ridden without a broker behind them.
For design work there is a dependency-free preview server that serves the
built portal together with canned answers for every `/v1` call, so each page
can be looked at (or screenshotted) with realistic data and no login:

```bash
pixi run -e portal design-preview                       # builds, then serves the "healthy" scenario
pixi run -e portal design-preview --scenario problems   # blocked services, expired proxy, maintenance on, ...
pixi run -e portal design-preview --port 4400           # default: a free port, printed on start
```

Everything it serves is **fictional example data** (`example-user-1`,
`mcp.example-facility.org`, ...) and exists for design review only; it is
never a stand-in for a real deployment. Fixtures live in
`portal/scripts/design-preview-fixtures/<scenario>/`, one JSON file per
endpoint, and mirror the response types in `portal/src/lib/api.ts`. Dates are
written as placeholders (`"@iso+3d"`) so "expires in 3 days" stays true.
Mutating calls (mint a token, set maintenance, ...) answer with a plausible
success and change nothing.

Two overrides work from the URL alone, so a headless browser needs no
rebuild: `?theme=light|dark` and `?accent=RRGGBB`, for example
`http://127.0.0.1:4400/tokens/?theme=dark&accent=800000`. The accent is kept
in a cookie, so it sticks for later pages until you pass `?accent=` (empty).

To capture every page at 1440 and 400 px wide, in light and dark, for both
scenarios (build first; needs a headless Chromium, by default the Playwright
cache, or `--chrome <path>` / `CHROME_BIN`):

```bash
pixi run -e portal build
cd portal && node scripts/design-screenshots.mjs --out /tmp/design-shots
# optional: --pages tokens,admin  --scenarios problems  --accent 800000
```

Files are named `<scenario>-<page>-<width>-<theme>.png`.

## Ports summary

| Port | Owned by         | Notes                                             |
|------|------------------|---------------------------------------------------|
| 8080 | broker API       | `/v1/*` and `/mcp/*`; no `/metrics` here          |
| 9090 | broker metrics   | Prometheus scrape target; separate for NetPol     |
| 4321 | portal dev       | `astro dev` — proxies `/v1/*` to the broker       |
