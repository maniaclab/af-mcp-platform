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

**Terminal 1 — broker on :8080:**

```bash
pixi run broker
```

Starts uvicorn with `--reload`. API is at <http://localhost:8080/docs>.

**Terminal 2 — portal on :4321:**

```bash
pixi run -e portal dev
```

`astro dev` proxies `/v1/*` to the broker automatically (see
`portal/astro.config.mjs`). Open <http://localhost:4321>.

Every fetch the Vue islands make goes through the vite proxy to the broker
you started in terminal 1.

## Getting past auth for UI work

At this point the broker will 401 on every `/v1/*` call because no bearer
is being sent. The broker ships a local-dev opt-in that returns a hardcoded
"dev principal" without inspecting the token.

Restart the broker in terminal 1 with the `bypass` environment — it sets
both env vars as pixi feature activation:

```bash
pixi run -e bypass broker
```

Equivalent long form, for one-off overrides:

```bash
export BROKER_DEV_INSECURE_PRINCIPAL='{"uid":1000,"gid":1000,"unixname":"devuser","email":"dev@localhost","groups":["af-users"]}'
export KEYCLOAK_ISSUER=http://localhost:8081/realms/dev
pixi run broker
```

You should see a very loud warning line at startup:

```json
{"message": "AUTH BYPASSED — DO NOT USE IN PRODUCTION",
 "event": "dev_auth_bypass_active",
 "keycloak_issuer": "http://localhost:8081/realms/x",
 "unixname": "devuser", "uid": 1000,
 "level": "warning", ...}
```

Every response is stamped with `X-Dev-Bypass: true` and every bypassed
request writes an `event="dev_auth_bypass_used"` log line. Refresh the
portal — the Vue islands now render with the dev principal.

> **Do not use this in production.** The broker will refuse to start
> unless the configured `KEYCLOAK_ISSUER` looks local (hostname is
> `localhost`, `127.0.0.1`, `::1`, or ends in `.localhost` / `.local` /
> `.test`). The env var is never set by the Helm chart, containers, or
> CI — it exists exclusively for a developer machine.

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
Authorization Code + PKCE flow against AF Keycloak instead, edit that file
locally (never commit real values):

```json
{
  "oidc": {
    "issuer": "https://keycloak-prod.tempest.uchicago.edu/realms/connect",
    "clientId": "mcp-portal",
    "scope": "openid profile email mcp-gateway"
  },
  "brokerOrigin": "http://localhost:8080"
}
```

`http://localhost:4321/callback` is already a registered redirect URI on the
`mcp-portal` client, so this works without any Keycloak-side changes. You'll still need a broker that accepts the resulting token —
either a real `KEYCLOAK_ISSUER`/`KEYCLOAK_AUDIENCE` pointed at the same
realm, or continue using the bypass broker (it ignores the Bearer either
way, so this is only useful for exercising the portal's own OIDC code path,
not an end-to-end auth check).

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
pixi run -e dev test         # pytest broker/ -v
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

## Ports summary

| Port | Owned by         | Notes                                             |
|------|------------------|---------------------------------------------------|
| 8080 | broker API       | `/v1/*` and `/mcp/*`; no `/metrics` here          |
| 9090 | broker metrics   | Prometheus scrape target; separate for NetPol     |
| 4321 | portal dev       | `astro dev` — proxies `/v1/*` to the broker       |
