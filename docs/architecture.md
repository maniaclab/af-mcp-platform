# Architecture

## Overview

The AF MCP Platform sits between LLM clients (Claude, Gemini, or any MCP-capable
agent framework) and a growing set of ATLAS/AF backend services. Its job is to
ensure that tool calls are authenticated, authorized, and executed with the right
per-user credentials — without ever handing raw secrets to the LLM or requiring
backends to implement their own auth plumbing.

Two distinct client identities obtain tokens for the same audience
(`aud=mcp-gateway`) against AF Keycloak, then hit the broker the same way:

```
mcp-portal              MCP-client identities
(portal SPA;        (Claude Desktop et al. — placeholder for
 Code+PKCE)           a future MCP-client identity; not yet implemented)
     │                          │
     └──────────┬───────────────┘
                 ▼
       AF Keycloak OIDC (connect realm)
                 │  issues aud=mcp-gateway access token
                 ▼
       Bearer sent directly by the client
```

```
LLM client / Portal SPA
    │  Authorization: Bearer <aud=mcp-gateway token>
    ▼
AF Credential Broker  — validates the Bearer itself
    │  (HTTPBearer + keycloak_dependency; no ForwardAuth proxy
    │   in this path — see docs/auth.md)
    ▼
FastMCP Aggregator  ◄────────────────  tool registry (in-memory, hot-reload)
    │  internal call: tool_name + args + principal
    ▼
AF Credential Broker  (/v1 HTTP API)
    │  brokered credential (rucio token, x509 proxy, IAM token, …)
    ▼
Backend MCP server  (rucio-mcp, ami-mcp, panda-mcp, …)
    │  result / error
    ▼  (back up the chain)
LLM client / Portal SPA
```

oauth2-proxy still exists, but only in front of the portal's HTML/static
assets (`ingress-portal.yaml`) — it is not in the request path for `/v1/*`
or `/mcp/*` on either host (`ingress-mcp.yaml` for mcpHost,
`ingress-portal-api.yaml` for portalHost). Every caller obtains its own
`aud=mcp-gateway` token and presents it directly; the broker's validator is
identical regardless of which client identity issued the token. See
[docs/auth.md](auth.md) for the full design record.

---

## The Four Broker Subsystems

### 1. Identity

Extracts and validates the AF principal from the incoming request.

- Validates the caller's Keycloak-issued JWT directly (`HTTPBearer` +
  `keycloak_dependency`) — there's no ForwardAuth proxy forwarding it; every
  caller (portal SPA, Claude Desktop, `curl`) presents its own Bearer. See
  [docs/auth.md](auth.md) for the per-client-identity breakdown.
- Resolves the POSIX `uid` / `gid` for the principal (needed for NFS-scoped
  credential operations).
- Produces a `Principal` dataclass that flows through the rest of the call.

### 2. Authorization

Answers: "is this principal allowed to call this tool?"

- Policy is declarative YAML (`policy.yaml`) — no code change needed to add a
  capability.
- Each backend target requires a capability (e.g., rucio requires `read_data`,
  panda requires `submit_jobs`) via `target_capabilities` in `policy.yaml`.
- A principal's capabilities come from their Keycloak group memberships via
  `group_capabilities` in `policy.yaml` (shipped in the chart's policy
  ConfigMap).
- Authorization failures are logged with structured fields (uid, tool, capability)
  and return HTTP 403 to the aggregator.

### 3. Credentialing

Fetches or mints the per-user credential required by the backend, given an
authorized principal.

Two axes define the provider matrix:

| | **Short-lived mint** | **Stored brokered token** |
|---|---|---|
| **IAM-based** | Keycloak token exchange (AF-internal only) | `GET /realms/connect/broker/atlas-oidc/token` → ATLAS IAM token |
| **x509/VOMS** | Ephemeral k8s Job (NFS subPath mount of `~/.globus`) | N/A — always minted fresh |

The `CredentialCache` (in-process, async-safe) stores minted credentials keyed by
`(uid, target)` for their lifetime, avoiding redundant minting. See
`spikes/credential-isolation/` for the concurrency validation.

Important: Keycloak Standard Token Exchange (V2) is internal-to-AF only. It
**cannot** mint a token that `atlas-auth.cern.ch` will accept. Use the stored
brokered token path via `GET /realms/connect/broker/atlas-oidc/token` for any
credential that must be accepted by external ATLAS services (Rucio, PanDA, AMI).

#### Client ID Metadata Document (CIMD)

Some backends act as their own OAuth 2.1 authorization server rather than
delegating entirely to Keycloak (rucio-mcp is the first). Instead of
pre-registering the broker as a client via Dynamic Client Registration against
every such backend, the broker publishes a public, unauthenticated
`GET /.well-known/cimd` endpoint implementing
[draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/):
a self-describing JSON document whose `client_id` is the URL of the document
itself. A backend's authorization server fetches this URL directly to learn
the broker's `redirect_uris` (one per `oauth21-direct` entry in
`Settings.identity_providers`) and client metadata, with no per-backend
registration step required.

#### Identity providers are a single, unified list

`Settings.identity_providers` (env `IDENTITY_PROVIDERS`, chart
`broker.identityProviders`) is the one config surface for every identity
provider the broker can link a user's account to. Each entry is a
discriminated union on `type`:

- `keycloak-brokered` — Keycloak's stored-broker-token pattern (see below),
  handled by `OIDCProvider`. `alias` must match the IdP alias configured in
  the OIDC issuer's realm (e.g. `atlas-oidc`).
- `oauth21-direct` — the broker acting as a direct OAuth 2.1 client (see
  CIMD above), handled by `OAuth21Provider`.

An entry's `alias` doubles as the portal-facing id on `GET /v1/identities` —
there is no separate id-to-alias mapping. `app.py`'s lifespan builds one
`CredentialProvider` instance per entry, keyed by alias, on
`app.state.identity_providers`, and registers each entry's `targets` with the
`CredentialRegistry` the same way regardless of provider type. The identities
API (`api/identities.py`) iterates this dict — in the same order the entries
were configured — to build `GET /v1/identities`'s `providers` list, with no
hardcoded provider set of its own.

#### Linkage detection is per-provider

Before calling `issue()`, the API layer (`api/credentials.py`) gates on
`provider.is_linked(principal)` — an abstract method every `CredentialProvider`
implements against its own storage backend, since linkage state lives in
whichever system actually holds it and cannot be represented uniformly as a
JWT claim:

- `OIDCProvider` probes Keycloak's stored-brokered-token endpoint
  (`GET /realms/connect/broker/<alias>/token`) with the principal's own
  bearer token; HTTP 200 means linked. The result is cached per uid for a
  short TTL to avoid a Keycloak round-trip on every call.
- `OAuth21Provider` checks the `TokenStore` for a non-expired stored token
  for `(principal.sub, alias)`.
- `X509Provider` checks for a readable `usercert.pem` + `userkey.pem` pair
  under the principal's home directory.
- `ServiceProvider` always reports linked — the broker's own service account
  is the credential source, so there is no user-side linkage to check.

An unlinked provider surfaces as `404` before `issue()` is ever called, rather
than as an opaque failure from inside the provider. `GET /v1/identities`'s
`providers[].linked` is built the same way — by probing `is_linked()` — so it
reflects Keycloak's (or the OAuth 2.1 `TokenStore`'s) actual state instead of
a claim that may be absent from the token.

#### Passphrase-unlock rate limiting

`~/.globus` is readable by anyone colocated on the same NFS-mounted home
directory, so a passphrase is the only thing standing between a local
attacker and a user's x509 proxy. `CredentialCache` (`credentials/cache.py`)
counts failed cache lookups and bad passphrase attempts per uid and raises
`RateLimitError` once a threshold is exceeded within a fixed window, to
slow brute-force guessing. `X509Provider.mint()` calls
`cache.check_unlock_rate_limit()` before doing any minting work, so a
locked-out uid never reaches the k8s Job / subprocess path (`x509.py`).

The threshold and window are configurable via `Settings`:

| Env var | Settings field | Default |
|---|---|---|
| `CREDENTIAL_UNLOCK_MAX_FAILURES` | `credential_unlock_max_failures` | 5 attempts |
| `CREDENTIAL_UNLOCK_WINDOW_SECONDS` | `credential_unlock_window_seconds` | 900s (15 min) |

Five attempts is generous enough to tolerate a mistyped passphrase but tight
enough to slow a brute-force guesser; fifteen minutes roughly matches how
often a browser session's token refresh forces re-authentication anyway.
Both must be >= 1 — `Settings` rejects zero or negative values, since either
would silently disable the limit.

On trip, `RateLimitError` propagates out of `X509Provider.mint()` (and out of
`CredentialCache.get()` on the ordinary cache-miss path used by both the OIDC
and x509 providers). A global handler in `app.py`
(`@app.exception_handler(RateLimitError)`) maps it to `429 Too Many Requests`
with a `Retry-After` header, so it never reaches a client as a bare `500`.
`retry_after_seconds` on the exception is computed at the raise site as
`max(0, window_start + credential_unlock_window_seconds - now)` — the time
left before the uid's fixed window closes — and the handler mirrors it into
both the `Retry-After` header (seconds, per RFC 7231 §7.1.3) and the response
body, so HTTP clients that honor the header and the portal (which wants a
wall-clock timestamp to render a countdown) are both served:

```json
{
  "detail": "Too many failed unlock attempts. Try again in 42 seconds.",
  "retry_after_seconds": 42,
  "retry_at": "2026-07-22T18:34:12Z"
}
```

### 4. Audit

Structured log (structlog + JSON) of every tool invocation, including:
- principal uid and Keycloak subject
- tool name and backend
- authorization decision (allow / deny) and capability checked
- credential provider used
- response status and latency
- request ID (propagated in `X-Request-ID` header)

Prometheus metrics expose per-tool latency histograms and error counters,
served as `/metrics` on a dedicated port (9090, `METRICS_PORT`) so the
chart's NetworkPolicy can allow Prometheus scraping without opening the API
port. The API port does not serve `/metrics`.

---

## The `/v1` Broker Contract

The FastAPI `/v1` HTTP API is the **platform boundary**. Anything behind it
(aggregator, backends, credential providers) is an implementation detail.
Anything in front of it (LLM clients, the portal SPA) sees only this
surface — and presents its own bearer token directly; oauth2-proxy is not
in this path (see [docs/auth.md](auth.md)).

Key endpoints:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/identities` | Caller identity, linked accounts, linkable providers |
| `GET` | `/v1/capabilities` | Caller's granted capabilities |
| `POST` | `/v1/authorize` | Check one entitlement (used by the aggregator per call) |
| `GET` | `/v1/catalog` | Tools visible to the caller after entitlement filtering |
| `POST` | `/v1/credential` | Issue or return a cached credential for a target |
| `POST` | `/v1/x509/proxy` | Mint and cache a VOMS proxy (passphrase unlock) |
| `GET` | `/v1/x509/proxy/status` | Proxy cache status |
| `GET` | `/v1/healthz` | Liveness probe |
| `GET` | `/v1/readyz` | Readiness probe (gated on JWKS reachability only; backends config is reported informationally) |

Tool execution itself flows through the MCP mount (`/mcp`); the aggregator
authorizes and fetches credentials by calling `/v1/authorize` and
`/v1/credential` per tool call. Prometheus metrics are served on the
dedicated metrics port (9090), not under `/v1`.

All requests require a valid AF bearer token. The aggregator translates
MCP-over-HTTP into `/v1` calls; external callers can also hit `/v1` directly
(useful for scripting and debugging).

### Reserved paths on the portal host

The portal (`mcp-portal.af.uchicago.edu`) is a static Astro build; its API
client fetches `/v1/*` same-origin. A dedicated `ingress-portal-api.yaml`
Ingress object (same host, no oauth2-proxy annotations) routes `/v1` and
`/mcp` to the broker Service, ahead of `ingress-portal.yaml`'s `/`
catch-all via nginx's longest-prefix matching — see
[docs/auth.md](auth.md#portal-auth-oidc-public-client). Current portal page
routes: `/`, `/callback/`, `/catalog/`, `/identities/`, `/status/`.

**New portal pages MUST NOT use the `/v1/` or `/mcp/` prefixes** — those are
reserved for the broker on both hosts and would be silently shadowed. A
future `tokens` page, for example, belongs at `/tokens/`, not `/mcp-tokens/`
or anything else starting with a reserved prefix.

---

## Aggregation Extraction Path

The current design embeds FastMCP as a library inside the broker process. This is
the simplest correct thing. The extraction path if it becomes necessary:

1. **Embedded FastMCP** (current) — FastMCP runs in-process, broker handles both
   MCP protocol and credential brokering.
2. **Standalone FastMCP sidecar** — FastMCP runs as a separate container in the
   same pod, talking to the broker via loopback. Useful if FastMCP needs
   independent scaling.
3. **agentgateway** — if the agentgateway spike (see `docs/agentgateway-spike.md`)
   passes, agentgateway can replace the FastMCP aggregator while the broker
   remains unchanged. The `/v1` contract is invariant.

---

## Full Data Flow for a Tool Call

1. LLM sends `tools/call` MCP message over HTTPS to `mcp.af.uchicago.edu`,
   with its own `aud=mcp-gateway` Bearer (see [docs/auth.md](auth.md) for how
   each client identity obtains one).
2. The FastMCP Aggregator receives the `tools/call`, extracts tool name + args,
   and calls the broker's `POST /v1/authorize` and `POST /v1/credential`.
3. The broker Identity subsystem validates the Bearer directly (no ForwardAuth
   proxy in this path) and resolves the `Principal`.
4. The Authorization subsystem checks `principal.capabilities` against the tool's
   `required_capability`. Deny → 403 logged and returned.
5. The Credential subsystem looks up `(uid, target)` in the `CredentialCache`. On
   miss, it invokes the appropriate provider (token exchange or x509 mint Job).
6. The broker constructs the backend request, injecting the credential, and calls
   the target backend MCP server.
7. The backend response is returned through the broker → aggregator → LLM client.
8. The Audit subsystem writes a structured log line and updates Prometheus counters.
