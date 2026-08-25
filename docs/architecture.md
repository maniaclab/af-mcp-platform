# Architecture

## Overview

The AF MCP Platform sits between LLM clients (Claude, Gemini, or any MCP-capable
agent framework) and a growing set of ATLAS/AF backend services. Its job is to
ensure that tool calls are authenticated, authorized, and executed with the right
per-user credentials — without ever handing raw secrets to the LLM or requiring
backends to implement their own auth plumbing.

Two distinct client identities authenticate against the same Keycloak realm,
then hit the broker the same way, but end up with different credential shapes:

```
mcp-portal              MCP-client identities
(portal SPA;         (Claude Desktop, Claude Code, et al. — bootstrap a
 Code+PKCE)            broker-issued PAT instead; see docs/auth.md#mcp-
                       oauth-discovery-pat-bootstrap-issue-140)
     │                          │
     ▼                          ▼
AF Keycloak OIDC          Broker's own /v1/oauth/authorize,
(operator-configured        which itself logs in against the
 realm) issues an            same Keycloak realm on the client's
 aud=mcp-gateway token       behalf, then mints a PAT (mcp_pat_…)
     │                          │
     └──────────┬───────────────┘
                 ▼
       Bearer sent directly by the client — a raw Keycloak JWT for
       the portal, a broker-issued PAT for most MCP clients
```

```
LLM client / Portal SPA
    │  Authorization: Bearer <aud=mcp-gateway token>
    ▼
FastMCP Aggregator (mounted at /mcp)
    │  IdentityMiddleware — validates the Bearer itself, same
    │  identity.get_principal() /v1 uses; no ForwardAuth proxy
    │  in this path — see docs/auth.md
    ▼
    │  EntitlementMiddleware (tools/list) / AuthorizationMiddleware
    │  (tools/call) — capability check in-process against the same
    │  functions POST /v1/authorize calls; AuthorizationMiddleware
    │  also writes the audit record for every call
    ▼
    │  client_factory — for auth_type="bearer" backends, mints the
    │  caller's credential in-process via the same provider code
    │  POST /v1/credential calls (rucio token, x509 proxy, IAM token, …)
    ▼
Backend MCP server  (rucio-mcp, ami-mcp, panda-mcp, …)
    │  result / error
    ▼  (back up the chain)
LLM client / Portal SPA
```

oauth2-proxy still exists, but only in front of the portal's authenticated
pages (`ingress-portal-authenticated.yaml`) — the public landing page and
the static assets every portal page loads are served without it
(`ingress-portal.yaml`'s `/` catch-all), and it is not in the request path
for `/v1/*` or `/mcp/*` on either host (`ingress-mcp.yaml` for mcpHost,
`ingress-portal-api.yaml` for portalHost). Every caller obtains its own
`aud=mcp-gateway` token and presents it directly; the broker's validator is
identical regardless of which client identity issued the token. See
[docs/auth.md](auth.md) for the full design record.

### `/mcp` transport mode and replica safety (issue #128)

MCP streamable-HTTP sessions are **in-process state**: the session a
client's `initialize` creates lives only in the memory of whichever broker
pod handled it. At `replicaCount: 1` that's a non-issue; at
`replicaCount > 1` it matters, because the chart's ingress load-balances
each request independently with no session pinning by default.

- **Stateless (`broker.mcpStatelessHttp: true`, the default)** — every
  request is fully self-contained; the server never consults or requires
  cross-request session state, so any replica can serve any request with
  no affinity infrastructure. Progress/log notifications emitted *during*
  a tool call are still delivered on that call's own response stream
  (verified against fastmcp 3.4.4). What's lost is the standalone GET SSE
  stream used for messages *outside* an active call —
  `notifications/tools/list_changed` and any future server-initiated
  sampling/elicitation request.
- **Stateful (`broker.mcpStatelessHttp: false`)** — required only if a
  backend/feature needs that standalone stream. Safe at `replicaCount > 1`
  *only* with session-affinity in front of the ingress, e.g.:
  ```yaml
  nginx.ingress.kubernetes.io/upstream-hash-by: "$binary_remote_addr"
  ```
  Hashing on `$http_mcp_session_id` instead does **not** work: `initialize`
  carries no session header, so it hashes an empty value onto an arbitrary
  pod, and that pod's newly-minted session id may itself hash to a
  *different* pod for the client's next request. Client-IP hashing needs
  the ingress to see the real client IP (real-IP/forwarded-headers
  configuration, or every client behind the same NAT egress lands on one
  pod) but needs no client cooperation, unlike cookie affinity. A shared
  session store (Redis/etc.) is not a viable alternative: the SDK session
  holds a live `anyio` task group and open memory streams, not
  serializable state.
- Running a stateful aggregator at `replicaCount > 1` without that
  affinity in place produces exactly the failure issue #128 describes: a
  session's later request lands on a replica that never created it, which
  terminates it — surfacing as an intermittent `McpError: Session
  terminated` that no single-replica test will ever catch. The broker
  cannot see whether affinity is configured upstream, so it can only warn
  (`mcp_stateful_multi_replica` in the broker logs) rather than refuse to
  start; the chart's `NOTES.txt` warns at install/upgrade time for the
  same combination.

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
- Each backend target's required capability is declared by
  `required_capability` in `services.yaml` (e.g., rucio requires `read_data`,
  panda requires `submit_jobs`) — services.yaml is the sole source of truth
  for that mapping; `policy.yaml` doesn't enumerate targets. It's optional:
  omit it and the credential layer becomes the gate instead (the broker
  refuses to start if that would leave the backend with no gate at all), or
  set it to `__none__` to explicitly open the backend to any authenticated
  user. See `docs/adding-a-service.md` for the full model.
- A principal's capabilities come from their Keycloak group memberships via
  `group_capabilities` in `policy.yaml` (shipped in the chart's policy
  ConfigMap). Every credential type resolves those groups from Keycloak's
  Admin REST API via the `PrincipalDirectory`/principal cache, not from a
  JWT claim — see
  [docs/auth.md#authorization-is-an-attribute-of-the-principal-not-the-token](auth.md#authorization-is-an-attribute-of-the-principal-not-the-token).
- Authorization failures are logged with structured fields (uid, tool, capability)
  and return HTTP 403 to the aggregator.

### 3. Credentialing

Fetches or mints the per-user credential required by the backend, given an
authorized principal.

Two axes define the provider matrix:

| | **Short-lived mint** | **Stored brokered token** |
|---|---|---|
| **IAM-based** | Keycloak token exchange (AF-internal only) | `GET /realms/<realm>/broker/<alias>/token` → ATLAS IAM token |
| **x509/VOMS** | Ephemeral k8s Job (NFS subPath mount of `~/.globus`) | N/A — always minted fresh |

The `CredentialCache` (in-process, async-safe) stores minted credentials keyed by
`(subject, target)` for their lifetime, avoiding redundant minting. See
`spikes/credential-isolation/` for the concurrency validation.

Important: Keycloak Standard Token Exchange (V2) is internal-to-AF only. It
**cannot** mint a token that `atlas-auth.cern.ch` will accept. Use the stored
brokered token path via `GET /realms/<realm>/broker/<alias>/token` for any
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

Every `redirect_uris` entry, and the `redirect_uri` the broker itself sends
in the authorize/token-exchange calls, is built from
`Settings.broker_public_origin` (chart `broker.publicOrigin`) — the
canonical `<scheme>://<host>` the portal SPA is served from, with no
trailing slash. Neither URL is derived from the incoming request: the same
broker deployment is reachable through more than one ingress host, and the
linking flow's nonce cookie is host-only, so a request-relative callback
would land on whichever host a given request happened to arrive through and
drop the cookie on the callback leg. `broker_public_origin` is required
(the broker refuses to start otherwise) whenever `identity_providers`
contains an `oauth21-direct` entry.

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
- `x509` — VOMS proxies from the user's grid certificate, handled by
  `X509Provider`; delivered by backend-side redemption rather than header
  injection (see `docs/auth.md`'s identity-provider-types table).

An entry's `alias` doubles as the portal-facing id on `GET /v1/identities` —
there is no separate id-to-alias mapping. `app.py`'s lifespan builds one
`CredentialProvider` instance per entry, keyed by alias, on
`app.state.identity_providers`, and registers each entry's `targets` with the
`CredentialRegistry` the same way regardless of provider type — `x509`
entries included: every backend wired with `auth_type: x509` must be
covered by an explicit `x509` entry, or the lifespan refuses to start
(there is no synthesized fallback — see `docs/auth.md`). The identities API
(`api/identities.py`) iterates this dict — in the same order the entries
were configured — to build `GET /v1/identities`'s `providers` list.

#### Linkage detection is per-provider

Before calling `issue()`, the API layer (`api/credentials.py`) gates on
`provider.is_linked(principal)` — an abstract method every `CredentialProvider`
implements against its own storage backend, since linkage state lives in
whichever system actually holds it and cannot be represented uniformly as a
JWT claim:

- `OIDCProvider` probes Keycloak's stored-brokered-token endpoint
  (`GET /realms/<realm>/broker/<alias>/token`) with the principal's own
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
counts actual failed unlock attempts — a bad passphrase or a minting-backend
failure, recorded via `record_failed_unlock()` — per uid and raises
`RateLimitError` once a threshold is exceeded within a fixed window, to
slow brute-force guessing. `X509Provider.mint()` calls
`cache.check_unlock_rate_limit()` before doing any minting work, so a
locked-out uid never reaches the k8s Job / subprocess path (`x509.py`).

Plain cache misses from `CredentialCache.get()` — "nothing cached yet, no
passphrase given" — do **not** count against this budget. That used to be a
single combined bucket (any cache miss counted the same as a bad passphrase
attempt), but it made the ordinary `NeedsUnlock` probe an MCP client makes
before ever prompting for a passphrase indistinguishable from an attack: a
handful of routine retries could burn through the whole budget and lock the
user out of their own next (correct) unlock attempt — including the very
`POST /v1/x509/proxy` call that would have succeeded, since it also goes
through `get()` first (issue #93).

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

On trip, `RateLimitError` propagates out of `X509Provider.mint()` (via
`check_unlock_rate_limit()`/`record_failed_unlock()`) — never out of
`CredentialCache.get()`, which only ever returns `None` on a miss. A global
handler in `app.py`
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

#### Vault storage layering

Two independent pieces of state persist to Vault/OpenBao KV-v2: the
oauth21-direct `TokenStore` above, and the manual bearer-token registry (see
"Programmatic client bootstrap" in `docs/auth.md`). Both compose the same
`VaultKV` (`vault_kv.py`) rather than each re-implementing Kubernetes auth
and the KV-v2 verbs:

```
VaultKV (auth, get/write_cas/list/delete_metadata)
  ├── VaultTokenStore        (credentials/vault.py)  -- oauth21 credentials
  └── VaultTokenRegistryBackend (token_registry.py)   -- token inventory
```

`VaultKV` is transport only — Kubernetes auth (with the re-authentication
caching/safety-margin/single-flight-lock behavior), the four KV-v2 verbs,
and error taxonomy (`VaultError`, `CasConflict`). It has no opinion on path
layout, record shape, or retry policy: each consumer above owns its own KV
path prefix, (de)serialization, and CAS retry loop. `app.py`'s lifespan
constructs one `VaultKV` per process (one Kubernetes auth login, shared by
whichever of the two consumers is configured to use Vault) and passes it to
each. A future Vault-backed store should compose the same `VaultKV` rather
than re-implementing this transport.

Neither consumer's Vault entries are pruned by the running broker process
itself. `VaultTokenStore` leans on Vault's own credential lifetime; the token
registry needs an external janitor instead, since a revoked or expired token
record otherwise persists forever — see "Programmatic client bootstrap" §4
in `docs/auth.md` for `token_sweep.py` and the `tokenSweep` CronJob.

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

`metrics.py` defines the broker's custom counters (beyond the generic HTTP
metrics `prometheus-fastapi-instrumentator` already provides) once, against
`prometheus_client`'s default registry, so the same `start_http_server()`
call above serves them without extra wiring:

| Metric | Labels | Incremented in |
|---|---|---|
| `af_mcp_tool_invocations_total` | `backend`, `tool`, `action_type` | `mcp/middleware/authorization_mw.py`, next to `write_audit()` |
| `af_mcp_tool_invocations_denied_total` | `backend`, `action_type` | same, denials only |
| `af_mcp_tool_invocations_unmapped_total` | *(none)* | same, when a tool name matches no registered backend prefix |
| `af_mcp_credential_cache_hits_total` / `..._misses_total` | `target` | `credentials/cache.py`'s `CredentialCache.get()` |
| `af_mcp_x509_proxy_mints_total` | *(none)* | `credentials/x509.py`'s `HomeDirVomsBackend._store_proxy_and_parse()` |

Cardinality policy: no metric above carries a user identifier (username,
unixname, subject, or otherwise) — ever. `identity` was on an early draft of
`af_mcp_tool_invocations_total` and `username` on the mint counter, but both
were dropped: the audit log above already records every invocation with the
caller's identity attached, at full fidelity and behind access control,
while these Prometheus series are long-retained and broadly readable via
Grafana. A per-user label here would duplicate the audit log at worse
fidelity while adding storage cost and a privacy surface, so per-identity
questions are answered from the audit log, not from these counters.
`backend`, `action_type`, and `target` are drawn from operator-configured
`services.yaml`/`policy.yaml`; `tool` is bounded by a service's own fixed
schema. A tool name that matches no backend is client-supplied and
unbounded, so it is never used as a label — see `metrics.py`'s module
docstring for the full reasoning, and avoid adding a raw token, jti, or
request ID as a label on any future metric for the same reason.

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

Tool execution itself flows through the MCP mount (`/mcp`); the aggregator's
middleware pipeline authorizes and mints credentials by calling the same
in-process functions the `/v1/authorize` and `/v1/credential` route bodies
call, rather than looping back over HTTP to them — see
`mcp/middleware/authorization_mw.py` and `mcp/aggregator.py`'s
`client_factory`. Prometheus metrics are served on the dedicated metrics
port (9090), not under `/v1`.

All requests require a valid AF bearer token. External callers can also hit
`/v1` directly (useful for scripting and debugging) — the `/v1` route bodies
remain the canonical authorization/credential logic either way.

### Reserved paths on the portal host

The portal host (the chart's `portalHost`, e.g. `mcp-portal.af.uchicago.edu`
for the UChicago AF deployment) is a static Astro build; its API
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

1. LLM sends `tools/call` MCP message over HTTPS to the broker's MCP host
   (the chart's `mcpHost`, e.g. `mcp.af.uchicago.edu` for the UChicago AF
   deployment), with its own Bearer — a raw `aud=mcp-gateway` Keycloak JWT,
   or (most MCP clients) a broker-issued PAT (see [docs/auth.md](auth.md)
   for how each client identity obtains one).
2. `IdentityMiddleware` validates the Bearer directly (no ForwardAuth proxy
   in this path), the same way `identity.get_principal()` does for `/v1`,
   and resolves the `Principal`.
3. `AuthorizationMiddleware` maps the tool name to a backend by prefix and
   checks `principal`'s capabilities against that backend's
   `required_capability`, in-process against the same function
   `POST /v1/authorize` calls. Deny → a clean MCP error, audited as
   `"denied"`, and the call never reaches credential resolution.
4. `mcp/aggregator.py`'s `client_factory` resolves the caller's credential
   for `auth_type: "bearer"` backends, in-process against the same provider
   code `POST /v1/credential` calls — cache hit or a fresh mint (token
   exchange or x509 mint Job) either way. `auth_type: "none"` backends skip
   this step; `auth_type: "x509"` backends get an AF Broker Identity Token
   (`aud` = the backend) minted locally by the broker's own signing key, and
   redeem the caller's VOMS proxy server-side via
   `POST /v1/credentials/x509/redeem` (issue #112).
5. The aggregator forwards the call to the target backend MCP server with
   the minted credential injected as `Authorization: Bearer <token>` — the
   caller's own inbound bearer is never forwarded.
6. The backend's response streams back through the aggregator to the LLM
   client.
7. `AuthorizationMiddleware` writes a structured audit log line
   (`outcome: "success"`/`"denied"`/`"error"`) and updates Prometheus
   counters exactly once per call, regardless of outcome.
