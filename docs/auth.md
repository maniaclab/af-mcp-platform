# Authentication & Credential Chain

## Full Auth Chain

Every caller of the broker — the portal SPA, Claude Desktop, `curl`, any
future MCP client — obtains its **own** OAuth token for the broker's
audience (`mcp-gateway`) and sends it as a Bearer directly. The broker
validates it itself (`HTTPBearer` + `keycloak_dependency` in `identity.py`);
there is no ForwardAuth proxy in this path. oauth2-proxy still exists in
front of the portal, but only to gate the portal's HTML/static assets — see
[Portal auth](#portal-auth-oidc-public-client) below and #42 for the full
design record.

```
ATLAS AF User
    │
    │  (1) Login via AF portal / device flow
    ▼
AF Keycloak  ──────────────────────────────────────────────────────────────
    │  issues AF access token (JWT, audience: mcp-gateway)
    ▼
AF Credential Broker  (Identity subsystem)
    │  validates JWT signature + expiry + audience (broker is the sole
    │  validator on this path — no ForwardAuth proxy in front of it)
    │  resolves uid/gid from the token's posix claim
    │  resolves capabilities from the token's groups claim via policy.yaml
    ▼
Credential subsystem
    │
    ├── Path A: ATLAS IAM token (for Rucio, PanDA, AMI)
    │       GET /realms/connect/broker/atlas-oidc/token
    │       (Keycloak's stored brokered token for the principal's linked
    │        atlas-auth.cern.ch identity — this is the ONLY way to obtain
    │        a token that atlas-auth.cern.ch will accept)
    │
    ├── Path B: AF-internal token exchange (for AF-local services only)
    │       POST /realms/<realm>/protocol/openid-connect/token
    │       grant_type=urn:ietf:params:oauth:grant-type:token-exchange
    │       subject_token=<af-token>
    │       requested_token_type=urn:ietf:params:oauth:token-type:access_token
    │       audience=<af-internal-service>
    │       *** THIS TOKEN IS NOT ACCEPTED BY atlas-auth.cern.ch ***
    │
    └── Path C: x509/VOMS proxy (for grid jobs, SRM, FTS)
            Ephemeral k8s Job mounts ~/.globus/{usercert,userkey}.pem
            via NFS subPath, runs voms-proxy-init, returns proxy
            (see spikes/nfs-subpath/ for validation)
    │
    ▼
Backend MCP server  (receives brokered credential in the Authorization header
                     or as a file-mount via a shared emptyDir)
```

---

## Portal auth (OIDC public client)

The portal (`mcp-portal.af.uchicago.edu`) is a static Astro/Vue SPA — there's
no server-side session to hold a token, so it becomes its own OAuth 2.0
**public client** (`mcp-portal`) and runs Authorization Code + PKCE against
the `connect` realm itself, the same way any other caller of the broker does
(see [Full Auth Chain](#full-auth-chain) above). This is Phase B of #42;
Phase A (mcpHost bypassing oauth2-proxy for Claude Desktop) landed in #43.

```
Browser (portal SPA)
    │
    │  (1) No valid session → redirect to Keycloak
    │      GET /realms/connect/protocol/openid-connect/auth
    │      ?client_id=mcp-portal&response_type=code
    │      &code_challenge=<S256>&scope=openid profile email mcp-gateway
    ▼
AF Keycloak (connect realm)
    │  (2) Already has an oauth2-proxy-established SSO cookie on
    │      .af.uchicago.edu? → silent redirect back with `code`, no
    │      interactive login. Otherwise: user signs in once.
    ▼
GET /callback?code=...&state=...     (portal/src/pages/callback.astro)
    │  (3) Exchange code + PKCE verifier for tokens
    │      POST /realms/connect/protocol/openid-connect/token
    ▼
sessionStorage                        (portal/src/lib/auth.ts)
    │  access_token: aud=["mcp-gateway", ...], refresh_token, id_token
    ▼
Every /v1/* and /mcp/* fetch          (portal/src/lib/api.ts)
    │  Authorization: Bearer <access_token>
    ▼
AF Credential Broker  — validates the Bearer exactly like it validates
                         Claude Desktop's or curl's; no special-casing.
```

Key points:

- **Client identity vs. resource/audience.** `mcp-portal` is the OAuth
  *client* that runs the code+PKCE flow; `mcp-gateway` is the *audience*
  the broker's `KEYCLOAK_AUDIENCE` expects in the token — configured via a
  Keycloak client scope with an Audience mapper, assigned as a default scope
  on `mcp-portal` (and on any future MCP-client identity, e.g. #24's
  `claude-desktop`). Different clients, same audience — that's what lets the
  broker's validator stay identical for every caller.
- **Token storage: `sessionStorage`, not `localStorage`.** Confines a token
  stolen via XSS to the tab's lifetime rather than indefinitely across tabs
  and browser restarts, at the cost of losing the session on tab close (a
  fresh — usually silent — SSO redirect recovers it immediately). The
  portal's XSS surface is bounded: it renders only build-time constants and
  Vue-escaped typed broker responses, under the CSP in
  `portal/nginx.conf.template`. See the top-of-file comment in
  `portal/src/lib/auth.ts` for the full tradeoff writeup, and #42 for the
  decision record.
- **Refresh tokens, not re-login.** Keycloak's Standard flow issues a
  refresh token alongside the access token; `oidc-client-ts`'s
  `signinSilent()` uses it via the refresh_token grant (a plain `fetch()` to
  the token endpoint — no hidden iframe, so the CSP only needs
  `connect-src`, not `frame-src`). `api.ts` calls it automatically on an
  expired token or an unexpected 401 before giving up and surfacing
  "session expired."
- **oauth2-proxy's role shrank to HTML-gating.** It still fronts the portal
  host so an anonymous browser can't fetch the static assets, but it is no
  longer in the request path for `/v1/*` or `/mcp/*` on either host — see
  `charts/af-mcp-platform/templates/ingress-portal.yaml` (HTML, oauth2-proxy)
  vs. `ingress-portal-api.yaml` (`/v1` + `/mcp`, no oauth2-proxy, same host).
  Because oauth2-proxy's SSO cookie and the portal's own Keycloak session
  share the same realm and browser, step (2) above is normally silent — a
  user who's already visited any `.af.uchicago.edu` page doesn't see a
  second interactive login.
- **Runtime, not build-time, OIDC config.** The issuer/client id/scope the
  portal uses come from `GET /config.json` (see `configmap-portal-config.yaml`
  → `portal.oidc.*` values), fetched once at startup — not baked into the
  image. One built portal image is deployable against any realm, client, or
  institution's fork via a values change and a rolling restart, mirroring
  how the broker itself takes `KEYCLOAK_ISSUER` from an env var rather than
  a build constant. Locally, an empty `oidc.issuer` (the checked-in
  `portal/public/config.json` placeholder) makes the portal skip OIDC
  entirely and run in unauthenticated / dev-bypass mode against a broker
  started with `BROKER_DEV_INSECURE_PRINCIPAL` (see
  `docs/local-development.md`).

---

## Critical Note: Keycloak Token Exchange Limitations

**Keycloak Standard Token Exchange (V2) is internal-to-AF only.**

When the broker calls Keycloak's token exchange endpoint on behalf of a principal,
the resulting token has:

- Issuer: `https://keycloak-prod.tempest.uchicago.edu/realms/connect`
- Audience: whatever `audience` was requested (an AF-internal service)

`atlas-auth.cern.ch` (the CERN IAM instance that issues tokens for Rucio, PanDA,
and AMI) **will reject** this token. It only trusts tokens issued by itself or
by federation partners it has explicitly configured.

**The correct path for ATLAS service credentials** is the stored brokered token
that Keycloak holds after the principal has linked their CERN account:

```
GET https://keycloak-prod.tempest.uchicago.edu/realms/connect/broker/atlas-oidc/token
Authorization: Bearer <af-token>
```

(`atlas-oidc` is the IdP alias in the connect realm; configurable via
`ATLAS_IAM_BROKER_ALIAS`.)

This returns the ATLAS IAM access token that Keycloak obtained during the
account-linking flow. That token:

- Is issued by `atlas-auth.cern.ch`
- Carries the principal's CERN identity and VO attributes
- Is accepted by Rucio, PanDA, and AMI

The broker always uses this path when the target backend requires an ATLAS IAM
credential. Operators must ensure that:

1. AF Keycloak is configured as an identity provider for `atlas-auth.cern.ch`
   (or vice versa — the federation direction matters).
2. Users have completed the account-linking step in the AF portal before their
   first tool call that requires an ATLAS credential.
3. The broker's service account has permission to call the broker token endpoint
   (Keycloak fine-grained authorization, `view-token` scope on the `atlas-oidc`
   identity provider).

---

## Token Lifetime and Refresh

| Credential type | Typical lifetime | Refresh strategy |
|---|---|---|
| AF access token (portal SPA) | 5 minutes | `oidc-client-ts` silent renew via refresh_token grant (see [Portal auth](#portal-auth-oidc-public-client)) |
| AF access token (other MCP clients) | 5 minutes | Client-specific — e.g. Claude Desktop's own OAuth flow (#24, not yet landed) |
| ATLAS IAM token (brokered) | 1 hour | Broker re-fetches from Keycloak on cache miss |
| x509 VOMS proxy | 12–96 hours (configurable) | Re-mint Job triggered when cache entry expires |

The `CredentialCache` stores each credential with its `expires_at` timestamp.
A background janitor coroutine sweeps the cache every 60 seconds and evicts
expired entries, triggering a fresh mint on the next request.

---

## Group-to-Capability Mapping Example

From the shipped `policy.yaml` (mounted from the chart's policy ConfigMap):

```yaml
group_capabilities:
  atlas: [read_data, read_metadata, read_monitoring, read_gitlab,
          submit_jobs, manage_jobs, launch_compute, manage_jupyter,
          manage_gitlab]
  escape: [read_data, read_metadata]
  # Any authenticated user (no group membership required)
  __authenticated__: [read_metadata, read_monitoring]

target_capabilities:
  rucio: read_data
  ami: read_metadata
  panda: submit_jobs
  docs: __none__     # open to any authenticated user
```

Keycloak group membership is resolved once per request from the validated
token's `groups` claim. There is no group-membership cache in the broker —
Keycloak is the authoritative source.

---

## Auth-edge decision

#26 found the shared oauth2-proxy (`provider = "keycloak-oidc"`, v7.6.0)
validates a Bearer's `aud` claim against its own `client_id`, not the
broker's audience — so mcpHost's ForwardAuth gate 302'd every Bearer
request, including Claude Desktop's, instead of letting it reach the
broker's own JWT validator:

```
$ curl -sS -o /dev/null -w "HTTP %{http_code}\nLocation: %{redirect_url}\n" https://mcp.af.uchicago.edu/mcp/
HTTP 302
Location: https://oauth2-proxy.af.uchicago.edu/oauth2/sign_in?rd=%2Fmcp%2F
```

Phase A (`ingress-mcp.yaml` / `ingress-portal.yaml` split, #43) removed the
oauth2-proxy annotations from mcpHost so the broker validates Bearers
itself there. Phase B (this doc's [Portal auth](#portal-auth-oidc-public-client)
section, #42) carries the same fix to portalHost: `/v1` and `/mcp` move to a
separate `ingress-portal-api.yaml` with no oauth2-proxy annotations, and the
portal SPA obtains its own `aud=mcp-gateway` Bearer instead of relying on a
cookie oauth2-proxy never actually forwarded as a header anyway. oauth2-proxy
remains in front of portalHost's `/` rule (`ingress-portal.yaml`) purely to
gate the HTML/static assets.
