# Authentication & Credential Chain

## Overview

Every caller — the portal, Claude Desktop, `curl`, any future MCP client — authenticates to
AF Keycloak on its own and hands the broker a credential: either a short-lived Keycloak-issued
JWT, or a broker-issued PAT obtained through one of the flows below. From there, one fact
explains almost everything else in this document: **the broker never trusts anything a token
claims about what its holder is allowed to do** — no `groups` claim, no `posix` claim, nothing.
It re-resolves the caller's groups, POSIX identity, and (from those) permissions live from
Keycloak's own directory on every request (see
[Authorization is an attribute of the principal, not the token](#authorization-is-an-attribute-of-the-principal-not-the-token)).
A JWT and a PAT differ only in *how* the broker learns "who is this caller" — both defer to the
same live lookup for "what are they allowed to do."

That design choice is also the source of most of the surprising-until-you-trace-it behavior
operators run into. A few common questions, and where to read the answer:

| If you're wondering... | Read |
|---|---|
| How does a browser or CLI get its first token at all? | [Portal auth (OIDC public client)](#portal-auth-oidc-public-client) |
| Does `mcp-gateway`'s audience decide who's allowed to do what, or just who's talking to the broker at all? | [`mcp-gateway`/`mcp-ops-gateway`: audience is population, not permission](#mcp-gatewaymcp-ops-gateway-audience-is-population-not-permission) |
| Why did `read-token`/`broker` appear or vanish from someone's token when their group membership changed? | [Client scope Scope tab: a filter, not a grant](#client-scope-scope-tab-a-filter-not-a-grant) |
| How does an MCP client (Claude Desktop, Claude Code) get a credential without a human visiting the portal? | [MCP OAuth discovery + PAT bootstrap](#mcp-oauth-discovery-pat-bootstrap-issue-140) |
| Why can't a leaked PAT just mint itself a replacement? | [Where PATs are accepted — and where they deliberately are not](#where-pats-are-accepted-and-where-they-deliberately-are-not) |
| Why doesn't removing someone from a Keycloak group take effect instantly everywhere? | [Authorization is an attribute of the principal, not the token](#authorization-is-an-attribute-of-the-principal-not-the-token) |
| Which Keycloak clients/roles/scopes do I need to create, and why so many? | [Keycloak operator setup reference](#keycloak-operator-setup-reference) |
| Why does Rucio/PanDA/AMI reject a token the broker minted? | [Critical Note: Keycloak Token Exchange Limitations](#critical-note-keycloak-token-exchange-limitations) |

The rest of this document reads narrative-first — what happens when someone uses the system —
followed by an operator-facing Keycloak configuration reference: what you actually click
through in the Keycloak admin console to make the narrative true.

---

## Full Auth Chain

Every caller of the broker — the portal SPA, Claude Desktop, `curl`, any
future MCP client — obtains its **own** OAuth token for the broker's
audience (`mcp-gateway`) and sends it as a Bearer directly. The broker
validates it itself (`HTTPBearer` + `keycloak_dependency` in `identity.py`);
there is no ForwardAuth proxy in this path, or in front of the portal's
HTML/static assets — the portal enforces its own client-side OIDC login —
see [Portal auth](#portal-auth-oidc-public-client) below.

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
    │  resolves current groups and POSIX uid/gid/unixname from the
    │  PrincipalDirectory (issue #144 steps 3/3b — NOT from groups/posix
    │  claims; any such claims are ignored), then permissions from those
    │  groups via policy.yaml
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
    └── Path C: x509/VOMS proxy (for AMI, grid jobs, SRM, FTS)
            Linked once at the portal (user passphrase). Two mint paths
            coexist behind the x509 identity_providers entry's
            `service_url` (see the x509 row below):

            • voms-token-service (service_url set): the broker asks
              voms-token-service — the only component that mounts user
              homes — to run voms-proxy-init with the passphrase, then
              persists BOTH the proxy and the Globus passphrase in
              Vault/OpenBao (the issue #112 custodianship decision). The
              stored passphrase enables HANDS-FREE RENEWAL: an expired
              stored proxy is re-minted on the user's behalf with no
              interaction. If that re-mint fails on a bad passphrase
              (the user changed their Globus password), the identity is
              unlinked and the portal prompts a re-link.

            • legacy ephemeral-Job NFS-subPath path (service_url unset):
              minted per unlock into the broker's tmpfs, nothing
              persisted — exactly the pre-voms-token-service behavior.

            An x509 backend (auth_type: x509) is called over /mcp with
            an AF Broker Identity Token (aud = the backend) and redeems
            the caller's proxy itself via
            POST /v1/credentials/x509/redeem — issue #112's
            "backend calls back" wire format. In voms-token-service mode
            redeem serves the Vault-stored proxy, renewing it hands-free
            in the same request when expired (failed renewals write
            outcome=error audit records). The redeem response is the
            ONE deliberate exception to "the PEM never leaves the broker":
            scoped to authenticated backend targets, released once per
            request over in-cluster TLS, audited as a distinct
            x509_proxy_release event, and never persisted backend-side
            (per-call temp file, deleted when the AMI call finishes).
    │
    ▼
Backend MCP server  (receives the brokered credential in the Authorization
                     header; x509 backends redeem their proxy server-side)
```

---

## Identity provider types

The broker links a user's account to an external identity three ways,
declared side by side in `Settings.identity_providers` (env
`IDENTITY_PROVIDERS`, chart `broker.identityProviders`). All authenticate
the principal via Keycloak first (the chain above) — they differ only in
*how the backend credential is obtained, stored, and delivered* once that's
done:

| | `keycloak-brokered` | `oauth21-direct` | `x509` |
|---|---|---|---|
| Handled by | `OIDCProvider` | `OAuth21Provider` | `X509Provider` |
| Backend credential source | Keycloak's stored-broker-token pattern — the user links via `kc_action=LINK_IDP`, Keycloak stores the resulting token internally | The broker itself is an OAuth 2.1 client to the backend's own authorization server (PKCE + CIMD `client_id`, see `docs/architecture.md#client-id-metadata-document-cimd`) | A VOMS proxy minted from the user's grid certificate — the user enters their Globus passphrase once at the portal; with a `service_url`, voms-token-service mints and Vault persists (hands-free renewal); without one, the legacy ephemeral-Job path mints into tmpfs |
| Broker retrieves it via | `GET /realms/<realm>/broker/<alias>/token` | `TokenStore.get(sub, alias)`, refreshing on demand near expiry | `VaultX509Store.get_proxy(sub)`, re-minting hands-free with the stored passphrase when expired (service mode) |
| Credential persistence | Keycloak (broker holds no copy) | The broker's own `TokenStore` (in-memory or Vault-backed — see PR3) | Vault KV-v2 (service mode) / broker tmpfs (legacy) |
| Delivery to the backend | `Authorization: Bearer` header injected by the aggregator | `Authorization: Bearer` header injected by the aggregator | **Backend-side redemption, not header injection**: the aggregator injects only an AF Broker Identity Token (`aud` = the backend), and the backend redeems the proxy PEM itself via `POST /v1/credentials/x509/redeem` — issue maniaclab/af-mcp-platform#112's "backend calls back" wire format, chosen so proxy material never transits the aggregator |
| Requires backend to be | An OIDC-compatible IdP Keycloak can broker to | An OAuth 2.1 authorization server (no OIDC discovery needed) | An MCP server that verifies broker JWTs and redeems proxies (ami-mcp's `--auth broker`, via `af-credentials`), marked `auth_type: x509` in `services.yaml` |
| Portal `link_url` | Always `null` — the portal re-runs its own client-side `startIdpLink()` flow | Full URL to the broker's own `/v1/oauth/authorize/{alias}` | Always `null` — `link_mechanism: "passphrase"`, an in-portal form POSTing the Globus passphrase to `/v1/x509/proxy` |

Use `keycloak-brokered` when the backend is (or can be registered as) an
OIDC identity provider Keycloak already understands — this is the path for
ATLAS IAM (`atlas-oidc`). Use `oauth21-direct` when the backend is an OAuth
2.1 authorization server in its own right and cannot be made to look like an
OIDC IdP to Keycloak — this is the path for rucio-mcp. See
[Rucio: Per-Site Setup](rucio-per-site-setup.md) for the concrete, deployed
`oauth21-direct` configuration rucio-mcp uses, one entry per Rucio site.
Use `x509` for backends whose real credential is a VOMS proxy (ami-mcp) —
see [x509 deployment notes](x509-deployment-notes.md) for the deployed
configuration.

A fourth `identity_providers` type, `broker-issued`, is deliberately **not**
in the table above: it links nothing, because there is no external identity
to link. It is the native half of the two-class doctrine below.

An `x509` entry carries one extra coupling the other types don't: each of
its targets must also be marked `auth_type: x509` in `services.yaml` — that
flag is what drives the aggregator's identity-JWT injection branch and the
redeem endpoint's audience gate. The broker refuses to start when the two
drift in either direction (an x509 backend no entry targets, or an entry
targeting a non-x509 backend) — **there is no synthesized fallback**: every
`auth_type: x509` backend must be covered by an explicit entry, even a bare
legacy one (`service_url` omitted). A service-mode entry (`service_url`
set) also requires the broker signing key — the same fail-closed reasoning
as the broker-issued/condor-token checks; a keyless legacy entry instead
gets a loud startup warning, since the shipped `services.yaml` has always
declared an x509 backend. Multiple x509 entries with different
voms-token-service URLs/VOs are supported.

The global `VOMS_TOKEN_SERVICE_URL` env var (and its
`VOMS_TOKEN_SERVICE_AUDIENCE`/`_VOMS`/`_VALID` companions) is removed —
declare an `identity_providers` entry of type `x509` instead (see
[x509 deployment notes](x509-deployment-notes.md)).

`GET /v1/identities` surfaces each entry like any other, with `linked`
probed from `X509Provider.is_linked()` and `proxy_expires_at` from the
cached proxy metadata. Every entry also carries `link_mechanism`, which
tells the portal how a linking flow starts: `"redirect"`
(keycloak-brokered, oauth21-direct), `"passphrase"` (x509 — there is no URL
to redirect to, so `link_url` stays null), or `"none"` (the AF-native types
below, which have no linking step).

---

## Portal auth (OIDC public client)

The portal (`mcp-portal.af.uchicago.edu`) is a static Astro/Vue SPA — there's
no server-side session to hold a token, so it becomes its own OAuth 2.0
**public client** (`mcp-portal`) and runs Authorization Code + PKCE against
the `connect` realm itself, the same way any other caller of the broker does
(see [Full Auth Chain](#full-auth-chain) above). This is Phase B; Phase A
(mcpHost's own direct Bearer validation for Claude Desktop) is in place.

```
Browser (portal SPA)
    │
    │  (1) No valid session → redirect to Keycloak
    │      GET /realms/connect/protocol/openid-connect/auth
    │      ?client_id=mcp-portal&response_type=code
    │      &code_challenge=<S256>&scope=openid profile email mcp-gateway
    ▼
AF Keycloak (connect realm)
    │  (2) Already has a Keycloak SSO session cookie from a previous login
    │      to any client in this realm? → silent redirect back with `code`,
    │      no interactive login. Otherwise: user signs in once.
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
  the broker's `OIDC_AUDIENCE` expects in the token — configured via a
  Keycloak client scope with an Audience mapper, assigned as a default scope
  on `mcp-portal` (and on any future MCP-client identity, e.g. a
  `claude-desktop` client). Different clients, same audience — that's what
  lets the broker's validator stay identical for every caller.
- **Token storage: `sessionStorage`, not `localStorage`.** Confines a token
  stolen via XSS to the tab's lifetime rather than indefinitely across tabs
  and browser restarts, at the cost of losing the session on tab close (a
  fresh — usually silent — SSO redirect recovers it immediately). The
  portal's XSS surface is bounded: it renders only build-time constants and
  Vue-escaped typed broker responses, under the CSP in
  `portal/nginx.conf.template`. See the top-of-file comment in
  `portal/src/lib/auth.ts` for the full tradeoff writeup.
- **Refresh tokens, not re-login.** Keycloak's Standard flow issues a
  refresh token alongside the access token; `oidc-client-ts`'s
  `signinSilent()` uses it via the refresh_token grant (a plain `fetch()` to
  the token endpoint — no hidden iframe, so the CSP only needs
  `connect-src`, not `frame-src`). `api.ts` calls it automatically on an
  expired token or an unexpected 401 before giving up and surfacing
  "session expired."
- **No ForwardAuth proxy gates the portal at all.** `ingress-portal.yaml`'s
  `/` catch-all serves every portal page — public landing, authenticated
  pages (`/overview`, `/catalog`, `/identities`, `/tokens`, `/callback`,
  ...), and static assets — alike. Auth for the authenticated pages is
  enforced entirely client-side: `Base.astro` calls `getUser()` on mount and,
  if there's no valid local session, calls `login()` immediately (keeping a
  splash screen up so the last thing visible is the splash, not a flash of
  portal chrome, before Keycloak's redirect takes over) — see
  `portal/src/layouts/Base.astro`. `/v1/*` and `/mcp/*` carry no gate of
  their own on either host either — see `ingress-portal-api.yaml`.
  An earlier design fronted the authenticated pages with a shared
  oauth2-proxy ForwardAuth gate; it was removed once this client-side guard
  covered the same case, since oauth2-proxy was otherwise out of the `/v1`
  and `/mcp` paths entirely and added a redundant login hop.
- **Runtime, not build-time, OIDC config.** The issuer/client id/scope the
  portal uses come from `GET /config.json` (see `configmap-portal-config.yaml`
  → top-level `oidc.issuer` plus `portal.oidc.clientId`/`scope`), fetched once
  at startup — not baked into the
  image. One built portal image is deployable against any realm, client, or
  institution's fork via a values change and a rolling restart, mirroring
  how the broker itself takes `OIDC_ISSUER` from an env var rather than
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

- Issuer: `https://auth.af.uchicago.edu/realms/connect`
- Audience: whatever `audience` was requested (an AF-internal service)

`atlas-auth.cern.ch` (the CERN IAM instance that issues tokens for Rucio, PanDA,
and AMI) **will reject** this token. It only trusts tokens issued by itself or
by federation partners it has explicitly configured.

**The correct path for ATLAS service credentials** is the stored brokered token
that Keycloak holds after the principal has linked their CERN account:

```
GET https://auth.af.uchicago.edu/realms/connect/broker/atlas-oidc/token
Authorization: Bearer <af-token>
```

(`atlas-oidc` is the IdP alias in the connect realm; configurable via the
`alias` field of this provider's `keycloak-brokered` entry in
`Settings.identity_providers` / `broker.identityProviders`.)

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

The broker itself does not infer linkage from anything in the caller's JWT —
Keycloak is the only source of truth for whether a user has completed
account-linking, and that state can't be represented as a token claim anyway
(it's per-IdP, and x509/GitLab-style linkage lives in entirely different
storage). Each `CredentialProvider` instead calls its own `is_linked()` check
against the storage backend it actually understands before `issue()` runs;
for `OIDCProvider` that means a live probe of the broker token endpoint above.
See [docs/architecture.md](architecture.md#linkage-detection-is-per-provider)
for the other providers.

---

## Authorization is an attribute of the principal, not the token

**Issue maniaclab/af-mcp-platform#144 steps 3 and 3b unified this for every credential type.** Before
this change, a JWT was self-contained -- it carried `groups`/`posix` claims
re-validated on every request -- while a PAT (carrying no authorization or
identity data of its own) always deferred to the principal cache. Two
sources of the same facts, which could in principle disagree: a user could
hold a valid JWT whose embedded claims disagreed with what the directory
currently said about them. As of step 3, `identity.py` never reads a
`groups` claim, even when a token happens to carry one -- **every**
credential type, JWT and identity PAT alike, resolves current groups from
the principal cache. As of step 3b, the same is true for `posix`
(uid/gid/unixname) -- see "Keycloak: POSIX User Attribute mappers" below.
The token answers only "who is this?"; the directory answers "what groups/
POSIX identity do they have?" POSIX identity remains optional on every
principal regardless of source (issue maniaclab/af-mcp-platform#148) -- only x509 credential minting
genuinely needs it, enforced at that point of use.

Three separate concerns, deliberately kept separate in the code:

- **PAT store** (`token_registry.py`) — "who is this token?" (PATs only;
  a JWT's own signature already answers this for JWT callers).
- **Principal cache** (`principal_cache.py`) — "what groups/POSIX identity
  does this user *currently* have?", keyed by **principal id** (the
  Keycloak `sub`), not by credential, so multiple PATs (and any number of
  JWTs) belonging to one user share cached state, and rotating/revoking a
  PAT never disturbs it. A group removal still propagates — within one refresh
  interval (default ~45s, `PRINCIPAL_CACHE_REFRESH_SECONDS`) rather than
  instantly, since neither credential type carries fresh claims of its own
  to re-derive this from anymore. Stale-while-revalidate: a refresh failure
  serves the last-known value for up to
  `PRINCIPAL_CACHE_MAX_STALENESS_SECONDS` (default 6 hours) before failing
  closed, logging loudly the whole time — a brief Keycloak outage should
  not instantly lock out every authenticated caller.
- **Permission engine** (`authorization/`) — unchanged; still gates on
  `group_permissions` from whatever groups the principal cache currently
  reports, regardless of which credential type asked.

**Availability regression for JWT callers (issue maniaclab/af-mcp-platform#144 steps 3/3b) -- read
this before relying on it in production.** A JWT used to be self-contained:
Keycloak being unreachable never blocked authentication, because the
token's own signature and claims were the whole answer. That is no longer
true. A JWT holder whose principal this cache has never resolved before --
a genuinely new user, or a cold-started replica that has never seen them --
hit during a Keycloak outage has no last-known value to fall back on and
**cannot authenticate at all**, receiving a 503 (`identity.
PrincipalDirectoryUnavailableError`) rather than a 401, specifically so the
error reads as a platform outage rather than a bad credential. maniaclab/af-mcp-platform#150's
persisted cache (below) covers the *restart* case for a principal already
seen by some replica before the outage; it does nothing for a principal no
replica has ever resolved. This is a deliberate tradeoff, not an oversight:
it is what makes group removal a real kill switch for every credential type
uniformly (the entire point of this unification), and it trades a rare,
bounded, loudly-logged unavailability window for eliminating the
JWT-claim/directory disagreement described above. Operators should
understand this before removing the Group Membership mapper or the four
POSIX User Attribute mappers (see below, both) as irreversible without a
plan: after removal, there is no fallback path left at all if the Keycloak
admin service account itself becomes unreachable for an extended period.

**Persisted across restarts (issue maniaclab/af-mcp-platform#144 step 2b).** The principal cache is
backed by a `PrincipalCacheBackend`, selected via
`PRINCIPAL_CACHE_BACKEND`/`broker.principalCache.backend` the same way
`TOKEN_REGISTRY_BACKEND` selects the PAT store's backend — `in_memory`
(single-replica, lost on restart) or `vault` (the same Vault/OpenBao
instance the PAT store and oauth21 token store use, under its own
`broker.principalCache.kvPathPrefix`). Each persisted record carries the
wall-clock time it was resolved; a cold start (process restart) loads it as
this replica's initial last-known value, subject to the exact same
`PRINCIPAL_CACHE_MAX_STALENESS_SECONDS` bound as an in-process refresh
failure — a record persisted three days ago is not served when the
staleness bound is six hours, same as any other stale value. A resolve is
written back to Vault when its attributes actually differ from what's
currently held (comparing content, not timestamps, so a changed value
writes immediately) *or* when the last write is older than
`PRINCIPAL_CACHE_HEARTBEAT_SECONDS` (default 3 hours, comfortably below the
6-hour staleness bound) — the second condition matters because group
memberships are typically stable for weeks, and writing on content-diff
alone would leave a stable principal's persisted record dated from its
last actual change, defeating the point of persisting at all once that
date is further in the past than the staleness bound. Together, a
population of principals whose groups rarely change still writes only once
per heartbeat, not once per ~45s refresh, while guaranteeing a healthy,
reachable system always has a persisted record well inside the staleness
bound; a Vault read/write failure degrades to the in-memory-only behavior
of the previous design rather than failing a request — see
`principal_cache.py`'s module docstring for the full read/write layering
and the write-amplification arithmetic. Before this persistence existed, a
cold broker restart during a Keycloak outage had no last-known value to
serve for any PAT-authenticated principal and failed closed for them until
the directory recovered — even though their actual authority hadn't
changed. This persistence covers the *restart* case for any principal some
replica had already resolved before the outage started, for both credential
types now that step 3 unified groups resolution -- but not a principal no
replica has ever resolved (see the availability regression callout above).

**Data at rest.** A persisted principal-cache record contains that user's
group memberships and POSIX uid/gid/unixname — the same underlying data
Keycloak already holds, but (when `PRINCIPAL_CACHE_BACKEND=vault`) now also
resident in Vault, alongside the PAT store's own records (see above).

---

## AF Broker Identity Token (issue #162)

### Two classes of backends: federated vs AF-native

Every backend the broker fronts falls into one of two classes, and the
credential story is different for each:

**External identity systems** (Rucio, ATLAS IAM — anything whose source of
truth is not AF) are *federation* problems. They require account linking
and a federated credential: OAuth 2.1 (`oauth21-direct`), a brokered OIDC
token (`keycloak-brokered`), or an x509/VOMS proxy. This is the provider
set documented above, unchanged.

**AF-native services** (condor-token-service, future jupyter-mcp,
condor-mcp, and every future internal backend) are the opposite: AF is the
source of truth. No federation occurs, no linking, no exchange — **the
broker is authoritative.** The key architectural fact: *there is no trust
boundary crossed by involving Keycloak in this path.* Round-tripping
through Keycloak per call to re-encode facts the broker already resolved
from the directory (subject, POSIX identity) is an availability and latency
cost with no trust gain. The broker is already the authorization decision
point; having AF-native services trust broker-issued identity assertions
**preserves** that trust boundary rather than expanding it.

In the provider hierarchy:

```
CredentialProvider (ABC — contract unchanged)
├── federated providers      # linking + external credential
│     OAuth21Provider, OIDCProvider (brokered), X509Provider
└── native providers         # broker-authoritative, no linking
      BrokerIssuedProvider   # credentials/broker_issued.py
```

Because there is no linking step, an AF-native backend shows `available`
on the catalog from day one — `is_linked()` is unconditionally true, no
portal action exists or is needed, and `GET /v1/identities` lists the
provider as always linked with no `link_url` and
`link_mechanism: "none"`.

### The token format — an internal protocol

Broker-issued JWTs are **identity assertions, nothing more** (SPIFFE-style:
documented once, every AF-native backend consumes the same format; future
backends — slurm-mcp, k8s-mcp, cvmfs-mcp — never invent a new
authentication story). RS256, signed by the broker's own key, TTL
`BROKER_TOKEN_TTL_SECONDS` (default 600 s — deliberately 2× the credential
cache's 300 s min-remaining floor, so cached tokens are actually servable;
a TTL at or below that floor makes every call a fresh mint).

| Claim      | Required | Value |
|------------|----------|-------|
| `iss`      | yes      | The broker issuer URL — `BROKER_TOKEN_ISSUER`, defaulting to `BROKER_PUBLIC_ORIGIN` |
| `sub`      | yes      | The principal's subject (Keycloak `sub`) |
| `aud`      | yes      | The service's `effective_audience` — its `ServiceSpec.audience` if set, else its `name` (issue #257) — consumers **MUST reject** tokens whose `aud` is not exactly themselves |
| `exp` / `iat` | yes   | Mint time and mint time + TTL |
| `jti`      | yes      | Unique per token (uuid4) |
| `uid` / `gid` / `unixname` | optional | POSIX identity from the directory-backed `Principal` (the same source x509 minting uses — never a token claim), included **only** for services that set `requires_posix` |

**Deliberately absent: permissions, groups, or any authorization claim.**
Authorization is an attribute of the principal, decided per-call by the
broker's entitlement check — it must never migrate into tokens (see
"Authorization is an attribute of the principal, not the token" above; the
same reasoning). If a backend is ever written to test `token.permissions`,
this design has failed. Backends use the token to answer "who is this and
did the broker send them," nothing else.

Consumers verify against the broker's JWKS at
`GET /.well-known/jwks.json` (public, unauthenticated, served next to the
other well-known documents and routed by the same ingress) with any
standard JWT library: select the key by the token header's `kid`, then
check signature, `iss`, `aud`, and `exp`. `kid` is the RFC 7638 JWK
thumbprint of the key, so it is stable across replicas and restarts with
no coordination. This also lets services like HTCondor trust the broker as
a token issuer directly via their native token auth (SCITOKENS issuer
config) — no Keycloak in the path.

**First consumer: condor-token-service**
([maniaclab/condor-token-service](https://github.com/maniaclab/condor-token-service)),
verifying `aud=condor-token-service` against this JWKS.

### Configuration

The token contract lives on the **service** entry (issue #257): the
`audience` it mints and whether it carries POSIX identity are properties of
the backend, so they sit next to `name`, not on the provider. The
`broker-issued` `identity_providers` entry only declares who mints (the
alias) and which services it serves (`targets`), plus the signing key:

```yaml
aggregator:
  services:
    - name: af-jupyterlab-mcp
      prefix: jlab
      url: "http://af-jupyterlab-mcp.mcp.svc.cluster.local:80/mcp"
      transport: http
      required_permission: manage_jupyter
      auth_type: bearer
      # audience omitted ⇒ aud = name (af-jupyterlab-mcp). Set it explicitly to
      # rename `name` without moving the aud the backend validates — renaming
      # `name` alone silently re-points the contract and 401s the backend.
      requires_posix: true      # launches the notebook AS the caller
broker:
  identityProviders:
    - type: broker-issued
      alias: af-native
      displayName: "AF-native services"
      targets: ["af-jupyterlab-mcp"]   # must match the service name
  identityToken:
    existingSigningKeySecret: af-mcp-identity-token-signing-key
```

`audience` (the exact `aud` the backend validates) and `requires_posix`
(stamp the caller's directory-resolved uid/gid/unixname, and 404 if the
caller has none) are read from the service's `ServiceSpec` at wiring time —
so every token property of a service is declared in one place. `audience`
defaults to `name`; **renaming `name` while a backend still expects the old
`aud` is exactly what 401'd every AF-native backend on 2026-08-26** — set an
explicit `audience` and the rename is safe.

The Secret must carry the RS256 private key PEM under the key name
`signing-key.pem`; the chart mounts it read-only and points
`BROKER_SIGNING_KEY_FILE` at it. **Fail-closed:** a `broker-issued` entry
with no signing key configured refuses to boot (a startup `RuntimeError`,
consistent with the `unreachable_permissions`/`ungated_backends` checks)
rather than failing at first request; a broker with neither configured
boots cleanly with the feature absent (`/.well-known/jwks.json` answers
503). A service with `requires_posix` whose caller has no POSIX identity
gets an actionable 404 naming the backend at issue time — the same
point-of-use requirement as x509's `PosixIdentityRequiredError`.

Generate a key for local development (never commit one, never auto-generate
in production paths — production keys arrive as SealedSecrets like every
other broker secret):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out /tmp/broker-signing-key.pem
export BROKER_SIGNING_KEY_FILE=/tmp/broker-signing-key.pem
```

### Key rotation

Rotation is publish-before-use with an overlap window, entirely through the
JWKS — consumers never hardcode a key:

1. **Publish the successor.** Generate the new keypair; add its *public*
   PEM (a `*.pem` key in the Secret named by
   `broker.identityToken.existingAdditionalPublicKeysSecret`, mounted at
   `BROKER_ADDITIONAL_PUBLIC_KEYS_DIR`). The JWKS now serves both keys;
   nothing signs with the new one yet.
2. **Switch signing.** Replace the signing-key Secret's `signing-key.pem`
   with the new private key, and move the *old* key's public PEM into the
   additional-public-keys Secret. Roll the Deployment. New tokens carry the
   new `kid`; tokens signed by the old key keep verifying because its
   public half is still published.
3. **Retire the old key.** After at least one full token TTL (default
   600 s — in practice wait longer, e.g. a day, to absorb clock skew and
   consumer JWKS caches), remove the old public PEM from the
   additional-public-keys Secret and roll again.

The overlap property (a token signed by the retiring key verifies against
a JWKS whose active key is the successor) is regression-tested in
`broker/tests/test_broker_issued.py`.

### CondorTokenProvider: HTCondor IDTOKENs (issue #169)

HTCondor IDTOKENS are signed with the pool password — a **symmetric** key
that can mint tokens for any identity in the pool, so it never leaves
Condor infrastructure and never enters the broker. `CondorTokenProvider`
(`credentials/condor.py`) is the second native provider and the identity
token's first end-to-end use: it mints an AF Broker Identity Token with
`aud=condor-token-service` and the principal's `uid`/`gid`/`unixname`
claims, exchanges it at condor-token-service's `POST /v1/token` (which
runs `condor_token_create -identity <unixname>@af.uchicago.edu` next to
the pool key), and caches the returned IDTOKEN in the `CredentialCache`
keyed `(subject, target)` with TTL = the service's `expires_at`. Delivery
to condor-mcp is the existing aggregator `bearer` branch — no aggregator
changes.

Configuration is one `identity_providers` entry of type `condor-token`
with a required `service_url` (the service's base URL — the provider
appends `/v1/token`) and an `audience` defaulting to
`condor-token-service`:

```yaml
broker:
  identityProviders:
    - type: condor-token
      alias: condor
      displayName: "HTCondor"
      targets: ["condor-mcp"]
      serviceUrl: http://condor-token-service.af-mcp.svc:8080
```

The same fail-closed rule applies as for `broker-issued`: a
`condor-token` entry with no signing key configured refuses to boot,
since the provider cannot mint the identity token it exchanges. POSIX
identity is required unconditionally (not per-target config — an IDTOKEN
*is* a unix-account credential): a principal without one gets an
actionable 404 naming the backend at issue time. Service failures surface
generically — a 429 passes through with its `Retry-After`; everything
else (the service rejecting the broker's token, minting failure,
unreachable) maps to a 502 whose detail never carries the service's
response body. IDTOKENS are not server-side revocable; `revoke()` drops
the cache entry and the short lifetime is the actual revocation bound. If
HTCondor is later configured to trust the broker's JWKS directly
(SCITOKENS issuer config), only this provider's implementation changes —
the `CredentialProvider` contract, condor-mcp, and the registry wiring
are untouched.

### KrbTokenProvider: CERN Kerberos tickets (issue #274)

Unlike `CondorTokenProvider` above, krb5-token-service holds no standing
secret the broker can redeem on its own: the CERN password is a live,
non-recoverable secret (krb5-token-service runs `kinit` against CERN's
realm with it) that must be supplied fresh on every mint call, not a
passphrase that merely unlocks an already-stored credential.
`KrbTokenProvider` (`credentials/krb5.py`) therefore raises `NeedsUnlock`
(pointing at `POST /v1/krb5/ticket`) whenever nothing usable can be
produced with no user interaction, mirroring `X509Provider`'s
passphrase-unlock doctrine rather than `CondorTokenProvider`'s
unconditional `is_linked() -> True`.

`issue()` works through a five-tier fallback before ever raising
`NeedsUnlock`. Tiers 1-4 all need **no user interaction**: once a keytab
is linked (see `POST /v1/krb5/keytab` below), renew and remint can keep
a linked user's tickets flowing indefinitely without ever prompting for
a password again:

1. **Cache** — an unexpired ticket already sits in the in-process
   `CredentialCache`.
2. **Vault repopulation** — a fresh-enough ticket sits in Vault even
   though the in-process cache was evicted or the pod restarted; served
   straight from there with no network call.
3. **Renew** — the Vault-stored ticket is past its `not_after` but still
   within its own `renew_until` window: `Krb5TokenServiceClient.renew()`
   (`POST /v1/renew`) extends it with **no credential at all**.
4. **Keytab remint** — a keytab was previously linked via
   `KrbTokenProvider.link_keytab()` (below):
   `Krb5TokenServiceClient.mint()` with `keytab_b64` mints a fresh ticket
   with **no live password**. A rejected keytab (e.g. the CERN password
   backing it was rotated) proactively unlinks the identity and falls
   through as if no link had ever existed.

Only when none of those four tiers can produce a ticket does `issue()`
raise `NeedsUnlock` — tiers 3 and 4 in particular mean a linked user with
a linked keytab never has to re-enter a password at all, the same
hands-free renewal story `X509Provider` already has for VOMS proxies.
Tier 5, the interactive fresh mint, still requires a live username and
password:

`POST /v1/krb5/ticket` (`KrbTicketRequest` → `KrbTicketMetadata`,
`api/credentials.py`) accepts `username`, `password` (a `SecretStr`,
never logged or echoed), an optional `target` (defaults to the entry's
first configured target), and optional `lifetime`/`renewable_lifetime`
strings forwarded verbatim to krb5-token-service. The response carries
`target`, `principal`, `realm`, `expires_at`, `remaining_seconds`, and
`renew_until` (null when the ticket isn't renewable) —
**`ccache_b64` is deliberately absent**: the ticket is cached
server-side in the `CredentialCache`, the same "credentials never
transit to the client" rule x509's proxy metadata follows for the PEM.

```jsonc
// POST /v1/krb5/ticket
{"username": "gstark", "password": "<cern password>"}

// 201
{
  "target": "krb5-token-service",
  "principal": "gstark@CERN.CH",
  "realm": "CERN.CH",
  "expires_at": "2026-09-04T18:00:00+00:00",
  "remaining_seconds": 36000,
  "renew_until": "2026-09-11T06:00:00+00:00"
}
```

**The broker cannot mint a keytab itself.** The obvious approach —
bootstrapping one from the same password a caller just typed, via
krb5-token-service's `cern-get-keytab`-backed `mint_keytab()` — is
unreachable from this facility's network: `cern-get-keytab`'s
`msktutil` backend needs CERN-internal LDAP/AD reachability (to
`cerndc.cern.ch`, on a port other than the KDC's 88) plus an HTTPS call
to `lxkerbwin.cern.ch`, and neither host is reachable from here
(confirmed by testing: the call hangs and times out after
`CERN_GET_KEYTAB_TIMEOUT_SECONDS`). An SSH-tunnel-through-lxplus
workaround was investigated and ruled out: lxplus enforces mandatory
multi-factor SSH (Kerberos plus a registered SSH key plus an
interactive 2FA prompt), and that interactive step cannot be satisfied
by an unattended service. Tier 4 above (remint from an already-linked
keytab) is **unaffected** by any of this: `kinit -kt` only needs the
CERN KDC on port 88, already open and already used by every other tier.

Instead, `POST /v1/krb5/keytab` (`KrbKeytabLinkRequest` →
`KrbTicketMetadata`, same response shape as `/krb5/ticket` above) lets
the user upload a keytab they generated **themselves** — e.g. on
lxplus, which has no such reachability problem since it runs directly
on CERN's network. `KrbTokenProvider.link_keytab()`
(`credentials/krb5.py`) validates the upload by minting a ticket with
it — the exact same `Krb5TokenServiceClient.mint(..., keytab_b64=...)`
call tier 4 already uses, so a bad keytab surfaces as the same
`Krb5TokenBadCredentialError` (400) tier 4's remint already handles —
and only on success stores it via `Krb5VaultStore.store_link()`, the
identical link-half schema and tier-4 remint logic the old "remember"
auto-bootstrap used to populate. Validation happens **before** the
store, never after: a caller can never end up with a bad keytab
persisted to Vault.

```jsonc
// POST /v1/krb5/keytab
{"username": "gstark", "keytab_b64": "<base64-encoded keytab bytes>"}

// 201 — same KrbTicketMetadata shape as /krb5/ticket
{
  "target": "krb5-token-service",
  "principal": "gstark@CERN.CH",
  "realm": "CERN.CH",
  "expires_at": "2026-09-04T18:00:00+00:00",
  "remaining_seconds": 36000,
  "renew_until": "2026-09-11T06:00:00+00:00"
}
```

Both routes map krb5-token-service failures onto the same HTTP statuses
(see the table below): 400 bad credential, 403 account error, 422
invalid request, 429 rate-limited, and 502 for anything else (including
the broker's own token being rejected by krb5-token-service — see the
401-folding note below).

`Krb5VaultStore` (`credentials/krb5_vault.py`) persists one KV-v2 record
per subject and mirrors `VaultX509Store`'s **link half / ticket half**
split:

- the **link half** — a keytab and its username, written only via
  `store_link()`, called from `link_keytab()` when the user uploads a
  keytab they generated themselves. This is the durable, custody-gated
  piece that makes tier 4 (keytab remint) possible.
- the **ticket half** — the last-minted ccache and its `not_after` /
  `renew_until` deadlines, written on *every* successful mint or renewal
  regardless of whether a keytab is linked. This is what makes tier 3
  (renew) possible for every linked user, not just ones who've linked a
  keytab.

Unlike x509's `store_link` (which wipes a stale proxy on re-link, since a
new passphrase may not be able to re-mint the old one), a krb5 ticket's
validity has nothing to do with which keytab is currently on file, so
`Krb5VaultStore.store_link()` never touches the ticket half.

`is_linked()` reports True on the first hit among: a live cached ticket
for one of the entry's targets, a stored keytab (link half), or a
still-renewable stored ticket — so a linked identity reads as linked
even between mints, unlike a bare cached-ticket check which can flip
`linked: true` → `false` purely because the cache entry expired.
`GET /v1/identities` marks the entry's `link_mechanism` as `"credential"`
— a two-field username+password form, distinct from x509's one-field
`"passphrase"` — so the portal renders the right form shape.

`DELETE /v1/identities/link/{alias}` now has a real `krb5-token` branch:
it calls `KrbTokenProvider.unlink()`, which deletes the entire Vault
record (keytab **and** any ticket half) via `Krb5VaultStore.delete()` —
the same "forget me" scope as `oauth21-direct`'s existing unlink, and
distinct from `revoke()` (drops only the cached/Vault ticket half,
leaving a stored keytab in place so the next `issue()` can still remint
via tier 4). This is a stronger operation than x509 has today: x509 has
no user-initiated unlink route at all, only the automatic self-unlink
`X509Provider.renew_from_stored_link()` performs when a stored
passphrase is rejected — see `api/identities.py`'s `unlink_identity` for
the comment marking that gap as a deliberate, tracked-separately scope
decision rather than an oversight.

`Krb5TokenServiceClient.mint()` (`credentials/krb5_service.py`) maps
krb5-token-service's `POST /v1/mint` responses onto exceptions the
endpoint turns into HTTP statuses, the same client-actionable-vs-infra
split `CondorTokenProvider` and `VomsTokenServiceClient` already use:

| krb5-token-service status | Exception | Endpoint status |
|---|---|---|
| 400 (wrong username/password) | `Krb5TokenBadCredentialError` | 400 |
| 403 (account revoked or password expired) | `Krb5TokenAccountError` | 403 |
| 422 (malformed username/lifetime) | `Krb5TokenInvalidRequestError` | 422 |
| 429 (rate-limited) | `Krb5TokenRateLimitedError`, `Retry-After` forwarded | 429 |
| anything else — unreachable, timeout, **401**, 5xx | `Krb5TokenMintError` | 502 |

401 is deliberately folded into the generic 502 rather than surfaced as a
client-facing 401: it means krb5-token-service rejected the *broker's
own* AF Broker Identity Token, a broker↔service contract failure the end
user cannot act on — it must never read as "your CERN password was
wrong." As with `VomsTokenServiceClient` and `CondorTokenProvider`, the
service's response body is never logged or relayed verbatim; every
mapped error carries a fixed, generic message instead.

Configuration is one `identity_providers` entry of type `krb5-token`
with a required `service_url` (the service's base URL — the provider
appends `/v1/mint`) and an `audience` defaulting to
`krb5-token-service`. **Unlike the mint-only version of this section,
Vault connection settings are now unconditionally required**: a
`krb5-token` entry has no legacy/service-mode split the way x509 does —
`service_url` is mandatory on every entry — and since a given entry
can't declare ahead of time whether any caller will ever link a keytab,
`Settings._validate_vault_config` (`config.py`) requires
`vault_addr`/`vault_auth_role` at boot for *any* `krb5-token` entry, not
only ones a caller actually links a keytab through. A `krb5-token` entry
with no Vault connection configured refuses to boot, the same fail-closed
doctrine as a `vault`-backed token store or principal cache with no
Vault settings:

```yaml
broker:
  identityProviders:
    - type: krb5-token
      alias: krb5
      displayName: "CERN Kerberos ticket"
      enables: "Kerberos-authenticated access"
      # No downstream aggregator.services consumer is defined yet (issue
      # #274) -- leave targets empty until one is chosen.
      targets: []
      serviceUrl: http://krb5-token-service.invalid

  # Vault connection settings -- shared by every Vault-backed store
  # (oauth21's token store, the token registry, the principal cache,
  # x509 service mode, and now any krb5-token entry above), even though
  # the field lives under oauth21.tokenStore for historical reasons.
  # Required as soon as ANY krb5-token entry exists, whether or not a
  # caller ever links a keytab.
  oauth21:
    tokenStore:
      vault:
        addr: https://vault.example.com
        authRole: af-mcp-broker
```

The same fail-closed rule applies as for `broker-issued`/`condor-token`:
a `krb5-token` entry with no signing key configured refuses to boot,
since the provider cannot mint the identity token it exchanges with
krb5-token-service.

**Redeeming the ticket: `POST /v1/credentials/krb5/redeem`.** Mirrors
`redeem_x509_proxy` exactly in shape (`api/credentials.py`): mounted on
the same `backend_router` as `POST /v1/credentials/x509/redeem` (not the
Keycloak-gated router), authenticated by an AF Broker Identity Token in
the `Authorization` header rather than a Keycloak JWT, and requiring its
`aud` to map to a configured krb5 target via `app.state.krb5_audiences`
— an `effective_audience -> target` reverse map, the same shape as
`x509_audiences` (issue #257's audience/target split applies here too,
since the token's `aud` is the service's `effective_audience`, which can
differ from the krb5 target name the ticket/provider are keyed under).
An `aud` that doesn't map to any krb5 target 403s and writes a
`krb5_ticket_release` audit record with `outcome="denied"` — the same
audit scope x509's redeem writes on its own audience-mismatch path.

**Read-only — this route never mints or renews.** Once the audience
resolves to a target, it calls `KrbTokenProvider.peek_ticket(subject,
target, min_remaining_seconds=0)`: whatever is already cached in-process
or Vault-stored, at **zero** freshness margin — not `issue()`'s
300-second "plenty of runway" default. A synchronous backend-to-backend
call has no way to prompt a user for a CERN password, so unlike x509's
redeem (which can hands-free-renew from a stored passphrase in
voms-token-service mode), there's nothing this route can do to freshen an
expiring ticket — it serves whatever is valid *right now*, at zero
margin, or 404s with a hint pointing at `POST /v1/krb5/ticket`. A
300-second buffer here would silently 404 tickets that are still
genuinely usable for tens of minutes; using `issue()`'s default was
exactly this route's own shipped bug, and 0 is the fix.

On success, it writes a second `krb5_ticket_release` audit record
(`outcome="success"`, `args_summary` naming the released principal and
target — never the ccache itself) and returns `KrbTicketRedeemResponse`:
`ccache_b64`, `principal`, `realm`, `expires_at`, `remaining_seconds`,
and `renew_until` (null when the ticket isn't renewable). This is the
krb5 analogue of `ProxyRedeemResponse` — the same deliberate, audited
exception to "credentials never transit to the client" that x509's PEM
redeem makes, scoped identically: authenticated backend targets only,
over in-cluster TLS, one release per request.

**The aggregator's `auth_type: "krb5"` dispatch.** `_make_client_factory`
(`mcp/aggregator.py`) carries a `krb5` branch identical in shape to the
existing `x509` one: on an authorized `tools/call`, it gates on
`_require_linked`, then mints an AF Broker Identity Token (`aud` = the
service's `effective_audience`) and injects it as `Authorization:
Bearer` — mint-and-inject only, exactly like x509. The backend is
expected to redeem its own ccache via `POST /v1/credentials/krb5/redeem`
above; no ccache material ever transits the aggregator. On a
`tools/list` (or a stale-cache refresh — no `authorized_call_target`
match), it falls back to the same best-effort identity-header mint the
x509 branch uses, gated by `_might_be_entitled`, so a listing never
hard-fails or eats a wasted mint attempt just because a krb5 service is
in the catalog. `resolve_list_time_credential` — the portal's
per-service tool-listing entry point into this same logic
(`api/catalog_tools.py`) — folds `"x509"` and `"krb5"` into one shared
`auth_type in ("x509", "krb5")` branch, since the two were byte-identical:
mint an identity token, return it as an `Authorization` header, and
— critically — never call `provider.issue()` for either, since minting
a real credential is exactly the operation a best-effort, unauthenticated
list-time code path must never trigger.

**No `services.yaml` entry uses `auth_type: krb5` yet.** `targets` ships
empty by default, and the aggregator/list-time dispatch branches above
exist and are exercised by tests, but no backend in the shipped
`services.yaml` declares `auth_type: krb5` — issue #274 remains
provider-type plumbing (the mint path, the `/v1/krb5/ticket` endpoint,
the `/v1/credentials/krb5/redeem` endpoint above, and the aggregator/
list-time dispatch) for a consumer that hasn't been chosen yet. That
remains a separate, not-yet-made decision.

---

## Programmatic client bootstrap

The chain above ("Full Auth Chain") describes the interactive path: the
portal's own OIDC login (`portal/src/lib/auth.ts`) handles browser-based
login transparently, and a signed-in user never fetches, pastes, or
configures a raw bearer token by hand. That story is unchanged and remains
the default for anyone opening `mcp.af.uchicago.edu` in a browser-capable
client.

It does not cover MCP clients that speak MCP-over-HTTP but can't yet perform
OAuth discovery — Claude Desktop today. Those clients have no browser session
to inherit and no way to run the OIDC dance themselves, so they need a static
credential to put directly in their config's `Authorization` header. The
portal's `mcp-portal.af.uchicago.edu/tokens` page exists for exactly this,
and (issue maniaclab/af-mcp-platform#144 step 2a) it now mints a **broker-issued identity PAT**
(Personal Access Token) rather than exchanging the caller's Keycloak JWT for
another JWT:

1. **Mint** — `POST /v1/tokens` generates a 256-bit random secret and a
   non-secret `lookup_id`, formatted `mcp_pat_<lookup_id>_<secret>`
   (`pat.mint_pat`). No Keycloak round trip is involved in minting — the
   broker is the sole issuer. Only the SHA-256 hash of the secret is ever
   persisted (`pat.hash_secret`; see that module for why plain SHA-256 is
   correct for a 256-bit random secret, unlike a slow KDF meant for
   low-entropy human passwords); the **plain token value is shown exactly
   once**, in this response — the portal never displays it again, and the
   broker never persists it. The registry (below) stores only metadata
   (`lookup_id`, `secret_hash`, the owning principal id, an optional
   user-supplied name or a server-generated `mcp-YYYYMMDD-<lookup_id
   prefix>` default, an optional free-text note, created/expiry/last-used
   times, revocation state) — never anything the token could be
   reconstructed from, and never any groups/permissions (see below).
   `name` is a unique-per-principal identifier, not free text: minting a
   second token whose name matches an existing *live* one for the same
   principal (case-insensitive) is rejected with 409. Live means neither
   revoked nor expired (or never-expiring) — a name freed up by revocation
   or natural expiry can be reused, since the dead token can no longer be
   mistaken for the new one. `note`, unlike `name`, is purely
   self-descriptive free text (up to 256 chars) that the broker never
   inspects or acts on. Expiry defaults to 90 days
   (`Settings.pat_default_expiry_days`, `PAT_DEFAULT_EXPIRY_DAYS`);
   never-expiring is an explicit opt-in (`never_expires: true` in the mint
   request), logged loudly (`pat_minted_without_expiry`) and never the
   default.
2. **List** — `GET /v1/tokens` shows metadata for PATs minted through this
   endpoint, including ones already revoked (shown with a revoked status
   rather than removed, so the portal can distinguish active/revoked/
   expired). Also covers PATs minted via the MCP OAuth discovery bootstrap
   flow below (issue maniaclab/af-mcp-platform#140) — both mint through the same registry, so a PAT
   obtained either way shows up here identically, named after the MCP
   client's own CIMD `client_name` when the bootstrap flow minted it.
3. **Revoke** — `DELETE /v1/tokens/{lookup_id}` marks the PAT revoked in the
   registry. Unlike the mint-rate-limit window (still per-replica, in-memory
   — see the module docstring in `api/tokens.py` for why that's an
   acceptable tradeoff for a soft anti-abuse counter), the registry itself
   is durable and HA-safe: it's backed by the same Vault/OpenBao KV-v2
   pattern `credentials/vault.py`'s `VaultTokenStore` uses (one entry per
   principal, CAS writes, a flat revoked-lookup-ids index), selected via
   `TOKEN_REGISTRY_BACKEND=vault` the same way `TOKEN_STORE_BACKEND` selects
   the oauth21 token store — so a PAT minted on one broker replica can be
   listed and revoked from another, and survives a pod restart. Revocation
   is **enforced**, not cosmetic, on `/mcp` (see "Where PATs are accepted"
   below); a revoked PAT is rejected with 401 once
   `REVOKED_JTI_CACHE_REFRESH_SECONDS` (default 30s) has elapsed.
4. **Sweep** (operations) — unaffected by this change; see
   `token_sweep.py`/`tokenSweep.*` as before. A never-expiring PAT
   (`expires_at` unset) is never touched by the sweep — there is no natural
   expiry to sweep against; it only ever leaves the registry via an explicit
   revoke.

### MCP OAuth discovery + PAT bootstrap (issue #140)

The portal's mint page above still requires a signed-in human to visit it and
copy-paste a token. Issue maniaclab/af-mcp-platform#140 adds a second way to obtain a PAT that a
spec-compliant MCP client drives entirely itself, with no manual step: point
the client at `mcp.af.uchicago.edu/mcp` with no credential at all, and it
discovers and completes the login on its own.

The broker becomes an **OAuth-facing authorization endpoint for MCP clients
that delegates user authentication to Keycloak and issues broker-native PATs
after successful authentication.** It is emphatically *not* becoming an
identity provider — no passwords, no MFA, no account lifecycle, no login UI
of its own; those stay with Keycloak permanently. The returned PAT is not an
OAuth access token in the security architecture — it is merely *transported*
in the `access_token` field because that is the shape OAuth clients
understand (RFC 6749 deliberately does not specify access-token format, which
is why introspection, RFC 7662, exists at all).

1. **Discovery.** An unauthenticated `/mcp` request now returns a genuine
   HTTP 401 (issue maniaclab/af-mcp-platform#138/maniaclab/af-mcp-platform#144 step 1) carrying
   `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp"`.
   That URL, and its un-suffixed root form (both served identically —
   `api/wellknown.py`), are RFC 9728 protected-resource metadata naming
   **the broker itself** — not the Keycloak realm — as the authorization
   server: `{"resource": "https://mcp.af.uchicago.edu/mcp",
   "authorization_servers": ["https://mcp.af.uchicago.edu"]}`. The broker in
   turn serves its own RFC 8414 metadata at
   `/.well-known/oauth-authorization-server`, describing
   `/v1/oauth/authorize`/`/v1/oauth/token` and advertising
   `client_id_metadata_document_supported: true`.
2. **Client registration is CIMD** (Client ID Metadata Documents,
   `draft-ietf-oauth-client-id-metadata-document`), mirroring rucio-mcp's
   in-house reference implementation (`rucio_mcp/server.py`/`auth/cimd.py`):
   an MCP client's `client_id` is an `https://` URL the broker dereferences
   at authorize time (`cimd_client.py` — SSRF-guarded fetch, self-reference
   check, port-agnostic loopback `redirect_uri` matching for native/CLI
   clients that bind an ephemeral port at runtime). No `/register` endpoint,
   no per-client database. This sidesteps AF Keycloak not advertising CIMD
   itself (it advertises DCR instead) — irrelevant here, since MCP clients
   register with the broker, not Keycloak.
3. **`GET /v1/oauth/authorize`** validates the client's CIMD document and
   `redirect_uri`, then redirects the browser to Keycloak's own login using
   the broker's *own* confidential client (see "Operator setup: the MCP
   OAuth discovery bootstrap login client" below), requesting
   `scope=openid mcp-gateway` — PKCE plus a Fernet-
   encrypted `state` token (`oauth_state.py`'s `McpAuthorizePayload`,
   sibling to the account-linking flow's `StatePayload`) carrying the MCP
   client's own pending `redirect_uri`/`state`/PKCE challenge across the
   round trip, since nothing else survives it.
4. **`GET /v1/oauth/keycloak-login/callback`** receives Keycloak's redirect
   back (nonce-cookie CSRF check, same shape as the account-linking flow's
   callback), exchanges the code at Keycloak's token endpoint, verifies the
   resulting `id_token`, and — issue maniaclab/af-mcp-platform#245 — verifies the exchange's
   **access token** against the broker's `mcp-gateway` audience with the
   same decode `/v1` applies to every bearer
   (`identity.decode_broker_bearer`). The id_token proves *who* logged in;
   the access token proves the login went through a client actually
   entitled to request `mcp-gateway` (see "`mcp-gateway`/`mcp-ops-gateway`:
   audience is population, not permission" below) — a login that somehow
   lacks the audience gets an `access_denied` redirect — no authorization
   code, no PAT — symmetric with the `TokenAudienceError` a JWT caller
   would get on `/mcp`. Only then does the broker mint a
   short-lived, single-use, in-process
   authorization code (`mcp_auth_codes.py` — a few seconds' lifetime, not
   Vault-backed; a broker restart mid-flow just means the MCP client retries
   from `/authorize`) before redirecting the browser back to the MCP
   client's own `redirect_uri` with that code and its original `state`.
5. **`POST /v1/oauth/token`** redeems the code: validates it hasn't been
   used already, that `client_id`/`redirect_uri` match, and that the
   presented `code_verifier` hashes to the stored PKCE challenge — only then
   mints a **new** PAT (never reuses one) via the same registry the portal's
   `POST /v1/tokens` uses, named after the MCP client's CIMD `client_name`
   when available (falling back to the usual dated default), and returns it
   as `{"access_token": "mcp_pat_…", "token_type": "Bearer", "expires_in": …}`.

`/v1` stays Keycloak-JWT-only throughout this flow, exactly as for the
portal's own mint path — see "Where PATs are accepted" immediately below.

### Where PATs are accepted — and where they deliberately are not

**`/mcp` accepts both identity PATs and Keycloak JWTs.**
`mcp/middleware/identity_mw.py`'s `AsgiAuthMiddleware` recognizes a bearer
starting with `mcp_pat_` and routes it to `pat_auth.resolve_pat_principal`;
anything else follows the existing JWT path (`identity.get_principal`)
unchanged. This is deliberately a *recognition* dispatch, not a cutover —
both credential types work side by side until a future issue maniaclab/af-mcp-platform#144 step 5
flips `/mcp` to PAT-only, now that the OAuth discovery bootstrap flow above
gives every client a way to obtain a PAT without visiting the portal first.
That cutover is deliberately not part of this change — see issue maniaclab/af-mcp-platform#144's
"PAT-only must be the last step, not an early one" resolution.

**`/v1` remains Keycloak-JWT-only, including `POST /v1/tokens` itself.**
`keycloak_dependency` is untouched by this design: a PAT is not a valid JWT,
so it is rejected by ordinary JWT decoding, the same way any other
non-JWT bearer always has been. This is a deliberate security property, not
an oversight: if a PAT could authenticate on `/v1`, a PAT could mint further
PATs — a single leaked credential would become self-renewing, and revocation
would degrade into whack-a-mole against tokens the leaked one itself
created (GitHub disallows this by default for the same reason). A PAT is
therefore always traceable back to an interactive Keycloak login, whether
initiated from the portal or from the MCP OAuth discovery bootstrap flow
above — both authenticate via Keycloak first, and (issue maniaclab/af-mcp-platform#245) both mints
sit behind the same `mcp-gateway` audience gate: the portal mint because
`POST /v1/tokens` requires an audienced Keycloak JWT like the rest of
`/v1`, the bootstrap mint because its callback verifies the login
exchange's access token against that same audience before an
authorization code is ever issued. The portal SPA itself is
never issued a PAT — it keeps using its short-lived Keycloak JWT, since
handing a long-lived credential to browser storage would be strictly worse
than a JWT that expires in minutes.

### Permission PATs (issue #144 step 4)

Every PAT described above is an **identity PAT**: it says "I am this user",
and its authority is always the caller's current permissions, derived
fresh from the principal cache's groups on every request — exactly as if
the caller had presented a Keycloak JWT. A **permission PAT** additionally
carries an explicit grant: a fixed set of permission names, chosen at mint
time, for least-privilege automation credentials (a CI job that only ever
needs `read_data` has no business holding a token that can also mint x509
proxies or submit jobs, even though its owner can).

**The grant is a RESTRICTION, never a source of authority.** This is the
one binding refinement worth over-stating, because the naive design (the
grant supplies authority *instead of* deferring to the principal cache) is
wrong and must not be reintroduced:

> effective permissions = the principal's *current* permissions ∩ the
> grant

Concretely, `authorization.get_principal_permissions` computes the same
group-derived permission set it always has — unchanged for a JWT or an
identity PAT — and, only when `Principal.permission_grant` is not `None`,
intersects that set with the grant before returning it. Two consequences
fall out of intersecting rather than substituting:

1. **The kill switch survives.** If a grant conferred authority
   independently of the principal cache, minting a permission PAT with
   `read_data` and later being removed from the ATLAS group would leave
   that PAT fully functional — reintroducing exactly the staleness problem
   snapshotting groups into a PAT was rejected for (see "Open design gap"
   in issue maniaclab/af-mcp-platform#144). Intersecting means removing a Keycloak group still kills
   every credential the user holds, of any type, within one principal-cache
   refresh interval — a permission PAT included.
2. **Escalation is structurally impossible, not merely validated against.**
   A user cannot mint (or otherwise come to hold) a permission PAT granting
   more than they currently hold, because the intersection can never exceed
   the group-derived set above, regardless of what the grant itself
   contains. `POST /v1/tokens`' `permissions` field is still validated as a
   subset of the caller's permissions at mint time (`MintTokenRequest
   .permissions`, `api/tokens.py`) — but purely for a clear, immediate
   error naming the offending permissions. That check is advisory only and
   is never the only thing standing between a caller and extra access:
   enforcement is the intersection above, on every request, and does not
   consult whether mint-time validation ever ran.

Semantics, stated plainly: *this token may use at most these permissions,
and only while its owner still currently holds them.* A permission PAT is
an identity PAT plus a narrowing filter — it still requires the same
principal-cache lookup an identity PAT does (see "Authorization is an
attribute of the principal, not the token" above); a permission PAT is not
a way to avoid that dependency, because the kill switch it preserves is
exactly what that lookup provides.

**Minting one.** `POST /v1/tokens` accepts an optional `permissions` field
— a list of permission names. Omitted (`None`, the default) mints an
ordinary identity PAT, unchanged from every PAT minted before this field
existed. A non-`None` value (including `[]`, a token scoped to nothing)
mints a permission PAT; the response's and every subsequent `GET
/v1/tokens` row's `permission_grant` field is `null` for an identity PAT or
the sorted list of granted permission names otherwise. The portal's mint
dialog (`TokensPage.vue`) offers this as an opt-in "Restrict permissions"
checkbox that, when checked, lists the caller's *current* permissions
(`GET /v1/permissions`) as choices — never a static or cached list, since
a stale choice list would misrepresent what the resulting grant could
possibly enforce. The token list shows each row's scope via
`tokenDisplay.ts`'s `permissionGrantLabel()`: "Full account access" for an
identity PAT, or the comma-joined permission names for a permission PAT.

**When to prefer one.** An identity PAT remains the right default for a
human's own interactive tooling (Claude Desktop, a personal script) — its
authority tracks whatever the human is currently entitled to, with no
extra bookkeeping. A permission PAT is the better choice for **CI and
long-lived automation** specifically because it is least-privilege: a
credential checked into a pipeline or left running unattended should hold
only the permission it actually exercises, so that a leak exposes the
narrowest possible blast radius — and because the grant can never exceed
what its owner (the human or service account that minted it) currently
holds, rotating that owner's group membership continues to bound every
permission PAT they've ever minted, not just their own interactive access.

**Audit.** A denied tool call's audit record (`AuditRecord
.principal_permission_grant`, written by `mcp/middleware/authorization_mw
.py`) carries the calling PAT's effective permission grant when it has
one — `null` for a JWT or an identity PAT. This is what lets an admin
reading a denial tell "the principal doesn't hold this permission at all"
(grant is `null`, or the permission is missing from a non-`null` grant that
still wouldn't have covered it) apart from "the principal holds it, but
this particular PAT is scoped away from it" (the grant is a non-`null` list
that omits the denied permission) — two very different remediation stories
that a bare denial reason can't distinguish on its own.

### Migrating existing PATs (capability → permission rename)

PAT records stored before the capability → permission rename keep their
grant under the old `capability_grant` key. The broker's decoder fails
**closed** on such a record: an unmigrated *scoped* PAT is treated as
granting nothing (deny-all, with a `token_registry.unmigrated_grant_denied`
warning naming the `lookup_id`) rather than decoding as unrestricted, and
an unmigrated *unscoped* identity PAT (`capability_grant: null`) keeps
working unchanged. So the safe rollout ordering is **deploy the renamed
broker first, then migrate** — in the window between the two, scoped PATs
are denied, never widened.

Run the one-time migration inside a broker pod (which already carries the
Vault/OpenBao environment). The image deliberately does not ship
`scripts/`, and `kubectl exec` bypasses the entrypoint so `python` is not
on `PATH` — pipe the script from a repo checkout over stdin into the pixi
environment's interpreter (arguments go after python's `-`):

```bash
# Dry run (the default): reports every record it would rewrite, writes nothing.
kubectl exec -i -n mcp deploy/af-mcp-platform-broker -- \
    /app/.pixi/envs/broker/bin/python - < scripts/migrate-pat-capability-grant.py

# Execute. Idempotent: already-migrated records are counted and skipped.
kubectl exec -i -n mcp deploy/af-mcp-platform-broker -- \
    /app/.pixi/envs/broker/bin/python - --apply < scripts/migrate-pat-capability-grant.py
```

The final summary counts migrated / already-migrated / unscoped-null /
skipped-unknown records; a record carrying BOTH keys or an unrecognizable
grant shape is reported and left untouched (nonzero exit) for a human to
inspect.

---

## Token Lifetime and Refresh

| Credential type | Typical lifetime | Refresh strategy |
|---|---|---|
| AF access token (portal SPA) | 5 minutes | `oidc-client-ts` silent renew via refresh_token grant (see [Portal auth](#portal-auth-oidc-public-client)) |
| Broker-issued PAT (most MCP clients) | 90 days by default, or never-expiring by explicit opt-in | Not refreshed — revoke and re-mint (manually, or via [MCP OAuth discovery](#mcp-oauth-discovery-pat-bootstrap-issue-140) again) |
| ATLAS IAM token (brokered) | 1 hour | Broker re-fetches from Keycloak on cache miss |
| x509 VOMS proxy | 12–192 hours (configurable) | voms-token-service mode: hands-free re-mint with the Vault-stored passphrase when the stored proxy expires. Legacy mode: re-mint Job on the next portal unlock |

The `CredentialCache` stores each credential with its `expires_at` timestamp.
A background janitor coroutine sweeps the cache every 60 seconds and evicts
expired entries, triggering a fresh mint on the next request.

---

## Keycloak operator setup reference

Everything below is Keycloak-side configuration the broker depends on but never manages
itself — clients, roles, client-scope role restrictions, and group-to-role assignments. Read
this section together when standing up a new realm or debugging why a token doesn't carry
what you expected; the sections above it describe what the broker does at runtime once this
configuration already exists.

### Operator setup: the Keycloak admin service account

Resolving any principal's current groups/uid/gid/unixname means *asking
Keycloak*, which requires a service account with standing read access to
every user's profile and group membership — a real, deliberate privilege
increase over the broker's original design, which only ever read claims
from a token the user themselves presented. Mitigated by scoping the
account to the narrowest roles that satisfy the two Admin REST API calls
`principal_directory.KeycloakPrincipalDirectory` makes
(`GET /admin/realms/{realm}/users/{id}` and
`GET /admin/realms/{realm}/users/{id}/groups`):

1. **Clients → Create client**, in the same realm as `oidc.issuer`.
2. **Client authentication: On** — a confidential client authenticating via
   `client_credentials`, not a public/redirect-based one.
3. **Service accounts roles: On**, then assign the client's service account
   these realm-management client roles ONLY: **`view-users`** and
   **`query-groups`**. Do not grant broader `realm-admin` or `manage-users`
   — this account only ever needs to read, never write, user/group data.
4. Note the client's **Client ID** and, from the **Credentials** tab, its
   **Client secret**. These become `KEYCLOAK_ADMIN_CLIENT_ID` /
   `KEYCLOAK_ADMIN_CLIENT_SECRET` (`Settings.keycloak_admin_client_id`/
   `keycloak_admin_client_secret`) — like `TOKEN_MINT_CLIENT_ID`/`SECRET`
   before it, this is a confidential-client credential the broker
   authenticates *as*, not a per-user credential.

**This account is now required for all authentication, not only PATs
(issue maniaclab/af-mcp-platform#144 step 3).** Before step 3, both empty (the chart default) was a
valid, degraded state: the broker logged `keycloak_admin_not_configured`
and only PAT authority resolution was unavailable -- a JWT's own claims were
enough on their own. That fallback no longer exists. As of step 3, the
broker's startup (`app.py`'s lifespan) **refuses to start** when
`KEYCLOAK_ADMIN_CLIENT_ID`/`KEYCLOAK_ADMIN_CLIENT_SECRET` are both empty
*and* the local-dev bypass (`BROKER_DEV_INSECURE_PRINCIPAL`, which
short-circuits the directory entirely -- see "Local-development auth
bypass" in `docs/local-development.md`) is not active. Refusing to start,
rather than degrading silently as before, follows the same reasoning as the
`unreachable_permissions`/`ungated_backends` startup checks elsewhere in
`app.py`'s lifespan: this is Kubernetes, so a Deployment rollout with a
failing new pod leaves the previous ReplicaSet serving traffic unaffected --
a loud startup failure surfaces the misconfiguration as a visible rollout
failure with zero outage risk, which is strictly better than a broker that
accepts every request and can authenticate none of them. See the
availability regression this account being unreachable *after* a successful
startup introduces for JWT callers specifically, under "Authorization is an
attribute of the principal, not the token" above.

The Helm chart wires both env vars from `broker.keycloakAdmin.clientId` (a
plain value — the client id is not a secret) and
`broker.keycloakAdmin.existingClientSecretSecret` (the name of a
pre-existing Secret with a `keycloak-admin-client-secret` key), the same
existing-Secret-by-reference pattern `broker.oauth21.existingStateKeySecret`
and `broker.tokenMint.existingClientSecretSecret` use:

```bash
kubectl create secret generic keycloak-admin-client-secret \
  --dry-run=client \
  --from-literal=keycloak-admin-client-secret='<client secret from the Credentials tab>' \
  -o yaml \
  | kubeseal --controller-namespace=sealed-secrets --format=yaml \
  > keycloak-admin-client-secret.sealed.yaml
```

Commit `keycloak-admin-client-secret.sealed.yaml` to the cluster's GitOps
repo alongside the other broker SealedSecrets, then reference it from the
deploying `HelmRelease`:

```yaml
spec:
  values:
    broker:
      keycloakAdmin:
        clientId: "mcp-keycloak-admin"
        existingClientSecretSecret: "keycloak-admin-client-secret"
```

### Operator setup: the MCP OAuth discovery bootstrap login client

`broker.tokenMint.*`/`TOKEN_MINT_CLIENT_ID`/`TOKEN_MINT_CLIENT_SECRET`
(`Settings.keycloak_login_client_id`/`keycloak_login_client_secret`) existed
only to support the RFC 8693 token-exchange design the "broker-issued
identity PATs" section above replaced, and sat configured-but-unread until
issue maniaclab/af-mcp-platform#140 repurposed the identical "confidential client + sealed secret"
shape for a different grant type: the broker's own `/v1/oauth/authorize`
(`api/mcp_oauth.py`) authenticates *as* this client when it redirects an MCP
client's browser through a real Keycloak login on that MCP client's behalf
(see "MCP OAuth discovery + PAT bootstrap" above for the full flow). Same
env var names, same chart values, same reasoning as the Keycloak admin
service account above for why removing/re-adding chart values on every
design change would be needless churn for a deployment that already has the
Secret in place.

1. **Clients → Create client**, in the same realm as `oidc.issuer`.
2. **Client authentication: On** — a confidential client (this leg is
   server-to-server: the broker itself talks to Keycloak's token endpoint,
   never a browser), authenticating via `authorization_code`.
3. **Standard flow: On** (authorization_code); every other flow (implicit,
   direct access grants, service accounts) **Off** — this client only ever
   completes one specific redirect-based login, nothing else.
4. **Valid redirect URIs**: exactly
   `{broker_public_origin}/v1/oauth/keycloak-login/callback` — the broker's
   own callback for this leg, not to be confused with the account-linking
   callback (`/v1/oauth/callback/{alias}`) or any MCP client's own
   redirect_uri (which Keycloak never sees; that hop is entirely between the
   broker and the MCP client).
5. **Advanced → Proof Key for Code Exchange Code Challenge Method: S256** —
   the broker always sends PKCE on this leg in addition to the client
   secret, defence in depth rather than a substitute for either.
6. **Client scopes → Add client scope → `mcp-gateway`, attached as
   `Default`** — REQUIRED (issue maniaclab/af-mcp-platform#245). The bootstrap callback verifies
   this login's access token against the broker's `mcp-gateway` audience —
   the same gate `/v1` applies to every bearer — and the audience only
   appears in tokens minted through a client that has the scope (and its
   Audience mapper) attached. *Default* means Keycloak evaluates the scope
   on every token request from this client, with no `scope=` request
   needed; *Optional* means only when explicitly requested — the broker
   does request it, so Optional also works, but Default is the required
   baseline so the gate cannot be skipped. The scope itself carries no
   per-user role restriction (see "`mcp-gateway`/`mcp-ops-gateway`: audience
   is population, not permission" below) — the audience mints for any
   `connect`-realm user who authenticates through this client, unconditionally.
   **Fail-closed symptom:** with this attachment missing, no access
   token from this client ever carries the audience, so *every* bootstrap
   login — entitled users included — ends in an `access_denied` redirect
   back to the MCP client (the broker logs
   `mcp_oauth.bootstrap_not_entitled`).
7. Note the client's **Client ID** and, from the **Credentials** tab, its
   **Client secret**. These become `TOKEN_MINT_CLIENT_ID`/
   `TOKEN_MINT_CLIENT_SECRET`.

The Helm chart wires both env vars from `broker.tokenMint.clientId` (a plain
value) and `broker.tokenMint.existingClientSecretSecret` (the name of a
pre-existing Secret with a `token-mint-client-secret` key), the same
existing-Secret-by-reference pattern used throughout this file:

```bash
kubectl create secret generic token-mint-client-secret \
  --dry-run=client \
  --from-literal=token-mint-client-secret='<client secret from the Credentials tab>' \
  -o yaml \
  | kubeseal --controller-namespace=sealed-secrets --format=yaml \
  > token-mint-client-secret.sealed.yaml
```

```yaml
spec:
  values:
    broker:
      tokenMint:
        clientId: "mcp-login-client"
        existingClientSecretSecret: "token-mint-client-secret"
```

Both this client and `broker.publicOrigin`/`BROKER_STATE_KEY` (already
required for the oauth21-direct linking flow above, and reused here — see
`Settings._validate_mcp_oauth_config`) must be configured together before
the discovery endpoints in the next section do anything but 503.

### Required Keycloak role: `broker`'s `read-token`

Retrieving a stored external-IdP token via
`GET /realms/<realm>/broker/<alias>/token` (the call `credentials/oidc.py`
makes for the ATLAS IAM path above) requires the caller's access token to
grant the **`read-token`** client role from Keycloak's built-in **`broker`**
client. Without it, Keycloak returns:

```
HTTP 403
{"errorMessage":"Client [<client_id>] not authorized to retrieve tokens from identity provider [<alias>]."}
```

This is **in addition to**, not instead of, "Store Tokens: ON" and "Stored
Tokens Readable: ON" on the IdP config (Identity Providers → `atlas-oidc` →
Settings). Both the IdP flags and the role are required; either one missing
produces the same 403.

**Why it's easy to miss:** it's a Keycloak-specific authorization check, not
part of the OAuth 2.0 or OIDC standard. The admin UI doesn't surface it when
you flip "Store Tokens" on an IdP — that toggle lives under Identity
Providers, while the role lives under Clients → `broker`, with no cross-link
between the two screens. Keycloak's own "Retrieving External IdP Tokens"
docs mention the role, but not prominently enough to catch before you hit
the 403 above.

**What `broker` is:** a built-in client that ships with every Keycloak
realm — not created by anything in this repo. Its purpose is precisely to
hang roles like `read-token` off of, for this exact permission model.

**Ways to grant it:**

- **Per-user** — Users → find the user → Role Mapping → Assign role →
  filter by clients: `broker` → check `read-token`. Simple; doesn't scale.
- **At production scale** — a client scope's Scope tab is *not* a grant
  mechanism, despite looking like one. See the next section for why, and
  for the two mechanisms that actually grant the role to many users.

**Verifying:** decode the caller's access token and confirm `read-token`
appears in `resource_access.broker.roles`. `credentials/oidc.py` is the
only code path in this repo that exercises `/broker/<alias>/token` — grep
there if you need to trace how the broker consumes the resulting token.

**Distinguishing "missing the role" from "never linked":** a principal
without `read-token` gets a 403 from every call this section describes —
including the `is_linked()`/`link_status()` probe `api/identities.py` runs
to build the portal's Identities page. Before `link_status()` existed
(`credentials/oidc.py`), that 403 collapsed into the same `linked: false`
an ordinary not-yet-linked user gets, so someone who genuinely lacks
`read-token` could run the entire IdP linking flow to completion and the
portal would still show "not linked" forever, with nothing pointing at the
real cause. `link_status()` now returns an `OIDCLinkStatus(linked,
permission_denied)`, and `/v1/identities`' `providers[]` entries carry the
`permission_denied` bit through as `link_permission_denied` — the portal's
`IdentityLink.vue` renders a distinct "access required" state (pointing the
user at the platform team) instead of the plain "not linked" + clickable
"Link account" a role-less user would otherwise see indefinitely.

### Client scope Scope tab: a filter, not a grant

A client scope's **Scope** tab looks like a place to grant `read-token` to
everyone who gets that scope. It isn't — Keycloak's own admin UI says so,
in the info banner on that tab:

> If there is no role scope mapping defined, each user is permitted to use
> this client scope. If there are role scope mappings defined, the user must
> be a member of at least one of the roles.

Populating the Scope tab **restricts** the scope to users who already hold
one of the listed roles; it does not grant the role to anyone. Add
`read-token` there without users already having it some other way, and
Keycloak silently excludes every user from the scope.

**The cascading failure:** a scope's audience mapper — the thing that puts
a backend's expected audience into the token's `aud` claim — only fires
for users who actually get the scope. Excluded from the scope means
excluded from the mapper too, so minted tokens are missing the audience
entirely, not just the role. If a decoded token's `aud` doesn't contain the
audience you expected on a client scope that *does* carry a Scope-tab role
restriction, suspect this before anything else in the credential path — as
of this writing, that applies to nothing `mcp-gateway`/`mcp-ops-gateway`
related (see the next section), but the mechanism is generic and any
future scope could hit it.

**How to actually grant `read-token` at scale:**

- **Realm default role** — Realm settings → Realm roles →
  `default-roles-<realm>` → Associated roles → assign `read-token`. Every
  user in the realm gets it transitively, with no per-user or per-group
  admin. Right for a realm dedicated to one purpose (e.g. an AF-only realm).
- **Group membership** — Groups → new group → add users → the group's Role
  Mapping tab → assign `read-token`. Users in the group get the role,
  users outside don't. Right for a realm serving multiple purposes, where
  only some users should get broker-token access.

Once one of those actually grants the role, the Scope tab becomes optional
belt-and-suspenders — it can additionally restrict which users obtain a
given scope — but it is never itself where the grant happens.

**AF's setup:** the `connect` realm has a `default-roles-connect` composite,
but we grant `read-token` via group membership (`af-mcp-users`) instead of
adding it there, since `connect` serves more than just the AF and
`read-token` is a single, coarse, all-brokered-IdPs-or-nothing permission —
opening it realm-wide would let any `connect` user retrieve a stored token
from *any* brokered IdP the realm ever configures, not just `atlas-oidc`.

### `mcp-gateway`/`mcp-ops-gateway`: audience is population, not permission

Earlier revisions of this setup also listed `read-token` on `mcp-gateway`'s
(and `mcp-ops-gateway`'s) own Scope tab, so the audience only minted for
members of the same `af-mcp-users` group `read-token` came from. That
coupling is now removed (issue tracked alongside the ops-platform usability
pass): **`mcp-gateway` and `mcp-ops-gateway` are Optional client scopes with
an empty Scope tab**, explicitly requested by their portal client
(`portal.oidc.scope` in the Helm values already includes it) — the audience
mints unconditionally for any `connect`-realm user who authenticates
through that client, full stop.

**Why the coupling existed, and why it was the wrong lever:** `read-token`
had to stay group-scoped for the retrieval-blast-radius reason above,
regardless of anything to do with the gateway audience. Riding
`mcp-gateway`'s own population on that same role meant "who can reach the
broker's API at all" was accidentally decided by a permission that exists
purely to gate ATLAS-IAM/Rucio stored-token retrieval — unrelated
subsystems sharing a control neither actually wanted shared. Two concrete
symptoms this produced: a user could complete the ATLAS-IAM linking flow
and still never see `mcp-gateway` in their token if they weren't also in
`af-mcp-users` (fixed independently — see "Distinguishing 'missing the
role' from 'never linked'" above); and `entitlements.group_permissions`'
`__authenticated__` tier (meant to give every signed-in user some baseline
permission, e.g. `read_monitoring`) was unreachable in practice for anyone
outside `af-mcp-users`, since they had no audience to reach the broker with
at all.

**What decides access now:** `entitlements.group_permissions` alone — the
audience gate answers "is this a token for the MCP gateway", and the
group-permissions map answers "what can this principal do", and only the
second question is actually about authorization. This also makes standing
up a new facility simpler: `mcp-gateway`'s Keycloak config (client scope +
Audience mapper, Optional, empty Scope tab) is stock, generic, and requires
no group to pre-provision; only `read-token`/ATLAS-IAM linking (if a
deployment even has that integration — `mcp-ops-platform` in `flux_apps`,
condor-only, does not) needs its own group.

**Consequence for `resource_access.broker`:** Keycloak's built-in `roles`
client scope ships an **Audience Resolve** mapper that unconditionally adds
`broker` to `aud` for any token whose holder has a `resource_access.broker`
entry — which `read-token`-holders always do, independent of
`mcp-gateway`. A user's token can therefore still show `aud` containing
both `mcp-gateway` and `broker` (the latter purely from holding
`read-token` for IAM purposes) — `identity.py`'s `keycloak_dependency` only
ever checks that `aud` *contains* `mcp-gateway`, so the extra `broker`
entry is inert to the broker and safe to ignore.

### Configurable POSIX attribute names and group-path matching (issue #148)

`principal_directory.py`'s `KeycloakPrincipalDirectory` reads a principal's
POSIX identity directly from Keycloak's Admin REST API, bypassing the JWT
mapper layer entirely — so, as of issue maniaclab/af-mcp-platform#144 step 3b, this is the *only*
path (JWT and PAT alike; see above), and it needs to know the *real* profile
attribute key, not whatever a mapper used to normalize it to. Three
settings, all defaulting to AF's own convention:

| Setting | Env var | Default |
|---|---|---|
| `posix_uid_attribute` | `POSIX_UID_ATTRIBUTE` | `uid` |
| `posix_gid_attribute` | `POSIX_GID_ATTRIBUTE` | `gid` |
| `posix_unixname_attribute` | `POSIX_UNIXNAME_ATTRIBUTE` | `unixname` |

A facility whose POSIX identity is LDAP-federated under different names —
the common spelling is `uidNumber`/`gidNumber` — overrides these
(`broker.posixAttributes.*` in the chart) rather than the broker hardcoding
AF's own convention, the same reasoning as `entitlements.group_permissions`
(see "Group-to-Permission Mapping Example" below). When none of the
configured keys are present for a given user, the corresponding
`PrincipalAttributes` field is simply left `None` — not an error — and the
actionable error an x509-backed target eventually raises for that principal
names exactly which keys it looked for, so the operator's first diagnostic
step is checking those keys against the real attribute names above, not
guessing.

A related, separate setting: `principal_directory_group_full_path`
(`PRINCIPAL_DIRECTORY_GROUP_FULL_PATH`, default `false`) controls whether
the directory matches a Keycloak group by its bare `name` (e.g. `atlas`) or
its full `path` (e.g. `/atlas/users`). As of issue maniaclab/af-mcp-platform#144 step 3 this governs
group matching for **every** authenticated request, JWT and PAT alike —
groups resolution is fully unified through the directory, so there is no
separate "JWT path" convention left to keep in sync with it. Set this
`true` if your realm's group names, as the Admin REST API returns them,
need the full path to be unambiguous; the default (`false`, bare name)
matches `policy.yaml`'s `group_permissions` keys directly, and is what the
now-removable Group Membership mapper described below used to produce for
JWTs when "Full group path" was left OFF.

### Group-to-Permission Mapping Example

The chart ships the UChicago ATLAS AF's own `group_permissions` mapping as
its default (below) — a convenience for that one deployment and a template
for what an overlay looks like, **not** a generic default. Group names come
from the deployer's own Keycloak realm, so a same-named group in a
different realm could mean something else entirely: any analysis facility
other than the UChicago AF **must** override `entitlements.group_permissions`
in its `HelmRelease` overlay with its own group names (see the non-ATLAS
worked example below), or every backend whose `required_permission` isn't
`__none__` becomes unreachable by everyone. The broker's startup check (see
`app.py`'s lifespan) walks every backend's `required_permission` and
**refuses to start** if no group grants it, naming both the backend and the
permission — a Kubernetes rollout failure with zero outage (the previous
ReplicaSet keeps serving) is far more visible than a config that silently
deploys broken.

This is the ATLAS AF's own mapping, the chart default, copyable as a
starting point if you're deploying for that AF or want a similar shape:

```yaml
group_permissions:
  # Full ATLAS analysis + compute access.
  atlas: [read_data, read_metadata, read_monitoring, submit_jobs, manage_jobs, launch_compute, manage_jupyter, read_files]
  # Analysis + compute access, no Jupyter management.
  cms: [read_data, read_metadata, read_monitoring, submit_jobs, manage_jobs, launch_compute, read_files]
  # Analysis + compute access, no monitoring dashboards.
  dune: [read_data, read_metadata, submit_jobs, manage_jobs, launch_compute, read_files]
  # Read-only data + metadata access.
  escape: [read_data, read_metadata, read_files]
  # Full access plus data management and platform administration.
  af-admins: [read_data, read_metadata, read_monitoring, submit_jobs, manage_jobs, launch_compute, manage_jupyter, manage_data, admin, read_files]
  # Any authenticated user (no group membership required)
  __authenticated__: [read_metadata, read_monitoring]
```

#### Worked example: a non-ATLAS site

If you are running this chart for a facility other than the UChicago ATLAS
AF, override `entitlements.group_permissions` entirely — the group names
on the left must match Keycloak group names in *your* realm exactly (see
"Create the groups you reference in `group_permissions`" above); reusing
`atlas`/`cms`/`dune`/`escape`/`af-admins` only makes sense if your realm
happens to define groups with those same names. For example, a facility
whose Keycloak realm defines `myexperiment-users` and
`myexperiment-admins` groups instead might set:

```yaml
group_permissions:
  # Ordinary analysts: read data/metadata, submit jobs.
  myexperiment-users: [read_data, read_metadata, submit_jobs]
  # Full access plus data management and platform administration.
  myexperiment-admins: [read_data, read_metadata, read_monitoring, submit_jobs, manage_jobs, manage_data, admin]
  # Any authenticated user (no group membership required)
  __authenticated__: [read_metadata]
```

The permission names on the right (`read_data`, `submit_jobs`, ...) are not
site-specific — they're the fixed vocabulary this policy engine understands
(see `PERMISSIONS` in `broker/src/af_mcp_broker/authorization/base.py`),
matched against whatever `required_permission` values your `services.yaml`
declares.

Which permission a backend target requires is declared alongside the
service itself, in `services.yaml`'s `required_permission` field, not in
`policy.yaml` (see `docs/adding-a-service.md`):

```yaml
backends:
  - name: rucio
    required_permission: read_data
  - name: ami
    required_permission: read_metadata
  - name: condor-mcp
    required_permission: submit_jobs
  - name: docs
    required_permission: __none__     # open to any authenticated user
```

Keycloak group membership is resolved from `PrincipalDirectory` via the
principal cache (issue maniaclab/af-mcp-platform#144 step 3) -- not from a token claim, for either
credential type. Keycloak remains the authoritative source; the cache is a
stale-while-revalidate layer in front of it (see "Authorization is an
attribute of the principal, not the token" above), refreshed roughly every
`principal_cache_refresh_seconds` (default ~45s) rather than on every single
request.

### Keycloak: POSIX User Attribute mappers

**As of issue maniaclab/af-mcp-platform#144 step 3b, the broker never reads a `posix` claim from any
token.** Every credential type -- JWT and identity PAT alike -- resolves a
principal's current POSIX identity (`uid`/`gid`/`unixname`) the same way:
from `PrincipalDirectory` (the Keycloak Admin REST API lookup above), via
the principal cache -- completing what step 3 did for groups. If your
realm's four POSIX User Attribute mappers on the `posix` client scope exist
only to satisfy this broker, **you may remove them (and the scope itself).**

**Check first whether anything else in your realm reads the `posix` claim.**
A Keycloak realm often serves more applications than this broker, and the
`posix` scope in particular tends to predate it -- the UChicago AF realm
keeps these mappers precisely because other Connect applications consume
the claim. Removing them is safe *for the broker* and says nothing about
your other consumers. Leaving them costs nothing here: the broker simply
never looks at the claim.
The settings that control which Keycloak profile attributes the directory
reads are `posix_uid_attribute`/`posix_gid_attribute`/
`posix_unixname_attribute` (see "Configurable POSIX attribute names and
group-path matching" above) -- there is no longer a separate JWT-side mapper
convention they need to stay consistent with, because there is no longer a
JWT-side source of POSIX identity at all.

**POSIX identity remains optional (issue maniaclab/af-mcp-platform#148).** The broker still requires
no POSIX attributes to authenticate a request: a principal the directory has
no `uid`/`gid`/`unixname` for still authenticates successfully, with those
fields simply left `None` on the resulting `Principal`. Only x509/VOMS proxy
minting (`credentials/x509.py`) genuinely needs a POSIX identity — the mint
Job's NFS home subPath and `runAsUser`/`runAsGroup` all require real
uid/gid/unixname values — and that requirement is enforced at that one point
of use: a principal with no POSIX identity who reaches an x509-backed target
gets a clear, actionable error naming the backend ("this backend needs a
grid identity your account doesn't have") rather than being refused at the
door for an unrelated backend. Everything else that used to read
`principal.uid` (cache keys, audit fields, log context) uses
`principal.subject` instead, which every principal has.

If your realm still has the four legacy POSIX User Attribute mappers on a
`posix` client scope, they're inert now — the broker never reads the
`posix` claim they used to produce — safe to leave in place or remove
independently of the steps above.

#### Verify (current)

POSIX identity now takes effect through Keycloak profile-attribute
assignment alone -- there is no token claim to inspect (any lingering
`posix` claim in a token is ignored). Set (or change) a user's
`posix_uid_attribute`/`posix_gid_attribute`/`posix_unixname_attribute`
profile attributes in Keycloak and confirm the broker-resolved
uid/gid/unixname changes within `principal_cache_refresh_seconds` (default
~45s; see "Authorization is an attribute of the principal, not the token"
above) on their next request, regardless of which credential type they
present.

**Finding your real Keycloak attribute keys (issue maniaclab/af-mcp-platform#148).** The directory's
configurable attribute names (`Settings.posix_uid_attribute`/
`posix_gid_attribute`/`posix_unixname_attribute`, below) refer to a
Keycloak profile attribute — an operator needs the real key, not the
display label the admin console shows by default:

- **Realm settings → User profile → Attributes** lists every profile
  attribute with its key shown alongside its display label — the trap is
  that the *label* (e.g. "Unix UID") is what's visually prominent, while the
  *key* (e.g. `uidNumber`) is what the settings below actually need.
- **Client Scopes → `posix` → Mappers** (if the mappers haven't been removed
  yet), for each of the four mappers, shows its source **User Attribute** —
  a convenient cross-check, since it names the same profile attribute the
  directory itself reads.

### Keycloak: Group Membership mapper

**As of issue maniaclab/af-mcp-platform#144 step 3, the broker never reads a `groups` claim from any
token.** Every credential type -- JWT and identity PAT alike -- resolves a
principal's current groups the same way: from `PrincipalDirectory` (the
Keycloak Admin REST API lookup above), via the principal cache. If your
realm has a Group Membership mapper on the `mcp-gateway` client scope purely
to satisfy this broker, **you may remove it** -- but as with the POSIX
mappers above, check first that nothing else in your realm reads the
`groups` claim.

**Remove only the mapper, never the scope.** The `mcp-gateway` client scope
also carries the **Audience mapper** that puts `mcp-gateway` into a token's
`aud` claim, which the broker validates on every single request. Deleting
the scope, or excluding users from it, breaks authentication entirely and in
a way that is hard to trace -- see "The cascading failure" above.

The setting that controls how
the directory matches group names is `principal_directory_group_full_path`
(see "Configurable POSIX attribute names and group-path matching" above) --
there is no longer a separate JWT-side mapper convention it needs to stay
consistent with, because there is no longer a JWT-side source of groups at
all.

**Create the groups you reference in `group_permissions`** and assign
users to them. Group names are entirely up to you — the chart ships no
site-specific default, so pick names that match your own Keycloak realm
(see the worked example below). The broker's own dev-only fallback policy
(`broker/src/af_mcp_broker/authorization/policy.yaml`, used when no
`POLICY_FILE` is configured) mirrors the ATLAS AF's own group names:
`atlas`, `cms`, `dune`, `escape`, `af-admins`.

If your realm still has a legacy Group Membership mapper on the
`mcp-gateway` client scope, it's inert now — the broker never reads the
`groups` claim it used to produce — safe to leave in place or remove
independently of the steps above.

#### Verify (current)

Group membership now takes effect through Keycloak group assignment alone
-- there is no token claim to inspect. Assign (or remove) a user from a
Keycloak group referenced in `group_permissions` and confirm their
permissions change within `principal_cache_refresh_seconds` (default
~45s; see "Authorization is an attribute of the principal, not the token"
above) on their next request, regardless of which credential type they
present.

---

## Auth-edge decision

The shared oauth2-proxy (`provider = "keycloak-oidc"`, v7.6.0) validates a
Bearer's `aud` claim against its own `client_id`, not the broker's
audience — so mcpHost's ForwardAuth gate 302'd every Bearer request,
including Claude Desktop's, instead of letting it reach the broker's own
JWT validator:

```
$ curl -sS -o /dev/null -w "HTTP %{http_code}\nLocation: %{redirect_url}\n" https://mcp.af.uchicago.edu/mcp/
HTTP 302
Location: https://oauth2-proxy.af.uchicago.edu/oauth2/sign_in?rd=%2Fmcp%2F
```

Phase A (`ingress-mcp.yaml` / `ingress-portal.yaml` split) removed the
oauth2-proxy annotations from mcpHost so the broker validates Bearers
itself there. Phase B (this doc's [Portal auth](#portal-auth-oidc-public-client)
section) carries the same fix to portalHost: `/v1` and `/mcp` move to a
separate `ingress-portal-api.yaml` with no oauth2-proxy annotations, and the
portal SPA obtains its own `aud=mcp-gateway` Bearer instead of relying on a
cookie oauth2-proxy never actually forwarded as a header anyway. Phase C
removed oauth2-proxy from the portal's authenticated pages too, once
`Base.astro`'s client-side `getUser()`-or-`login()` guard was confirmed to
cover the same "no valid session → redirect to Keycloak" case on its own —
see [Portal auth](#portal-auth-oidc-public-client) above. No ForwardAuth
proxy is left anywhere in this platform's request path.
(`ingress-portal-authenticated.yaml`) — see [Portal
auth](#portal-auth-oidc-public-client) above for why the public landing page
and shared static assets are carved out of that gate.
