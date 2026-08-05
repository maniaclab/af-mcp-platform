# Authentication & Credential Chain

## Full Auth Chain

Every caller of the broker — the portal SPA, Claude Desktop, `curl`, any
future MCP client — obtains its **own** OAuth token for the broker's
audience (`mcp-gateway`) and sends it as a Bearer directly. The broker
validates it itself (`HTTPBearer` + `keycloak_dependency` in `identity.py`);
there is no ForwardAuth proxy in this path. oauth2-proxy still exists in
front of the portal, but only to gate the portal's HTML/static assets — see
[Portal auth](#portal-auth-oidc-public-client) below.

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

## Identity provider types

The broker links a user's account to an external identity two ways, declared
side by side in `Settings.identity_providers` (env `IDENTITY_PROVIDERS`,
chart `broker.identityProviders`). Both authenticate the principal via
Keycloak first (the chain above) — they differ only in *how the backend
token is obtained and stored* once that's done:

| | `keycloak-brokered` | `oauth21-direct` |
|---|---|---|
| Handled by | `OIDCProvider` | `OAuth21Provider` |
| Backend token source | Keycloak's stored-broker-token pattern — the user links via `kc_action=LINK_IDP`, Keycloak stores the resulting token internally | The broker itself is an OAuth 2.1 client to the backend's own authorization server (PKCE + CIMD `client_id`, see `docs/architecture.md#client-id-metadata-document-cimd`) |
| Broker retrieves it via | `GET /realms/<realm>/broker/<alias>/token` | `TokenStore.get(sub, alias)`, refreshing on demand near expiry |
| Token persistence | Keycloak (broker holds no copy) | The broker's own `TokenStore` (in-memory or Vault-backed — see PR3) |
| Requires backend to be | An OIDC-compatible IdP Keycloak can broker to | An OAuth 2.1 authorization server (no OIDC discovery needed) |
| Portal `link_url` | Always `null` — the portal re-runs its own client-side `startIdpLink()` flow | Full URL to the broker's own `/v1/oauth/authorize/{alias}` |

Use `keycloak-brokered` when the backend is (or can be registered as) an
OIDC identity provider Keycloak already understands — this is the path for
ATLAS IAM (`atlas-oidc`). Use `oauth21-direct` when the backend is an OAuth
2.1 authorization server in its own right and cannot be made to look like an
OIDC IdP to Keycloak — this is the path for rucio-mcp. See
[Rucio: Per-Site Setup](rucio-per-site-setup.md) for the concrete, deployed
`oauth21-direct` configuration rucio-mcp uses, one entry per Rucio site.

---

## Token claims required by the broker

**POSIX identity is optional (issue #148).** The broker no longer requires
any claim to authenticate a request. A `posix` claim, if the token carries
one, is resolved opportunistically: `uid`/`gid`/`unixname` are read
individually, and each is simply left unset on the resulting `Principal` if
absent — an entirely missing `posix` object, or one missing one or more of
the three keys, is no longer a rejection. `broker/src/af_mcp_broker/
identity.py` (`_extract_principal`) is the authoritative logic. This is a
deliberate relaxation from earlier behavior, where a `posix`-less token was
rejected with HTTP 401 for every backend, including ones (bearer/oauth21
targets like Rucio) that never touch POSIX identity at all.

**Why it used to be required, and why almost nothing actually needs it.**
Only x509/VOMS proxy minting (`credentials/x509.py`) genuinely needs a POSIX
identity — the mint Job's NFS home subPath and `runAsUser`/`runAsGroup` all
require real uid/gid/unixname values. Everything else that used to read
`principal.uid` (cache keys, audit fields, log context) has moved to
`principal.subject` instead, which every principal has. The requirement is
now enforced at that one point of use: a principal with no POSIX identity
who reaches an x509-backed target gets a clear, actionable error naming the
backend ("this backend needs a grid identity your account doesn't have")
rather than being refused at the door for an unrelated backend.

**Operators: what you can now remove.** If your Keycloak realm's only reason
for the `posix` client scope's User Attribute mappers was satisfying this
broker, you may remove them (and the scope itself) once every principal that
needs an x509-backed target has POSIX profile attributes resolvable another
way — see the PAT path below, which reads them directly via the Admin REST
API rather than through a minted JWT's claims. Do this only after confirming
which of your backends are x509-backed (`backends.yaml`'s `auth_type:
x509`); everything else was never affected by the claim's presence at all.

The claim shape, when present, is unchanged:

```json
{
  "posix": {
    "uid": 33155,
    "gid": 33155,
    "unixname": "kratsg"
  }
}
```

**How Keycloak provides it (AF's implementation, for context).** AF Keycloak
has a realm-level client scope named `posix`. Inside that scope, four User
Attribute protocol mappers copy `uid`, `gid`, `unixname` (and optionally
`unixname-v2`) from each user's Keycloak profile attributes into the token
under the `posix.*` namespace. Those profile attributes are themselves
populated by upstream identity brokering (CERN → ATLAS IAM → Keycloak) or LDAP
sync, depending on the deployment. The `posix` client scope must be assigned
to every OAuth client that needs to obtain broker-ready tokens (e.g.
`mcp-portal`) — either as a Default scope (auto-included in every token) or an
Optional scope (the client must explicitly request `scope=posix`).

**Common footgun:** each of the four User Attribute mappers has the same
two-name-field shape as the Group Membership mapper above — **Name** (an
internal identifier) and **Token Claim Name** (the key that actually
appears in the JWT payload). Leaving Token Claim Name blank produces an
inert mapper: no `posix.uid` (or `.gid` / `.unixname` / `.unixname-v2`)
claim ever appears in the token, silently. Token Claim Name **must** be
set explicitly, using the dotted path that nests it under `posix`
(`posix.uid`, `posix.gid`, `posix.unixname`, ...) to match the claim shape
above. Verify via Client Scopes → `posix` → **Evaluate** tab — select the
target user and client, and the Generated Access Token panel shows exactly
what each mapper actually contributed.

**Non-Keycloak IdPs.** `posix` as a client-scope name is a Keycloak-side
convention, not a broker requirement. Any OIDC IdP — Dex, Zitadel, Auth0, Ory
Hydra, etc. — can satisfy the broker as long as the decoded access token has
a top-level `posix` claim in the shape above. How that claim gets populated
is IdP-specific: some use scopes and mappers the same way Keycloak does,
others use custom claims, hooks, or rules.

**Verifying.** Decode a client's access token (paste the middle segment into
any JWT decoder) and confirm `posix` appears as a top-level key with
`uid`/`gid`/`unixname` populated. Absence is no longer a broker-wide outage —
only x509-backed targets (see above) are affected, and even then the
resulting error names the backend so it's easy to tell apart from any other
failure.

**Finding your real Keycloak attribute keys (issue #148).** Both the PAT
path's configurable attribute names (`Settings.posix_uid_attribute`/
`posix_gid_attribute`/`posix_unixname_attribute`, below) and the JWT
mappers' source attribute above refer to the same underlying Keycloak
user-profile attribute — an operator debugging either path needs the real
key, not the display label the admin console shows by default:

- **Realm settings → User profile → Attributes** lists every profile
  attribute with its key shown alongside its display label — the trap is
  that the *label* (e.g. "Unix UID") is what's visually prominent, while the
  *key* (e.g. `uidNumber`) is what every mapper and the settings below
  actually need.
- **Client Scopes → `posix` → Mappers**, for each of the four mappers, shows
  its source **User Attribute** — authoritative because it is exactly what
  the working JWT path already reads today, so it can never disagree with
  reality the way a written-down convention might.

## Configurable POSIX attribute names and group-path matching (issue #148)

The PAT-authenticated path (`principal_directory.py`'s
`KeycloakPrincipalDirectory`) reads a principal's POSIX identity directly
from Keycloak's Admin REST API, bypassing the JWT mapper layer entirely — so
unlike the JWT path above, it needs to know the *real* profile attribute key,
not whatever a mapper normalizes it to. Three settings, all defaulting to
AF's own convention:

| Setting | Env var | Default |
|---|---|---|
| `posix_uid_attribute` | `POSIX_UID_ATTRIBUTE` | `uid` |
| `posix_gid_attribute` | `POSIX_GID_ATTRIBUTE` | `gid` |
| `posix_unixname_attribute` | `POSIX_UNIXNAME_ATTRIBUTE` | `unixname` |

A facility whose POSIX identity is LDAP-federated under different names —
the common spelling is `uidNumber`/`gidNumber` — overrides these
(`broker.posixAttributes.*` in the chart) rather than the broker hardcoding
AF's own convention, the same reasoning as `entitlements.group_capabilities`
(see "Group-to-Capability Mapping Example" above). When none of the
configured keys are present for a given user, the corresponding
`PrincipalAttributes` field is simply left `None` — not an error — and the
actionable error an x509-backed target eventually raises for that principal
names exactly which keys it looked for, so the operator's first diagnostic
step is checking those keys against the real attribute names above, not
guessing.

A related, separate setting: `principal_directory_group_full_path`
(`PRINCIPAL_DIRECTORY_GROUP_FULL_PATH`, default `false`) controls whether
this same PAT path matches a Keycloak group by its bare `name` (e.g.
`atlas`) or its full `path` (e.g. `/atlas/users`). The default matches the
JWT path's Group Membership mapper convention ("Full group path: OFF", see
below) — a site with that mapper switched **ON** must set this `true` too,
or every PAT-authenticated capability lookup silently returns nothing (the
group names never match `policy.yaml`'s `group_capabilities`) even though
the equivalent JWT path works fine.

---

## Portal auth (OIDC public client)

The portal (`mcp-portal.af.uchicago.edu`) is a static Astro/Vue SPA — there's
no server-side session to hold a token, so it becomes its own OAuth 2.0
**public client** (`mcp-portal`) and runs Authorization Code + PKCE against
the `connect` realm itself, the same way any other caller of the broker does
(see [Full Auth Chain](#full-auth-chain) above). This is Phase B; Phase A
(mcpHost bypassing oauth2-proxy for Claude Desktop) is in place.

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

## Required Keycloak role: `broker`'s `read-token`

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

---

## Client scope Scope tab: a filter, not a grant

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
`mcp-gateway` (or whatever audience a backend expects) into the token's
`aud` claim — only fires for users who actually get the scope. Excluded
from the scope means excluded from the mapper too, so minted tokens are
missing the audience entirely, not just the role. If a decoded token's
`aud` doesn't contain the audience you expected, suspect this before
anything else in the credential path.

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
but we grant `read-token` via group membership instead of adding it there,
since `connect` serves more than just the AF. The `mcp-gateway` scope's
Scope tab also lists `read-token`, purely as a second filter: group
membership is what actually grants the role, and users get both the role
and the scope's audience together.

---

## Token Lifetime and Refresh

| Credential type | Typical lifetime | Refresh strategy |
|---|---|---|
| AF access token (portal SPA) | 5 minutes | `oidc-client-ts` silent renew via refresh_token grant (see [Portal auth](#portal-auth-oidc-public-client)) |
| AF access token (other MCP clients) | 5 minutes | Client-specific — e.g. Claude Desktop's own OAuth flow (not yet implemented) |
| ATLAS IAM token (brokered) | 1 hour | Broker re-fetches from Keycloak on cache miss |
| x509 VOMS proxy | 12–96 hours (configurable) | Re-mint Job triggered when cache entry expires |

The `CredentialCache` stores each credential with its `expires_at` timestamp.
A background janitor coroutine sweeps the cache every 60 seconds and evicts
expired entries, triggering a fresh mint on the next request.

---

## Keycloak: Group Membership mapper (required)

The broker's authorization gates on a top-level `groups` claim in the access
token. If Keycloak isn't configured to add it, no user is granted any
capability and `/v1/catalog` returns an empty list for everyone. This applies
to the JWT path only -- the separate PAT path's equivalent setting is
`principal_directory_group_full_path` (see "Configurable POSIX attribute
names and group-path matching" above), which must be kept consistent with
this mapper's "Full group path" toggle or PAT-authenticated capability
lookups silently break while the JWT path keeps working.

### One-time setup

1. **Add a Group Membership mapper to the `mcp-gateway` client scope**
   (or your equivalent scope):
   - Admin → Client Scopes → `mcp-gateway` → Mappers → Add mapper → **Group Membership**
   - Name: `groups`
   - Token Claim Name: `groups`
   - Full group path: **OFF** (the broker string-matches literal group
     names; a leading `/` would prevent every policy match)
   - Add to ID token: OFF
   - Add to access token: **ON**
   - Add to userinfo: OFF

   **Common footgun:** the mapper form has two similarly-named fields —
   **Name** (an internal identifier for the mapper itself) and **Token
   Claim Name** (the key that actually appears in the JWT payload). Both
   look optional. Set `Name: groups` and leave Token Claim Name blank, and
   the mapper is inert: no `groups` claim ever appears in the token,
   silently — no error, no warning, nothing to notice until you decode a
   minted token. Token Claim Name **must** be set to `groups` explicitly.
   Verify via Client Scopes → `mcp-gateway` → **Evaluate** tab — select the
   target user and the `mcp-portal` client, and the Generated Access Token
   panel shows exactly what the mapper actually contributed.

2. **Create the groups you reference in `group_capabilities`** and
   assign users to them. Group names are entirely up to you — the chart
   ships no site-specific default, so pick names that match your own
   Keycloak realm (see the worked example below). The broker's own
   dev-only fallback policy (`broker/src/af_mcp_broker/authorization/
   policy.yaml`, used when no `POLICY_FILE` is configured) mirrors the
   ATLAS AF's own group names: `atlas`, `cms`, `dune`, `escape`,
   `af-admins`.

### Verify

Mint a fresh token (via `scripts/mint-token.py`) and confirm the payload
has a top-level `groups` claim listing your group names as strings.
Without it, the broker treats the caller as `__authenticated__`-only.

---

## Group-to-Capability Mapping Example

The chart ships the UChicago ATLAS AF's own `group_capabilities` mapping as
its default (below) — a convenience for that one deployment and a template
for what an overlay looks like, **not** a generic default. Group names come
from the deployer's own Keycloak realm, so a same-named group in a
different realm could mean something else entirely: any analysis facility
other than the UChicago AF **must** override `entitlements.group_capabilities`
in its `HelmRelease` overlay with its own group names (see the non-ATLAS
worked example below), or every backend whose `required_capability` isn't
`__none__` becomes unreachable by everyone. The broker's startup check (see
`app.py`'s lifespan) walks every backend's `required_capability` and
**refuses to start** if no group grants it, naming both the backend and the
capability — a Kubernetes rollout failure with zero outage (the previous
ReplicaSet keeps serving) is far more visible than a config that silently
deploys broken.

This is the ATLAS AF's own mapping, the chart default, copyable as a
starting point if you're deploying for that AF or want a similar shape:

```yaml
group_capabilities:
  # Full ATLAS analysis + compute + GitLab access.
  atlas: [read_data, read_metadata, read_monitoring, read_gitlab, submit_jobs, manage_jobs, launch_compute, manage_jupyter, manage_gitlab]
  # Analysis + compute access, no GitLab/Jupyter management.
  cms: [read_data, read_metadata, read_monitoring, submit_jobs, manage_jobs, launch_compute]
  # Analysis + compute access, no monitoring dashboards.
  dune: [read_data, read_metadata, submit_jobs, manage_jobs, launch_compute]
  # Read-only data + metadata access.
  escape: [read_data, read_metadata]
  # Full access plus data management and platform administration.
  af-admins: [read_data, read_metadata, read_monitoring, read_gitlab, submit_jobs, manage_jobs, launch_compute, manage_jupyter, manage_gitlab, manage_data, admin]
  # Any authenticated user (no group membership required)
  __authenticated__: [read_metadata, read_monitoring]
```

### Worked example: a non-ATLAS site

If you are running this chart for a facility other than the UChicago ATLAS
AF, override `entitlements.group_capabilities` entirely — the group names
on the left must match Keycloak group names in *your* realm exactly (see
"Create the groups you reference in `group_capabilities`" above); reusing
`atlas`/`cms`/`dune`/`escape`/`af-admins` only makes sense if your realm
happens to define groups with those same names. For example, a facility
whose Keycloak realm defines `myexperiment-users` and
`myexperiment-admins` groups instead might set:

```yaml
group_capabilities:
  # Ordinary analysts: read data/metadata, submit jobs.
  myexperiment-users: [read_data, read_metadata, submit_jobs]
  # Full access plus data management and platform administration.
  myexperiment-admins: [read_data, read_metadata, read_monitoring, submit_jobs, manage_jobs, manage_data, admin]
  # Any authenticated user (no group membership required)
  __authenticated__: [read_metadata]
```

The capability names on the right (`read_data`, `submit_jobs`, ...) are not
site-specific — they're the fixed vocabulary this policy engine understands
(see `CAPABILITIES` in `broker/src/af_mcp_broker/authorization/base.py`),
matched against whatever `required_capability` values your `backends.yaml`
declares.

Which capability a backend target requires is declared alongside the
backend itself, in `backends.yaml`'s `required_capability` field, not in
`policy.yaml` (see `docs/adding-a-backend.md`):

```yaml
backends:
  - name: rucio
    required_capability: read_data
  - name: ami
    required_capability: read_metadata
  - name: panda
    required_capability: submit_jobs
  - name: docs
    required_capability: __none__     # open to any authenticated user
```

Keycloak group membership is resolved once per request from the validated
token's `groups` claim. There is no group-membership cache in the broker —
Keycloak is the authoritative source.

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
cookie oauth2-proxy never actually forwarded as a header anyway. oauth2-proxy
remains in front of portalHost's `/` rule (`ingress-portal.yaml`) purely to
gate the HTML/static assets.

---

## Programmatic client bootstrap

The chain above ("Full Auth Chain") describes the interactive path:
oauth2-proxy handles browser-based OIDC login transparently, and a signed-in
user never fetches, pastes, or configures a raw bearer token by hand. That
story is unchanged and remains the default for anyone opening
`mcp.af.uchicago.edu` in a browser-capable client.

It does not cover MCP clients that speak MCP-over-HTTP but can't yet perform
OAuth discovery — Claude Desktop today. Those clients have no browser session
to inherit and no way to run the OIDC dance themselves, so they need a static
credential to put directly in their config's `Authorization` header. The
portal's `mcp-portal.af.uchicago.edu/tokens` page exists for exactly this,
and (issue #144 step 2a) it now mints a **broker-issued identity PAT**
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
   reconstructed from, and never any groups/capabilities (see below).
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
   expired). Still only covers PATs minted here — a future OAuth bootstrap
   flow (a later step of issue #144) would mint through the same store, so
   this gap is expected to close rather than widen.
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

### Where PATs are accepted — and where they deliberately are not

**`/mcp` accepts both identity PATs and Keycloak JWTs.**
`mcp/middleware/identity_mw.py`'s `AsgiAuthMiddleware` recognizes a bearer
starting with `mcp_pat_` and routes it to `pat_auth.resolve_pat_principal`;
anything else follows the existing JWT path (`identity.get_principal`)
unchanged. This is deliberately a *recognition* dispatch, not a cutover —
both credential types work side by side until issue #144 step 5 flips
`/mcp` to PAT-only, once an OAuth bootstrap flow gives every client a way to
obtain a PAT without visiting the portal first.

**`/v1` remains Keycloak-JWT-only, including `POST /v1/tokens` itself.**
`keycloak_dependency` is untouched by this design: a PAT is not a valid JWT,
so it is rejected by ordinary JWT decoding, the same way any other
non-JWT bearer always has been. This is a deliberate security property, not
an oversight: if a PAT could authenticate on `/v1`, a PAT could mint further
PATs — a single leaked credential would become self-renewing, and revocation
would degrade into whack-a-mole against tokens the leaked one itself
created (GitHub disallows this by default for the same reason). A PAT is
therefore always traceable back to an interactive Keycloak login, whether
initiated from the portal (today) or, in a future step of issue #144, an
OAuth bootstrap flow that also authenticates via Keycloak first. The portal
SPA itself is never issued a PAT — it keeps using its short-lived Keycloak
JWT, since handing a long-lived credential to browser storage would be
strictly worse than a JWT that expires in minutes.

### Authorization is an attribute of the principal, not the token

A JWT is self-contained: it carries `groups`/`posix` claims re-validated on
every request, so removing someone from a Keycloak group is a real kill
switch — their next request re-evaluates capabilities from scratch. A PAT
carries **no** authorization data at all — the registry above stores
identity and metadata only. Three separate concerns, deliberately kept
separate in the code:

- **PAT store** (`token_registry.py`) — "who is this token?"
- **Principal cache** (`principal_cache.py`) — "what groups/uid does this
  user *currently* have?", keyed by **principal id** (the Keycloak `sub`),
  not by PAT, so multiple PATs belonging to one user share cached
  authorization state and rotating/revoking a PAT never disturbs it. A
  group removal still propagates — within one refresh interval (default
  ~45s, `PRINCIPAL_CACHE_REFRESH_SECONDS`) rather than instantly, since a
  PAT-authenticated request has no fresh claims of its own to re-derive
  this from. Stale-while-revalidate: a refresh failure serves the
  last-known value for up to `PRINCIPAL_CACHE_MAX_STALENESS_SECONDS`
  (default 6 hours) before failing closed, logging loudly the whole time —
  a brief Keycloak outage should not instantly lock out every
  PAT-authenticated caller.
- **Capability engine** (`authorization/`) — unchanged; still gates on
  `group_capabilities` from whatever groups the principal cache (or a JWT's
  own claims) currently reports.

**Persisted across restarts (issue #144 step 2b).** The principal cache is
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
and the write-amplification arithmetic. Before this, a cold broker restart
during a Keycloak outage had no last-known value to serve for any
PAT-authenticated principal and failed closed for them until the directory
recovered — even though their actual authority hadn't changed.
JWT-authenticated callers were, and remain, unaffected (self-contained
tokens).

**Data at rest.** A persisted principal-cache record contains that user's
group memberships and POSIX uid/gid/unixname — the same underlying data
Keycloak already holds, but (when `PRINCIPAL_CACHE_BACKEND=vault`) now also
resident in Vault, alongside the PAT store's own records (see above).

### Operator setup: the Keycloak admin service account

Resolving a PAT's current groups/uid/gid/unixname means *asking Keycloak*,
which requires a service account with standing read access to every user's
profile and group membership — a real, deliberate privilege increase over
today's broker, which has only ever read claims from a token the user
themselves presented. Mitigated by scoping the account to the narrowest
roles that satisfy the two Admin REST API calls
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

Both empty (the chart default) is a valid, degraded state: the broker logs
`keycloak_admin_not_configured` at startup and every `mcp_pat_...` bearer on
`/mcp` is rejected the same way an invalid one is — there is no
identity-PAT authority to resolve without this account, but the broker
still starts and everything else (JWT auth, x509, oauth21-direct) is
unaffected.

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

### `broker.tokenMint.*` is now unused

The token-mint confidential client and its `TOKEN_MINT_CLIENT_ID`/
`TOKEN_MINT_CLIENT_SECRET` chart values (`broker.tokenMint.*`) existed only
to support the RFC 8693 token-exchange design this section replaces;
`api/tokens.py` no longer performs any Keycloak call to mint a PAT, so
those values are dead as of this change. Left in the chart rather than
removed — a later step of issue #144 may repurpose the same "confidential
client + sealed secret" shape again, and removing/re-adding chart values is
needless churn for a deployment that already has the Secret in place.
