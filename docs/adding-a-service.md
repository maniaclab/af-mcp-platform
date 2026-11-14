# Adding a Service

The platform is designed so that adding the Nth service requires **no code
changes** — only configuration. The five steps below are the complete procedure.

---

## Adding a new Identity Provider

If your new service needs its own credential-linking flow (rather than
reusing one already configured), add an entry to `broker.identityProviders`
in your HelmRelease values. Each entry's `alias` doubles as the id shown on
the portal's Identities page — no separate mapping to keep in sync.

- **`type: oauth21-direct`** — use this when the service is itself an OAuth
  2.1 authorization server (e.g. rucio-mcp). No Keycloak IdP configuration
  is needed at all; the broker is a direct OAuth 2.1 client via its own
  CIMD document (`GET /.well-known/cimd`). Also requires
  `broker.publicOrigin` to be set to the portal's origin (see below) — the
  broker refuses to start otherwise. See
  [Rucio: Per-Site Setup](rucio-per-site-setup.md) for a concrete, deployed
  worked example of this provider type (one entry per Rucio site).

  ```yaml
  broker:
    publicOrigin: "https://mcp-portal.af.uchicago.edu"
    identityProviders:
      - type: oauth21-direct
        alias: my-service-oauth
        targets: ["my-new-service"]
        authorizationEndpoint: "https://my-new-service.example/authorize"
        tokenEndpoint: "https://my-new-service.example/token"
        issuer: "https://my-new-service.example"
        displayName: "My New Service"
        enables: "Access to my-new-service on your behalf"
  ```

  `broker.publicOrigin` is the canonical origin (scheme + host, no trailing
  slash) every OAuth 2.1 URL the broker constructs itself is built from: the
  `redirect_uri` it sends to the service's authorization server, and every
  `redirect_uris` entry in the CIMD document above. Register the service's
  authorization server client with exactly
  `<publicOrigin>/v1/oauth/callback/<alias>` as its redirect_uri whitelist
  entry (or point it at the CIMD document, which advertises the same URL).

  If the authorization server only accepts pre-registered clients (e.g.
  JupyterHub), see
  [Confidential oauth21-direct clients](#confidential-oauth21-direct-clients)
  below.

- **`type: keycloak-brokered`** — use this when the service is (or can be
  registered as) an OIDC identity provider. This *does* require configuring
  the service as an Identity Provider in Keycloak (Settings → Identity
  Providers), with "Store Tokens" and "Stored Tokens Readable" both on, plus
  the `read-token` client role from Keycloak's `broker` client granted to
  callers (see `docs/auth.md`).

  ```yaml
  broker:
    identityProviders:
      - type: keycloak-brokered
        alias: my-service-oidc
        targets: ["my-new-service"]
        displayName: "My New Service"
        enables: "Access to my-new-service on your behalf"
  ```

- **`type: x509`** — use this when the service's real credential is a VOMS
  proxy (e.g. ami-mcp). Unlike the two types above, delivery is
  **service-side redemption, not header injection**: the aggregator injects
  only an AF Broker Identity Token, and the service redeems the caller's
  proxy itself via `POST /v1/credentials/x509/redeem` (issue maniaclab/af-mcp-platform#112's wire
  format — proxy PEM material never transits the aggregator). The service
  must also be marked `auth_type: x509` in the aggregator service list
  (Step 1); the broker refuses to start when the entry's `targets` and the
  `auth_type: x509` services drift in either direction — including when a
  service has no explicit entry at all, since there is no synthesized
  fallback. With `serviceUrl` set it also requires the broker signing key
  (`broker.identityToken.existingSigningKeySecret`) and the shared Vault
  connection (`broker.oauth21.tokenStore.vault`) — omit `serviceUrl` for the
  legacy ephemeral-Job mint path (signing key omitted there just warns).
  This entry replaces the removed global
  `broker.env.VOMS_TOKEN_SERVICE_URL` — see
  [x509 deployment notes](x509-deployment-notes.md).

  ```yaml
  broker:
    identityProviders:
      - type: x509
        alias: x509
        targets: ["my-x509-service"]
        serviceUrl: "http://voms-token-service.voms-token.svc.cluster.local:8080"
        voms: "atlas"       # optional, default "atlas"
        valid: "192:00"     # optional, default "192:00"
        displayName: "Grid certificate (x509)"
        enables: "VOMS proxy minting for x509-authenticated services"
  ```

See `docs/auth.md#identity-provider-types` for how the types differ.

### Confidential oauth21-direct clients

Some authorization servers cannot identify the broker by its CIMD URL
because they only accept clients registered ahead of time, often as
confidential clients. JupyterHub is one: every OAuth client is a hub
service with a fixed `oauth_client_id`, and its token endpoint requires a
`client_secret`. For these, give the entry its own `clientId` and, if the
client is confidential, an `existingClientSecretSecret`:

```yaml
broker:
  publicOrigin: "https://mcp.af.uchicago.edu"
  identityProviders:
    - type: oauth21-direct
      alias: jupyterhub
      targets: ["jupyterhub_service"]
      authorizationEndpoint: "https://jupyterhub.af.uchicago.edu/hub/api/oauth2/authorize"
      tokenEndpoint: "https://jupyterhub.af.uchicago.edu/hub/api/oauth2/token"
      issuer: "https://jupyterhub.af.uchicago.edu"
      # JupyterHub scopes are space-separated in the OAuth `scope` param.
      scope: "servers!user access:servers!user read:users:name!user"
      clientId: "service-af-mcp-platform"
      existingClientSecretSecret: "af-mcp-platform-jupyterhub-client"
      displayName: "JupyterHub"
      enables: "Launching and driving your JupyterHub servers via af-jupyterhub-mcp"
```

- **`clientId`**: the id the AS registered the broker under. If you leave
  it out, the broker uses its CIMD URL. If every oauth21-direct entry has
  its own `clientId`, the CIMD id is never used. Entries with their own
  `clientId` are also left out of the CIMD document's `redirect_uris`.
- **`existingClientSecretSecret`**: the name of a pre-existing Secret
  (create it with a SealedSecret; the chart does not create it) whose
  `client-secret` key holds the client secret. Setting it makes the entry
  confidential. The chart passes the secret to the broker as the env var
  `OAUTH21_CLIENT_SECRET_<ALIAS>`, never in `IDENTITY_PROVIDERS`.
  `<ALIAS>` is the alias uppercased with each non-alphanumeric character
  replaced by `_`, so `jupyterhub` becomes `OAUTH21_CLIENT_SECRET_JUPYTERHUB`.
  The broker sends the secret with `client_secret_post` on the code
  exchange, refresh and revocation calls. It refuses to start if a
  confidential entry's secret is missing or empty, or if the entry has no
  `clientId`.
- **PKCE** is always sent. An AS that ignores it, as JupyterHub does,
  still works.

On the JupyterHub side, register the broker as a hub service whose
`api_token` is the same value as the Secret above. JupyterHub uses a
service's `api_token` as its OAuth client secret.

```yaml
jupyterhub:
  hub:
    services:
      af-mcp-platform:
        oauth_client_id: service-af-mcp-platform
        oauth_redirect_uri: https://mcp.af.uchicago.edu/v1/oauth/callback/jupyterhub
        oauth_no_confirm: true
        oauth_client_allowed_scopes:
          - servers!user
          - access:servers!user
          - read:users:name!user
```

JupyterHub never issues refresh tokens, and its tokens last 14 days by
default. The broker serves the linked token until 60 seconds before it
expires. After that the user re-links from the portal's Identities page.
JupyterHub has no revocation endpoint either, so unlinking deletes only
the broker's stored copy, and the token stays valid at the hub until it
expires. See [Token Lifetime and Refresh](auth.md#token-lifetime-and-refresh).

### Backends must reject a bad bearer with HTTP 401

The broker learns that an `oauth21-direct` token was revoked only when the
MCP server it was sent to answers **HTTP 401**. Verify the bearer at the
transport, before any tool runs: pass a `token_verifier` that checks the
token against the AS, the way af-jupyterhub-mcp's `HubTokenVerifier` checks
`/hub/api/user`. A rejection reported as a tool error inside a 200 response
is invisible to the broker, which then keeps serving the token.

This matters most for an AS whose tokens never expire and that issues no
refresh token, such as Indico or a GitHub OAuth App. Its token response
leaves out `expires_in`, and the broker serves the token until a backend
rejects it. The caller's catalog entry then reads `link_required` with
`link_state: "rejected"` until they re-link. See
[Rejected `oauth21-direct` tokens](auth.md#rejected-oauth21-direct-tokens).

### Migrating from the pre-unification chart values

Older chart releases configured identity providers across four separate
values. All four are consolidated into `broker.identityProviders` above:

| Old value | New equivalent |
|---|---|
| `broker.oidc.idpAlias` | A `keycloak-brokered` entry's `alias` |
| `broker.oauth21.providers` | `oauth21-direct` entries (same fields, still camelCase) |
| `broker.cimd.idpAliases` | Derived automatically from `oauth21-direct` entries — remove this value entirely |
| `broker.identitiesLinkClientId` | Removed entirely — `keycloak-brokered` entries no longer need it; the portal links them via its own client-side flow regardless |

---

## Step 1 — Add the service to the aggregator service list

Edit the HelmRelease for the platform (typically
`clusters/<cluster>/af-mcp-platform/helmrelease.yaml`) and add one entry under
`values.aggregator.services`:

```yaml
values:
  aggregator:
    services:
      # existing services omitted for brevity
      - name: my-new-service
        url: http://my-new-service.af-mcp-backends.svc.cluster.local:8000/mcp
        required_permission: my-new-service:use
        timeout_seconds: 30
        auth_type: none  # or "bearer" (default) / "x509" -- see below
        tools_cache_ttl: 300  # seconds; see below
```

`required_permission` is the permission string the broker's Authorization
subsystem will check before forwarding any tool call to this service.
When adding a service, also state its trust tier (Elwood v5 / Shannon:
user-tier, service-tier, or infrastructure-tier) in its deployment
manifests in the GitOps repo, and choose `required_permission` accordingly
— see docs/architecture.md "Trust tiers". `required_permission: __none__`
(open to any authenticated user) is only appropriate for user-tier
read-only services.

`auth_type` controls what per-user credential the aggregator injects into
the service call and **defaults to `bearer`** if omitted — meaning the
broker will try to mint a per-user credential for every caller, which
requires an identity provider configured for this service's `name` (see
"Adding a new Identity Provider" above) and fails with a friendly
"not linked" error otherwise. Set `auth_type: none` explicitly if the
service authorizes itself some other way (e.g. a platform k8s service
account) and needs no per-user credential forwarded at all. `auth_type: x509`
marks a service whose per-user credential is a VOMS proxy (e.g. ami-mcp):
the aggregator injects an AF Broker Identity Token (`aud` = the service's
`audience`, defaulting to its `name` — issue maniaclab/af-mcp-platform#257) and the service
redeems the caller's cached proxy itself via
`POST /v1/credentials/x509/redeem` (issue maniaclab/af-mcp-platform#112) — this requires the broker
signing key to be mounted (`broker.identityToken.existingSigningKeySecret`),
and the service to run in a mode that verifies broker JWTs and redeems
proxies (ami-mcp's `--auth broker`, via the `af-credentials` library). The new service's `name` must be added to some `identityProviders` entry's
`targets` — every `auth_type: x509` service needs an explicit entry
covering it, or the broker refuses to start naming it (there is no
synthesized fallback; see "Adding a new Identity Provider" above).
For a `bearer` service, the aggregator also attempts a best-effort per-user
credential mint during `tools/list` (not only `tools/call`), so a service
whose own MCP endpoint requires auth just to list tools (e.g. rucio-mcp)
isn't invisible to every caller — see `mcp/aggregator.py`'s
`_make_client_factory` docstring for the full rationale.
For every auth type that carries a per-user credential (`bearer`, `x509`,
`krb5` and `servicex`), a caller must have linked the credential for the
service's tools to be listed: an unlinked caller's listing is skipped (no
token minted, the backend not contacted, even if it would list its tools
without a credential) and recorded as `not_linked`; a direct call of one of
its tools still returns the not-linked error. A caller whose linked
credential was rejected (`oauth21-direct` only) is likewise not listed and
is recorded as `unauthorized`. A `bearer` service whose provider needs no
user action (`broker-issued`, `condor-token`, the service-account provider)
counts as always linked, so it is listed for everyone entitled to it, and a
mint that fails for an operational reason is `unavailable`, not
`not_linked`. A `bearer` service with no resolvable credential provider is
still listed without a credential.

`tools_cache_ttl` (seconds, default 300, matching fastmcp's own
`ProxyProvider` default) controls how long a cached component list for this
service may be served from a by-name lookup (e.g. resolving a tool during a
`tools/call`) before refreshing. Tool *schemas* are assumed
caller-independent, so a schema cached under one caller's credential being
served to another isn't a credential leak — only set this to `0` for a
service whose tool list genuinely personalizes per caller.

`timeout_seconds` (default 30) is the per-request read timeout for calls to
this service. It does not bound `tools/list`: the broker gives each service
one broker-wide listing deadline, `MCP_LIST_TIMEOUT_SECONDS` (default 10),
covering that service's whole listing attempt including list-time credential
setup. A service that has not answered by then is left out of that `tools/list`
(the other services' tools are returned as normal), logged as
`aggregator.service_list_failed` with `reason: unavailable`, and shown as
`unavailable` to every caller until a listing succeeds. The failure is
negative-cached for 30 seconds per caller, so a service that stays down costs
each caller the deadline at most once per 30 seconds. The deadline also bounds
`GET /v1/catalog/{service}/tools` (the portal's Methods list). The chart does
not expose it; set the environment variable on the broker pod if the default
does not suit.

### `apply_namespace` — tool naming

`apply_namespace` controls whether the aggregator mounts this service's
tools as `<prefix>_<toolname>` and **defaults to `true`** — the safe
choice, since it's what prevents two services from advertising the same
tool name and one silently shadowing the other in `tools/list`. Leave it
unset unless you have a specific reason to change it.

Set it to `false` only for a service whose tools are already self-prefixed
at the source (baked into the tool names the service itself advertises,
not added by the aggregator). rucio-mcp is the shipped example: it serves
tools already named `rucio_list_dids`, `rucio_whoami`, etc., so leaving
`apply_namespace: true` would double-prefix them into
`rucio_rucio_list_dids`. The shipped `services.yaml` therefore sets
`apply_namespace: false` on its `rucio` entry, and callers see the plain
`rucio_list_dids` name. The aggregator routes calls to an `apply_namespace:
false` service by that same prefix, so every tool it advertises must be
named `<prefix>_<tool>` -- a tool name missing the prefix is unreachable,
and it is hidden from `tools/list` unless its name happens to match another
service's prefix (in which case it is attributed to that service instead).

`false` is only safe when no other configured service can advertise an
overlapping tool name — with one rucio site configured, that holds. It
stops holding the moment a second self-prefixed service enters the picture:
configuring both an ATLAS and an ESCAPE rucio site as separate services
(see the shipped `services.yaml` comment) means both would advertise the
same un-namespaced `rucio_*` names, and fastmcp resolves un-namespaced
mounts in registration order — the second one silently shadows the first
instead of failing loudly. The accepted fix for that case is to set
`apply_namespace: true` on both site entries and accept the resulting
double-prefixed names (`rucio_atlas_rucio_whoami`, `rucio_escape_rucio_whoami`)
— ugly, but unambiguous and requires no upstream rucio-mcp change. See
maniaclab/af-mcp-platform#113 for the
full tradeoff discussion.

#### `apply_namespace: false` couples `prefix` to the backend's tool names

With `apply_namespace: false`, `prefix` is no longer a name the broker
chooses: it has to match the prefix the backend puts on its own tool
names. The same goes for every per-tool `required_permission` key and
every `exclude_tools` entry, since those are written with the backend's
names too. Routing, entitlement and audit all find a tool's service from
`<prefix>_`. A tool without that prefix belongs to no service, so callers
never see it.

So a backend-side rename breaks the service even though the broker config
never changed. When atlas-search-mcp-bridge renamed `atlas_opensearch_*` to
`aos_*` while the deployment still had `prefix: atlas_opensearch`, all of
the service's tools disappeared for every caller. This happened twice. Each
time the backend was reachable and listed its tools without error, so
nothing looked broken. The fix is config-only: set `prefix` to the
backend's new prefix (`aos`) and rename the `required_permission` and
`exclude_tools` keys to match. Upgrade the backend and the service entry in
the same change.

The broker reports the mismatch in the following places, as of the last
time any caller listed the service's tools:

- **Tool mapping drift** (`GET /v1/admin/tool-mapping-drift`, also the
  portal Admin page): the service appears with its expected `prefix`,
  `routable` / `advertised` counts, and an **unroutable** list of the
  backend's offending tool names. A dict-form `required_permission` also
  shows every old key as **stale**.
- **Service status**: if the backend advertises tools and none of them can
  be routed, `GET /v1/catalog` and `af_list_mcp_servers` report the service
  as `misconfigured` ("No routable tools ...") rather than `available`.
- **Metrics**: `af_mcp_service_tools_advertised` and
  `af_mcp_service_tools_routable` (gauges, by `service`), and
  `af_mcp_tool_mapping_drift_total{kind="unroutable"}`. The chart's optional
  `prometheusRule` (`prometheusRule.enabled: true`) alerts as
  `AfMcpServiceNoRoutableTools` once routable stays at 0 with advertised
  above 0 for 15 minutes.
- **Logs**: one `aggregator.tool_prefix_mismatch` warning per upstream
  listing per service, carrying `service`, `prefix`, `count` and a `sample`
  of the offending names.

If only some of the tools are unroutable, the service stays `available`
(the rest still work), but drift still lists the unroutable ones.

Whatever you choose, the deployed tool names are what callers actually see
via `tools/list` on `/mcp` — confirm the names you expect show up there (see
Verification below) rather than assuming from the config alone. `GET
/v1/catalog` and the portal's Catalog page show the service itself (name,
permission, auth type); the individual tool names live one level down at
`GET /v1/catalog/{service}/tools`, which the portal fetches when a server
card's Tools section is expanded.

### `exclude_tools` — hiding backend tools entirely

`exclude_tools` is a list of native (pre-namespace) tool names a backend
should never be exposed for, at all — not "gated behind a permission", but
absent from `tools/list` and refused on `tools/call` exactly as if the
backend never advertised them:

```yaml
- name: condor_service
  prefix: condor
  url: "http://condor-mcp:8000/mcp"
  required_permission: manage_jobs
  exclude_tools: ["advertise_to_collector"]
```

Use this for a backend tool that's infrastructure-facing with no user story
behind the broker (condor-mcp's `advertise_to_collector`, the shipped
example), not for something you merely want fewer callers to reach — that's
what per-tool `required_permission` (Step 2 below) is for. Names are
whatever the provider itself sees, which follows `apply_namespace` the same
way `required_permission`'s dict keys do: the backend's own name for the
(default) namespaced case, or the raw name including its self-declared
prefix when `apply_namespace: false`. A name that never appears in the
backend's own listing logs a one-time `aggregator.exclude_tools_not_found`
warning — almost always a typo.

### Naming conventions

New services are named `<backend>_service` per the Elwood v5 glossary (e.g.
`rucio_service`). Methods (MCP "tools") use `verb_noun` naming (e.g.
`list_dids`, `submit_job`). This documents the convention for new services —
it renames nothing that already exists.

**`name` is the registry identity, not the wire audience.** For AF-native
(x509/broker-issued) services, the broker mints an AF Broker Identity Token
whose `aud` each backend validates. That `aud` is the service's `audience`
field, defaulting to `name` — so set an explicit `audience` and you can adopt
the `<backend>_service` name (registry key, catalog, audit label) while the
backend keeps validating its historical audience. Renaming `name` *without* an
explicit `audience` silently re-points the contract and 401s the backend
(learned the hard way, 2026-08-26 — see docs/auth.md's "AF Broker Identity
Token"). A rename is: `name: <backend>_service` + `audience: <old-name>`, with
the identity-provider `targets` updated to the new name in lockstep.

**Reserved: the `af` prefix and the builtin gateway service name.** The
registry always carries a builtin gateway service (issue maniaclab/af-mcp-platform#240) — the
gateway's own identity, catalog, and usage methods (`af_whoami`,
`af_list_identities`, `af_list_mcp_servers`, `af_link_identity`, `af_usage`,
`af_search_tools`),
served by the aggregator itself rather than proxied to any backend. Its name
defaults to `gateway_service` and is deployment-configurable
(`broker.builtinServiceName` / `BUILTIN_SERVICE_NAME`); the reserved `af`
prefix is fixed, since the method wire-names are built from it. It is not a
`services.yaml` entry and cannot be one: an entry claiming the `af` prefix or
the configured builtin name fails registration with a clear error, since
either would let a configured service shadow (or replace) the methods a caller
relies on precisely when everything else is broken.

---

## Step 2 — Pick (or reuse) a permission for the service

`required_permission` in `services.yaml` (Step 1 above) is the **sole**
declaration of what a service target requires — the service registry, not
`policy.yaml`, is authoritative here (see issue maniaclab/af-mcp-platform#60). `policy.yaml`'s only
remaining job is mapping permissions to Keycloak groups via
`group_permissions` (Step 3 below).

`required_permission` has four forms:

- **A permission name** (e.g. `read_data`) — the caller must hold that
  permission, granted via `group_permissions`, for every tool this service
  exposes.
- **`__none__`** — open to any authenticated user; no permission needed.
  Use this only as a deliberate, explicit opt-in.
- **Omitted entirely** — no permission gate; the credential layer becomes
  the gate instead (the caller must have a linked identity / mintable
  credential for this target, which is itself the authorization). The
  broker **refuses to start** if a service omits `required_permission` and
  no credential provider resolves for its target either (e.g. `auth_type:
  bearer` with no `identity_providers` entry naming it, or `auth_type: none`
  with nothing registered) — that combination would mean the service has no
  gate at all, neither a permission nor a credential requirement.
- **A dict, keyed by tool name** — different tools of the same service can
  require different permissions:

  ```yaml
  required_permission:
    __default__: manage_jobs     # optional -- see below
    query_jobs: read_monitoring
    query_history_db: read_monitoring
  ```

  Keys are the tool's **native** name — the name the backend itself
  advertises, before the aggregator's `<prefix>_` namespacing is applied (or
  the raw name, unchanged, if `apply_namespace: false`) — so the same key
  works regardless of that choice. `__default__` is the permission any tool
  *not* listed as its own key falls back to, and it's **optional, not
  required**: if you omit it, an unlisted tool is disabled outright (nobody
  can call it, regardless of what they hold) rather than silently inheriting
  some other tool's permission or falling open. This is deliberate —
  per-tool gating is opt-in, so a new tool a backend adds later can never
  slip through under a permission nobody meant to grant it. Give every tool
  you want reachable its own key, or set `__default__` to whatever you want
  the safe fallback to be — usually the service's *most* privileged
  permission, with only the genuinely read-only tools de-escalated by their
  own key, exactly as the example above does for `query_jobs`/
  `query_history_db`. A service can appear as a target under more than one
  permission's "your access" grants (`GET /v1/permissions`) when it uses
  this form, and
  `GET /v1/catalog/{service}/tools` reports each visible tool's own resolved
  permission — `GET /v1/catalog`'s single `permission` field is `null` for a
  dict form with no `__default__`, since there's no one value to summarize.

  If a backend renames or adds tools, the dict and the backend's listing
  drift apart: **unmapped** tools (advertised, no key, no `__default__`) are
  silently disabled, and **stale** keys map nothing (for an
  `apply_namespace: false` service a rename can also make the tools
  **unroutable** — see the `apply_namespace` section above). The broker logs
  `entitlement.tool_mapping_drift` once per change, counts them in
  `af_mcp_tool_mapping_drift_total`, and lists them at
  `GET /v1/admin/tool-mapping-drift` (the portal's admin page), as observed
  when a caller lists the service's tools.

**Permission names must be built-in or declared.** Besides the built-in
permissions (`read_data`, `submit_jobs`, ... see `PERMISSIONS` in
`authorization/base.py`), a site can invent its own, but it must declare the
permission's action type (`read` or `state_change`) so the catalog and audit
labels are right:

```yaml
entitlements:
  custom_permissions:
    exec_jobs: state_change
```

The broker **refuses to start** if a service requires a permission that is
neither built-in nor listed in `custom_permissions` (an unknown name could
otherwise only be labelled `read`). Declaring it does not grant it to anyone;
Step 3 still applies.

**Overriding a tool's action type.** A tool's `action_type` (`read` or
`state_change`) comes from its permission. To override it for specific tools,
use `entitlements.target_action_types`. Keys are **service names** (the
`name` in `services.yaml`, not the `prefix`), and the globs match the **wire
tool name** a caller sees, including the `<prefix>_` namespace unless the
service sets `apply_namespace: false`:

```yaml
entitlements:
  target_action_types:
    condor_service:
      "condor_exec_*": state_change
```

A key naming no registered service, or a glob matching no tool, silently
overrides nothing.

If an existing permission already covers the new service (e.g. a generic
`read_metadata` that several services already require), reuse it and skip to
Step 4 — no policy change needed. Only continue to Step 3 if you're
introducing a genuinely new permission name.

---

## Step 3 — Map the permission to Keycloak groups (if new)

If you added a new permission in Step 2, map it to one or more AF Keycloak groups
in the HelmRelease values:

```yaml
values:
  entitlements:
    group_permissions:
      # existing mappings omitted
      af-my-new-service-users:
        - my-new-service:use
```

Principals in the `af-my-new-service-users` Keycloak group will be granted
`my-new-service:use`. If you forget this step (or typo the permission name),
the broker **refuses to start**, naming both the service and the permission
it can't reach — see docs/auth.md's "Group-to-Permission Mapping Example".

---

## Step 4 — Allow egress to the service in NetworkPolicy (if needed)

The broker's NetworkPolicy allows in-cluster egress to service pods **in the
same namespace** as the broker, on a configured list of ports. If your new
service is in the same namespace and uses one of the default ports (8000,
8080), no change is needed.

If it listens on a different port, append it to
`networkPolicy.broker.servicePorts` in your `HelmRelease` values — no template
edit needed:

```yaml
values:
  networkPolicy:
    broker:
      servicePorts:
        - 8000
        - 8080
        - 9000  # e.g. rucio-mcp
```

**Cross-namespace services** are not currently exposed through values — the
namespace selector in `templates/networkpolicy.yaml` is scoped to the release
namespace. To reach a service in a different namespace you'd need to either
move it into the broker's namespace or extend the chart's egress rule. If
that becomes a recurring need, file an issue to parameterize
`serviceNamespaces` similarly.

---

## Step 5 — Redeploy

```bash
flux reconcile helmrelease af-mcp-platform --namespace flux-system --with-source
```

Flux will render the new HelmRelease values, update the aggregator ConfigMap, and
roll the broker pods. The new service appears as its own entry in
`GET /v1/catalog` once the pods are healthy; its individual tool names show up
in `tools/list` over `/mcp` (see Verification below).

---

## Tool-authoring conventions

Steps 1–5 wire a service in with no code. The tools the backend itself
advertises are a separate matter: the aggregator forwards them verbatim, so the
quality of each tool's description, schema, annotations and error text is set
at the source. Those conventions, and the rest of what a backend must do to fit
the platform (transport, authentication, size limits), are the
[MCP Design Guide](mcp-design.md), a MUST/SHOULD checklist with a way to verify
each item. Two of its items are service-entry fields you set alongside the
Step 1 entry and are documented in the guide: [`agent_policy`](mcp-design.md#p2-write-an-agent_policy-for-the-service)
and [`trust_tier`](mcp-design.md#p3-declare-a-trust_tier).

---

## Verification

```bash
# Check the broker sees the new service as a catalog entry
kubectl exec -n af-mcp deploy/af-mcp-broker -- \
  curl -s http://localhost:8080/v1/catalog | jq '.servers[].name'

# Confirm the new service's entry has the fields you expect
kubectl exec -n af-mcp deploy/af-mcp-broker -- \
  curl -s http://localhost:8080/v1/catalog | jq '.servers[] | select(.name=="my-new-service")'
```

`/v1/catalog` reports one entry per service, not per tool — per-tool
enumeration lives at `GET /v1/catalog/{service}/tools` (namespaced the same
way `/mcp` namespaces them). To confirm the actual tool names callers will
see end-to-end, talk to the aggregator's MCP protocol surface directly:

```bash
read -s -p "Bearer token: " MCP_BEARER_TOKEN
export MCP_BEARER_TOKEN
pixi run -e dev python scripts/verify-mcp-flow.py
```

This is the same script [Connecting a Client](connecting-a-client.md)
recommends for sanity-checking a token — it prints every tool visible to the
caller, grouped by inferred service prefix.
