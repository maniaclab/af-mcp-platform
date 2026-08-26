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
  proxy itself via `POST /v1/credentials/x509/redeem` (issue #112's wire
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
the aggregator injects an AF Broker Identity Token (`aud` = the service
name) and the service redeems the caller's cached proxy itself via
`POST /v1/credentials/x509/redeem` (issue #112) — this requires the broker
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

`tools_cache_ttl` (seconds, default 300, matching fastmcp's own
`ProxyProvider` default) controls how long a cached component list for this
service may be served from a by-name lookup (e.g. resolving a tool during a
`tools/call`) before refreshing. Tool *schemas* are assumed
caller-independent, so a schema cached under one caller's credential being
served to another isn't a credential leak — only set this to `0` for a
service whose tool list genuinely personalizes per caller.

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
`rucio_list_dids` name.

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
[#113](https://github.com/maniaclab/af-mcp-platform/issues/113) for the
full tradeoff discussion.

Whatever you choose, the deployed tool names are what callers actually see
via `tools/list` on `/mcp` — confirm the names you expect show up there (see
Verification below) rather than assuming from the config alone. `GET
/v1/catalog` and the portal's Catalog page show the service itself (name,
permission, auth type); the individual tool names live one level down at
`GET /v1/catalog/{service}/tools`, which the portal fetches when a server
card's Tools section is expanded.

### Naming conventions

New services are named `<backend>_service` per the Elwood v5 glossary (e.g.
`rucio_service`); existing deployed services predate this convention and keep
their JWT-audience-bearing names until a rename can be coordinated. Methods
(MCP "tools") use `verb_noun` naming (e.g. `list_dids`, `submit_job`). This
documents the convention for new services — it renames nothing that already
exists.

**Reserved: the `af` prefix and the `af-mcp` name.** The registry always
carries a builtin `af-mcp` service (issue #240) — the gateway's own
identity, catalog, and usage methods (`af_whoami`, `af_list_identities`,
`af_list_mcp_servers`, `af_link_identity`, `af_usage`), served by the
aggregator itself rather than proxied to any backend. It is not a
`services.yaml` entry and cannot be one: an entry claiming the `af` prefix
or the `af-mcp` name fails registration with a clear error, since either
would let a configured service shadow (or replace) the methods a caller
relies on precisely when everything else is broken.

---

## Step 2 — Pick (or reuse) a permission for the service

`required_permission` in `services.yaml` (Step 1 above) is the **sole**
declaration of what a service target requires — the service registry, not
`policy.yaml`, is authoritative here (see issue #60). `policy.yaml`'s only
remaining job is mapping permissions to Keycloak groups via
`group_permissions` (Step 3 below).

`required_permission` has three forms:

- **A permission name** (e.g. `read_data`) — the caller must hold that
  permission, granted via `group_permissions`.
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
