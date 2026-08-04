# Adding a Backend MCP Server

The platform is designed so that adding the Nth backend requires **no code
changes** — only configuration. The five steps below are the complete procedure.

---

## Adding a new Identity Provider

If your new backend needs its own credential-linking flow (rather than
reusing one already configured), add an entry to `broker.identityProviders`
in your HelmRelease values. Each entry's `alias` doubles as the id shown on
the portal's Identities page — no separate mapping to keep in sync.

- **`type: oauth21-direct`** — use this when the backend is itself an OAuth
  2.1 authorization server (e.g. rucio-mcp). No Keycloak IdP configuration
  is needed at all; the broker is a direct OAuth 2.1 client via its own
  CIMD document (`GET /.well-known/cimd`). Also requires
  `broker.publicOrigin` to be set to the portal's origin (see below) — the
  broker refuses to start otherwise.

  ```yaml
  broker:
    publicOrigin: "https://mcp-portal.af.uchicago.edu"
    identityProviders:
      - type: oauth21-direct
        alias: my-backend-oauth
        targets: ["my-new-backend"]
        authorizationEndpoint: "https://my-new-backend.example/authorize"
        tokenEndpoint: "https://my-new-backend.example/token"
        issuer: "https://my-new-backend.example"
        displayName: "My New Backend"
        enables: "Access to my-new-backend on your behalf"
  ```

  `broker.publicOrigin` is the canonical origin (scheme + host, no trailing
  slash) every OAuth 2.1 URL the broker constructs itself is built from: the
  `redirect_uri` it sends to the backend's authorization server, and every
  `redirect_uris` entry in the CIMD document above. Register the backend's
  authorization server client with exactly
  `<publicOrigin>/v1/oauth/callback/<alias>` as its redirect_uri whitelist
  entry (or point it at the CIMD document, which advertises the same URL).

- **`type: keycloak-brokered`** — use this when the backend is (or can be
  registered as) an OIDC identity provider. This *does* require configuring
  the backend as an Identity Provider in Keycloak (Settings → Identity
  Providers), with "Store Tokens" and "Stored Tokens Readable" both on, plus
  the `read-token` client role from Keycloak's `broker` client granted to
  callers (see `docs/auth.md`).

  ```yaml
  broker:
    identityProviders:
      - type: keycloak-brokered
        alias: my-backend-oidc
        targets: ["my-new-backend"]
        displayName: "My New Backend"
        enables: "Access to my-new-backend on your behalf"
  ```

See `docs/auth.md#identity-provider-types` for how the two types differ.

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

## Step 1 — Add the backend to the aggregator backend list

Edit the HelmRelease for the platform (typically
`clusters/<cluster>/af-mcp-platform/helmrelease.yaml`) and add one entry under
`values.aggregator.backends`:

```yaml
values:
  aggregator:
    backends:
      # existing backends omitted for brevity
      - name: my-new-backend
        url: http://my-new-backend.af-mcp-backends.svc.cluster.local:8000/mcp
        required_capability: my-new-backend:use
        timeout_seconds: 30
        auth_type: none  # or "bearer" (default) / "x509" -- see below
        tools_cache_ttl: 300  # seconds; see below
```

`required_capability` is the capability string the broker's Authorization
subsystem will check before forwarding any tool call to this backend.

`auth_type` controls what per-user credential the aggregator injects into
the backend call and **defaults to `bearer`** if omitted — meaning the
broker will try to mint a per-user credential for every caller, which
requires an identity provider configured for this backend's `name` (see
"Adding a new Identity Provider" above) and fails with a friendly
"not linked" error otherwise. Set `auth_type: none` explicitly if the
backend authorizes itself some other way (e.g. a platform k8s service
account) and needs no per-user credential forwarded at all. `auth_type: x509`
is not yet deliverable over `/mcp` (see `mcp/aggregator.py`'s `TODO(#58)`).
For a `bearer` backend, the aggregator also attempts a best-effort per-user
credential mint during `tools/list` (not only `tools/call`), so a backend
whose own MCP endpoint requires auth just to list tools (e.g. rucio-mcp)
isn't invisible to every caller — see `mcp/aggregator.py`'s
`_make_client_factory` docstring for the full rationale.

`tools_cache_ttl` (seconds, default 300, matching fastmcp's own
`ProxyProvider` default) controls how long a cached component list for this
backend may be served from a by-name lookup (e.g. resolving a tool during a
`tools/call`) before refreshing. Tool *schemas* are assumed
caller-independent, so a schema cached under one caller's credential being
served to another isn't a credential leak — only set this to `0` for a
backend whose tool list genuinely personalizes per caller.

### `apply_namespace` — tool naming

`apply_namespace` controls whether the aggregator mounts this backend's
tools as `<prefix>_<toolname>` and **defaults to `true`** — the safe
choice, since it's what prevents two backends from advertising the same
tool name and one silently shadowing the other in `tools/list`. Leave it
unset unless you have a specific reason to change it.

Set it to `false` only for a backend whose tools are already self-prefixed
at the source (baked into the tool names the backend itself advertises,
not added by the aggregator). rucio-mcp is the shipped example: it serves
tools already named `rucio_list_dids`, `rucio_whoami`, etc., so leaving
`apply_namespace: true` would double-prefix them into
`rucio_rucio_list_dids`. The shipped `backends.yaml` therefore sets
`apply_namespace: false` on its `rucio` entry, and callers see the plain
`rucio_list_dids` name.

`false` is only safe when no other configured backend can advertise an
overlapping tool name — with one rucio site configured, that holds. It
stops holding the moment a second self-prefixed backend enters the picture:
configuring both an ATLAS and an ESCAPE rucio site as separate backends
(see the shipped `backends.yaml` comment) means both would advertise the
same un-namespaced `rucio_*` names, and fastmcp resolves un-namespaced
mounts in registration order — the second one silently shadows the first
instead of failing loudly. The accepted fix for that case is to set
`apply_namespace: true` on both site entries and accept the resulting
double-prefixed names (`rucio_atlas_rucio_whoami`, `rucio_escape_rucio_whoami`)
— ugly, but unambiguous and requires no upstream rucio-mcp change. See
[#113](https://github.com/maniaclab/af-mcp-platform/issues/113) for the
full tradeoff discussion.

Whatever you choose, the deployed tool names are what callers actually see
in `GET /v1/catalog` and the portal's tool list — confirm the names you
expect show up there (see Verification below) rather than assuming from
the config alone.

---

## Step 2 — Pick (or reuse) a capability for the backend

`required_capability` in `backends.yaml` (Step 1 above) is the **sole**
declaration of what a backend target requires — the backend registry, not
`policy.yaml`, is authoritative here (see issue #60; `policy.yaml` used to
carry a parallel `target_capabilities` section that had to be kept in sync
by hand, and drifting out of sync silently broke authorization in
production). `policy.yaml`'s only remaining job is mapping capabilities to
Keycloak groups via `group_capabilities` (Step 3 below).

`required_capability` has three forms:

- **A capability name** (e.g. `read_data`) — the caller must hold that
  capability, granted via `group_capabilities`.
- **`__none__`** — open to any authenticated user; no capability needed.
  Use this only as a deliberate, explicit opt-in.
- **Omitted entirely** — no capability gate; the credential layer becomes
  the gate instead (the caller must have a linked identity / mintable
  credential for this target, which is itself the authorization). The
  broker **refuses to start** if a backend omits `required_capability` and
  no credential provider resolves for its target either (e.g. `auth_type:
  bearer` with no `identity_providers` entry naming it, or `auth_type: none`
  with nothing registered) — that combination would mean the backend has no
  gate at all, neither a capability nor a credential requirement.

If an existing capability already covers the new backend (e.g. a generic
`read_metadata` that several backends already require), reuse it and skip to
Step 4 — no policy change needed. Only continue to Step 3 if you're
introducing a genuinely new capability name.

---

## Step 3 — Map the capability to Keycloak groups (if new)

If you added a new capability in Step 2, map it to one or more AF Keycloak groups
in the HelmRelease values:

```yaml
values:
  entitlements:
    group_capabilities:
      # existing mappings omitted
      af-my-new-backend-users:
        - my-new-backend:use
```

Principals in the `af-my-new-backend-users` Keycloak group will be granted
`my-new-backend:use`.

---

## Step 4 — Allow egress to the backend in NetworkPolicy (if needed)

The broker's NetworkPolicy allows in-cluster egress to backend pods **in the
same namespace** as the broker, on a configured list of ports. If your new
backend is in the same namespace and uses one of the default ports (8000,
8080), no change is needed.

If it listens on a different port, append it to
`networkPolicy.broker.backendPorts` in your `HelmRelease` values — no template
edit needed:

```yaml
values:
  networkPolicy:
    broker:
      backendPorts:
        - 8000
        - 8080
        - 9000  # e.g. rucio-mcp
```

**Cross-namespace backends** are not currently exposed through values — the
namespace selector in `templates/networkpolicy.yaml` is scoped to the release
namespace. To reach a backend in a different namespace you'd need to either
move it into the broker's namespace or extend the chart's egress rule. If
that becomes a recurring need, file an issue to parameterize
`backendNamespaces` similarly.

---

## Step 5 — Redeploy

```bash
flux reconcile helmrelease af-mcp-platform --namespace flux-system --with-source
```

Flux will render the new HelmRelease values, update the aggregator ConfigMap, and
roll the broker pods. The new backend's tools appear in `GET /v1/catalog` once
the pods are healthy.

---

## Verification

```bash
# Check the broker sees the new backend
kubectl exec -n af-mcp deploy/af-mcp-broker -- \
  curl -s http://localhost:8080/v1/catalog | jq '.tools[].backend' | sort -u

# Confirm the new backend's tools are listed
kubectl exec -n af-mcp deploy/af-mcp-broker -- \
  curl -s http://localhost:8080/v1/catalog | jq '.tools[] | select(.backend=="my-new-backend")'
```
