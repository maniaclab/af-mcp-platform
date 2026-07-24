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
```

`required_capability` is the capability string the broker's Authorization
subsystem will check before forwarding any tool call to this backend.

---

## Step 2 — Ensure the capability exists in policy.yaml

Check `charts/af-mcp-platform/files/policy.yaml` (or the ConfigMap it renders
into). If `my-new-backend:use` is not already listed, add it:

```yaml
capabilities:
  # ...existing entries...
  - name: my-new-backend:use
    description: "Access to my-new-backend tools"
```

If the capability already exists (e.g., a generic `af:user` capability that covers
many backends), skip this step.

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

If the backend pod is not already covered by an existing egress rule, add it to
the broker's NetworkPolicy. Edit
`charts/af-mcp-platform/templates/networkpolicy.yaml` or the relevant values key:

```yaml
values:
  networkPolicy:
    egressBackends:
      - namespace: af-mcp-backends
        podSelector:
          matchLabels:
            app.kubernetes.io/name: my-new-backend
```

If the backend is in the same namespace or already covered by a wildcard rule,
skip this step.

If the backend is in the same namespace as the broker but listens on a port
other than the chart's defaults (8000, 8080), append it to
`networkPolicy.broker.backendPorts` in your `HelmRelease` values instead —
no template edit needed:

```yaml
values:
  networkPolicy:
    broker:
      backendPorts:
        - 8000
        - 8080
        - 9000  # e.g. rucio-mcp
```

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
