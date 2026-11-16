# Deployment Runbook

An ordered procedure for deploying the `af-mcp-platform` Helm chart at a new
facility, from an empty Keycloak realm to a verified tool call. Every hostname,
realm and address below is a placeholder (`example.org`, the documentation
ranges `192.0.2.0/24` and `2001:db8::/32`); substitute your own.

The chart deploys the broker and the portal. It does not deploy Keycloak,
Vault/OpenBao, Postgres or Redis: you bring each, and the chart consumes them
through values and pre-existing Secrets. The chart never creates a Secret.

Companion pages:

- [Chart Values Reference](values-reference.md): every value, its type, default and whether it is required.
- [`examples/example-values.yaml`](https://github.com/maniaclab/af-mcp-platform/blob/main/charts/af-mcp-platform/examples/example-values.yaml): the facility-specific values the chart deliberately has no default for.
- [Authentication](auth.md): the Keycloak-side configuration in depth.
- [Adding a Service](adding-a-service.md): the `aggregator.services` and `identityProviders` entries.
- [Admin Capabilities](admin.md): the admin group and maintenance mode.

## The order of things

Create things in this order; each step needs the output of the ones before it.

| Step | What | Produces |
| --- | --- | --- |
| 1 | Pick names | namespace, release name, `mcpHost`, `portalHost` |
| 2 | Keycloak | `oidc.issuer`, portal client id, audience, admin client id and secret, group names |
| 3 | Vault/OpenBao (optional) | `vault.addr`, auth role, `kvRoot` |
| 4 | Postgres (optional) | DSN Secret |
| 5 | Redis (needed for more than one replica) | URL Secret |
| 6 | Kubernetes Secrets | every `existing*Secret` the values name |
| 7 | Values file | `my-values.yaml` |
| 8 | Render and lint | proof the values are complete, before anything is installed |
| 9 | Install | the release |
| 10 | Verify | health, API, tool call, NetworkPolicy |

## 1. Pick names

- **Namespace**: for example `af-mcp`. Everything the chart renders lands in the release namespace.
- **Release name**: the chart's resource names are `<release>-af-mcp-platform-broker`, `<release>-af-mcp-platform-portal` and so on. When the release name already contains `af-mcp-platform`, the chart name is not repeated. Set `fullnameOverride` only if you need an exact prefix.
- **Two hostnames**: `ingress.mcpHost` (the broker: `/v1`, `/mcp`, the `/.well-known/` documents) and `ingress.portalHost` (the portal; it also routes the broker paths, so a browser can call the API same-origin). Both need DNS and a TLS certificate. With cert-manager, put the `cert-manager.io/cluster-issuer` annotation under `ingress.annotations`; the chart sets none because the issuer is a fact about your cluster.

If your cluster has no ingress controller the chart manages, set `ingress.enabled: false`; the two hosts are then not required.

## 2. Keycloak

Everything here is configured in the one realm named by `oidc.issuer` (for example `https://auth.af.example.org/realms/example`). The broker never manages Keycloak; [Authentication](auth.md) has the click-by-click detail, summarised here in dependency order.

1. **Audience client scope.** Create a client scope (for example `mcp-gateway`) with an **Audience** mapper whose included custom audience is the string you will set as `broker.oidc.audience` (default `mcp-gateway`). Every token the broker accepts must carry this `aud`.
2. **Portal client** (public). Client authentication off, Standard flow on, PKCE method `S256`. Valid redirect URI `https://<portalHost>/callback`, post-logout redirect `https://<portalHost>/`, web origin `https://<portalHost>`. Attach the audience scope as a **default** scope. Its client id becomes `portal.oidc.clientId`; set `portal.oidc.scope` to `openid profile email <audience scope>`.
3. **Admin service-account client** (confidential, required). Client authentication on, service accounts on, Standard flow off. Under service account roles grant only the `realm-management` roles `view-users` and `query-groups`. The broker resolves every caller's current groups and POSIX identity from the Keycloak Admin REST API with this account and **refuses to start** without it. The client id becomes `broker.keycloakAdmin.clientId`; the secret goes in a Secret (step 6). See "Operator setup: the Keycloak admin service account" in [Authentication](auth.md).
4. **MCP OAuth bootstrap client** (confidential, optional but needed for clients that discover their credentials by OAuth, such as most desktop MCP clients). Standard flow on, everything else off, PKCE `S256`, valid redirect URI exactly `<broker.publicOrigin>/v1/oauth/keycloak-login/callback`, the audience scope attached as default. Its client id becomes `broker.tokenMint.clientId`. Setting it makes `broker.publicOrigin` and `broker.oauth21.existingStateKeySecret` mandatory. See "Operator setup: the MCP OAuth discovery bootstrap login client" in [Authentication](auth.md).
5. **Groups.** Create the groups that will receive permissions and the admin group. Group names are the keys of `entitlements.group_permissions`; the admin group is `broker.adminGroup`. If the broker should match a group by its full path (`/example/users`) rather than its name, set `broker.groupFullPath: true`.
6. **POSIX attributes** (only if a service needs the caller's uid/gid/unixname, for example home-directory access or job submission). The user profile attributes default to `uid`, `gid`, `unixname`; override `broker.posixAttributes.*` when your realm federates them under other names (for example `uidNumber`).

No groups claim mapper is needed on any client: group membership is read live from Keycloak, not from the token.

## 3. Vault or OpenBao (optional)

Skip this step if every store can stay in memory: single replica, no x509/krb5/servicex identity provider, no OAuth 2.1 linking that must survive a restart. Otherwise a Vault-compatible server with a KV v2 engine and the Kubernetes auth method is required. The chart does not deploy one.

The Vault-backed stores each live under one prefix, `<kvRoot>/<name>`, on the KV mount named by `broker.oauth21.tokenStore.vault.kvMount` (default `secret`):

`tokens`, `token-registry`, `principal-cache`, `maintenance-mode`, `x509`, `krb5`, `servicex`, `credmon`.

1. Enable KV v2 at the mount, if it is not already (`vault secrets enable -path=secret kv-v2`).
2. Enable the Kubernetes auth method (default mount `kubernetes`, value `broker.oauth21.tokenStore.vault.authMount`) and configure it for your cluster.
3. Write a policy granting the release its own subtree. Two releases sharing a KV mount must use different `kvRoot` values and different policies.

   ```hcl
   path "secret/data/af-mcp/*" {
     capabilities = ["create", "read", "update", "delete"]
   }
   path "secret/metadata/af-mcp/*" {
     capabilities = ["read", "list", "delete"]
   }
   ```

   Replace `secret` with your KV mount and `af-mcp` with your `kvRoot`. With HTCondor credmon enabled, [HTCondor Credmon](credmon.md) lists the extra grants.
4. Create a Kubernetes auth role bound to the broker's ServiceAccount (`<release>-af-mcp-platform` unless you set `serviceAccount.name`) in the release namespace, with that policy. Its name becomes `broker.oauth21.tokenStore.vault.authRole`.

Then, in values, select the stores that should be durable. Each is chosen separately; `kvRoot` is required as soon as any of them, or an x509, krb5-token or servicex-token identity provider, needs Vault:

```yaml
broker:
  vault:
    kvRoot: af-mcp
  oauth21:
    tokenStore:
      backend: vault
      vault:
        addr: https://vault.example.org
        authRole: af-mcp-broker
  tokenRegistry:
    backend: vault
  principalCache:
    backend: vault
  maintenanceMode:
    backend: vault        # or postgres
```

Changing `kvRoot` on a running release orphans the records stored under the old root.

## 4. Postgres (optional)

Needed for a durable usage store (`broker.usage.backend: postgres`) and, optionally, maintenance mode. With `in-memory` usage data is lost on restart and not shared between replicas.

1. Provide a database and a user that can create tables in its schema. With Crunchy PGO, the operator generates a `<cluster>-pguser-<user>` Secret whose `uri` key is exactly the DSN; see "Postgres via Crunchy PGO" in [Observability](observability.md).
2. Point `broker.usage.postgres.existingSecret.name` at that Secret (key `uri` by default).
3. Tell the NetworkPolicy generator which pods to allow: `broker.usage.postgres.networkPolicy.podSelector` (the labels of the Postgres pods; required), plus `namespace` (empty means the release namespace) and `port` (default 5432).

Maintenance mode on `postgres` reuses the usage DSN unless `broker.maintenanceMode.postgres.existingSecret` names another one. A separate database is unreachable while `networkPolicy.enabled` is true, because the egress rule is generated from the usage settings only.

## 5. Redis (needed for more than one replica)

The chart renders `replicaCount: 2` by default and refuses to render with more than one replica unless there is a shared store or you opt out with `broker.sharedState.allowPerReplicaState: true`. The unlock brute-force limiter, rate limits and the cache invalidation between replicas live on the store. Redis, Valkey, Dragonfly and KeyDB all work.

1. Provide the store. Put its URL (`redis://` or `rediss://`, with any password) in a Secret with key `url` and name it in `broker.sharedState.existingSecret.name`.
2. Declare its pods for the NetworkPolicy: `broker.sharedState.networkPolicy.podSelector` (required), `namespace`, `port`; or `cidr` for a managed instance outside the cluster.
3. If two releases share one store, give each its own `broker.sharedState.keyPrefix`. The default is `<release name>:`. A redis database number does not isolate releases from each other, because pub/sub ignores it.

## 6. Kubernetes Secrets

Create each Secret in the release namespace before installing. The names are yours; the **key** inside each is fixed by the chart.

| Values key naming the Secret | Required key in the Secret | Needed when |
| --- | --- | --- |
| `broker.keycloakAdmin.existingClientSecretSecret` | `keycloak-admin-client-secret` | always (the broker will not start without it) |
| `broker.tokenMint.existingClientSecretSecret` | `token-mint-client-secret` | the MCP OAuth bootstrap client is configured |
| `broker.oauth21.existingStateKeySecret` | `broker-state-key` | an `oauth21-direct` identity provider or the bootstrap client |
| `broker.identityToken.existingSigningKeySecret` | `signing-key.pem` | any `broker-issued`, `condor-token`, `krb5-token`, `servicex-token` or `x509` provider |
| `broker.identityToken.existingAdditionalPublicKeysSecret` | any `*.pem` | key rotation overlap |
| `broker.existingServiceTokenSecret` | `af-service-token` | a service uses the shared service token |
| `broker.usage.postgres.existingSecret.name` | `uri` (configurable) | Postgres usage store |
| `broker.sharedState.existingSecret.name` | `url` (configurable) | shared state |
| `broker.credmon.existingHtcondorApiTokenSecret` | `token` | credmon enabled |
| `broker.identityProviders[].existingClientSecretSecret` | `client-secret` | a confidential `oauth21-direct` provider |

Generating the two cryptographic ones:

```bash
# RS256 signing key (key name in the Secret: signing-key.pem)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing-key.pem

# Fernet key for the OAuth 2.1 state token (key name: broker-state-key)
openssl rand -base64 32 | tr '+/' '-_'
```

Create the Secrets however the cluster manages secrets (SealedSecrets, External Secrets, `kubectl create secret generic`). Do not commit plaintext.

## 7. The values file

Start from [`examples/example-values.yaml`](https://github.com/maniaclab/af-mcp-platform/blob/main/charts/af-mcp-platform/examples/example-values.yaml) and the [Chart Values Reference](values-reference.md).

### Values the schema requires

`values.schema.json` rejects a values file without these, at `helm lint`, `helm template` and `helm install`:

| Key | Notes |
| --- | --- |
| `oidc.issuer` | The realm URL, shared by the broker and the portal. |
| `portal.oidc.clientId` | The portal's public client. |
| `portal.brokerOrigin` | Usually `https://<mcpHost>`; also the portal's CSP `connect-src`. |
| `aggregator.services` | At least one service entry. |
| `entitlements.group_permissions` | At least one group. |
| `ingress.mcpHost`, `ingress.portalHost` | While `ingress.enabled` is true. |

### Values the chart or broker requires in combination

The "Caught by" column says where each combination is refused. A render failure names every missing key in one `helm` error (`values.schema.json`, plus a template check where a condition spans two selectors). The broker validates the same combinations at start as a backstop, and a pod that fails there goes into `CrashLoopBackOff` (the previous ReplicaSet keeps serving during a rollout).

| Condition | Required | Caught by |
| --- | --- | --- |
| always | `broker.keycloakAdmin.clientId` and its Secret | broker start |
| `broker.replicaCount` above 1 | `broker.sharedState.url` or `existingSecret.name`, or `allowPerReplicaState: true` | chart render and broker start |
| any Vault-backed store, or an x509, krb5-token or servicex-token provider | `broker.vault.kvRoot`, `broker.oauth21.tokenStore.vault.addr` and `authRole` | chart render |
| `broker.usage.backend: postgres` | `broker.usage.postgres.existingSecret.name` and `networkPolicy.podSelector` | chart render |
| `broker.maintenanceMode.backend: postgres` | `broker.maintenanceMode.postgres.existingSecret.name`, or `broker.usage.backend: postgres` with its secret (the DSN is reused) | chart render (template, since it spans two selectors) |
| an `oauth21-direct` provider | `broker.publicOrigin` (no trailing slash) and `broker.oauth21.existingStateKeySecret` | chart render; the trailing slash at broker start |
| `broker.tokenMint.clientId` | `broker.tokenMint.existingClientSecretSecret`, `broker.publicOrigin` and `broker.oauth21.existingStateKeySecret` | chart render |
| an x509 provider | `serviceUrl`, `voms`, the signing key, the Vault settings | chart render |
| a `broker-issued`, `condor-token`, `krb5-token`, `servicex-token` or x509 provider | `broker.identityToken.existingSigningKeySecret` | chart render |
| `broker.credmon.enabled` | `htcondorApiUrl`, `userDomain`, the token Secret | chart render |
| `broker.credmon.enabled` | a Vault-backed identity store | broker start |
| any OTLP signal enabled | `broker.otlp.endpoint` | chart render |
| a signing key and `ingress.enabled: false` | `broker.identityToken.issuer` | chart render |
| a service with a `required_permission` | some group in `entitlements.group_permissions` grants it | broker start |

Two values deserve a decision, not a copy:

- **`broker.identityToken.issuer`.** Backends verify the `iss` against the origin that serves the JWKS, which is the `mcpHost` origin. When empty, the chart sets the issuer to `https://<ingress.mcpHost>` if the ingress is enabled, and never falls back to `broker.publicOrigin` (it can be the portal origin). With the ingress disabled and a signing key set the value is required. Set it explicitly when the JWKS is served from another origin.
- **`broker.adminGroup`.** Empty means nobody is an admin. Set it before relying on maintenance mode, which an admin-less broker cannot turn off through the API.

### Network policy values

`networkPolicy.enabled` is true by default. The chart generates the broker's egress rules from the URLs it connects to, so the work is telling it what a URL cannot say:

- **Every in-cluster URL** needs an entry under `networkPolicy.egress.endpoints`, keyed by the host part of the URL (no scheme, no port), with a `podSelector` of the labels of the pods behind the Service. The render fails naming the host otherwise, so a rule never opens a whole namespace by accident. A single-label host (`http://svc:8080`) is a Service in the release namespace; `<service>.<namespace>.svc[.cluster.local]` names its namespace.
- **The pod port, not the Service port.** A NetworkPolicy matches the port the pod listens on, after the Service has translated it. When a URL carries the Service port and the pod port differs, set `targetPort` on the endpoint entry.
- **External hosts** share one rule to public addresses, on port 443 and the port of each external URL. Put your own node ranges in `networkPolicy.egress.external.exceptCidrs` (IPv4 and IPv6 together) so that rule cannot reach host-network services such as the kubelet or sshd.
- **Address families.** `networkPolicy.ipFamilies` defaults to `[IPv4, IPv6]`; a single-stack cluster lists one.
- **Who may reach the broker.** `networkPolicy.ingress.broker.sources` replaces its default list (the stock `ingress-nginx` namespace on 8080, a `monitoring` namespace on 9090); set it to your ingress controller's namespace and labels and your Prometheus namespace. `networkPolicy.ingress.portal.sources` does the same for the portal.
- **JWKS clients.** In-cluster services that fetch `/.well-known/jwks.json` (token services and backends that verify broker-signed tokens) are allowed in automatically, derived from the same URLs. `networkPolicy.ingress.broker.jwks.generate: false` turns that off.
- **Anything else** goes in `networkPolicy.egress.extraEgress` or `networkPolicy.ingress.broker.extraIngress`, written as plain NetworkPolicy rules; an `ipBlock` covers one address family, so add an IPv6 twin next to each IPv4 block.
- **The CNI must enforce NetworkPolicy.** If it does not, or you manage policies yourself, set `networkPolicy.enabled: false`.

## 8. Render and lint before installing

The cheapest way to find a missing value is to render the chart. Nothing here touches the cluster.

```bash
helm lint charts/af-mcp-platform -f my-values.yaml
helm template af-mcp charts/af-mcp-platform -f my-values.yaml > rendered.yaml
```

The commands use the chart directory of a checkout of this repository; use whatever chart source your deployment pulls from in its place. Every failure is a message that names the key (see [Failure modes](#failure-modes)). Read the rendered `NetworkPolicy` objects, the `ConfigMap`s for `policy.yaml` and `services.yaml`, and the Ingress hosts once before the first install.

## 9. Install

```bash
helm install af-mcp charts/af-mcp-platform \
  --namespace af-mcp --create-namespace \
  -f my-values.yaml
```

Or declare the same chart and values in a Flux `HelmRelease` or an Argo CD application. The chart's own `NOTES.txt` prints the endpoints and the remaining checks.

Wait for both Deployments:

```bash
kubectl -n af-mcp rollout status deploy/af-mcp-af-mcp-platform-broker
kubectl -n af-mcp rollout status deploy/af-mcp-af-mcp-platform-portal
```

A broker that does not become ready: read its log first (`kubectl -n af-mcp logs deploy/af-mcp-af-mcp-platform-broker`); startup validation prints the setting it refused.

## 10. Verify

### Health

The broker serves `/v1/healthz` (liveness) and `/v1/readyz`, which is ready only when the Keycloak JWKS is reachable. Both are routed through the ingress and need no credential.

```bash
curl -fsS https://mcp.af.example.org/v1/healthz
curl -fsS https://mcp.af.example.org/v1/readyz
curl -fsS https://mcp.af.example.org/.well-known/jwks.json   # 503 unless a signing key is configured
```

A `503 not_ready` from `readyz` with `jwks_reachable: false` means the broker cannot reach Keycloak: usually a NetworkPolicy or the hairpin case below.

### The API surface

`/openapi.json` and `/docs` are served by the broker pod and are not routed by the ingress. Reach them through a port-forward:

```bash
kubectl -n af-mcp port-forward svc/af-mcp-af-mcp-platform-broker 8080:8080 &
curl -fsS http://127.0.0.1:8080/openapi.json | head -c 200
```

Stop the port-forward when done.

### A tool call

With a bearer token for any user of the realm (see [Connecting a Client](connecting-a-client.md)), call the gateway's own `af_whoami` tool. It needs no linked identity and shows your subject, groups and effective permissions:

```bash
read -s -p "Bearer token: " MCP_BEARER_TOKEN
export MCP_BEARER_TOKEN
pixi run -e dev python scripts/verify-mcp-flow.py \
  --broker-url https://mcp.af.example.org \
  --call af_whoami
```

The script lists every tool the caller can see first. An empty list for a user who should have access means no group grants a permission any service requires. Then call a tool of a real backend to prove the broker reaches it.

### NetworkPolicy

The chart renders `<fullname>-broker` and `<fullname>-portal` policies. Confirm they exist and select the pods:

```bash
kubectl -n af-mcp get networkpolicy
kubectl -n af-mcp describe networkpolicy af-mcp-af-mcp-platform-broker
```

Then prove each dependency is reachable from the broker pod, which is what the policy actually decides. A refused connection means the packet reached a pod (check the port); a timeout means the policy dropped it.

```bash
kubectl -n af-mcp exec deploy/af-mcp-af-mcp-platform-broker -- \
  /app/.pixi/envs/broker/bin/python -c \
  "import socket; socket.create_connection(('auth.af.example.org', 443), 5); print('ok')"
```

The interpreter path is spelled out because `kubectl exec` bypasses the image entrypoint, so `python` is not on `PATH`. Repeat for Keycloak (or `broker.oidc.internalUrl`), Vault, Postgres, Redis and each backend in `aggregator.services`.

### First user

A user opens `https://portal.af.example.org`, signs in, and links any identities their services need from the Identities page. Until a user links an identity a service requires, its tools are visible but fail with a "not linked" error; that is a policy outcome, not an outage.

## Upgrades

1. Read the release notes for breaking values changes. Chart breaking changes are marked `!` in the commit title.
2. Render the new chart against your existing values file before touching the cluster: `helm template ... -f my-values.yaml`. This is the migration check, and it needs no cluster.
3. Fix what it reports, then `helm upgrade`.

**How the schema catches stale keys.** `values.schema.json` sets `additionalProperties: false` on every block of values, so a key the chart no longer reads, or that you misspelled, fails the render instead of being silently ignored:

```text
Error: values don't meet the specifications of the schema(s) in the following chart(s):
af-mcp-platform:
- at '/broker': additional properties 'keycloakAdmn' not allowed
```

Several errors are reported together. Types are checked too (`replicaCount: abc` fails). The schema is part of the chart version you render, so a stale key surfaces on the first render against the new chart.

Removed values that now fail, and what replaced them:

| Removed | Use instead |
| --- | --- |
| every `kvPathPrefix` key (token store, token registry, principal cache, maintenance mode) and `x509KvPathPrefix`, `krb5KvPathPrefix`, `servicexKvPathPrefix`, `credmonKvPathPrefix` | one `broker.vault.kvRoot` (records under the old prefixes are not moved; copy them in Vault if they must survive) |
| `networkPolicy.broker.servicePorts`, and the `clusterName` and `namespaceSelector` keys of the Postgres and shared-state `networkPolicy` blocks | `networkPolicy.egress.endpoints` with `podSelector` and `targetPort`; `broker.usage.postgres.networkPolicy` and `broker.sharedState.networkPolicy` take the same peer shape |
| `broker.tracing.endpoint`, `broker.tracing.networkPolicy` | `broker.otlp.endpoint`, shared by every OTLP signal (these two keys fail the render with a message naming the replacement) |
| built-in facility defaults for hosts, TLS Secret names, cert-manager issuer, home-directory PVC and Grafana namespace | set them in your values (`ingress.*`, `grafanaDashboard.namespace`); TLS Secret names derive from the release when left empty |

## Failure modes

### Missing required value

`helm template`, `helm lint` and `helm install` all stop with the schema error before rendering anything:

```text
- at '/oidc/issuer': minLength: got 0, want 1
- at '/ingress/mcpHost': minLength: got 0, want 1
- at '/portal/oidc/clientId': minLength: got 0, want 1
- at '/portal/brokerOrigin': minLength: got 0, want 1
- at '/entitlements/group_permissions': minProperties: got 0, want 1
- at '/aggregator/services': minItems: got 0, want 1
```

Template-level guards follow once the schema passes. The message names the key:

| Message starts with | Fix |
| --- | --- |
| `broker.replicaCount > 1 requires broker.sharedState.url` | set the shared store (step 5) or `allowPerReplicaState: true` |
| `broker.vault.kvRoot is required when a Vault-backed store is configured` | set `broker.vault.kvRoot` (step 3) |
| `"<host>" (from "<url>") is in-cluster namespace "<ns>": set networkPolicy.egress.endpoints.<host>.podSelector` | add the endpoint entry with the pods' labels |
| `<...>.podSelector is required: set it to the labels of the store's pods` | set `podSelector` under the Postgres or shared-state `networkPolicy` |
| `cannot derive a NetworkPolicy rule from "<url>"` | the URL has no host, or no port and an unknown scheme: add the port |
| `broker.otlp.endpoint is required when ...` | set the collector endpoint or disable the signal |
| `an x509 identityProviders entry needs serviceUrl` / `voms` | add the missing field |

Broker start-up failures show in the pod log, not at render time (Keycloak admin client unset; `VAULT_ADDR` or `VAULT_AUTH_ROLE` unset with a Vault store; `BROKER_PUBLIC_ORIGIN` missing or with a trailing slash; a service whose `required_permission` no group grants; an `auth_type: x509` service with no x509 entry). The message names the setting.

### A NetworkPolicy blocks something

Symptoms: timeouts (not refusals) from the broker to Keycloak, Vault, a backend or a store; `readyz` returning `not_ready`; a service missing from the catalog.

1. Find the failing destination from the broker log, then run the connectivity check from step 10 against it.
2. Compare it with the rendered rules: `helm template ... | grep -B2 -A30 'kind: NetworkPolicy'`, or `kubectl -n af-mcp get networkpolicy <name> -o yaml`.
3. A timeout to an in-cluster Service usually means a missing or wrong `networkPolicy.egress.endpoints.<host>` entry; a refusal usually means the pod port differs from the Service port (set `targetPort`).
4. To rule the generated policy in or out, set `networkPolicy.egress.generate: false` for one rollout (DNS and `extraEgress` remain). If the failure goes away, the generated rule is the cause. Restore it.
5. Policies are additive. Anything allowed by any policy selecting the pod is allowed, so a stale extra policy can hide a missing rule in the chart's own.

### Pod port versus Service port

A Service maps its port to a pod port; a NetworkPolicy sees only the pod port. The broker Service exposes 8080 and 9090 and the portal Service 8081, and the pods listen on the same numbers. A backend such as `http://rucio-mcp.mcp.svc.cluster.local:80/mcp` whose Service port 80 maps to pod port 9000 needs `targetPort: 9000` on its endpoint entry. The URL keeps the Service port; the policy needs the pod port.

### Public hostnames that resolve into the cluster (hairpin)

A URL naming a public hostname whose load-balancer IP is served by an ingress controller or gateway in the same cluster does not match the generated public-internet rule: kube-proxy rewrites the destination to a pod IP before policy runs, so the packet looks like pod-to-pod traffic. Symptoms are timeouts to that hostname only, from inside the cluster, while it works from outside.

Fix, in order of preference:

- Point the URL at the in-cluster Service instead (`broker.oidc.internalUrl` exists for exactly this, for Keycloak).
- Or declare the host under `networkPolicy.egress.endpoints` with `namespace`, `targetPort` and the `podSelector` of the controller pods, as in the example values.

### Stale policies and `prune: false`

Deleting a NetworkPolicy from the chart's output, or from your own manifests, does not delete the object when the tool applying it does not prune. In a Flux `Kustomization` with `prune: false`, removing a file from the repository leaves the object live and still allowing traffic. Helm itself removes objects a chart stops rendering, but extra policies you keep outside the chart do not get that treatment.

After removing or renaming a policy, list what is live and delete what you no longer declare:

```bash
kubectl -n af-mcp get networkpolicy
kubectl -n af-mcp delete networkpolicy <stale-name>
```

### Login works, every API call returns 401

The token's `aud` or `iss` does not match what the broker validates. Check that the audience scope is attached to the portal client as a default scope, that `portal.oidc.scope` includes it, that `broker.oidc.audience` equals the mapper's audience, and that the portal and broker use the same `oidc.issuer` (they share the one value).

### Every user authenticates and no tool is visible

No group in `entitlements.group_permissions` matches the user's Keycloak groups (names versus full paths: see `broker.groupFullPath`), or the groups grant no permission any service requires. Call `af_whoami` to see the groups and permissions the broker resolved.
