# Chart Values Reference

Every value of the `af-mcp-platform` Helm chart: its key path, type, default,
whether it must be set, and a one-line description. The full explanation of a
value is the comment above it in
[`values.yaml`](https://github.com/maniaclab/af-mcp-platform/blob/main/charts/af-mcp-platform/values.yaml).
For the order in which to set them, see the
[Deployment Runbook](deployment-runbook.md).

This page is generated from `values.yaml` and `values.schema.json`; do not edit
it. Regenerate it with `pixi run -e dev python scripts/gen-values-reference.py`.
A test fails when it is stale.

"Required" is what `values.schema.json` enforces at `helm template`/`helm install`
time. Values that are required only by a combination of other values (for
example `broker.vault.kvRoot` once a Vault-backed store is selected) are
explained in the Deployment Runbook.

## `global`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `global` | object | `{}` | no | Helm's reserved key for values shared with subcharts. |

## `image`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `image.registry` | string | `"ghcr.io/maniaclab"` | no | Container registry (with any organisation path) both images are pulled from. |
| `image.broker.repository` | string | `"af-mcp-platform-broker"` | no | Name of the broker image within the registry. |
| `image.broker.tag` | string | `""` | no | Tag of the broker image; defaults to .Chart.AppVersion when empty. |
| `image.broker.pullPolicy` | `Always`, `IfNotPresent`, `Never` | `"IfNotPresent"` | no | Kubernetes imagePullPolicy of the broker container. |
| `image.portal.repository` | string | `"af-mcp-platform-portal"` | no | Name of the portal image within the registry. |
| `image.portal.tag` | string | `""` | no | Tag of the portal image; defaults to .Chart.AppVersion when empty. |
| `image.portal.pullPolicy` | `Always`, `IfNotPresent`, `Never` | `"IfNotPresent"` | no | Kubernetes imagePullPolicy of the portal container. |

## `imagePullSecrets`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `imagePullSecrets` | array | `[]` | no | List of imagePullSecrets to add to all pods (name references only) |

## `nameOverride`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `nameOverride` | string | `""` | no | Replaces the chart name in the names of the resources the chart renders. |

## `fullnameOverride`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `fullnameOverride` | string | `""` | no | Replaces the whole generated resource name (release name plus chart name). |

## `serviceAccount`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `serviceAccount.create` | boolean | `true` | no | Whether the chart renders the ServiceAccount; false uses an existing one. |
| `serviceAccount.name` | string | `""` | no | Name of the ServiceAccount; if empty and create is true, a name is generated using the fullname template. |
| `serviceAccount.annotations` | object | `{}` | no | Annotations added to the rendered ServiceAccount. |

## `oidc`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `oidc.issuer` | string | `""` | yes | Realm URL of the OIDC issuer that both the broker and the portal trust, e.g. "`https://keycloak.example.com/realms/your-realm`". |

## `broker`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `broker.replicaCount` | integer | `2` | no | Number of broker pods. More than one needs broker.sharedState (or sharedState.allowPerReplicaState) so the replicas agree on shared state. |
| `broker.builtinServiceName` | string | `""` | no | Name of the builtin gateway service (issue #240) -- the entry the registry self-registers for the broker's own af_* methods (af_whoami, af_usage, ...), used as its catalog identity and its ... |
| `broker.adminGroup` | string | `""` | no | Keycloak group whose members see and can use admin-only broker surfaces (the Admin portal page, the usage-for-other-users view, maintenance mode). |
| `broker.accessGroups` | array | `[]` | no | Groups that gate the whole platform: a user holding ANY listed group (case insensitive, exact match -- a subgroup member must be listed explicitly, because the directory reports only direct ... |
| `broker.admin.userDisplayName.attributes` | array | `[firstName, lastName]` | no | Keycloak user fields (e.g. firstName, lastName) or custom user attributes joined with spaces into the name the search shows and matches on. |
| `broker.mcpStatelessHttp` | boolean | `true` | no | Whether the /mcp aggregator runs Streamable HTTP statelessly (issue #128). |
| `broker.resources.requests.cpu` | string | `"100m"` | no | CPU and memory requests and limits of the broker container. |
| `broker.resources.requests.memory` | string | `"256Mi"` | no | CPU and memory requests and limits of the broker container. |
| `broker.resources.limits.cpu` | string | `"2"` | no | CPU and memory requests and limits of the broker container. |
| `broker.resources.limits.memory` | string | `"2Gi"` | no | CPU and memory requests and limits of the broker container. |
| `broker.env` | object | `{}` | no | Extra environment variables merged into the broker container. |
| `broker.oidc.audience` | string | `"mcp-gateway"` | no | Resource-server audience (`aud`) the broker requires in every token it validates. |
| `broker.oidc.internalUrl` | string | `""` | no | Realm URL for the broker's server-to-server (back-channel) Keycloak calls — JWKS, token endpoint, Admin REST API, brokered-token fetch — independent of the top-level `oidc.issuer` used for `iss` ... |
| `broker.existingServiceTokenSecret` | string | `""` | no | Name of a pre-existing Secret providing the AF service token. |
| `broker.tokenMint.clientId` | string | `""` | no | Client id of the confidential client. Not a secret -- a plain value, like portal.oidc.clientId above. |
| `broker.tokenMint.existingClientSecretSecret` | string | `""` | no | Name of a pre-existing Secret providing the client secret. |
| `broker.keycloakAdmin.clientId` | string | `""` | no | Client id of the confidential client. Not a secret -- a plain value. |
| `broker.keycloakAdmin.existingClientSecretSecret` | string | `""` | no | Name of a pre-existing Secret providing the client secret. |
| `broker.posixAttributes.uid` | string | `"uid"` | no | Keycloak user-profile attribute holding the POSIX uid. |
| `broker.posixAttributes.gid` | string | `"gid"` | no | Keycloak user-profile attribute holding the POSIX gid. |
| `broker.posixAttributes.unixname` | string | `"unixname"` | no | Keycloak user-profile attribute holding the POSIX unix account name. |
| `broker.groupFullPath` | boolean | `false` | no | Whether the PAT path (KeycloakPrincipalDirectory) matches a Keycloak group by its full `path` (e.g. "/examplevo/users") instead of its bare `name` (e.g. "users") -- issue #148. |
| `broker.cimd.clientName` | string | `""` | no | Human-readable `client_name` published in the CIMD document; empty publishes none. |
| `broker.publicOrigin` | string | `""` | no | Canonical origin (scheme + host, no trailing slash, e.g. "`https://mcp-portal.af.example.org`") for every externally-visible OAuth 2.1 URL the broker constructs itself: the redirect_uri sent to a ... |
| `broker.identityProviders` | array | `[]` | no | Identity providers — one entry per identity provider the broker can link a user's account to, either Keycloak's stored-broker-token pattern (type: keycloak-brokered, e.g. a VO IAM) or the broker ... |
| `broker.identityToken.existingSigningKeySecret` | string | `""` | no | Name of a pre-existing Secret providing the RS256 private key PEM. |
| `broker.identityToken.existingAdditionalPublicKeysSecret` | string | `""` | no | Optional pre-existing Secret of ADDITIONAL public key PEMs published in the JWKS alongside the active key, for rotation overlap: publish the successor key here before switching signing to it, and ... |
| `broker.identityToken.issuer` | string | `""` | no | `iss` claim minted into every token. Consumers verify it against the origin that serves the broker's JWKS, the MCP host. |
| `broker.identityToken.ttlSeconds` | string / integer | `""` | no | Token TTL in seconds. Empty means the broker default (600). |
| `broker.credmon.enabled` | boolean | `false` | no | Whether the broker syncs per-user credmon top tokens into the facility's credd. |
| `broker.credmon.htcondorApiUrl` | string | `""` | no | Base URL of htcondor-api, e.g. `http://condor-mcp.mcp.svc.cluster.local:8080` |
| `broker.credmon.userDomain` | string | `""` | no | The pool's user domain (HTCondor UID_DOMAIN, e.g. "af.example.org"): credd only accepts the user a credential is stored for as <unixname>@<domain>. |
| `broker.credmon.existingHtcondorApiTokenSecret` | string | `""` | no | Name of a pre-existing Secret with key `token`: the bearer token the broker presents to htcondor-api. |
| `broker.credmon.servicePrefix` | string | `""` | no | Prefix of the credd service names: jobs request `use_oauth_services = af_krb5, af_x509`. |
| `broker.credmon.kinds` | array | `[]` | no | Kinds to sync (subset of x509, krb5, servicex). |
| `broker.credmon.topTokenTtlSeconds` | string / integer | `""` | no | Lifetime of each top token in seconds. Empty means broker defaults: 86400s top-token TTL, 14400s interval. |
| `broker.credmon.syncIntervalSeconds` | string / integer | `""` | no | Seconds between syncs of every user's top tokens; empty means the broker default (14400). |
| `broker.credmon.prometheusRule.enabled` | boolean | `false` | no | Alert when no replica has finished a sync for 2x the interval. |
| `broker.credmon.prometheusRule.namespace` | string | `""` | no | Namespace for the PrometheusRule; defaults to the release namespace. |
| `broker.credmon.prometheusRule.labels` | object | `{}` | no | Extra labels so your Prometheus' ruleSelector picks the rule up. |
| `broker.vault.kvRoot` | string | `""` | no | Root path under oauth21.tokenStore.vault.kvMount from which the broker derives the KV-v2 prefix of every Vault-backed store: tokens, token-registry, principal-cache, maintenance-mode, x509, krb5, ... |
| `broker.oauth21.existingStateKeySecret` | string | `""` | no | Name of a pre-existing Secret providing the Fernet key (urlsafe- base64-encoded 32 bytes) that encrypts the OAuth 2.1 linking flow's `state` token. |
| `broker.oauth21.stateIssuer` | string | `""` | no | `iss`/`aud` self-reference embedded in the state token. |
| `broker.oauth21.tokenStore.backend` | `in_memory`, `in-memory`, `vault` | `"in-memory"` | no | Where OAuth 2.1 credentials are stored: "in-memory" or "vault". |
| `broker.oauth21.tokenStore.vault.addr` | string | `""` | no | Vault HTTP API base URL, e.g. `https://vault.example.com`. |
| `broker.oauth21.tokenStore.vault.authMount` | string | `"kubernetes"` | no | Vault auth mount point for the Kubernetes auth method. |
| `broker.oauth21.tokenStore.vault.authRole` | string | `""` | no | Vault role the broker's ServiceAccount JWT is exchanged against. |
| `broker.oauth21.tokenStore.vault.kvMount` | string | `"secret"` | no | Vault KV-v2 secrets engine mount point. |
| `broker.tokenRegistry.backend` | `in_memory`, `in-memory`, `vault` | `"in-memory"` | no | Where the token registry is stored: "in-memory" or "vault". |
| `broker.principalCache.backend` | `in_memory`, `in-memory`, `vault` | `"in-memory"` | no | Where the principal cache is stored: "in-memory" or "vault". |
| `broker.metering.backend` | `in_process`, `in-process`, `inline` | `"in-process"` | no | Transport carrying success/error audit records from the tool-call hot path to the metering worker that measures and writes them (broker metering.py). |
| `broker.usage.backend` | `in_memory`, `in-memory`, `postgres` | `"in-memory"` | no | Where usage records are stored: "in-memory" or "postgres". |
| `broker.usage.batchMax` | integer | `100` | no | The metering worker buffers usage records and writes them to the store as one batch (one round trip, not one per tool call) once batchMax records are buffered or batchIntervalMs have passed since the ... |
| `broker.usage.batchIntervalMs` | integer | `1000` | no | Longest time in milliseconds a usage record waits in the buffer before its batch is written. |
| `broker.usage.retentionDays` | integer | `365` | no | Days of raw usage rows kept in the events table (Postgres backend only). |
| `broker.usage.rollupIntervalSeconds` | integer | `3600` | no | Seconds between attempts of the retention rollup job. |
| `broker.usage.postgres.existingSecret.name` | string | `""` | no | Secret carrying the asyncpg DSN, rendered as USAGE_POSTGRES_DSN via secretKeyRef only when backend="postgres". |
| `broker.usage.postgres.existingSecret.key` | string | `"uri"` | no | Secret carrying the asyncpg DSN, rendered as USAGE_POSTGRES_DSN via secretKeyRef only when backend="postgres". |
| `broker.usage.postgres.networkPolicy.namespace` | string | `""` | no | Namespace of the postgres pods; empty means the release namespace. |
| `broker.usage.postgres.networkPolicy.port` | integer | `5432` | no | Port of the postgres pods. |
| `broker.sharedState.url` | string | `""` | no | URL of the shared store (redis:// or rediss://), rendered as SHARED_STATE_URL. |
| `broker.sharedState.existingSecret.name` | string | `""` | no | Secret carrying the URL, rendered as SHARED_STATE_URL via secretKeyRef. |
| `broker.sharedState.existingSecret.key` | string | `"url"` | no | Secret carrying the URL, rendered as SHARED_STATE_URL via secretKeyRef. |
| `broker.sharedState.keyPrefix` | string | `""` | no | Prefix on every key and pub/sub channel the broker uses on the store, rendered as SHARED_STATE_KEY_PREFIX. |
| `broker.sharedState.allowPerReplicaState` | boolean | `false` | no | Explicit opt-in to replicaCount > 1 with no shared store. |
| `broker.sharedState.networkPolicy.cidr` | string | `""` | no | CIDR of an instance outside the cluster; replaces namespace and podSelector. |
| `broker.sharedState.networkPolicy.namespace` | string | `""` | no | Namespace of the store's pods; empty means the release namespace. |
| `broker.sharedState.networkPolicy.port` | integer | `6379` | no | Port of the store. |
| `broker.maintenanceMode.backend` | `in_memory`, `in-memory`, `vault`, `postgres` | `"in-memory"` | no | Where the maintenance flag is stored: "in-memory", "vault" or "postgres". |
| `broker.maintenanceMode.cacheTtlSeconds` | number | `5` | no | Seconds each replica caches the flag in-process (rendered as MAINTENANCE_MODE_CACHE_TTL_SECONDS). |
| `broker.maintenanceMode.postgres.existingSecret.name` | string | `""` | no | Secret carrying the asyncpg DSN, rendered as MAINTENANCE_MODE_POSTGRES_DSN via secretKeyRef only when backend="postgres" and this is set. |
| `broker.maintenanceMode.postgres.existingSecret.key` | string | `"uri"` | no | Secret carrying the asyncpg DSN, rendered as MAINTENANCE_MODE_POSTGRES_DSN via secretKeyRef only when backend="postgres" and this is set. |
| `broker.otlp.endpoint` | string | `""` | no | OTLP/HTTP collector base URL (the SDK appends each signal's /v1/<signal> path itself), e.g. `http://otel-collector.observability.svc:4318`. |
| `broker.otlp.headers.value` | string | `""` | no | Request headers for the collector, rendered as OTEL_EXPORTER_OTLP_HEADERS ("k1=v1,k2=v2") for every signal. |
| `broker.otlp.headers.existingSecret.name` | string | `""` | no | Secret whose `key` holds the whole header string, rendered through secretKeyRef. |
| `broker.otlp.headers.existingSecret.key` | string | `"headers"` | no | Secret whose `key` holds the whole header string, rendered through secretKeyRef. |
| `broker.tracing.enabled` | boolean | `false` | no | OpenTelemetry trace EMISSION (broker tracing.py, observability roadmap PR D). |
| `broker.tracing.sampleRatio` | string / number | `""` | no | Head sampling ratio in [0, 1]. When set, rendered as OTEL_TRACES_SAMPLER=parentbased_traceidratio with OTEL_TRACES_SAMPLER_ARG=<ratio>; empty means the SDK default (parentbased_always_on, i.e. every ... |
| `broker.metrics.otlp.enabled` | boolean | `false` | no | OpenTelemetry aggregate METRICS emission over OTLP (broker otel_metrics.py): calls, errors, duration and result-size sums by service, method, action_type and outcome -- never per-user. |
| `broker.usageEvents.otlp.enabled` | boolean | `false` | no | Per-call usage records emitted as OpenTelemetry LOG records over OTLP (broker usage/otel_events.py), beside the usage store above, which stays authoritative. |
| `broker.usage.postgres.networkPolicy.podSelector` | object |  | no | The postgres pods for the broker's NetworkPolicy egress rule (rendered only when backend="postgres" and networkPolicy.enabled). |
| `broker.sharedState.networkPolicy.podSelector` | object |  | no | The store for the broker's NetworkPolicy egress rule (rendered only when `url` or `existingSecret.name` is set and networkPolicy.enabled). |

## `tokenSweep`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `tokenSweep.enabled` | boolean | `false` | no | Deploys the CronJob below. Only useful when broker.tokenRegistry.backend="vault" — the CronJob's container refuses to run otherwise (see token_sweep.py). |
| `tokenSweep.schedule` | string | `"17 3 * * *"` | no | Cron schedule of the sweep, in standard cron syntax evaluated in the cluster's local time zone. |
| `tokenSweep.graceSeconds` | string / integer | `""` | no | Grace window (seconds) a record is kept after its expires_at passes, before the sweep removes it — see broker's TOKEN_SWEEP_GRACE_SECONDS (config.py). |

## `aggregator`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `aggregator.services` | array | `[]` | yes | The backend MCP services the aggregator serves, one ServiceSpec object per service, passed verbatim into services.yaml. |

## `entitlements`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `entitlements.group_permissions` | object | `{}` | yes | Maps each Keycloak group to the permissions its members get, rendered into policy.yaml (mounted at /etc/af-mcp/policy.yaml). |
| `entitlements.custom_permissions` | object | `{}` | no | Permissions your services.yaml `required_permission` uses that the broker doesn't ship, each with its action type (read \| state_change). |
| `entitlements.target_action_types` | object | `{}` | no | Per-tool action_type overrides (read \| state_change). |
| `entitlements.rate_limits` | array | `[]` | no | Per-principal call budgets. Each rule sets action_type (read \| state_change) and/or tool (fnmatch glob over the wire tool name), plus limit and window_seconds; every matching rule must pass. |

## `portal`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `portal.replicaCount` | integer | `2` | no | Number of portal pods. |
| `portal.resources.requests.cpu` | string | `"50m"` | no | CPU and memory requests and limits of the portal container. |
| `portal.resources.requests.memory` | string | `"128Mi"` | no | CPU and memory requests and limits of the portal container. |
| `portal.resources.limits.cpu` | string | `"500m"` | no | CPU and memory requests and limits of the portal container. |
| `portal.resources.limits.memory` | string | `"512Mi"` | no | CPU and memory requests and limits of the portal container. |
| `portal.oidc.clientId` | string | `""` | yes | Client id of the portal's public OIDC client, e.g. "your-portal-client": Client Authentication OFF, Standard flow ON, PKCE S256 required. |
| `portal.oidc.scope` | string | `"openid profile email"` | no | OAuth scopes the portal requests at login. |
| `portal.oidc.extraAuthorizeParams` | object | `{}` | no | Extra static query params forwarded to Keycloak's authorize endpoint on login (auth.ts's login()). |
| `portal.brokerOrigin` | string | `""` | yes | Origin the SPA calls for the broker's /v1 and /mcp paths, and what the portal's CSP connect-src allows. |
| `portal.branding.shortName` | string | `""` | no | Short mark in the sidebar/topbar logo, e.g. "Example AF Ops". |
| `portal.branding.fullName` | string | `""` | no | Full name, used in the logo links' aria-label ("<fullName> home"). |
| `portal.branding.facilityName` | string | `""` | no | Facility/institution name shown in the overview hero and footer. |
| `portal.branding.facilityUrl` | string | `""` | no | Optional http(s) URL of the facility's website. |
| `portal.branding.accentColor` | string | `""` | no | Optional accent colour as "#rrggbb", e.g. "#800000". |
| `portal.branding.accentColorDark` | string | `""` | no | Optional accent colour for the dark theme, as "#rrggbb". |

## `ingress`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `ingress.enabled` | boolean | `true` | no | Whether the chart renders the Ingress objects for the broker and portal hosts. |
| `ingress.className` | string | `"nginx"` | no | IngressClass the Ingress objects use. |
| `ingress.mcpHost` | string | `""` | when `ingress.enabled` is `true` | FQDN for the broker (REST + MCP) endpoints. |
| `ingress.portalHost` | string | `""` | when `ingress.enabled` is `true` | FQDN for the portal (static site). REQUIRED while ingress.enabled is true. |
| `ingress.annotations` | object | `{}` | no | Extra annotations merged onto the Ingress, e.g. the cert-manager ClusterIssuer that issues the TLS certificates |
| `ingress.tls.enabled` | boolean | `true` | no | Whether the Ingress terminates TLS with the secrets named below. |
| `ingress.tls.mcpSecretName` | string | `""` | no | Secret name for the broker TLS certificate (e.g. managed by cert-manager); empty derives "<fullname>-mcp-tls". |
| `ingress.tls.portalSecretName` | string | `""` | no | Secret name for the portal TLS certificate; empty derives "<fullname>-portal-tls". |

## `networkPolicy`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `networkPolicy.enabled` | boolean | `true` | no | Master switch. false renders no NetworkPolicy objects at all. |
| `networkPolicy.ipFamilies` | array | `[IPv4, IPv6]` | no | Address families the pods use. Every ipBlock the chart renders (the public-internet rule) is emitted once per family listed, and `egress.external.exceptCidrs` are split by family automatically (an ... |
| `networkPolicy.egress.generate` | boolean | `true` | no | Generate the egress rules from the URLs the broker connects to (see below). |
| `networkPolicy.egress.endpoints` | object | `{}` | no | What a URL cannot say, per host (the host part of the URL, no scheme or port). |
| `networkPolicy.egress.external.exceptCidrs` | array | `[]` | no | CIDRs the public rule must not reach, in addition to RFC-1918, IPv6 ULA (fc00::/7, which includes the pod range), link-local and the cloud metadata address (169.254.169.254/32), which are always ... |
| `networkPolicy.egress.extraEgress` | array | `[]` | no | NetworkPolicy egress rules appended verbatim to the broker's policy, for destinations no URL in these values names (a public hostname with no URL, a node service such as an S3 NodePort or an XCache, ... |
| `networkPolicy.ingress.broker.sources` | array | see `values.yaml` | no | Who may reach the broker pods (API and MCP on 8080, metrics on 9090). |
| `networkPolicy.ingress.broker.jwks.generate` | boolean | `true` | no | The in-cluster clients that fetch the broker's /.well-known/jwks.json (the identity providers' token services and the backends that verify a broker-signed token) may reach the API port (8080). |
| `networkPolicy.ingress.broker.extraIngress` | array | `[]` | no | NetworkPolicy ingress rules appended verbatim. |
| `networkPolicy.ingress.portal.sources` | array | see `values.yaml` | no | Who may reach the portal pods (port 8081). |
| `networkPolicy.ingress.portal.extraIngress` | array | `[]` | no | NetworkPolicy ingress rules appended verbatim. |

## `serviceMonitor`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `serviceMonitor.enabled` | boolean | `false` | no | Whether the chart renders the ServiceMonitor. |
| `serviceMonitor.interval` | string | `"30s"` | no | Prometheus scrape interval. |
| `serviceMonitor.namespace` | string | `""` | no | Namespace for the ServiceMonitor resource; defaults to the release namespace. |

## `prometheusRule`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `prometheusRule.enabled` | boolean | `false` | no | Alerts when a backend advertises tools but none of them carry its service's prefix (callers see zero tools; see docs/adding-a-service.md). |
| `prometheusRule.namespace` | string | `""` | no | Namespace for the PrometheusRule; defaults to the release namespace. |
| `prometheusRule.labels` | object | `{}` | no | Extra labels so your Prometheus' ruleSelector picks the rule up. |

## `grafanaDashboard`

| Key | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `grafanaDashboard.enabled` | boolean | `false` | no | Whether the chart renders the Grafana dashboard ConfigMap. |
| `grafanaDashboard.namespace` | string | `""` | no | Namespace where the ConfigMap is deployed; empty uses the release namespace. |
