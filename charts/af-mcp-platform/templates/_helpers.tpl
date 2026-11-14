{{/*
Expand the name of the chart.
*/}}
{{- define "af-mcp-platform.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "af-mcp-platform.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "af-mcp-platform.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource in this chart.
*/}}
{{- define "af-mcp-platform.labels" -}}
helm.sh/chart: {{ include "af-mcp-platform.chart" . }}
{{ include "af-mcp-platform.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/part-of: af-mcp-platform
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels (stable — used in matchLabels; do not add mutable fields here).
*/}}
{{- define "af-mcp-platform.selectorLabels" -}}
app.kubernetes.io/name: {{ include "af-mcp-platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "af-mcp-platform.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "af-mcp-platform.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Broker-specific fully qualified name.
*/}}
{{- define "af-mcp-platform.broker.fullname" -}}
{{- printf "%s-broker" (include "af-mcp-platform.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Broker common labels (includes component label).
*/}}
{{- define "af-mcp-platform.broker.labels" -}}
{{ include "af-mcp-platform.labels" . }}
app.kubernetes.io/component: broker
{{- end }}

{{/*
Broker selector labels (includes component label).
*/}}
{{- define "af-mcp-platform.broker.selectorLabels" -}}
{{ include "af-mcp-platform.selectorLabels" . }}
app.kubernetes.io/component: broker
{{- end }}

{{/*
Portal-specific fully qualified name.
*/}}
{{- define "af-mcp-platform.portal.fullname" -}}
{{- printf "%s-portal" (include "af-mcp-platform.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Portal common labels (includes component label).
*/}}
{{- define "af-mcp-platform.portal.labels" -}}
{{ include "af-mcp-platform.labels" . }}
app.kubernetes.io/component: portal
{{- end }}

{{/*
Portal selector labels (includes component label).
*/}}
{{- define "af-mcp-platform.portal.selectorLabels" -}}
{{ include "af-mcp-platform.selectorLabels" . }}
app.kubernetes.io/component: portal
{{- end }}

{{/*
Broker image reference.
*/}}
{{- define "af-mcp-platform.broker.image" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.broker.repository (.Values.image.broker.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Portal image reference.
*/}}
{{- define "af-mcp-platform.portal.image" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.portal.repository (.Values.image.portal.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Origin (scheme + host, no path) of the shared OIDC issuer — derived rather
than duplicated in values, so the portal's nginx CSP connect-src always
matches whatever `oidc.issuer` points at. Used to render the OIDC_ORIGIN env
var consumed by nginx.conf.template's envsubst.
*/}}
{{- define "af-mcp-platform.portal.oidcOrigin" -}}
{{- $issuer := required "oidc.issuer must be set (e.g. via your deploying HelmRelease values)" .Values.oidc.issuer -}}
{{- $u := urlParse $issuer -}}
{{- printf "%s://%s" $u.scheme $u.host -}}
{{- end }}

{{/*
JSON-serialized IDENTITY_PROVIDERS env var value, converting
`broker.identityProviders`' camelCase chart-value keys into the snake_case
field names `IdentityProviderConfig` (broker/src/af_mcp_broker/config.py)
parses from JSON. Every entry carries alias/type/targets/displayName/enables;
oauth21-direct entries additionally carry the endpoint/issuer/scope fields
plus clientId and `confidential` (true iff existingClientSecretSecret is set
-- the secret itself is rendered separately as an env var by
af-mcp-platform.oauth21ClientSecretEnv, never into this JSON),
broker-issued entries carry nothing more -- each target's aud/POSIX options
now live on the service entry (aggregator.services' audience/requires_posix,
issue #257), condor-token entries their serviceUrl/audience (issue #169),
krb5-token entries their serviceUrl/audience (issue #274), x509 entries
their serviceUrl/voms/valid/audience (serviceUrl omitted =
the legacy k8s-Job mint path; replaces the removed global
broker.env.VOMS_TOKEN_SERVICE_URL -- every auth_type: x509 backend now
needs an explicit entry, there is no synthesized fallback), and
servicex-token entries their serviceUrl/audience/externalLoginUrl (issue
#295; externalLoginUrl is the portal's ServiceXIdentityCard "Get your
ServiceX token" link, optional).
*/}}
{{- define "af-mcp-platform.identityProviders" -}}
{{- $providers := list -}}
{{- range .Values.broker.identityProviders -}}
{{- if eq .type "oauth21-direct" -}}
{{- $providers = append $providers (dict
      "type" .type
      "alias" .alias
      "targets" (.targets | default (list))
      "display_name" (.displayName | default "")
      "enables" (.enables | default "")
      "authorization_endpoint" .authorizationEndpoint
      "token_endpoint" .tokenEndpoint
      "issuer" .issuer
      "scope" (.scope | default "openid profile email")
      "client_id" (.clientId | default nil)
      "confidential" (not (empty .existingClientSecretSecret))
    ) -}}
{{- else if eq .type "broker-issued" -}}
{{- $providers = append $providers (dict
      "type" .type
      "alias" .alias
      "targets" (.targets | default (list))
      "display_name" (.displayName | default "")
      "enables" (.enables | default "")
    ) -}}
{{- else if eq .type "condor-token" -}}
{{- $providers = append $providers (dict
      "type" .type
      "alias" .alias
      "targets" (.targets | default (list))
      "display_name" (.displayName | default "")
      "enables" (.enables | default "")
      "service_url" .serviceUrl
      "audience" (.audience | default "condor-token-service")
    ) -}}
{{- else if eq .type "krb5-token" -}}
{{- $providers = append $providers (dict
      "type" .type
      "alias" .alias
      "targets" (.targets | default (list))
      "display_name" (.displayName | default "")
      "enables" (.enables | default "")
      "service_url" .serviceUrl
      "audience" (.audience | default "krb5-token-service")
    ) -}}
{{- else if eq .type "x509" -}}
{{- $providers = append $providers (dict
      "type" .type
      "alias" .alias
      "targets" (.targets | default (list))
      "display_name" (.displayName | default "")
      "enables" (.enables | default "")
      "service_url" (.serviceUrl | default nil)
      "voms" (.voms | default "atlas")
      "valid" (.valid | default "192:00")
      "audience" (.audience | default "voms-token-service")
    ) -}}
{{- else if eq .type "servicex-token" -}}
{{- $providers = append $providers (dict
      "type" .type
      "alias" .alias
      "targets" (.targets | default (list))
      "display_name" (.displayName | default "")
      "enables" (.enables | default "")
      "service_url" .serviceUrl
      "audience" (.audience | default "servicex-token-service")
      "external_login_url" (.externalLoginUrl | default nil)
    ) -}}
{{- else -}}
{{- $providers = append $providers (dict
      "type" .type
      "alias" .alias
      "targets" (.targets | default (list))
      "display_name" (.displayName | default "")
      "enables" (.enables | default "")
    ) -}}
{{- end -}}
{{- end -}}
{{- $providers | toJson -}}
{{- end }}

{{/*
One OAUTH21_CLIENT_SECRET_<ALIAS> env var per oauth21-direct
broker.identityProviders entry with existingClientSecretSecret set, read from
that Secret's `client-secret` key. <ALIAS> is the alias uppercased with every
non-alphanumeric character replaced by "_" -- it must stay in lockstep with
OAuth21DirectProviderConfig.client_secret_env_var (broker config.py), which
reads it back. Part of the shared broker env (not deployment-only like
TOKEN_MINT_CLIENT_SECRET) because every pod that parses IDENTITY_PROVIDERS
runs the same startup validation, which refuses a confidential provider
whose secret is missing.
*/}}
{{- define "af-mcp-platform.oauth21ClientSecretEnv" -}}
{{- range .Values.broker.identityProviders -}}
{{- if and (eq .type "oauth21-direct") .existingClientSecretSecret }}
- name: {{ printf "OAUTH21_CLIENT_SECRET_%s" (regexReplaceAll "[^A-Za-z0-9]" .alias "_" | upper) }}
  valueFrom:
    secretKeyRef:
      name: {{ .existingClientSecretSecret | quote }}
      key: client-secret
{{- end -}}
{{- end -}}
{{- end }}

{{/*
True when at least one broker.identityProviders entry is type
"oauth21-direct" — gates OAUTH21_CLIENT_ID/OAUTH21_STATE_ISSUER env wiring,
which only matters for that provider type. BROKER_STATE_KEY is NOT gated on
this (see its own site below) — it also protects the plain MCP OAuth login
bootstrap flow's state, needed whenever tokenMint.clientId is configured,
independent of identityProviders.
*/}}
{{- define "af-mcp-platform.hasOAuth21Provider" -}}
{{- $has := false -}}
{{- range .Values.broker.identityProviders -}}
{{- if eq .type "oauth21-direct" -}}
{{- $has = true -}}
{{- end -}}
{{- end -}}
{{- $has -}}
{{- end }}

{{/*
True when at least one broker.identityProviders entry requires the Vault
connection settings independent of oauth21.tokenStore/tokenRegistry/
principalCache.backend being "vault" — mirrors config.py's
_validate_vault_config: a service-mode x509 entry (type "x509" with a
non-empty serviceUrl) implies the x509 Vault store, and krb5-token/
servicex-token entries always imply their own Vault store (no legacy/
no-Vault mode for either, unlike x509). Used to gate VAULT_ADDR/etc.
rendering below alongside the three backend checks.
*/}}
{{- define "af-mcp-platform.identityProvidersNeedVault" -}}
{{- $needs := false -}}
{{- range .Values.broker.identityProviders -}}
{{- if and (eq .type "x509") .serviceUrl -}}
{{- $needs = true -}}
{{- end -}}
{{- if eq .type "krb5-token" -}}
{{- $needs = true -}}
{{- end -}}
{{- if eq .type "servicex-token" -}}
{{- $needs = true -}}
{{- end -}}
{{- end -}}
{{- $needs -}}
{{- end }}

{{/*
Broker container environment variables — shared verbatim between the broker
Deployment (broker-deployment.yaml) and the token-sweep CronJob
(cronjob-token-sweep.yaml). The sweep CLI (token_sweep.py) builds a Settings
instance from the environment exactly like app.py's lifespan does, so it
needs the identical env: the same Vault connection (shared by
oauth21.tokenStore, tokenRegistry, and principalCache — see config.py's
_validate_vault_config), and the same oauth21-direct identityProviders
validation requirements (Settings() raises at construction time otherwise).
Callers pipe this through `nindent` at whatever depth their container's
`env:` list sits at.
*/}}
{{/*
Whether a shared cross-replica state store is configured (url or secret).
Renders "true" or nothing, for use in `if`.
*/}}
{{- define "af-mcp-platform.sharedState.configured" -}}
{{- if or .Values.broker.sharedState.url .Values.broker.sharedState.existingSecret.name -}}true{{- end -}}
{{- end }}

{{/*
Refuse to render more than one broker replica without a shared state store,
unless the operator opted into per-replica state. Mirrors the broker's own
startup refusal (Settings._validate_replica_state_config) for the chart path.
*/}}
{{- define "af-mcp-platform.sharedState.validate" -}}
{{- if and .Values.broker.sharedState.url .Values.broker.sharedState.existingSecret.name -}}
{{- fail "broker.sharedState.url and broker.sharedState.existingSecret.name are mutually exclusive; set only one." -}}
{{- end -}}
{{- if and (gt (.Values.broker.replicaCount | int) 1) (not (include "af-mcp-platform.sharedState.configured" .)) (not .Values.broker.sharedState.allowPerReplicaState) -}}
{{- fail "broker.replicaCount > 1 requires broker.sharedState.url (or broker.sharedState.existingSecret.name): the unlock brute-force limiter and other replica state must agree across replicas. Point it at a Redis instance (Valkey also works), or set broker.sharedState.allowPerReplicaState=true to accept per-replica state (see docs/architecture.md, Replica consistency)." -}}
{{- end -}}
{{- end }}

{{- define "af-mcp-platform.broker.env" -}}
# OIDC settings — names must match broker Settings fields. Issuer is the
# shared top-level `oidc.issuer` (also consumed by the portal); audience is
# broker-specific.
- name: OIDC_ISSUER
  value: {{ .Values.oidc.issuer | quote }}
- name: OIDC_AUDIENCE
  value: {{ .Values.broker.oidc.audience | quote }}
# Omitted when empty so the broker's back-channel calls use OIDC_ISSUER
# instead (see broker.oidc.internalUrl comment in values.yaml).
{{- if .Values.broker.oidc.internalUrl }}
- name: OIDC_INTERNAL_URL
  value: {{ .Values.broker.oidc.internalUrl | quote }}
{{- end }}
# Home directory root (broker constructs per-user paths from this)
- name: HOME_ROOT
  value: {{ .Values.broker.homeDir.homeRoot | quote }}
# Portal base URL for unlock hints and identity-linking redirects
- name: PORTAL_URL
  value: {{ printf "https://%s" .Values.ingress.portalHost | quote }}
# /mcp aggregator transport mode (issue #128) -- always set, same
# visibility rationale as TOKEN_STORE_BACKEND below. MCP_REPLICA_COUNT is
# not a knob of its own; it's this same replicaCount value, passed through
# purely so the broker's own startup check can warn when mcpStatelessHttp
# is disabled at more than one replica (see docs/architecture.md).
- name: MCP_STATELESS_HTTP
  value: {{ .Values.broker.mcpStatelessHttp | quote }}
- name: MCP_REPLICA_COUNT
  value: {{ .Values.broker.replicaCount | quote }}
# Shared cross-replica state store (see broker.sharedState in values.yaml).
{{- if .Values.broker.sharedState.existingSecret.name }}
- name: SHARED_STATE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.broker.sharedState.existingSecret.name | quote }}
      key: {{ .Values.broker.sharedState.existingSecret.key | quote }}
{{- else if .Values.broker.sharedState.url }}
- name: SHARED_STATE_URL
  value: {{ .Values.broker.sharedState.url | quote }}
{{- end }}
{{- if .Values.broker.sharedState.allowPerReplicaState }}
- name: ALLOW_PER_REPLICA_STATE
  value: "true"
{{- end }}
# Proxy tmpfs mount path
{{- if .Values.broker.tmpfsProxy.enabled }}
- name: PROXY_DIR
  value: {{ .Values.broker.tmpfsProxy.mountPath | quote }}
{{- end }}
# CIMD (/.well-known/cimd) settings — omitted when empty so the
# broker's pydantic defaults apply.
{{- if .Values.broker.cimd.clientName }}
- name: CIMD_CLIENT_NAME
  value: {{ .Values.broker.cimd.clientName | quote }}
{{- end }}
# Canonical origin for every OAuth 2.1 URL the broker constructs
# itself (redirect_uri, CIMD redirect_uris) — omitted when empty
# so the broker's pydantic default applies; the broker's own
# startup validation rejects an empty value when identityProviders
# has an oauth21-direct entry.
{{- if .Values.broker.publicOrigin }}
- name: BROKER_PUBLIC_ORIGIN
  value: {{ .Values.broker.publicOrigin | quote }}
{{- end }}
# Name of the builtin gateway service (issue #240) -- the broker's own af_*
# methods' catalog/audit identity. Omitted so the broker's pydantic default
# (gateway_service) applies unless a facility overrides it.
{{- if .Values.broker.builtinServiceName }}
- name: BUILTIN_SERVICE_NAME
  value: {{ .Values.broker.builtinServiceName | quote }}
{{- end }}
# Identity providers (issue #66 PR4) — one entry per
# keycloak-brokered or oauth21-direct provider the broker can
# link a user's account to. Omitted entirely when none are
# configured so the broker's pydantic default (empty list,
# degraded but valid) applies.
{{- if .Values.broker.identityProviders }}
- name: IDENTITY_PROVIDERS
  value: {{ include "af-mcp-platform.identityProviders" . | quote }}
{{- end }}
# Confidential oauth21-direct client secrets, one env var per provider with
# existingClientSecretSecret set (see af-mcp-platform.oauth21ClientSecretEnv).
{{- include "af-mcp-platform.oauth21ClientSecretEnv" . }}
# OAuth 2.1 direct-linking-flow infrastructure — only needed when at
# least one identityProviders entry is oauth21-direct.
{{- if eq (include "af-mcp-platform.hasOAuth21Provider" .) "true" }}
- name: OAUTH21_CLIENT_ID
  value: {{ printf "https://%s/.well-known/cimd" .Values.ingress.mcpHost | quote }}
{{- if .Values.broker.oauth21.stateIssuer }}
- name: OAUTH21_STATE_ISSUER
  value: {{ .Values.broker.oauth21.stateIssuer | quote }}
{{- end }}
{{- end }}
# BROKER_STATE_KEY protects both the oauth21-direct linking flow's state
# AND the plain MCP OAuth login bootstrap flow's state (broker Settings
# validation requires it whenever tokenMint.clientId/keycloak_login_client_id
# is configured, not only when an oauth21-direct provider is present) —
# rendered independently of hasOAuth21Provider above.
{{- if .Values.broker.oauth21.existingStateKeySecret }}
- name: BROKER_STATE_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.broker.oauth21.existingStateKeySecret | quote }}
      key: broker-state-key
{{- end }}
# OAuth 2.1 TokenStore backend — always set (pydantic default is
# "in_memory" so an unset value here is equivalent, but the env
# var is rendered unconditionally to make the active backend
# visible in `kubectl describe pod`/manifests).
- name: TOKEN_STORE_BACKEND
  value: {{ .Values.broker.oauth21.tokenStore.backend | replace "-" "_" | quote }}
# Token registry backend (issue #115) — durable storage for manually-minted
# bearer tokens (POST/GET/DELETE /v1/tokens). Always set, same visibility
# rationale as TOKEN_STORE_BACKEND above.
- name: TOKEN_REGISTRY_BACKEND
  value: {{ .Values.broker.tokenRegistry.backend | replace "-" "_" | quote }}
{{- if .Values.broker.tokenRegistry.kvPathPrefix }}
- name: TOKEN_REGISTRY_KV_PATH_PREFIX
  value: {{ .Values.broker.tokenRegistry.kvPathPrefix | quote }}
{{- end }}
# Principal cache persistence backend (issue #144 step 2b) -- durable
# storage for identity-PAT-authenticated principals' last-known
# groups/uid/gid/unixname/email, so a broker restart during a Keycloak
# outage doesn't fail closed for them. Always set, same visibility
# rationale as TOKEN_STORE_BACKEND above.
- name: PRINCIPAL_CACHE_BACKEND
  value: {{ .Values.broker.principalCache.backend | replace "-" "_" | quote }}
{{- if .Values.broker.principalCache.kvPathPrefix }}
- name: PRINCIPAL_CACHE_KV_PATH_PREFIX
  value: {{ .Values.broker.principalCache.kvPathPrefix | quote }}
{{- end }}
# Metering pipeline backend (audit/pipeline.py) -- transport for
# success/error audit records between the tool-call hot path and the
# worker that measures and writes them. Only "in-process" exists today;
# the broker fails closed at startup on any unknown value. Always set,
# same visibility rationale as TOKEN_STORE_BACKEND above.
- name: METERING_BACKEND
  value: {{ .Values.broker.metering.backend | replace "-" "_" | quote }}
# Usage store backend (broker usage/) -- per-user usage accounting behind
# GET /v1/usage. Always set, same visibility rationale as
# TOKEN_STORE_BACKEND above.
- name: USAGE_STORE_BACKEND
  value: {{ .Values.broker.usage.backend | replace "-" "_" | quote }}
# Usage write batching (see broker.usage.batchMax in values.yaml). Always
# set so the effective values are visible on the pod.
- name: USAGE_BATCH_MAX
  value: {{ .Values.broker.usage.batchMax | quote }}
- name: USAGE_BATCH_INTERVAL_MS
  value: {{ .Values.broker.usage.batchIntervalMs | quote }}
{{- if eq .Values.broker.usage.backend "postgres" }}
{{- if .Values.broker.usage.postgres.existingSecret.name }}
# asyncpg DSN for the postgres usage store -- with Crunchy PGO, typically
# the `uri` key of the operator-generated `<cluster>-pguser-<user>` secret
# (see broker.usage.postgres.existingSecret in values.yaml).
- name: USAGE_POSTGRES_DSN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.broker.usage.postgres.existingSecret.name | quote }}
      key: {{ .Values.broker.usage.postgres.existingSecret.key | quote }}
{{- end }}
{{- end }}
# Maintenance-mode backend -- always set, same visibility rationale as
# TOKEN_STORE_BACKEND above.
- name: MAINTENANCE_MODE_BACKEND
  value: {{ .Values.broker.maintenanceMode.backend | replace "-" "_" | quote }}
- name: MAINTENANCE_MODE_CACHE_TTL_SECONDS
  value: {{ .Values.broker.maintenanceMode.cacheTtlSeconds | quote }}
{{- if .Values.broker.maintenanceMode.kvPathPrefix }}
- name: MAINTENANCE_MODE_KV_PATH_PREFIX
  value: {{ .Values.broker.maintenanceMode.kvPathPrefix | quote }}
{{- end }}
{{- if eq .Values.broker.maintenanceMode.backend "postgres" }}
{{- if .Values.broker.maintenanceMode.postgres.existingSecret.name }}
# asyncpg DSN for the postgres maintenance-mode store. Omit this secret
# entirely to reuse broker.usage.postgres's DSN instead (Settings.
# maintenance_mode_effective_postgres_dsn falls back to it).
- name: MAINTENANCE_MODE_POSTGRES_DSN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.broker.maintenanceMode.postgres.existingSecret.name | quote }}
      key: {{ .Values.broker.maintenanceMode.postgres.existingSecret.key | quote }}
{{- end }}
{{- end }}
{{- if .Values.broker.adminGroup }}
# Admin group -- gates require_admin and every admin-only /v1 route. Only
# rendered when set; unset means no admin surface is reachable by anyone.
- name: ADMIN_GROUP
  value: {{ .Values.broker.adminGroup | quote }}
{{- end }}
{{- include "af-mcp-platform.validateOtlp" . }}
{{- if or .Values.broker.tracing.enabled .Values.broker.metrics.otlp.enabled }}
# OTLP transport (broker.otlp), rendered once for every enabled OpenTelemetry
# signal: the standard OTel env vars, read natively by the SDK's OTLP/HTTP
# exporters, which append each signal's /v1/<signal> path. The endpoint is
# transport only; each signal has its own on/off setting below.
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .Values.broker.otlp.endpoint | quote }}
{{- if .Values.broker.otlp.headers.existingSecret.name }}
# Collector request headers from a Secret so credentials never sit in values.
- name: OTEL_EXPORTER_OTLP_HEADERS
  valueFrom:
    secretKeyRef:
      name: {{ .Values.broker.otlp.headers.existingSecret.name | quote }}
      key: {{ .Values.broker.otlp.headers.existingSecret.key | quote }}
{{- else if .Values.broker.otlp.headers.value }}
- name: OTEL_EXPORTER_OTLP_HEADERS
  value: {{ .Values.broker.otlp.headers.value | quote }}
{{- end }}
{{- end }}
{{- if .Values.broker.tracing.enabled }}
# OpenTelemetry trace emission (broker tracing.py). Rendered only when
# tracing is enabled so a disabled deployment carries no tracing
# configuration at all.
- name: TRACING_ENABLED
  value: "true"
{{- if .Values.broker.tracing.sampleRatio }}
# Head sampling: honor an inbound sampled flag, otherwise keep this ratio of
# new traces. Unset (SDK default parentbased_always_on) keeps every trace.
- name: OTEL_TRACES_SAMPLER
  value: "parentbased_traceidratio"
- name: OTEL_TRACES_SAMPLER_ARG
  value: {{ .Values.broker.tracing.sampleRatio | quote }}
{{- end }}
{{- end }}
{{- if .Values.broker.metrics.otlp.enabled }}
# OpenTelemetry aggregate metrics (broker otel_metrics.py).
- name: OTEL_METRICS_ENABLED
  value: "true"
{{- end }}
{{- /*
Vault connection settings are shared by all Vault-backed stores above (one
VaultKV instance, per config.py/app.py) — rendered once whenever any of
them needs it, not duplicated per-backend. A service-mode x509 or
krb5-token identityProviders entry also implies a Vault-backed store (see
af-mcp-platform.identityProvidersNeedVault above) even when none of the
three backend settings below is "vault".

KNOWN GAP (not fixed here, out of scope for this branch): config.py's
_validate_vault_config also requires Vault when maintenance_mode_backend
is "vault", but this gate does not check .Values.broker.maintenanceMode.
backend. Not an active regression today — maintenanceMode.backend
defaults to something other than "vault" — but a future maintenanceMode:
{backend: vault} deployment would render cleanly here with VAULT_ADDR
missing and fail at broker startup instead. Needs a fourth `eq` clause
below (or a helper alongside identityProvidersNeedVault) when that gets
addressed.
*/}}
{{- if or (eq .Values.broker.oauth21.tokenStore.backend "vault") (eq .Values.broker.tokenRegistry.backend "vault") (eq .Values.broker.principalCache.backend "vault") (eq (include "af-mcp-platform.identityProvidersNeedVault" .) "true") }}
{{- if .Values.broker.oauth21.tokenStore.vault.addr }}
- name: VAULT_ADDR
  value: {{ .Values.broker.oauth21.tokenStore.vault.addr | quote }}
{{- end }}
{{- if .Values.broker.oauth21.tokenStore.vault.authMount }}
- name: VAULT_AUTH_MOUNT
  value: {{ .Values.broker.oauth21.tokenStore.vault.authMount | quote }}
{{- end }}
{{- if .Values.broker.oauth21.tokenStore.vault.authRole }}
- name: VAULT_AUTH_ROLE
  value: {{ .Values.broker.oauth21.tokenStore.vault.authRole | quote }}
{{- end }}
{{- if .Values.broker.oauth21.tokenStore.vault.kvMount }}
- name: VAULT_KV_MOUNT
  value: {{ .Values.broker.oauth21.tokenStore.vault.kvMount | quote }}
{{- end }}
{{- if eq .Values.broker.oauth21.tokenStore.backend "vault" }}
{{- if .Values.broker.oauth21.tokenStore.vault.kvPathPrefix }}
- name: VAULT_KV_PATH_PREFIX
  value: {{ .Values.broker.oauth21.tokenStore.vault.kvPathPrefix | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- if .Values.broker.existingServiceTokenSecret }}
- name: AF_SERVICE_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.broker.existingServiceTokenSecret | quote }}
      key: af-service-token
{{- end }}
# Keycloak admin service account (issue #144 step 2a) -- resolves an
# identity-PAT-authenticated request's current groups/uid/gid/unixname via
# the Admin REST API. Omitted entirely when unset so the broker's pydantic
# defaults (both empty) apply -- see docs/auth.md's "Operator setup: the
# Keycloak admin service account" section for the degraded-but-valid
# behavior that results (every mcp_pat_... bearer on /mcp rejected).
{{- if .Values.broker.keycloakAdmin.clientId }}
- name: KEYCLOAK_ADMIN_CLIENT_ID
  value: {{ .Values.broker.keycloakAdmin.clientId | quote }}
{{- end }}
{{- if .Values.broker.keycloakAdmin.existingClientSecretSecret }}
- name: KEYCLOAK_ADMIN_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .Values.broker.keycloakAdmin.existingClientSecretSecret | quote }}
      key: keycloak-admin-client-secret
{{- end }}
# Keycloak user-profile attribute keys for the PAT path's POSIX identity
# resolution (issue #148) -- always set, same visibility rationale as
# TOKEN_STORE_BACKEND above, since a misconfigured value here is exactly the
# kind of thing an operator needs visible in `kubectl describe pod`.
- name: POSIX_UID_ATTRIBUTE
  value: {{ .Values.broker.posixAttributes.uid | quote }}
- name: POSIX_GID_ATTRIBUTE
  value: {{ .Values.broker.posixAttributes.gid | quote }}
- name: POSIX_UNIXNAME_ATTRIBUTE
  value: {{ .Values.broker.posixAttributes.unixname | quote }}
# Whether the PAT path matches a Keycloak group by full path instead of bare
# name (issue #148) -- always set, same rationale as above.
- name: PRINCIPAL_DIRECTORY_GROUP_FULL_PATH
  value: {{ .Values.broker.groupFullPath | quote }}
# Extra env vars from values (key: value pairs)
{{- range $key, $val := .Values.broker.env }}
- name: {{ $key | quote }}
  value: {{ $val | quote }}
{{- end }}
{{- end }}

{{/*
Fails the render on OTLP configuration that cannot work: the pre-split
broker.tracing.endpoint / broker.tracing.networkPolicy keys (renamed, no
alias), a signal enabled with no collector endpoint, or both a literal and a
Secret for the collector headers. Emits nothing.
*/}}
{{- define "af-mcp-platform.validateOtlp" -}}
{{- if hasKey .Values.broker.tracing "endpoint" }}
{{- fail "broker.tracing.endpoint was removed: set broker.otlp.endpoint (the collector endpoint is now shared by every OpenTelemetry signal)" }}
{{- end }}
{{- if hasKey .Values.broker.tracing "networkPolicy" }}
{{- fail "broker.tracing.networkPolicy was removed: set broker.otlp.networkPolicy (the collector egress rule is now shared by every OpenTelemetry signal)" }}
{{- end }}
{{- if and (or .Values.broker.tracing.enabled .Values.broker.metrics.otlp.enabled) (not .Values.broker.otlp.endpoint) }}
{{- fail "broker.otlp.endpoint is required when broker.tracing.enabled or broker.metrics.otlp.enabled is true" }}
{{- end }}
{{- if and .Values.broker.otlp.headers.value .Values.broker.otlp.headers.existingSecret.name }}
{{- fail "set only one of broker.otlp.headers.value and broker.otlp.headers.existingSecret.name" }}
{{- end }}
{{- end }}
