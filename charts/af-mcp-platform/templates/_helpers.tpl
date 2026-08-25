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
oauth21-direct entries additionally carry the endpoint/issuer/scope fields,
broker-issued entries their per-target audience/includePosix options
(issue #162), condor-token entries their serviceUrl/audience (issue #169),
and x509 entries their serviceUrl/voms/valid/audience (serviceUrl omitted =
the legacy k8s-Job mint path; replaces the removed global
broker.env.VOMS_TOKEN_SERVICE_URL -- every auth_type: x509 backend now
needs an explicit entry, there is no synthesized fallback).
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
    ) -}}
{{- else if eq .type "broker-issued" -}}
{{- $targetOptions := dict -}}
{{- range $target, $opts := (.targetOptions | default (dict)) -}}
{{- $_ := set $targetOptions $target (dict
      "audience" ($opts.audience | default "")
      "include_posix" ($opts.includePosix | default false)
    ) -}}
{{- end -}}
{{- $providers = append $providers (dict
      "type" .type
      "alias" .alias
      "targets" (.targets | default (list))
      "display_name" (.displayName | default "")
      "enables" (.enables | default "")
      "target_options" $targetOptions
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
True when at least one broker.identityProviders entry is type
"oauth21-direct" — gates OAUTH21_CLIENT_ID/BROKER_STATE_KEY/
OAUTH21_STATE_ISSUER env wiring, which only matters for that provider type.
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
# Identity providers (issue #66 PR4) — one entry per
# keycloak-brokered or oauth21-direct provider the broker can
# link a user's account to. Omitted entirely when none are
# configured so the broker's pydantic default (empty list,
# degraded but valid) applies.
{{- if .Values.broker.identityProviders }}
- name: IDENTITY_PROVIDERS
  value: {{ include "af-mcp-platform.identityProviders" . | quote }}
{{- end }}
# OAuth 2.1 state-token infrastructure — only needed when at
# least one identityProviders entry is oauth21-direct.
{{- if eq (include "af-mcp-platform.hasOAuth21Provider" .) "true" }}
- name: OAUTH21_CLIENT_ID
  value: {{ printf "https://%s/.well-known/cimd" .Values.ingress.mcpHost | quote }}
{{- if .Values.broker.oauth21.stateIssuer }}
- name: OAUTH21_STATE_ISSUER
  value: {{ .Values.broker.oauth21.stateIssuer | quote }}
{{- end }}
{{- if .Values.broker.oauth21.existingStateKeySecret }}
- name: BROKER_STATE_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.broker.oauth21.existingStateKeySecret | quote }}
      key: broker-state-key
{{- end }}
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
{{- /*
Vault connection settings are shared by all Vault-backed stores above (one
VaultKV instance, per config.py/app.py) — rendered once whenever any of
them needs it, not duplicated per-backend.
*/}}
{{- if or (eq .Values.broker.oauth21.tokenStore.backend "vault") (eq .Values.broker.tokenRegistry.backend "vault") (eq .Values.broker.principalCache.backend "vault") }}
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
