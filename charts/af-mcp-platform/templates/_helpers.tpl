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
Origin (scheme + host, no path) of the portal's OIDC issuer — derived rather
than duplicated in values, so the portal's nginx CSP connect-src always
matches whatever `portal.oidc.issuer` points at. Used to render the
OIDC_ORIGIN env var consumed by nginx.conf.template's envsubst.
*/}}
{{- define "af-mcp-platform.portal.oidcOrigin" -}}
{{- $issuer := required "portal.oidc.issuer must be set (e.g. via your deploying HelmRelease values)" .Values.portal.oidc.issuer -}}
{{- $u := urlParse $issuer -}}
{{- printf "%s://%s" $u.scheme $u.host -}}
{{- end }}

{{/*
JSON-serialized IDENTITY_PROVIDERS env var value, converting
`broker.identityProviders`' camelCase chart-value keys into the snake_case
field names `IdentityProviderConfig` (broker/src/af_mcp_broker/config.py)
parses from JSON. Every entry carries alias/type/targets/displayName/enables;
oauth21-direct entries additionally carry the endpoint/issuer/scope fields.
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
