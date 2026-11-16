{{/*
URLs the broker connects to server-side, as a JSON list. Each one becomes an
egress rule through af-mcp-platform.netpol.targets. Browser-followed URLs (an
identity provider's authorizationEndpoint and externalLoginUrl) and
metadata-only URLs (an identity provider's issuer, and oidc.issuer while
broker.oidc.internalUrl carries the back-channel calls) are left out because
the broker never connects to them.
*/}}
{{- define "af-mcp-platform.netpol.urls" -}}
{{- $urls := list .Values.broker.oidc.internalUrl .Values.broker.oauth21.tokenStore.vault.addr .Values.broker.credmon.htcondorApiUrl -}}
{{- if not .Values.broker.oidc.internalUrl -}}
{{- $urls = append $urls .Values.oidc.issuer -}}
{{- end -}}
{{- range .Values.aggregator.services -}}
{{- $urls = append $urls .url -}}
{{- end -}}
{{- range $idp := .Values.broker.identityProviders -}}
{{- range $key := list "serviceUrl" "tokenEndpoint" "revocationEndpoint" -}}
{{- $urls = append $urls (get $idp $key) -}}
{{- end -}}
{{- end -}}
{{- if or .Values.broker.tracing.enabled .Values.broker.metrics.otlp.enabled .Values.broker.usageEvents.otlp.enabled -}}
{{- $urls = append $urls .Values.broker.otlp.endpoint -}}
{{- end -}}
{{- compact $urls | uniq | toJson -}}
{{- end }}

{{/*
Where each configured URL points, as JSON:

  hosts:       in-cluster host -> {namespace, podSelector, ports}
  publicPorts: ports of the public-internet rule (443 plus the port of every
               other external URL)

An in-cluster host is a single label (a Service in the release namespace) or
<service>.<namespace>.svc[.<cluster domain>]; its namespace is read from the
host. A host with networkPolicy.egress.endpoints[<host>].namespace is in-cluster in
that namespace whatever its name: this is how a public hostname served by
in-cluster pods is declared (kube-proxy DNATs the public LB IP to private pod
IPs before policy runs, so the public rule never matches it).

Every in-cluster host needs networkPolicy.egress.endpoints[<host>].podSelector
(an empty map opts into the whole namespace): a rule pairs the namespace with
the pods behind the Service, never the namespace alone by accident.
endpoints[<host>].targetPort is the pod's port when the URL carries the
Service's port; a NetworkPolicy matches the pod's port.

Any other host is external: a NetworkPolicy cannot select a DNS name, so
external hosts share one dual-stack ipBlock rule. The rule's port is the URL's
port, or the scheme's default (http 80, https 443); any other scheme needs an
explicit port.
*/}}
{{- define "af-mcp-platform.netpol.targets" -}}
{{- $endpoints := .Values.networkPolicy.egress.endpoints -}}
{{- $hosts := dict -}}
{{- $publicPorts := dict "443" true -}}
{{- range $url := include "af-mcp-platform.netpol.urls" . | fromJsonArray -}}
{{- $u := urlParse $url -}}
{{- $host := $u.hostname -}}
{{- if not $host -}}
{{- fail (printf "cannot derive a NetworkPolicy rule from %q: the URL has no host" $url) -}}
{{- end -}}
{{- $port := "" -}}
{{- if contains ":" $u.host -}}
{{- $port = trimPrefix (printf "%s:" $host) $u.host -}}
{{- else if eq $u.scheme "http" -}}
{{- $port = "80" -}}
{{- else if eq $u.scheme "https" -}}
{{- $port = "443" -}}
{{- else -}}
{{- fail (printf "cannot derive a NetworkPolicy rule from %q: it has no port and the %q scheme has no default port" $url $u.scheme) -}}
{{- end -}}
{{- $endpoint := get $endpoints $host | default dict -}}
{{- $namespace := "" -}}
{{- if $endpoint.namespace -}}
{{- $namespace = $endpoint.namespace -}}
{{- else if regexMatch "^[a-z0-9-]+$" $host -}}
{{- $namespace = $.Release.Namespace -}}
{{- else if regexMatch "^[a-z0-9-]+\\.[a-z0-9-]+\\.svc(\\..+)?$" $host -}}
{{- $namespace = regexReplaceAll "^[a-z0-9-]+\\.([a-z0-9-]+)\\.svc(\\..+)?$" $host "${1}" -}}
{{- end -}}
{{- if $namespace -}}
{{- if not (hasKey $endpoint "podSelector") -}}
{{- fail (printf "%q (from %q) is in-cluster namespace %q: set networkPolicy.egress.endpoints.%s.podSelector to the labels of the pods behind it (an empty podSelector allows the whole namespace)" $host $url $namespace $host) -}}
{{- end -}}
{{- $entry := get $hosts $host | default (dict "namespace" $namespace "podSelector" ($endpoint.podSelector | default dict) "ports" dict) -}}
{{- $_ := set $entry.ports (toString ($endpoint.targetPort | default $port | int)) true -}}
{{- $_ := set $hosts $host $entry -}}
{{- else -}}
{{- $_ := set $publicPorts $port true -}}
{{- end -}}
{{- end -}}
{{- dict "hosts" $hosts "publicPorts" (keys $publicPorts | sortAlpha) | toJson -}}
{{- end }}

{{/*
The CIDRs the public-internet rule excludes for one address family
(networkPolicy.egress.external.exceptCidrs mixes IPv4 and IPv6; those containing a
colon are IPv6). Takes {"family": "4"|"6", "root": $}; renders a JSON list.
*/}}
{{- define "af-mcp-platform.netpol.exceptCidrs" -}}
{{- $cidrs := list -}}
{{- if eq .family "4" -}}
{{- $cidrs = list "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "169.254.169.254/32" -}}
{{- else -}}
{{- $cidrs = list "fc00::/7" "fe80::/10" -}}
{{- end -}}
{{- range .root.Values.networkPolicy.egress.external.exceptCidrs -}}
{{- if eq (contains ":" .) (eq $.family "6") -}}
{{- $cidrs = append $cidrs . -}}
{{- end -}}
{{- end -}}
{{- toJson $cidrs -}}
{{- end }}

{{/*
Ingress rules for a list of networkPolicy.ingress.*.sources entries
({namespaceSelector, podSelector, ports}); each entry becomes one rule
allowing the pods it selects on its ports.
*/}}
{{- define "af-mcp-platform.netpol.sources" -}}
{{- range . }}
{{- $peer := dict }}
{{- if .namespaceSelector }}{{ $_ := set $peer "namespaceSelector" .namespaceSelector }}{{ end }}
{{- if .podSelector }}{{ $_ := set $peer "podSelector" .podSelector }}{{ end }}
- from:
    {{- toYaml (list $peer) | nindent 4 }}
  ports:
    {{- range .ports }}
    - protocol: TCP
      port: {{ . }}
    {{- end }}
{{- end }}
{{- end }}
