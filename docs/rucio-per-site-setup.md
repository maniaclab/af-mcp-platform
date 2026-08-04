# Rucio: Per-Site Setup

rucio-mcp fronts more than one Rucio VO/instance (ATLAS, ESCAPE, ...), and
each site is its own OAuth 2.1 authorization surface — rucio-mcp acts as an
OAuth 2.1 AS proxy per site, not one shared AS for all of them. This page is
the operator procedure for wiring up one additional site, as it has actually
been deployed, not the Keycloak-IdP-per-site design originally proposed for
this (see [Superseded design](#superseded-design-a-keycloak-idp-per-site)
below).

Each site is both an [Adding a Backend](adding-a-backend.md) case (a new
`aggregator.backends` entry) and an identity-provider case (a new
`broker.identityProviders` entry) — this page is the concrete, two-site
worked example; read those two pages first for what each field means in
general.

## The shape: `oauth21-direct`, not `keycloak-brokered`

rucio-mcp is itself an OAuth 2.1 authorization server, so it's wired up the
same way any `oauth21-direct` backend is (see
[auth.md's identity provider types](auth.md#identity-provider-types) and
[architecture.md's CIMD section](architecture.md#client-id-metadata-document-cimd)):
the broker acts as a direct OAuth 2.1 client to each site's authorize/token
endpoints, identifying itself via its own CIMD document
(`GET /.well-known/cimd`) instead of registering per site through Dynamic
Client Registration. **No Keycloak Identity Provider is created for rucio-mcp
at all** — that's the one departure from an earlier design for this that's
worth calling out explicitly, since it's easy to assume otherwise (see
[Superseded design](#superseded-design-a-keycloak-idp-per-site)).

This is a different shape from the `atlas-oidc` `keycloak-brokered` provider
that services PanDA and AMI: that one *is* a Keycloak Identity Provider (the
user links their CERN account, Keycloak stores the resulting token, and the
broker retrieves it via `GET /realms/<realm>/broker/atlas-oidc/token`). Rucio
sites don't use that path or its prerequisites — no "Store Tokens" IdP
config, no `read-token` client role (see
[auth.md's `read-token` role section](auth.md#required-keycloak-role-brokers-read-token))
— because there is no Keycloak IdP in the loop for them.

## Per-site endpoint pattern

rucio-mcp serves each site's OAuth 2.1 surface under `/site/{site}`, not a
shared path:

| Purpose | URL |
|---|---|
| Authorize | `https://rucio-mcp.example.org/site/<site>/authorize` |
| Token | `https://rucio-mcp.example.org/site/<site>/token` |
| Issuer | `https://rucio-mcp.example.org/site/<site>` |
| MCP endpoint (aggregator backend `url`) | `https://rucio-mcp.example.org/site/<site>` |

`<site>` is the Rucio VO/instance name (`atlas`, `escape`, ...). Everything
below is per-site: adding a third site means repeating both config blocks
with a new `<site>` value, not editing the existing entries.

## What to configure per site

Two config additions, both in the deploying HelmRelease's `values`, no chart
template edits:

**1. `broker.identityProviders` — an `oauth21-direct` entry.**

```yaml
broker:
  publicOrigin: "https://mcp-portal.example.org"  # see below — must be the portal's origin
  identityProviders:
    - type: oauth21-direct
      alias: rucio-mcp-<site>
      targets: ["rucio-mcp-<site>"]
      authorizationEndpoint: "https://rucio-mcp.example.org/site/<site>/authorize"
      tokenEndpoint: "https://rucio-mcp.example.org/site/<site>/token"
      issuer: "https://rucio-mcp.example.org/site/<site>"
      displayName: "Rucio MCP for <Site>"
      enables: "Access to rucio-mcp for <site> on your behalf"
```

`alias` and the single entry in `targets` both follow `rucio-mcp-<site>` —
this is convention, not a requirement, but it's what the deployed config
uses and keeps the identity-provider alias, its target, and the matching
`aggregator.backends` entry (below) trivially traceable to each other.

**2. `aggregator.backends` — a matching backend entry.**

```yaml
aggregator:
  backends:
    - name: rucio-mcp-<site>
      prefix: rucio-<site>
      url: "http://rucio-mcp.<namespace>.svc.cluster.local:80/site/<site>"
      transport: http
      required_capability: read_data
      auth_type: bearer
```

`name` must match the `targets` entry above — that's how
`CredentialRegistry` (see [adding-a-backend.md](adding-a-backend.md)) knows
which identity provider services this backend's credential. `prefix` is
distinct per site (`rucio-atlas`, `rucio-escape`, ...) so the aggregator can
tell the sites' tools apart; `url` is the in-cluster Service address rather
than the public hostname used for the authorize/token endpoints above, since
tool calls stay inside the cluster.

`required_capability: read_data` is the same capability across every site —
reuse it (see [adding-a-backend.md's Step
2](adding-a-backend.md#step-2-pick-or-reuse-a-capability-for-the-backend)),
no new `policy.yaml` entry needed as long as the groups you want to grant
Rucio access already map to `read_data` (the built-in default does, for
`atlas`, `cms`, `dune`, `escape` — see
[auth.md's Group-to-Capability Mapping Example](auth.md#group-to-capability-mapping-example)).

### Why `broker.publicOrigin` must be the portal's origin

`broker.publicOrigin` is what every `redirect_uri` the broker constructs for
*any* `oauth21-direct` provider is built from — not just rucio-mcp's, but
every site's. It must be the exact origin the portal SPA is served from
because the linking flow's nonce cookie is host-only: the portal's own
same-origin fetch to `/v1/oauth/authorize/{alias}` sets the cookie on
whichever host received that call, and the authorization server's redirect
back to `<publicOrigin>/v1/oauth/callback/{alias}` only carries that cookie
if it lands on the same host. This is a broker-wide setting, not a per-site
one — see
[architecture.md's CIMD section](architecture.md#client-id-metadata-document-cimd)
for the full mechanics, and set it once regardless of how many rucio-mcp
sites (or other `oauth21-direct` backends) you configure.

### The CIMD client-id mechanism, concretely for rucio-mcp

The broker's `GET /.well-known/cimd` document (served on the broker's own
host, e.g. `https://mcp.example.org/.well-known/cimd`) is a
self-describing client registration: its `client_id` is the literal URL used
to fetch it, and its `redirect_uris` list one entry per configured
`oauth21-direct` provider — so adding a second rucio-mcp site adds a second
`redirect_uris` entry automatically, no separate registration step. rucio-mcp
fetches this document to learn the broker's `client_id` and permitted
redirect URIs the same way for every site, rather than the broker
pre-registering as a client against each site individually via Dynamic
Client Registration.

## The linking flow the user experiences

1. On the portal's Identities page, the user clicks **Link** next to "Rucio
   MCP for ATLAS" (or whichever site's `displayName`).
2. The portal SPA calls `GET /v1/oauth/authorize/rucio-mcp-atlas` with its
   own bearer token and `Accept: application/json`, gets back an
   `authorize_url`, and navigates the browser there. The broker sets an
   HttpOnly nonce cookie on this call.
3. The browser lands on rucio-mcp's `/site/atlas/authorize` — rucio-mcp
   handles whatever authentication that site requires on its own; the broker
   is not involved in that step.
4. rucio-mcp redirects the browser back to the broker's
   `<publicOrigin>/v1/oauth/callback/rucio-mcp-atlas` with an authorization
   code (or an error, per OAuth 2.1 §4.1.2.1 — the broker surfaces either
   case, see `broker/src/af_mcp_broker/api/oauth21.py`'s `callback` route).
5. The broker validates the returned `state` and nonce cookie, exchanges the
   code for a token at rucio-mcp's `/site/atlas/token` endpoint, and stores
   the result in its own OAuth 2.1 `TokenStore` — Vault/OpenBao-backed in
   production (`broker.oauth21.tokenStore.backend: vault`), keyed by
   `(subject, alias)`. **This token lives in the broker's own store, not
   Keycloak** — unlike the `atlas-oidc` path, there's no Keycloak
   stored-broker-token involved anywhere in this flow.
6. The portal redirects back to the Identities page with a confirmation that
   `rucio-mcp-atlas` is now linked.

From here, a tool call against a rucio-mcp-backed tool the caller's
capabilities allow (`read_data`) has the broker fetch (and refresh, near
expiry) this stored token and forward it as the tool call's bearer
credential — the same `auth_type: bearer` path any other backend uses.

## Naming consequence: double-prefixed tool names

rucio-mcp's tools are already self-prefixed at the source (`rucio_whoami`,
`rucio_list_dids`, ...). With two sites configured, each as its own
`aggregator.backends` entry, `apply_namespace` is left at its default
(`true`) rather than set to `false` — a single un-namespaced `rucio_*` mount
would be ambiguous once a second site can advertise the same tool names (see
[adding-a-backend.md's `apply_namespace`
section](adding-a-backend.md#apply_namespace-tool-naming) for the full
tradeoff and why `false` only stays safe for exactly one rucio-mcp backend).
The result callers actually see is double-prefixed tool names —
`rucio-atlas_rucio_whoami`, `rucio-escape_rucio_whoami` — ugly, but
unambiguous. This isn't a per-site config knob; it falls directly out of
`apply_namespace`'s default once more than one self-prefixed backend is
configured, and applies equally to a third or fourth site.

## Superseded design: a Keycloak IdP per site

An earlier design for this (issue
[#62](https://github.com/maniaclab/af-mcp-platform/issues/62)) proposed
registering each Rucio site as a Keycloak Identity Provider — `type: OpenID
Connect v1.0`, alias `rucio-<site>`, "Store Tokens" / "Stored Tokens
Readable" both on, Keycloak holding the resulting session token against the
user's federated identity. **That is not what shipped.** The
`oauth21-direct` provider type (this page) replaced it: the broker talks to
each site directly as an OAuth 2.1 client via its own CIMD document, with no
Keycloak IdP, no "Store/Read Tokens" flags, and no `read-token` client role
anywhere in the rucio-mcp path. If you find older design notes describing
the Keycloak-IdP-per-site approach, they predate this page and no longer
reflect what's deployed.

## See also

- [Adding a Backend](adding-a-backend.md) — the general, backend-agnostic
  procedure this page is a worked example of.
- [Authentication](auth.md#identity-provider-types) — `keycloak-brokered` vs
  `oauth21-direct` in general, and why `atlas-oidc` (PanDA, AMI) uses the
  former while rucio-mcp uses the latter.
- [Architecture](architecture.md#client-id-metadata-document-cimd) — the
  CIMD mechanism in full.
