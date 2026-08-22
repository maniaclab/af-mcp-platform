# Connecting a Client

How to point an MCP client at an AF broker and get real AF tools (Rucio,
AMI, ...) inside it. Examples below use the UChicago ATLAS AF's deployment
(`https://mcp.af.uchicago.edu/mcp`) as the concrete worked example —
connecting to another facility's deployment follows the same flow against
that facility's own broker hostname and Keycloak realm. This page covers the
client side; see [Architecture](architecture.md) for how the broker itself
authenticates, authorizes, and brokers credentials for every call, and
[Authentication](auth.md) for the full credential chain.

## Prerequisites

Before a tool call succeeds, three things have to be true, in order:

1. **You have an AF account** that can obtain an `aud=mcp-gateway` access
   token from AF Keycloak's `connect` realm. This is the same login the
   portal (`mcp-portal.af.uchicago.edu`) uses.
2. **Your Keycloak group membership grants the capability the tool's
   backend requires** (e.g. Rucio tools require `read_data`). Capabilities
   come from the `groups` claim on your token via `policy.yaml`'s
   `group_capabilities` — see [Authorization](architecture.md#2-authorization).
   Missing this means the tool is invisible in `tools/list`, not just
   denied at call time (see [Errors](#errors-youll-see) below).
3. **For backends that need your own credential** (`auth_type: bearer` in
   `backends.yaml` — Rucio is the Phase 1 example), **you've linked that
   identity provider from the portal's Identities page**
   (`mcp-portal.af.uchicago.edu/identities/`). Without this, the tool is
   visible in `tools/list` (entitlement filtering only checks the
   capability, not linkage) but fails at call time with a "not linked"
   error.

## Getting a bearer token

Every MCP client presents its own `aud=mcp-gateway` bearer token directly —
there is no ForwardAuth proxy in front of `/mcp` (see
[Architecture](architecture.md)). There are now two ways to get one:

- **OAuth discovery (recommended)** — a client that speaks the MCP
  authorization spec bootstraps its own credential with no manual step at
  all. Point it at the server URL with no header/token configured; the
  first request 401s, the client discovers the broker's own
  `/v1/oauth/authorize`/`/v1/oauth/token` (RFC 9728 + RFC 8414 metadata,
  `client_id_metadata_document_supported: true` — see
  [MCP OAuth discovery + PAT bootstrap](auth.md#mcp-oauth-discovery-pat-bootstrap-issue-140)
  for the full mechanism), opens your browser to a real Keycloak login, and
  comes back with a working PAT it stores itself. This is now the default
  path for any interactive client below that supports it.
- **A manually minted PAT** — for CI, scripts, and clients that cannot do
  OAuth (no browser to open, or a client too old to implement the spec).
  Mint one at
  [`mcp-portal.af.uchicago.edu/tokens`](https://mcp-portal.af.uchicago.edu/tokens/)
  and paste it into your client's configuration once (see
  [Programmatic client bootstrap](auth.md#programmatic-client-bootstrap) for
  what that page's mint/list/revoke endpoints actually do, including the
  remaining known limitations and how revocation is enforced). The token's
  value is shown exactly once at mint time — if you lose it, revoke it from
  the portal and mint a new one, rather than trying to retrieve it again.

Either way, the resulting PAT behaves identically once you have it — same
`mcp_pat_…` shape, same `/tokens` list entry, same revocation. The sections
below say which path each client uses.

## Minting a token from the command line

Once you have one `aud=mcp-gateway` bearer (e.g. copied out of a logged-in
portal session), you can mint further tokens without going back to the
browser — handy for CI or scripts that need to rotate their own short-lived
token. The `/tokens` page has a copy-paste "Use from the command line"
section with these exact snippets pre-filled with your broker's origin; this
is the same request:

```bash
read -s -p "Bearer token: " MCP_BEARER_TOKEN
export MCP_BEARER_TOKEN

curl -sS -X POST "https://mcp.af.uchicago.edu/v1/tokens" \
  -H "Authorization: Bearer $MCP_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-laptop", "note": "optional free-text note"}'
```

`name` and `note` are both optional (see
[Programmatic client bootstrap](auth.md#programmatic-client-bootstrap)). The
response's `token` field is shown exactly once — the broker never returns a
minted token's value again.

**Only tokens minted this way — through `POST /v1/tokens` — show up in the
portal's `/tokens` list** (name, expiry, revoke). A token obtained directly
from Keycloak (e.g. a local PKCE script) is a perfectly valid `aud=mcp-gateway`
bearer, but the broker never saw it minted, so it has no metadata to list or
revoke there; see the [Programmatic client bootstrap](auth.md#programmatic-client-bootstrap)
known limitations for why.

## Claude (Claude.ai, Claude Desktop)

Add a custom connector with just the server URL — no header, no token:

1. Go to **Settings > Connectors > Add custom connector**.
2. Enter the server URL: `https://mcp.af.uchicago.edu/mcp/` (note the
   trailing slash — see [Errors](#errors-youll-see)).
3. Click **Add**, then enable the connector for your conversation via the
   "+" button's Connectors menu.

The first call triggers OAuth discovery: Claude opens a browser window to
Keycloak's login, and on success stores the resulting PAT itself — you never
see or handle the token directly. If your client predates OAuth support (or
the "custom connectors" feature isn't available to you yet), fall back to a
static bearer via **Request headers** instead:

- Name: `Authorization`
- Value: `Bearer <your-token>` — include the literal word `Bearer` and the
  space; Claude sends the value exactly as entered, with no scheme
  prepended.
- Mark it **Required**.

Claude stores either credential securely and does not display it again.

## Claude Code

```bash
claude mcp add --transport http atlas-af https://mcp.af.uchicago.edu/mcp/
```

No `--header` needed. The first tool call 401s, Claude Code discovers the
broker's OAuth metadata, and opens your browser to complete the Keycloak
login — the PAT it gets back is stored for you, not printed to the
terminal.

Equivalent JSON (`.mcp.json` for project scope, `~/.claude.json` for user
scope via `claude mcp add --scope user ...`):

```json
{
  "mcpServers": {
    "atlas-af": {
      "type": "http",
      "url": "https://mcp.af.uchicago.edu/mcp/"
    }
  }
}
```

If you'd rather skip the browser step entirely (e.g. a headless environment
with no way to open one), mint a PAT from the portal and wire it in as a
static header instead, the same way as before:

```bash
read -s -p "Bearer token: " MCP_BEARER_TOKEN
export MCP_BEARER_TOKEN

claude mcp add --transport http atlas-af https://mcp.af.uchicago.edu/mcp/ \
  --header "Authorization: Bearer $MCP_BEARER_TOKEN"
```

Claude Code expands `${MCP_BEARER_TOKEN}` from the environment at connect
time — the token itself never needs to be written into the JSON file.

## Any other MCP-over-HTTP client

The pattern is the same everywhere: HTTP (or SSE) transport, pointed at
`https://mcp.af.uchicago.edu/mcp/`. A client built on an MCP SDK with OAuth
support (e.g. the Python or TypeScript `mcp` SDKs' own client auth helpers)
needs nothing else configured — it follows the same discovery-then-login
sequence described above on its own. A client without that support still
needs an explicit `Authorization: Bearer <token>` header on every request,
using a PAT minted from the portal or the command line above. This is
exactly what `scripts/verify-mcp-flow.py` does via the `fastmcp` Python
client (bearer-header path, not OAuth discovery) — read its `--help` and
source for a minimal working example, or run it directly to sanity-check
your own token before wiring up a client:

```bash
read -s -p "Bearer token: " MCP_BEARER_TOKEN
export MCP_BEARER_TOKEN
pixi run -e dev python scripts/verify-mcp-flow.py
```

## What tools you should expect to see

`tools/list` is entitlement-filtered: you only see tools for backends whose
`required_capability` your Keycloak groups grant (see
[Authorization](architecture.md#2-authorization)). Tool names are
namespaced by backend prefix (`<prefix>_<toolname>`), except where a
backend already self-prefixes its own tools (rucio-mcp ships
`rucio_list_dids`, `rucio_whoami`, etc. — namespacing it again would double
up into `rucio_rucio_*`, so its `backends.yaml` entry opts out via
`apply_namespace: false`). Either way, every tool you see starts with its
backend's prefix, e.g. `rucio_whoami`.

## Diagnosing tool problems yourself

The broker exposes three tools directly on the aggregator, named with the
reserved `af_` prefix so a backend can never shadow them (see
[Architecture](architecture.md)). They need no capability and stay visible
and callable for every authenticated caller no matter what's broken
elsewhere — that's the point: they answer "why" when a tool is missing or a
call fails, without needing anything else to be working first.

| Tool | Call it when |
|---|---|
| `af_whoami` | A call fails with a capability/permission error, to see your own subject, groups, and effective capabilities. |
| `af_list_identities` | A call fails with a "not linked" error, or a backend's tools are missing/non-functional, to see which identity provider it needs and whether you've linked it. |
| `af_list_mcp_servers` | An expected tool is missing from `tools/list`, or a call fails for a reason that isn't an obviously bad argument — lists every backend, its tool prefix, the identity provider it depends on, and a short reason if it's unavailable. |

An MCP client that lets you invoke tools directly (or an LLM using the
broker through you) can call these the same way as any other tool — no
extra setup, since they don't proxy to a backend at all.

## Errors you'll see

These are the exact strings the aggregator raises (see
`broker/src/af_mcp_broker/mcp/aggregator.py` and
`mcp/middleware/authorization_mw.py`) — a client that surfaces raw MCP tool
errors to you will show one of these verbatim:

| Situation | What you'll see |
|---|---|
| No `Authorization` header sent at all | `Missing Authorization: Bearer <token> header` |
| Token invalid, expired, or wrong audience | `Invalid or expired token` |
| Tool call denied (capability missing) | `Authorization denied: principal lacks capability '<cap>'. Granted capabilities: [...]` |
| Tool name doesn't match any backend | `No backend registered for tool '<name>'` |
| Bearer backend, not linked | `<ProviderClassName> not linked. Visit the portal Identities page to connect it. Call af_list_identities to see which identity provider this backend needs, or af_list_mcp_servers for this backend's current status.` (e.g. `OAuth21Provider not linked...` for rucio-mcp-escape) |
| x509 backend needs unlock | `Credential unlock required. Visit the portal: <portal-url>/v1/x509/proxy` |
| x509 backend, broker has no signing key | `Backend '<name>' is an x509 backend, which needs the broker to sign AF Broker Identity Tokens, but no signing key is configured ...` — mount `broker.identityToken.existingSigningKeySecret` |
| x509 backend, no proxy minted yet | The backend's own tool error surfaces the redeem 404: `No valid x509/VOMS proxy is cached for this account — mint one at the AF portal and retry.` |
| Backend unreachable / times out | A clean MCP tool error naming the failure, never a raw traceback or the backend's HTTP body |

A tool you lack the capability for won't appear in `tools/list` at all
(entitlement filtering, not an error) — it isn't visible-but-denied the way
the "not linked" case is. If a tool you expect is missing, call
`af_list_mcp_servers` (see [above](#diagnosing-tool-problems-yourself)) or
check `GET /v1/capabilities` on the broker (or the portal's Catalog page)
before assuming your token is broken.

**Trailing slash**: point clients at `/mcp/` (trailing slash). Whether a
client that only supports a bare `/mcp` (no trailing slash) works depends
on how it handles the redirect Starlette's `Mount` issues — this is one of
the items pending live verification; see
[Phase 1 Acceptance Checklist](phase1-acceptance-checklist.md).

## See also

- [Architecture](architecture.md) — the full request path from your bearer
  token to a backend MCP server.
- [Authentication](auth.md) — how identity providers, IAM-brokered tokens,
  and x509/VOMS proxies work.
- The portal's [Identities page](https://mcp-portal.af.uchicago.edu/identities/)
  — link the accounts your tool calls need credentials for.
- [Phase 1 Acceptance Checklist](phase1-acceptance-checklist.md) — what's
  verified by automated tests vs. what still needs a live-deploy check with
  `scripts/verify-mcp-flow.py`.
