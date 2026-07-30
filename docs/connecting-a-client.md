# Connecting a Client

How to point an MCP client at `https://mcp.af.uchicago.edu/mcp` and get real
AF tools (Rucio, AMI, ...) inside it. This page covers the client side; see
[Architecture](architecture.md) for how the broker itself authenticates,
authorizes, and brokers credentials for every call, and
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
[Architecture](architecture.md)). **MCP OAuth discovery (RFC 8414) is not
implemented yet** (tracked by issue #58 as an explicit non-goal, deferred to
the portal's planned `/tokens` page), so no client can bootstrap its first
token automatically today — you obtain one via the portal and paste it into
your client's configuration once. The mechanism for doing that without the
token touching disk or shell history is client-specific; see each section
below.

## Claude (Claude.ai, Claude Desktop)

Claude's remote-MCP "custom connectors" support a static bearer token via a
**Request headers** field — this is currently a **beta** feature; if you
don't see it, ask your Anthropic account team for early access, or use
Claude Code / the MCP CLI below in the meantime.

1. Go to **Settings > Connectors > Add custom connector**.
2. Enter the server URL: `https://mcp.af.uchicago.edu/mcp/` (note the
   trailing slash — see [Errors](#errors-youll-see)).
3. Open **Request headers**, add a header:
   - Name: `Authorization`
   - Value: `Bearer <your-token>` — include the literal word `Bearer` and
     the space; Claude sends the value exactly as entered, with no scheme
     prepended.
   - Mark it **Required**.
4. Click **Add**, then enable the connector for your conversation via the
   "+" button's Connectors menu.

Claude stores the header value securely and does not display it again.

## Claude Code

```bash
claude mcp add --transport http atlas-af https://mcp.af.uchicago.edu/mcp/ \
  --header "Authorization: Bearer $MCP_BEARER_TOKEN"
```

Read the token into that env var first so it never lands in your shell
history:

```bash
read -s -p "Bearer token: " MCP_BEARER_TOKEN
export MCP_BEARER_TOKEN
```

Equivalent JSON (`.mcp.json` for project scope, `~/.claude.json` for user
scope via `claude mcp add --scope user ...`):

```json
{
  "mcpServers": {
    "atlas-af": {
      "type": "http",
      "url": "https://mcp.af.uchicago.edu/mcp/",
      "headers": {
        "Authorization": "Bearer ${MCP_BEARER_TOKEN}"
      }
    }
  }
}
```

Claude Code expands `${MCP_BEARER_TOKEN}` from the environment at connect
time — the token itself never needs to be written into the JSON file.

## Any other MCP-over-HTTP client

The pattern is the same everywhere: HTTP (or SSE) transport, pointed at
`https://mcp.af.uchicago.edu/mcp/`, with an `Authorization: Bearer <token>`
header on every request. This is exactly what `scripts/verify-mcp-flow.py`
does via the `fastmcp` Python client — read its `--help` and source for a
minimal working example, or run it directly to sanity-check your own token
before wiring up a client:

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
| Bearer backend, not linked | `<ProviderClassName> not linked. Visit the portal Identities page to connect it.` (e.g. `OAuth21Provider not linked...` for rucio-mcp-escape) |
| x509 backend needs unlock | `Credential unlock required. Visit the portal: <portal-url>/v1/x509/proxy` |
| x509 backend called via /mcp at all | `Backend '<name>' requires an x509/VOMS proxy credential ... not yet deliverable over /mcp tool calls.` — a known gap (issue #58's TODO), not a bug |
| Backend unreachable / times out | A clean MCP tool error naming the failure, never a raw traceback or the backend's HTTP body |

A tool you lack the capability for won't appear in `tools/list` at all
(entitlement filtering, not an error) — it isn't visible-but-denied the way
the "not linked" case is. If a tool you expect is missing, check
`GET /v1/capabilities` on the broker (or the portal's Catalog page) before
assuming your token is broken.

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
