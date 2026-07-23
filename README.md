# AF MCP Platform

The AF MCP Platform is a credential-brokered [Model Context Protocol](https://modelcontextprotocol.io/) gateway for the [UChicago ATLAS Analysis Facility](https://af.uchicago.edu/). It provides ~800 physics users a single endpoint — `mcp.af.uchicago.edu` — that authenticates with AF Keycloak, brokers per-user credentials to downstream systems (Rucio, PanDA, AMI, ATLAS GitLab, Jupyter, HTCondor, and more), and aggregates all registered MCP backends behind one URL. The broker is the strategic platform boundary: LLM clients never hold raw x509/IAM credentials, and all tool invocations pass through an authorization and audit layer before reaching any backend.

## Architecture

```
Claude / Gemini / any MCP client         Browser (portal SPA)
        │  own Bearer (OIDC)                     │  oauth2-proxy: HTML only
        ▼                                         ▼
mcp.af.uchicago.edu                     mcp-portal.af.uchicago.edu
(no oauth2-proxy — broker               (portal does its own OIDC; /v1
 validates the Bearer itself)            + /mcp bypass oauth2-proxy too)
        │                                         │
        └───────────────────┬─────────────────────┘
                             ▼
┌──────────────────────────────────────────────┐
│  FastMCP Aggregator  +  AF Credential Broker │
│  (FastAPI /v1 HTTP API)                      │
│  • Identity  • AuthZ  • Credential  • Audit  │
└──────────────────────────────────────────────┘
        │
        ├── rucio-mcp        (dataset / file catalog)
        ├── ami-mcp           (ATLAS metadata interface)
        ├── openmagic         (theory / MC generator tools)
        ├── panda-mcp         (PanDA job submission/status)
        ├── condor-mcp        (HTCondor local cluster)
        ├── gitlab-mcp        (ATLAS GitLab API)
        ├── jupyter-control   (kernel / notebook management)
        └── ...               (Nth backend — no code change)
```

## Quick Start for ATLAS AF Users

Point your MCP client at `https://mcp.af.uchicago.edu/mcp`. The endpoint speaks standard MCP-over-HTTP (SSE or streamable-HTTP), so any client that supports the HTTP transport (Claude Desktop, Gemini, the MCP CLI, etc.) can connect.

Example `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "atlas-af": {
      "url": "https://mcp.af.uchicago.edu/mcp"
    }
  }
}
```

### How authentication works

Every caller — the portal SPA in your browser, or an MCP client like Claude Desktop — obtains its own bearer token via OIDC Authorization Code + PKCE against AF Keycloak's `connect` realm, carrying `aud=mcp-gateway`. Nobody fetches, pastes, or configures a raw token by hand for the portal; MCP clients run the OIDC flow themselves.

- The broker's `HTTPBearer` dependency validates every request directly against the connect-realm JWKS — it's the sole validator, on both `mcp.af.uchicago.edu` and `mcp-portal.af.uchicago.edu`. There's no ForwardAuth proxy in the `/v1` or `/mcp` path on either host.
- oauth2-proxy still gates the portal's HTML for browser single sign-on across `.af.uchicago.edu`, but never sees or forwards the broker's own bearer tokens.
- Once validated, the broker resolves your POSIX identity and brokers per-user credentials (ATLAS IAM token, x509/VOMS proxy) to whichever backend the tool call targets. **Your MCP client never sees those brokered credentials.**
- **Current limitation:** MCP OAuth discovery isn't implemented yet, so a programmatic client needs another way to bootstrap its first bearer token. Issue #24 tracks a portal `/tokens` page for this (on hold pending #2's OpenBao design).

For the full credential chain — Keycloak, the broker's token validation, brokered ATLAS IAM tokens, and x509 proxy minting — see [docs/auth.md](docs/auth.md).

## For Operators

Deployment is via the Helm chart in [`charts/af-mcp-platform`](charts/af-mcp-platform) — `values.yaml` documents every configurable field. See [docs/architecture.md](docs/architecture.md) for the reference architecture and auth model.

## For Developers

The full new-contributor walkthrough lives in
[docs/local-development.md](docs/local-development.md): two-terminal broker +
portal workflow, the `BROKER_DEV_INSECURE_PRINCIPAL` bypass for clicking
through the UI without oauth2-proxy, `PORTAL_DEV_BROKER_URL` for a non-default
broker host, test/lint tasks, and a ports summary.

### Prerequisites

- [pixi](https://pixi.sh) installed (`curl -fsSL https://pixi.sh/install.sh | bash`)
- Node 22+ (for the portal)

### Start the broker locally

```bash
pixi run broker
```

The broker API is available at <http://localhost:8080/docs>.

### Start the portal locally

```bash
pixi run -e portal dev
```

### Run tests

```bash
pixi run -e dev test          # broker unit tests
pixi run test-spikes          # spike validation tests
pixi run -e portal test       # portal vitest suite
```

### Lint / format

```bash
pixi run -e dev lint
pixi run -e dev fmt
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
