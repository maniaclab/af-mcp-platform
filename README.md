# AF MCP Platform

The AF MCP Platform is a credential-brokered [Model Context Protocol](https://modelcontextprotocol.io/) gateway for the [UChicago ATLAS Analysis Facility](https://af.uchicago.edu/). It provides ~800 physics users a single endpoint — `mcp.af.uchicago.edu` — that authenticates with AF Keycloak, brokers per-user credentials to downstream systems (Rucio, PanDA, AMI, ATLAS GitLab, Jupyter, HTCondor, and more), and aggregates all registered MCP backends behind one URL. The broker is the strategic platform boundary: LLM clients never hold raw x509/IAM credentials, and all tool invocations pass through an authorization and audit layer before reaching any backend.

## Architecture

```
Claude / Gemini / any MCP client
        │
        ▼
mcp.af.uchicago.edu   (oauth2-proxy → AF Keycloak OIDC)
        │
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

Add the MCP endpoint to Claude Desktop (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "atlas-af": {
      "url": "https://mcp.af.uchicago.edu/mcp",
      "headers": {
        "Authorization": "Bearer <your-AF-token>"
      }
    }
  }
}
```

Get your bearer token from the AF portal: <https://portal.af.uchicago.edu/tokens>

For Gemini / other clients that support the MCP HTTP transport, use the same URL. The endpoint speaks standard MCP-over-HTTP (SSE or streamable-HTTP).

## For Operators

See [docs/deploy.md](docs/deploy.md) for Flux CD / Helm deployment instructions, secret management, and runbooks.

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
