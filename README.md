# AF MCP Platform

The AF MCP Platform is a credential-brokered [Model Context Protocol](https://modelcontextprotocol.io/) gateway that any ATLAS analysis facility can deploy: it authenticates callers against the facility's Keycloak, brokers per-user credentials to downstream systems (Rucio, PanDA, AMI, ATLAS GitLab, Jupyter, HTCondor, and more), and aggregates all registered MCP backends behind one URL. LLM clients never hold raw x509/IAM credentials — the broker is the strategic platform boundary, and all tool invocations pass through an authorization and audit layer before reaching any backend.

The reference deployment is the [UChicago ATLAS Analysis Facility](https://af.uchicago.edu/), which runs this platform at `mcp.af.uchicago.edu` for its ~800 physics users. The examples below (hostnames, realm names, group mappings) are that deployment's own configuration, not platform requirements — see [docs/adding-a-service.md](docs/adding-a-service.md) and [docs/auth.md](docs/auth.md) for what's configurable per deployment.

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
        ├── rucio-mcp        (dataset / file catalog; ATLAS + ESCAPE)
        ├── ami-mcp           (ATLAS metadata interface)
        ├── condor-mcp        (HTCondor local cluster)
        ├── jupyterlab-mcp    (JupyterLab server / notebook management)
        ├── filesystem-mcp    (read-only AF filesystem access)
        └── ...               (Nth service — no code change)
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

Most clients need nothing else configured: the first request 401s, the client discovers the broker's own OAuth endpoints, and a browser window opens to log in — Claude Desktop and Claude Code both work this way today. If your client can't do that browser-based flow (no browser to open, or it predates the MCP OAuth spec), mint a static Bearer token at `mcp-portal.af.uchicago.edu/tokens` and add it as an `Authorization` header instead — see [docs/auth.md](docs/auth.md#programmatic-client-bootstrap).

### How authentication works

Every caller — the portal SPA in your browser, or an MCP client like Claude Desktop — obtains its own bearer token via OIDC Authorization Code + PKCE against the facility's Keycloak realm (the `connect` realm on the UChicago AF reference deployment), carrying the configured audience claim (`aud=mcp-gateway` by default). Nobody fetches, pastes, or configures a raw token by hand for the portal; MCP clients run the OIDC flow themselves.

- The broker's `HTTPBearer` dependency validates every request directly against that realm's JWKS — it's the sole validator, on both the MCP host and the portal host (`mcp.af.uchicago.edu` / `mcp-portal.af.uchicago.edu` on the reference deployment). There's no ForwardAuth proxy in the `/v1` or `/mcp` path on either host.
- oauth2-proxy still gates the portal's HTML for browser single sign-on across the facility's domain, but never sees or forwards the broker's own bearer tokens.
- Once validated, the broker resolves your POSIX identity and brokers per-user credentials (ATLAS IAM token, x509/VOMS proxy) to whichever backend the tool call targets. **Your MCP client never sees those brokered credentials.**
- Most clients bootstrap their own bearer token via OAuth discovery against the broker's own `/v1/oauth/authorize`/`/v1/oauth/token` endpoints — see [docs/auth.md](docs/auth.md#mcp-oauth-discovery-pat-bootstrap-issue-140). A client that can't do that flow mints a static PAT from the portal's `/tokens` page instead — see [docs/auth.md](docs/auth.md#programmatic-client-bootstrap).

For the full credential chain — Keycloak, the broker's token validation, brokered ATLAS IAM tokens, and x509 proxy minting — see [docs/auth.md](docs/auth.md).

## Ecosystem

This repo is the broker + portal — the credential-brokering core. A full deployment pairs it with separate, independently-maintained backend MCP servers and credential-minting services, wired in through config, not code. The UChicago ATLAS AF reference deployment runs:

- **Backends:** [rucio-mcp](https://github.com/kratsg/rucio-mcp), [ami-mcp](https://github.com/kratsg/ami-mcp), [golang-htcondor](https://github.com/bbockelm/golang-htcondor) (HTCondor), [af-jupyterlab-mcp](https://github.com/maniaclab/af-jupyterlab-mcp), [af-filesystem-mcp](https://github.com/maniaclab/af-filesystem-mcp)
- **Credential-minting services:** [condor-token-service](https://github.com/maniaclab/condor-token-service), [krb5-token-service](https://github.com/maniaclab/krb5-token-service), [voms-token-service](https://github.com/maniaclab/voms-token-service), [af-credentials](https://github.com/maniaclab/af-credentials)

None of these are required by af-mcp-platform itself — a different facility registers its own mix of backends and credential services behind the same broker. See [docs/ecosystem.md](docs/ecosystem.md) for what each one does and how it plugs in.

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

MIT — see [LICENSE](LICENSE).
