# AF MCP Platform

The AF MCP Platform is a credential-brokered [Model Context Protocol](https://modelcontextprotocol.io/)
gateway for the [UChicago ATLAS Analysis Facility](https://af.uchicago.edu/). It
provides the AF's ~800 physics users a single endpoint —
`mcp.af.uchicago.edu` — that:

- authenticates callers against **AF Keycloak** — every caller (MCP client
  or the portal SPA) presents its own bearer token, which the broker
  validates directly;
- brokers per-user credentials to downstream systems (Rucio, PanDA, AMI,
  ATLAS GitLab, Jupyter, HTCondor, …);
- aggregates every registered backend MCP server behind one URL.

LLM clients never hold raw x509 or IAM credentials. Every tool invocation
passes through the broker's authorization and audit layer before reaching
any backend.

## Architecture at a glance

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
        ├── ami-mcp          (ATLAS metadata interface)
        ├── openmagic        (theory / MC generator tools)
        ├── panda-mcp        (PanDA job submission/status)
        ├── condor-mcp       (HTCondor local cluster)
        ├── gitlab-mcp       (ATLAS GitLab API)
        ├── jupyter-control  (kernel / notebook management)
        └── …                (Nth backend — no code change)
```

See [Architecture](architecture.md) for the full breakdown of the four
broker subsystems and the `/v1` contract, and
[Authentication](auth.md) for the credential-chain details.

## What this documentation covers

- [Architecture](architecture.md) — the four broker subsystems (Identity,
  Authorization, Credential, Audit) and the `/v1` HTTP contract that is the
  platform boundary.
- [Authentication](auth.md) — the full credential chain: AF Keycloak, the
  broker's own bearer-token validation, ATLAS IAM brokered tokens, and
  x509/VOMS proxy minting.
- [Adding a Backend](adding-a-backend.md) — the five-step, config-only
  procedure for wiring a new MCP backend into the aggregator.
- [agentgateway Spike](agentgateway-spike.md) — the acceptance test that
  decides whether agentgateway can replace the embedded FastMCP aggregator.

## Connecting an MCP client

For end-user setup — Claude Desktop, Gemini, and other MCP-capable clients —
see the [top-level README](https://github.com/maniaclab/af-mcp-platform#quick-start-for-atlas-af-users).
Every client obtains its own bearer token via OIDC against AF Keycloak and
presents it directly to the broker; users do not fetch or paste raw tokens
by hand. The [Authentication](auth.md) page walks through every hop of the
credential chain.

## Repository

Source, issues, and PRs live at
[maniaclab/af-mcp-platform](https://github.com/maniaclab/af-mcp-platform).
