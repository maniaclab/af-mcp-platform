# AF MCP Platform

The AF MCP Platform is a credential-brokered [Model Context Protocol](https://modelcontextprotocol.io/)
gateway that any analysis facility can deploy in front of its own backend MCP
servers. It gives an AF's users a single endpoint that:

- authenticates callers against the deployer's own Keycloak — every caller
  (MCP client or the portal SPA) presents its own bearer token, which the
  broker validates directly;
- brokers per-user credentials to downstream systems (Rucio, PanDA, AMI,
  ATLAS GitLab, Jupyter, HTCondor, …);
- aggregates every registered backend MCP server behind one URL.

LLM clients never hold raw x509 or IAM credentials. Every method invocation
(MCP "tool" call) passes through the broker's authorization and audit layer
before reaching any backend.

The reference deployment is the [UChicago ATLAS Analysis Facility](https://af.uchicago.edu/)
(`mcp.af.uchicago.edu`, ~800 physics users); the diagrams and examples below
use its endpoint names and values as one concrete instance of the platform,
not as universal facts.

## Architecture at a glance

```
Claude / Gemini / any MCP client         Browser (portal SPA)
        │  own Bearer (OIDC)                     │  own OIDC login (client-side)
        ▼                                         ▼
mcp.af.uchicago.edu                     mcp-portal.af.uchicago.edu
(broker validates the                   (portal does its own OIDC;
 Bearer itself)                          /v1 + /mcp carry no gate)
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
        ├── ami-mcp          (ATLAS metadata interface)
        ├── condor-mcp       (HTCondor local cluster)
        ├── jupyterlab-mcp   (JupyterLab server / notebook management)
        ├── filesystem-mcp   (read-only AF filesystem access)
        └── …                (Nth service — no code change)
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
- [Adding a Service](adding-a-service.md) — the five-step, config-only
  procedure for wiring a new MCP backend into the aggregator.
- [Rucio: Per-Site Setup](rucio-per-site-setup.md) — the concrete, deployed
  procedure for wiring up an additional Rucio VO/site behind rucio-mcp.
- [Connecting a Client](connecting-a-client.md) — end-user setup for Claude,
  Claude Code, and any other MCP-over-HTTP client, plus the exact error
  strings you'll see if a prerequisite (permission, linked identity) is
  missing.
- [Observability](observability.md) — operating the metering pipeline,
  usage store, metrics, and trace emission, plus the user-facing
  `GET /v1/usage` endpoint and how to join your own traces.
- [Admin Capabilities](admin.md) — configuring the admin group, the
  usage-for-other-users view, and maintenance mode (including its
  fail-open-on-store-outage limitation).
- [Phase 1 Acceptance Checklist](phase1-acceptance-checklist.md) — what's
  verified by automated tests vs. what still needs a live-deploy check.
- [agentgateway Spike](agentgateway-spike.md) — the acceptance test that
  decides whether agentgateway can replace the embedded FastMCP aggregator.

## Connecting an MCP client

See [Connecting a Client](connecting-a-client.md) for concrete config for
Claude, Claude Code, and other MCP-over-HTTP clients (the
[top-level README](https://github.com/maniaclab/af-mcp-platform#quick-start-for-atlas-af-users)
has a short version). Every client presents its own `aud=mcp-gateway` bearer
token directly to the broker; the portal obtains its own automatically via
OIDC, and MCP clients bootstrap theirs via MCP OAuth discovery against the
broker's own OAuth endpoints — the recommended path (issue maniaclab/af-mcp-platform#140). Pasting a
static token minted from the portal's `/tokens` page remains the fallback
for clients that can't run the discovery flow. The
[Authentication](auth.md) page walks through every hop of the credential
chain.

## Repository

Source, issues, and PRs live at
[maniaclab/af-mcp-platform](https://github.com/maniaclab/af-mcp-platform).
