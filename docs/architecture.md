# Architecture

## Overview

The AF MCP Platform sits between LLM clients (Claude, Gemini, or any MCP-capable
agent framework) and a growing set of ATLAS/AF backend services. Its job is to
ensure that tool calls are authenticated, authorized, and executed with the right
per-user credentials — without ever handing raw secrets to the LLM or requiring
backends to implement their own auth plumbing.

```
LLM client
    │  MCP-over-HTTP (SSE / streamable-HTTP)
    ▼
oauth2-proxy  ──────────────────────── AF Keycloak OIDC
    │  validated OIDC JWT (AF principal)
    ▼
FastMCP Aggregator  ◄────────────────  tool registry (in-memory, hot-reload)
    │  internal call: tool_name + args + principal
    ▼
AF Credential Broker  (/v1 HTTP API)
    │  brokered credential (rucio token, x509 proxy, IAM token, …)
    ▼
Backend MCP server  (rucio-mcp, ami-mcp, panda-mcp, …)
    │  result / error
    ▼  (back up the chain)
LLM client
```

---

## The Four Broker Subsystems

### 1. Identity

Extracts and validates the AF principal from the incoming request.

- Trusts only the Keycloak-issued JWT forwarded by oauth2-proxy.
- Resolves the POSIX `uid` / `gid` for the principal (needed for NFS-scoped
  credential operations).
- Produces a `Principal` dataclass that flows through the rest of the call.

### 2. Authorization

Answers: "is this principal allowed to call this tool?"

- Policy is declarative YAML (`policy.yaml`) — no code change needed to add a
  capability.
- Each tool is tagged with a `required_capability` (e.g., `rucio:read`,
  `panda:submit`).
- A principal's capabilities come from their Keycloak group memberships via
  `entitlements.group_capabilities` in the HelmRelease values.
- Authorization failures are logged with structured fields (uid, tool, capability)
  and return HTTP 403 to the aggregator.

### 3. Credentialing

Fetches or mints the per-user credential required by the backend, given an
authorized principal.

Two axes define the provider matrix:

| | **Short-lived mint** | **Stored brokered token** |
|---|---|---|
| **IAM-based** | Keycloak token exchange (AF-internal only) | `GET /realms/connect/broker/atlas-iam/token` → ATLAS IAM token |
| **x509/VOMS** | Ephemeral k8s Job (NFS subPath mount of `~/.globus`) | N/A — always minted fresh |

The `CredentialCache` (in-process, async-safe) stores minted credentials keyed by
`(uid, target)` for their lifetime, avoiding redundant minting. See
`spikes/credential-isolation/` for the concurrency validation.

Important: Keycloak Standard Token Exchange (V2) is internal-to-AF only. It
**cannot** mint a token that `atlas-auth.cern.ch` will accept. Use the stored
brokered token path via `GET /realms/connect/broker/atlas-iam/token` for any
credential that must be accepted by external ATLAS services (Rucio, PanDA, AMI).

### 4. Audit

Structured log (structlog + JSON) of every tool invocation, including:
- principal uid and Keycloak subject
- tool name and backend
- authorization decision (allow / deny) and capability checked
- credential provider used
- response status and latency
- request ID (propagated in `X-Request-ID` header)

Prometheus metrics (`/metrics`) expose per-tool latency histograms and error
counters, scraped by the cluster's Prometheus instance.

---

## The `/v1` Broker Contract

The FastAPI `/v1` HTTP API is the **platform boundary**. Anything behind it
(aggregator, backends, credential providers) is an implementation detail.
Anything in front of it (oauth2-proxy, LLM clients) sees only this surface.

Key endpoints:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/tools/{tool_name}` | Execute a tool call for the authenticated principal |
| `GET` | `/v1/tools` | List available tools (filtered by principal's capabilities) |
| `GET` | `/v1/health` | Liveness probe |
| `GET` | `/v1/ready` | Readiness probe (checks backend connectivity) |
| `GET` | `/metrics` | Prometheus metrics |

All requests require a valid AF bearer token. The aggregator translates
MCP-over-HTTP into `/v1` calls; external callers can also hit `/v1` directly
(useful for scripting and debugging).

---

## Aggregation Extraction Path

The current design embeds FastMCP as a library inside the broker process. This is
the simplest correct thing. The extraction path if it becomes necessary:

1. **Embedded FastMCP** (current) — FastMCP runs in-process, broker handles both
   MCP protocol and credential brokering.
2. **Standalone FastMCP sidecar** — FastMCP runs as a separate container in the
   same pod, talking to the broker via loopback. Useful if FastMCP needs
   independent scaling.
3. **agentgateway** — if the agentgateway spike (see `docs/agentgateway-spike.md`)
   passes, agentgateway can replace the FastMCP aggregator while the broker
   remains unchanged. The `/v1` contract is invariant.

---

## Full Data Flow for a Tool Call

1. LLM sends `tools/call` MCP message over HTTPS to `mcp.af.uchicago.edu`.
2. oauth2-proxy validates the bearer token against Keycloak and forwards the
   request with the validated JWT in a header.
3. The FastMCP Aggregator receives the `tools/call`, extracts tool name + args,
   and calls the broker's `POST /v1/tools/{tool_name}`.
4. The broker Identity subsystem validates the JWT and resolves the `Principal`.
5. The Authorization subsystem checks `principal.capabilities` against the tool's
   `required_capability`. Deny → 403 logged and returned.
6. The Credential subsystem looks up `(uid, target)` in the `CredentialCache`. On
   miss, it invokes the appropriate provider (token exchange or x509 mint Job).
7. The broker constructs the backend request, injecting the credential, and calls
   the target backend MCP server.
8. The backend response is returned through the broker → aggregator → LLM client.
9. The Audit subsystem writes a structured log line and updates Prometheus counters.
