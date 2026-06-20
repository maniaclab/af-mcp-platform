# Spike: agentgateway as MCP Aggregation Layer

## Purpose

[agentgateway](https://agentgateway.dev/) is an open-source MCP proxy/gateway
that can multiplex many MCP backends behind a single endpoint. This spike
evaluates whether agentgateway can replace the embedded FastMCP aggregator in
the AF MCP Platform.

The broker architecture is **invariant** regardless of this spike's outcome.
The `/v1` contract, credential brokering, authorization, and audit subsystems
are unchanged either way. The only question is whether agentgateway is a viable
aggregation frontend.

---

## Acceptance Test

The spike passes if and only if agentgateway satisfies **all** of the following:

> **Does agentgateway expose an `ext_authz` / `ext_proc` hook (or equivalent
> interceptor mechanism) that:**
> 1. fires on every `tools/call` invocation,
> 2. receives the tool name, tool arguments, and calling identity (principal),
> 3. can **block** the call (return an error to the client) before the backend
>    receives it, and
> 4. supports **server-side credential injection** — i.e., the hook or a
>    downstream filter can modify the outbound request to the backend
>    (e.g., add/replace an Authorization header) without the LLM client ever
>    seeing the credential?

All four conditions must be met. A "maybe with a workaround" is a **Fail**.

---

## Test Procedure

1. Deploy agentgateway (latest stable) in a test namespace with two stub MCP
   backends.
2. Configure a test interceptor (Envoy `ext_proc` filter, Lua filter, or
   agentgateway's native plugin API — whatever it exposes).
3. Issue a `tools/call` from a test MCP client with a known identity.
4. Observe whether the interceptor fires, receives the expected fields, and
   can return a synthetic error.
5. Implement a minimal credential injector: intercept the outbound call to the
   backend and replace the `Authorization` header with a fake brokered token.
   Verify the backend receives the injected token and the client never sees it.

---

## Outcome Recording

Update this section after the spike is run.

### Result: [ ] Pass / [ ] Fail

**Date tested:**
**agentgateway version:**
**Tester:**

**Findings:**
(Describe what was observed for each of the four acceptance criteria.)

**Decision:**
- Pass → agentgateway is eligible as a future replacement for the embedded
  FastMCP aggregator. Add a Phase N task to the roadmap to evaluate migration
  cost.
- Fail → agentgateway is excluded from the architecture. The embedded FastMCP
  aggregator remains. Do not re-open this question without a concrete upstream
  issue or PR that addresses the gap.

---

## Architecture Invariance

Regardless of outcome, the following are unchanged:

- `POST /v1/tools/{tool_name}` is the broker's tool-execution interface.
- The FastMCP aggregator (or agentgateway) calls the broker; it does not
  hold credentials or make authorization decisions.
- The `CredentialCache` and all four broker subsystems remain in the broker
  process.
- The Helm chart structure, Flux GitOps workflow, and Kubernetes manifests
  are unchanged.

The aggregation layer is the only component this spike affects.
