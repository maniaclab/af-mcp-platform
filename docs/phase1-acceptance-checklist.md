# Phase 1 Acceptance Checklist — FastMCP Aggregator (#58)

Issue #58's acceptance test is "one AF login → Rucio tools in Claude." This
page maps that test, and the aggregator behaviors it depends on, to their
current status: implemented-and-tested by the automated suite, or still
needing a check against a real deployment. It complements
[issue #70](https://github.com/maniaclab/af-mcp-platform/issues/70)'s
broader live-test tracker for the `/v1` credential-brokering surface, which
this page does not duplicate.

**Do not check off a "pending live verification" row from reading code.**
Run `scripts/verify-mcp-flow.py` against the actual deployment (see
[Connecting a Client](connecting-a-client.md))
and update the row with what you observed, or open a follow-up issue if it
surfaces a defect.

## Implemented and covered by automated tests

These are exercised by `pixi run -e dev pytest broker/ -v` (unit tests and
in-process integration tests against real toy MCP backends and real signed
JWTs — no mocked HTTP calls) and don't need a live check beyond the
"still green after this PR" spot-check below.

| Item | Test coverage |
|---|---|
| FastMCP aggregator mounted at `/mcp`, replacing the placeholder `FastAPI()` | `test_mcp_aggregator.py`, `test_mcp_aggregator_integration.py` |
| Services registered from `services.yaml` with no code change | `test_mcp_registry.py` |
| Bearer validated on every MCP request (`initialize`, `tools/list`, `tools/call`) via the same `identity.get_principal()` `/v1` uses | `test_mcp_middleware_identity.py` |
| `tools/list` filtered to permissions the caller's Keycloak groups grant | `test_mcp_middleware_entitlement.py` |
| `tools/call` re-checks entitlement before any credential is minted; denial never reaches the credential provider | `test_mcp_middleware_authorization.py` |
| Per-user credential injected for `auth_type: bearer` backends, mirroring `POST /v1/credential` | `test_mcp_credential_injection_integration.py` |
| Two different principals get two different, isolated minted credentials | `test_mcp_credential_injection_integration.py::test_per_user_credential_isolation` |
| `auth_type: none` backends skip credential resolution entirely | `test_mcp_credential_injection_integration.py::test_auth_type_none_skips_credential_resolution` |
| "Not linked" / "needs unlock" / x509-not-yet-supported surface as clean `ToolError`s, never a stack trace | `test_mcp_credential_injection_integration.py`, `test_mcp_aggregator.py` |
| Caller's inbound `Authorization` header is never forwarded to a backend | `test_mcp_aggregator_integration.py::test_authorization_header_not_forwarded_to_backend`, `test_mcp_credential_injection_integration.py` |
| Audit record written per tool call, with `outcome` of `success`/`denied`/`error` | `test_audit.py`, `test_mcp_middleware_authorization.py` |
| Per-backend `timeout_seconds` enforced on the wire | `test_mcp_registry.py`, `test_mcp_aggregator.py` |
| Backend `progress`/`log` notifications reach the caller without adopting `ProxyClient`'s header-forwarding | `test_mcp_notification_passthrough.py` |
| A dead/unreachable backend is omitted from `tools/list` without breaking the others | `test_mcp_aggregator_integration.py` (`provider_error_strategy="warn"`) |
| Backend 4xx/5xx/timeout surfaces as a clean `ToolError`, not a raw body or traceback | `test_mcp_call_time_errors.py` |

## Pending live verification

These require a real deployment, a real AF Keycloak token, and (for the
credential-injection rows) a real linked identity — none of which a unit
test can stand in for. Use `scripts/verify-mcp-flow.py` against
`https://mcp.af.uchicago.edu` for each.

- [ ] `verify-rucio-flow.py` steps 1-5 (the `/v1` surface this PR doesn't
      touch: identity, `is_linked`, catalog, authorize, credential) are
      still green after this PR lands — regression check, not new scope.
- [ ] `scripts/verify-mcp-flow.py` (no `--call`) against the live broker
      with a real bearer: connects, and `tools/list` shows the expected
      Rucio tools namespaced per `services.yaml` (`apply_namespace: false`
      for rucio, so `rucio_whoami`/`rucio_list_dids`/... not
      `rucio_rucio_*`).
- [ ] `scripts/verify-mcp-flow.py --call rucio_whoami --args-json '{}'`
      against `rucio-mcp-escape` (the working OAuth 2.1 target per issue
      #70 — `rucio-mcp-atlas` is blocked upstream on an ATLAS-side x509
      issue, unrelated to this PR) succeeds end-to-end: the broker mints
      the IAM-brokered credential, rucio-mcp does its own RFC 8693
      exchange, and a real Rucio response comes back through the
      aggregator to the client.
- [ ] The same call, run before linking `rucio-mcp-escape` from the
      portal, shows the friendly `OAuth21Provider not linked...` error via
      `/mcp` (not a crash, not a raw 404) — the middleware/client_factory
      contract this PR's tests assert in-process, confirmed over the wire.
- [ ] An audit log line (JSON, structlog) is emitted in the broker's
      stdout for the `rucio_whoami` call above, with `outcome: "success"`.
- [ ] Point Claude Desktop or Claude Code at `https://mcp.af.uchicago.edu/mcp/`
      per [Connecting a Client](connecting-a-client.md) and confirm a real
      client (not just the fastmcp `Client` the verification script and
      test suite use) can complete the same flow.
- [ ] Trailing-slash behavior: confirm whether a client configured with
      `https://mcp.af.uchicago.edu/mcp` (no trailing slash) works via
      Starlette's mount-redirect, or whether it hangs/fails for streaming
      HTTP clients that don't follow redirects on the initial POST. If it
      fails, `docs/connecting-a-client.md`'s trailing-slash guidance needs
      to become a hard requirement rather than a recommendation.
- [ ] §12 Phase 1 acceptance test ("one AF login → Rucio tools in Claude")
      — complete once every row above is checked.

## Known non-goals (not blocking the above)

- MCP OAuth discovery (RFC 8414) for clients to bootstrap their first
  token without the portal — explicitly deferred (issue #58's non-goals),
  pending the portal's `/tokens` page (#24), itself pending OpenBao (#2).
  (Both have since shipped: the portal's `/tokens` page exists, and issue
  #140 delivered the OAuth discovery flow.)
- x509 backends (`ami`) callable via `/mcp` — no per-call delivery
  mechanism defined yet for a credential that's consumed server-side from
  an NFS-mounted home directory; tracked as a TODO in `mcp/aggregator.py`,
  not a Phase 1 blocker (Phase 1's acceptance test is Rucio-specific).
