# shelf-mcp: a reference MCP server for the AF MCP platform

A small, runnable server over a fake in-memory data source. It follows every
MUST and SHOULD in [`docs/mcp-design.md`](https://github.com/maniaclab/af-mcp-platform/blob/main/docs/mcp-design.md)
that applies to a read-only server, and is kept that way by tests in the
`af-mcp-builder` skill. Copy the shape, then replace `data.py` with your
service's native client library and rename the `shelf` prefix.

## Layout

| File | Role |
|------|------|
| `shelf_mcp/server.py` | Tool registration, `/healthz`, the ASGI app, `main()` |
| `shelf_mcp/auth.py` | `JwksCache` and `BrokerTokenVerifier` |
| `shelf_mcp/observability.py` | Request id, JSON logs, access log, optional spans |
| `shelf_mcp/data.py` | The fake data client (stands in for the native client library) |
| `test_shelf_auth.py`, `test_shelf_tools.py` | Unit tests for auth, integration tests for the tools |

Run it with `SHELF_JWKS_URI`, `SHELF_ISSUER` and `SHELF_AUDIENCE` set, then
`python -m shelf_mcp.server`. Set `OTEL_EXPORTER_OTLP_ENDPOINT` (and
`OTEL_SERVICE_NAME`) to export spans; with it unset, tracing is off.

## Request flow

1. The broker POSTs to `/mcp` with `Authorization: Bearer <broker token>` and
   `X-Request-ID: <correlation id>`.
2. `RequestLogMiddleware` binds the request id to the request's context.
3. fastmcp calls `BrokerTokenVerifier`, which looks the token's `kid` up in the
   cached JWKS and checks signature, `iss`, `aud` and `exp`. A failure answers
   HTTP 401 before any tool runs.
4. `ToolCallMiddleware` starts a span (continuing a `traceparent` found in the
   request's `_meta`), and runs the tool.
5. The tool calls `ShelfClient`, bounds the rows, and returns a typed model:
   `structuredContent` plus a JSON text block. A caller-actionable failure is a
   `ToolError` that names the next step.
6. `ToolCallMiddleware` writes one `tool.call` line; `RequestLogMiddleware`
   writes one `http.request` line. Both carry `request_id`.

## Code to guide rule

| Part of the code | Rule |
|------------------|------|
| Tool names `shelf_list_datasets`, `shelf_get_dataset` | N1, P1 |
| First-line docstrings, argument and next-step text | N2, N3 |
| Two tools only, no UI plumbing | N4 |
| `Annotated[..., Field(description=...)]`, `ge`/`le` on `limit` | S1, S2 |
| Return annotations are pydantic models (`ListResult`, `DatasetResult`) | O1, O2 |
| `Dataset` has four fields, sizes in GB, DIDs-style names verbatim | O3 |
| `READ_ONLY` annotations | A1 |
| `ToolError` with a next step, never an error string | E1, E2, E4 |
| `_unavailable()`: transient failure says to retry | E3 |
| `limit` with a default and a maximum, lazy `iter_datasets`, `truncated` and `next_step` | B1 |
| `create_app`: `stateless_http=True`, streamable HTTP only | X1 |
| `BrokerTokenVerifier` returns None, fastmcp answers 401 | X2 |
| Tools registered up front, `tools/list` calls nothing downstream | X3 |
| Explicit `timeout` on the HTTP client and `ShelfClient` | X5 |
| `/healthz` reports this process only | X5 |
| Only the broker token is accepted; it is never forwarded | U1 |
| `jwt.decode` with `issuer`, `audience`, required `exp` | U2 |
| No credential argument, result or log field | U3 |
| Only `sub` is read from the token, no groups or permissions | U5 |
| No `user` or `owner` argument; `subject` comes from the token | U6 |
| `JwksCache`: TTL, early refetch only on an unknown `kid`, rate limited | U7 |
| `RequestLogMiddleware` binds `X-Request-ID`, `JsonFormatter` writes `request_id` | L1 |
| `JsonFormatter` and `ToolCallMiddleware` fields | L2 |
| No `http.request` line for a successful `/healthz`; failures logged | L3 |
| `configure_tracing`, `ToolCallMiddleware` span, off unless `OTEL_*` is set | L4 |
| `data.py` is a client-library stand-in, not a CLI wrapper | I1 |
| Tests call the tools through a client and the server over HTTP | T1 |

Not shown because they do not apply to a read-only, in-memory server: P2 to P5
are `services.yaml` and write-tool concerns; B2 needs a long call; B3 needs a
shared backend; U4 needs a credential redeem. The guide describes each.
