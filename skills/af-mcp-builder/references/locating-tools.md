# Locating tools in an MCP server's source

Produce one list of every tool name with `file:line` before auditing. Search
for the registration call, then follow it: tools are often registered from a
helper or a loop, so a grep count is a starting point, not the answer. When a
running server is available, its `tools/list` is the authority; compare the two.

## Python

### `mcp` SDK 2.x (`mcp.server.mcpserver.MCPServer`) and fastmcp 3/4

- Registration: `@mcp.tool(...)` or `@server.tool(...)`, `mcp.add_tool(...)`,
  `FastMCP(...).tool(...)`. Search: `rg -n "\.tool\(|add_tool\(" --glob '*.py'`.
- Tools registered in a module-level `register(mcp)` function (ami-mcp's
  `src/ami_mcp/tools/*.py`) are called from the server setup; follow the call.
- Name: the function name unless `name=` is given. Description: the docstring
  unless `description=` is given. The SDKs do not turn a docstring `Args:` section
  into per-argument schema descriptions; those need `Field(description=...)` or
  `Annotated[..., Field(description=...)]`. Check the generated schema.
- Annotations: `annotations=ToolAnnotations(...)` on the decorator. Look for
  `read_only_hint`, `destructive_hint`, `idempotent_hint`, `open_world_hint`, `title`.
- Output schema: the return annotation (`-> Model`, or
  `Annotated[CallToolResult, Model]` when text is curated). `Context`,
  `CallToolResult`, `TextContent`, `ToolAnnotations` and the result models must be
  runtime imports, not `TYPE_CHECKING`-only (guide O2).
- Errors: `is_error=True` on a returned `CallToolResult`, or the SDK's tool-error
  exception. A tool that returns `str` for a failure is an E1 finding.
- HTTP app and statelessness: `streamable_http_app(...)` or `http_app(...)` and
  its `stateless_http` setting (default false). Auth: a `token_verifier` or
  `auth=` argument, and whether it checks `aud`.

### Mechanical check without starting the full server

If the server imports facility-only packages, import its tool registration in a
scratch script instead, build the server object, and call `list_tools()` on it
in-process; the audit script's checks work on any list of tool objects.

## Go

API names below are from each SDK's documentation; confirm them against the
version pinned in `go.mod`.

### `mark3labs/mcp-go`

- Registration: `s.AddTool(mcp.NewTool("name", ...), handler)`. Search:
  `rg -n "NewTool\(|AddTool\(" --glob '*.go'`.
- Description: `mcp.WithDescription(...)`. Arguments: `mcp.WithString`,
  `mcp.WithNumber`, ... each takes `mcp.Description(...)`, `mcp.Required()`,
  `mcp.Enum(...)`, `mcp.Min(...)`/`mcp.Max(...)`.
- Annotations: `mcp.WithReadOnlyHintAnnotation`, `mcp.WithDestructiveHintAnnotation`,
  `mcp.WithIdempotentHintAnnotation`, `mcp.WithOpenWorldHintAnnotation`,
  `mcp.WithTitleAnnotation`.
- Output schema: `mcp.WithOutputSchema[T]()` and `mcp.NewToolResultStructured(...)`.
- Errors: `mcp.NewToolResultError(...)` sets `isError`. Returning a Go `error`
  from a handler becomes a JSON-RPC error (E4): use it only for protocol problems.
- Transport: `server.NewStreamableHTTPServer(s, server.WithStateLess(true))`.

### `modelcontextprotocol/go-sdk`

- Registration: `mcp.AddTool(server, &mcp.Tool{Name: ..., Description: ...}, handler)`
  or `server.AddTool`. Annotations: `Tool.Annotations` (`*mcp.ToolAnnotations`).
  Schemas are inferred from the handler's input and output types; descriptions come
  from `jsonschema:"..."` struct tags.
- Errors: a result with `IsError: true`.
- Transport: `mcp.NewStreamableHTTPHandler(..., &mcp.StreamableHTTPOptions{Stateless: true})`.

### golang-htcondor `webapi/mcpserver` style

The server uses `modelcontextprotocol/go-sdk` types (`mcp.ToolAnnotations`) and
defines tools in its own registry rather than one call per tool. Look for:

- the tool table and its handlers (`handlers*.go`, `server.go`);
- `annotations.go` (a name-to-`ToolAnnotations` map, with `readOnlyAnn`/`writeAnn` helpers);
- `structured.go` and `structured_contract.go` (output schemas and the payload contract);
- `toolerror.go` (how a failure becomes an `isError` result);
- `tool_limits.go` (the listing ceiling and truncation note, guide B1);
- `read_only.go` and `disabled_tools.go` (the read-only mode and the operator's
  disabled-tool list, guide P4 and P5).

A map keyed by tool name needs a check that every registered tool has an entry;
look for a test that enforces it (`annotations_test.go`, `structured_contract_test.go`).

## Other servers

For another language, find the SDK's tool registration call, then the same
five things: name, description, argument schema, annotations, result and error
construction. Use the audit script against the running server for the rest.
