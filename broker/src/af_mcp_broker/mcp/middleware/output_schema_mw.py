from __future__ import annotations

# Validates a proxied tool result's structured content against the output
# schema the aggregator already holds for that tool. The backend client
# relays results without validating them (backend_client.RelayingClientSession),
# because the SDK's own validation learns the schema by listing the backend's
# tools on every call; this middleware does the same check against the
# schema from the aggregator's cached listing instead.
import hashlib
import json
from typing import TYPE_CHECKING, Any, cast

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware
from fastmcp.server.providers.proxy import ProxyTool
from jsonschema import SchemaError  # type: ignore[import-untyped]
from jsonschema import (  # type: ignore[import-untyped]
    exceptions as jsonschema_exceptions,
)
from jsonschema.validators import validator_for  # type: ignore[import-untyped]
from referencing import Registry
from referencing.exceptions import Unresolvable

if TYPE_CHECKING:
    import mcp.types as mt
    from fastmcp.server.middleware import CallNext, MiddlewareContext
    from fastmcp.tools.base import ToolResult

# Upper bound on compiled validators held at once: one per distinct output
# schema across all services, far below this in practice.
_MAX_COMPILED_VALIDATORS = 1024


class OutputSchemaValidator:
    """Checks structured content against a tool's output schema, compiling each distinct schema once.

    Mirrors ``mcp.client.session.ClientSession.validate_tool_result`` -- the
    check an unproxied client would run -- including its error texts, so a
    caller sees the same failure whether the backend is reached directly or
    through the aggregator. Compiling a validator costs far more than running
    one, hence the cache, keyed by the schema's canonical JSON so that equal
    schemas share a validator.
    """

    def __init__(self) -> None:
        self._validators: dict[str, Any] = {}

    def _validator(self, name: str, output_schema: dict[str, Any]) -> Any:
        key = hashlib.sha256(
            json.dumps(output_schema, sort_keys=True).encode()
        ).hexdigest()
        if (validator := self._validators.get(key)) is not None:
            return validator
        validator_cls = validator_for(output_schema)
        try:
            validator_cls.check_schema(output_schema)
        except SchemaError as exc:
            raise RuntimeError(f"Invalid schema for tool {name}: {exc}") from exc
        # An explicit empty registry: `$ref`s resolve within the schema
        # document and the bundled metaschemas, never over the network.
        validator = validator_cls(output_schema, registry=Registry())
        if len(self._validators) >= _MAX_COMPILED_VALIDATORS:
            self._validators.pop(next(iter(self._validators)))
        self._validators[key] = validator
        return validator

    def validate(
        self,
        name: str,
        output_schema: dict[str, Any] | None,
        structured_content: Any,
    ) -> None:
        """Raise ``RuntimeError`` when *structured_content* does not satisfy *output_schema*; a tool with no output schema is never checked.

        *name* is the backend's own tool name, as in the SDK's messages.
        """
        if output_schema is None:
            return
        if structured_content is None:
            raise RuntimeError(
                f"Tool {name} has an output schema but did not return structured content"
            )
        validator = self._validator(name, output_schema)
        try:
            error = cast(
                "Exception | None",
                jsonschema_exceptions.best_match(
                    validator.iter_errors(structured_content)
                ),
            )
        except Unresolvable as exc:
            raise RuntimeError(f"Invalid schema for tool {name}: {exc}") from exc
        if error is not None:
            raise RuntimeError(
                f"Invalid structured content returned by tool {name}: {error}"
            ) from error


class OutputSchemaMiddleware(Middleware):
    """Validates a backend tool's result against the output schema of the tool as the aggregator lists it.

    Registered inside ``AuthorizationMiddleware`` so a violation propagates
    through its error path and is audited as ``outcome="error"``. The tool is
    resolved through the aggregator's own lookup, which the preceding listing
    (the authorization middleware warms it before a call) has already cached:
    a cold cache costs one backend listing, a warm one costs no request.
    A tool-reported error (``isError``) is relayed unvalidated, as the SDK
    does; local (non-proxied) tools are not checked.
    """

    def __init__(self, validator: OutputSchemaValidator | None = None) -> None:
        self._validator = validator or OutputSchemaValidator()

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        result = await call_next(context)
        if result.is_error:
            return result
        fastmcp_context = context.fastmcp_context
        if fastmcp_context is None:
            return result
        tool = await fastmcp_context.fastmcp.get_tool(context.message.name)
        if isinstance(tool, ProxyTool):
            # ``_backend_name`` is fastmcp's own record of the name the
            # backend knows the tool by (its proxy sends the same one).
            try:
                self._validator.validate(
                    tool._backend_name or tool.name,
                    tool.output_schema,
                    result.structured_content,
                )
            except RuntimeError as exc:
                # The text fastmcp's own call_tool gives a tool's unexpected
                # exception, which is what a violation raised inside the
                # proxied call surfaces as; raised here, below that handler,
                # it would otherwise reach the caller as an opaque internal
                # error. The aggregator does not mask error details.
                raise ToolError(
                    f"Error calling tool {context.message.name!r}: {exc}"
                ) from exc
        return result
