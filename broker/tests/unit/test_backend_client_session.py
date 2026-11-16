from __future__ import annotations

import inspect

from fastmcp.client import Client
from fastmcp.client.transports.base import TransportOptions
from mcp.client.session import ClientSession

from af_mcp_broker.backend_client import (
    BackendClient,
    RelayingClientSession,
    build_client,
)
from af_mcp_broker.service_registry import ServiceSpec


def _spec() -> ServiceSpec:
    return ServiceSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
    )


def test_fastmcp_client_options_attribute_still_exists() -> None:
    """``BackendClient`` sets fastmcp's private ``Client._transport_options``;
    a fastmcp release that renames or drops it must fail here, loudly, rather
    than silently reverting to a validating session."""
    assert Client("http://example.invalid/mcp")._transport_options is None


def test_session_validation_hook_is_a_coroutine_on_clientsession() -> None:
    assert inspect.iscoroutinefunction(ClientSession.validate_tool_result)


def test_backend_client_relays_and_never_forwards_caller_headers() -> None:
    options = BackendClient("http://example.invalid/mcp")._transport_options

    assert options == TransportOptions(session_class=RelayingClientSession)
    assert options is not None
    assert options.forward_incoming_headers is False


def test_new_client_keeps_the_relaying_session() -> None:
    options = build_client(_spec()).new()._transport_options

    assert options is not None
    assert options.session_class is RelayingClientSession


async def test_relaying_session_skips_output_schema_validation() -> None:
    session = RelayingClientSession.__new__(RelayingClientSession)

    assert await session.validate_tool_result("any", None) is None  # type: ignore[arg-type]
