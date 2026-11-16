"""The lifespan's shared outbound HTTP client: built once, closed on teardown, held by the state."""

from __future__ import annotations

from contextlib import AsyncExitStack

from af_mcp_broker.wiring.http_client import build_http_client


async def test_the_client_is_open_while_the_stack_is_and_closed_after() -> None:
    async with AsyncExitStack() as stack:
        client = build_http_client(stack)

        assert not client.is_closed

    assert client.is_closed


async def test_each_build_is_a_separate_client() -> None:
    async with AsyncExitStack() as stack:
        assert build_http_client(stack) is not build_http_client(stack)
