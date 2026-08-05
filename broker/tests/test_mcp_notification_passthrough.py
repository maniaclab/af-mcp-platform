from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from conftest import make_claims, run_aggregator_async
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.dependencies import get_context
from fastmcp.utilities.tests import run_server_async

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.mcp.aggregator import build_aggregator
from af_mcp_broker.mcp.registry import BackendRegistry, BackendSpec

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# ---------------------------------------------------------------------------
# PR A/B's client_factory builds a plain Client (never fastmcp's ProxyClient)
# so the caller's inbound Authorization header is never forwarded to a
# backend -- see aggregator.py's _make_client_factory docstring. A
# consequence flagged for PR C: ProxyClient's default handlers also forward
# progress/log *notifications* from backend to the aggregator's own caller,
# and a plain Client without those handlers attached would silently swallow
# them (logging locally instead). This file proves that consequence is
# handled: the aggregator installs the same forwarding handlers
# (_build_client in aggregator.py) without reinstating header forwarding.
# ---------------------------------------------------------------------------


def _progress_backend() -> FastMCP:
    mcp = FastMCP(name="progress-backend")

    @mcp.tool
    async def report_progress_twice() -> str:
        ctx = get_context()
        await ctx.report_progress(progress=1, total=2, message="halfway")
        await ctx.report_progress(progress=2, total=2, message="done")
        return "finished"

    return mcp


@pytest.fixture
async def progress_backend_url() -> AsyncIterator[str]:
    async with run_server_async(_progress_backend(), path="/mcp") as url:
        yield url


@pytest.fixture
def aggregator_url(settings, progress_backend_url, static_principal_cache):
    """A real build_aggregator() wired to the progress-reporting backend
    above, auth_type="none" so this test stays focused on notification
    pass-through rather than credential injection (which has its own
    dedicated coverage in test_mcp_credential_injection_integration.py)."""
    principal_cache, _directory = static_principal_cache
    registry = BackendRegistry()
    registry.register(
        BackendSpec(
            name="progress",
            prefix="progress",
            url=progress_backend_url,
            transport="http",
            required_capability="__none__",
            auth_type="none",
        )
    )

    policy = EntitlementPolicy()

    async def _run():
        mcp = build_aggregator(
            registry,
            settings,
            policy,
            CredentialRegistry(),
            principal_cache=principal_cache,
        )
        async with run_aggregator_async(mcp, path="/mcp") as url:
            yield url

    return _run


async def test_backend_progress_notifications_reach_the_aggregators_caller(
    aggregator_url, sig_key, prime_jwks
) -> None:
    """The concrete regression this file exists for: a backend tool that
    calls ctx.report_progress() must have those notifications forwarded all
    the way through the aggregator to the caller's own progress_handler --
    not just logged locally inside the aggregator process."""
    prime_jwks([sig_key.jwk])
    token = sig_key.sign(make_claims())

    received: list[tuple[float, float | None, str | None]] = []

    async def _collect(
        progress: float, total: float | None, message: str | None
    ) -> None:
        received.append((progress, total, message))

    async for base_url in aggregator_url():
        transport = StreamableHttpTransport(
            base_url, headers={"Authorization": f"Bearer {token}"}
        )
        client = Client(transport, progress_handler=_collect)
        async with client:
            result = await client.call_tool("progress_report_progress_twice", {})

    assert result.data == "finished"
    assert received == [(1, 2, "halfway"), (2, 2, "done")]
