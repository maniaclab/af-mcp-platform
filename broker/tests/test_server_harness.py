"""Regression tests for the test-server harness itself.

CI runs used to hang silently (until the 6-hour Actions job timeout) when a
uvicorn server task failed to start -- typically the ``find_available_port``
TOCTOU race on a contended runner: the port probed as free gets grabbed before
uvicorn binds it, ``serve()``/``run_http_async()`` dies inside its task, and
the harness's unbounded startup wait (``while not server.started`` /
``await mcp._started.wait()``) spins forever with the task's exception
swallowed. These tests reproduce that failure deterministically by occupying
the port first, and assert the harness now raises promptly instead of
hanging. The ``timeout`` marks keep a regression from wedging this very file.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

# Import from conftest at module level ONLY: pytest imports every collected
# conftest.py under the bare name "conftest", and the CI invocation
# (`pytest broker/ spikes/`) collects spikes/credential-isolation/conftest.py
# AFTER this module is imported -- replacing sys.modules["conftest"]. A
# module-level import here binds broker's conftest at collection time (like
# every other test file); a function-level `from conftest import ...` would
# resolve at test time and get the spikes one.
from conftest import (
    _CLIENT_SESSION_HOTFIX,
    _await_server_started,
    _contained,
    run_asgi_app,
)


async def _hello_app(scope, receive, send):  # pragma: no cover - trivial ASGI app
    assert scope["type"] == "http"
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


@pytest.fixture
def occupied_port() -> int:
    """A port something is already listening on for the duration of the test."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    yield port
    sock.close()


@pytest.mark.timeout(30)
async def test_run_asgi_app_bind_failure_raises_instead_of_hanging(
    occupied_port: int,
) -> None:
    # run_asgi_app binds the socket itself (eliminating the TOCTOU race
    # outright), so an occupied port surfaces as an immediate plain OSError
    # from bind -- not a hang, and not even a server task.
    with pytest.raises(OSError, match=r"[Aa]ddress already in use"):
        async with run_asgi_app(_hello_app, port=occupied_port):
            pytest.fail("bind on an occupied port must fail")


@pytest.mark.timeout(30)
async def test_dead_server_task_surfaces_instead_of_hanging() -> None:
    """The shared wait used by run_aggregator_async and run_asgi_app: a
    server task that dies with SystemExit (uvicorn's startup-failure signal,
    which asyncio would otherwise re-raise into the event loop itself) is
    contained and reported, instead of the started-flag wait spinning
    forever."""

    async def _dying_server() -> None:
        raise SystemExit(3)

    task = asyncio.create_task(_contained(_dying_server()))
    with pytest.raises(RuntimeError, match="server task exited") as excinfo:
        await _await_server_started(task, lambda: False)
    # The original uvicorn failure stays on the chain for diagnosis.
    assert "uvicorn exited during startup" in str(excinfo.value.__cause__)


# ---------------------------------------------------------------------------
# ClientSession hotfix (conftest's autouse client_session_hotfix fixture):
# modelcontextprotocol/python-sdk#1144 -- fixed upstream in mcp v2, which
# needs fastmcp v4 (beta). Until that migration, an MCP client whose
# streamable-HTTP response dies mid-flight waits forever: an Exception object
# sent into the session's read stream is handled by a no-op, and a connection
# that goes dead without ever delivering anything produces no event at all.
# ---------------------------------------------------------------------------


@pytest.mark.timeout(30)
async def test_stream_exception_fails_pending_request_instead_of_hanging() -> None:
    """An Exception arriving on the read stream (what the streamable-HTTP
    transport sends when the response body dies mid-parse) must fail the
    pending request promptly -- the hotfix closes the read stream, letting
    the receive loop's own teardown deliver CONNECTION_CLOSED to waiters."""
    import anyio
    from mcp.client.session import ClientSession
    from mcp.shared.exceptions import McpError

    srv_send, cli_recv = anyio.create_memory_object_stream(8)
    cli_send, _srv_recv = anyio.create_memory_object_stream(8)

    async def _inject_after_request_is_pending() -> None:
        # what streamablehttp_client does on a parse failure; must land
        # AFTER send_ping has registered its response stream, or teardown
        # has nothing to fail yet.
        await asyncio.sleep(0.05)
        await srv_send.send(ValueError("truncated SSE event"))

    async with ClientSession(cli_recv, cli_send) as session:
        with anyio.fail_after(10):  # the pre-hotfix behavior: hangs here
            inject = asyncio.create_task(_inject_after_request_is_pending())
            with pytest.raises(McpError, match="Connection closed"):
                await session.send_ping()
            await inject


@pytest.mark.timeout(30)
async def test_dead_connection_times_out_instead_of_hanging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session whose server never answers (dead-but-open connection -- the
    CI hang observed on #237) must fail at the injected default read timeout
    rather than wait forever."""
    from datetime import timedelta

    import anyio
    from mcp.client.session import ClientSession
    from mcp.shared.exceptions import McpError

    monkeypatch.setitem(_CLIENT_SESSION_HOTFIX, "read_timeout", timedelta(seconds=0.5))
    _srv_send, cli_recv = anyio.create_memory_object_stream(8)
    cli_send, _srv_recv = anyio.create_memory_object_stream(8)
    async with ClientSession(cli_recv, cli_send) as session:
        with anyio.fail_after(10):
            with pytest.raises(McpError):
                await session.send_ping()
