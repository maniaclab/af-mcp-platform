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

import socket

import pytest
from conftest import run_asgi_app


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
    import asyncio

    from conftest import _await_server_started, _contained

    async def _dying_server() -> None:
        raise SystemExit(3)

    task = asyncio.create_task(_contained(_dying_server()))
    with pytest.raises(RuntimeError, match="server task exited") as excinfo:
        await _await_server_started(task, lambda: False)
    # The original uvicorn failure stays on the chain for diagnosis.
    assert "uvicorn exited during startup" in str(excinfo.value.__cause__)
