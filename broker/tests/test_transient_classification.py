from __future__ import annotations

import anyio
import httpx2
import pytest
from fastmcp.exceptions import ToolError

from af_mcp_broker.mcp.errors import (
    ERROR_CLASS_BACKEND,
    ERROR_CLASS_TRANSIENT,
    classify_backend_error,
)

# Unit tests for classify_backend_error (issue #216 A.3): does an exception
# raised by a backend tool call read as a known-transient connection failure
# (connection reset / socket EOF / connect timeout) or a genuine backend
# error? Observability only -- the classification never changes control flow.


@pytest.mark.parametrize(
    "exc",
    [
        httpx2.ConnectError("connection refused"),
        httpx2.ConnectTimeout("connect timed out"),
        httpx2.ReadError("no more data to read from socket"),
        httpx2.WriteError("failed to write to socket"),
        httpx2.RemoteProtocolError("server disconnected without sending a response"),
        anyio.EndOfStream(),
        anyio.ClosedResourceError(),
        anyio.BrokenResourceError(),
        ConnectionResetError("connection reset by peer"),
        ConnectionAbortedError("closed connection"),
    ],
)
def test_transient_connection_exceptions_are_classified_transient(
    exc: BaseException,
) -> None:
    assert classify_backend_error(exc) == ERROR_CLASS_TRANSIENT


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("credential provider unreachable"),
        ValueError("bad argument"),
        ToolError("boom from backend"),
        httpx2.HTTPStatusError(
            "500",
            request=httpx2.Request("GET", "http://x"),
            response=httpx2.Response(500),
        ),
        httpx2.LocalProtocolError("we sent a malformed request"),
    ],
)
def test_non_transient_exceptions_are_classified_backend_error(
    exc: BaseException,
) -> None:
    assert classify_backend_error(exc) == ERROR_CLASS_BACKEND


def test_transient_cause_wrapped_in_tool_error_is_seen_through_the_chain() -> None:
    """FastMCP core call_tool re-raises a backend exception as
    ``ToolError(...) from e`` (mask_error_details=False), so the original
    transient exception survives on ``__cause__`` -- the classifier must walk
    the chain, not just inspect the top-level type. Setting ``__cause__``
    directly is exactly what ``raise ... from`` records."""
    exc = ToolError("Error calling tool 'ami_get_dataset_info'")
    exc.__cause__ = httpx2.RemoteProtocolError("Closed Connection")
    assert classify_backend_error(exc) == ERROR_CLASS_TRANSIENT


def test_transient_cause_on_implicit_context_is_seen_through_the_chain() -> None:
    """A bare ``raise`` inside an ``except`` chains via ``__context__`` rather
    than ``__cause__`` (what setting the attribute directly emulates here);
    both must be followed."""
    exc = RuntimeError("wrapped without from")
    exc.__context__ = ConnectionResetError("connection reset by peer")
    assert classify_backend_error(exc) == ERROR_CLASS_TRANSIENT
