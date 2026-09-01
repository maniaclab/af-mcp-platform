from __future__ import annotations

import anyio
import httpx

# Transient-vs-genuine classification of a failed backend tool call (issue
# #216 A.3). This is OBSERVABILITY ONLY: it names an error for the audit log's
# error_class field and changes no control flow -- nothing retries, nothing is
# swallowed, the call still fails exactly as it did. The point is to get real
# numbers on how often backends fail transiently across all users before
# deciding whether the broker should ever retry on their behalf.

# The error_class values a failed call is tagged with. A success/denied/
# unmapped call is never an executed-and-failed backend call, so it carries
# none of these (error_class stays None -- see AuditRecord.error_class).
#
# ERROR_CLASS_TRANSIENT and ERROR_CLASS_BACKEND are classify_backend_error()'s
# two outcomes for a call that raised: the RPC itself never completed
# cleanly, whether because the dial/socket failed (TRANSIENT) or some other
# exception reached the middleware (BACKEND) -- see that function's
# docstring. ERROR_CLASS_TOOL_REPORTED is a third, disjoint case
# classify_backend_error never produces: the RPC completed entirely
# normally, and the tool itself decided to report failure via the MCP
# isError result convention rather than raising (authorization_mw.py's
# on_call_tool sets this directly, no classification needed -- there is
# nothing to walk an exception chain over). Keeping it distinct from
# ERROR_CLASS_BACKEND matters because the two are diagnostically different
# questions: "did our own plumbing (credential minting, the connection
# itself, an unexpected bug) break" vs "did a fully-reachable downstream
# tool deliberately refuse this specific call".
ERROR_CLASS_TRANSIENT = "transient_connection"
ERROR_CLASS_BACKEND = "backend_error"
ERROR_CLASS_TOOL_REPORTED = "tool_reported"

# Known-transient exception types a broker->backend HTTP tool call raises when
# the connection itself fails, as opposed to the backend running and returning
# an application error. Deliberately scoped to the three categories issue #216
# names -- connection reset, socket EOF / "closed connection", connect timeout
# -- and no wider: an HTTP 5xx (httpx.HTTPStatusError) or a read timeout on an
# already-established connection is a backend problem, not a transient dial
# failure, and stays ERROR_CLASS_BACKEND.
#
#   - httpx.ConnectError / ConnectTimeout: the dial failed (refused/reset) or
#     timed out before a connection was established.
#   - httpx.ReadError / WriteError: the socket failed mid-exchange ("No more
#     data to read from socket").
#   - httpx.RemoteProtocolError: the server closed the connection without a
#     complete response (EOF / "Closed Connection").
#   - anyio.EndOfStream / ClosedResourceError / BrokenResourceError: the same
#     failures surfaced at the anyio stream layer fastmcp's client rides on.
#   - builtin ConnectionError: covers ConnectionReset/Aborted/RefusedError
#     when a raw socket op raises rather than httpx.
_TRANSIENT_CONNECTION_EXC_TYPES: tuple[type[BaseException], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadError,
    httpx.WriteError,
    httpx.RemoteProtocolError,
    anyio.EndOfStream,
    anyio.ClosedResourceError,
    anyio.BrokenResourceError,
    ConnectionError,
)


def classify_backend_error(exc: BaseException) -> str:
    """Classify a failed backend tool call as transient-connection or backend error.

    Returns ``ERROR_CLASS_TRANSIENT`` when *exc* -- or any exception in its
    cause/context chain -- is one of the known-transient connection types,
    else ``ERROR_CLASS_BACKEND``. The chain walk matters because fastmcp's
    core ``call_tool`` re-raises a backend exception as ``ToolError(...) from
    e`` (mask_error_details defaults to False), so the original httpx/anyio
    connection error survives only on ``__cause__`` (or ``__context__`` for a
    bare re-raise), never as the top-level type the middleware catches.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, _TRANSIENT_CONNECTION_EXC_TYPES):
            return ERROR_CLASS_TRANSIENT
        current = current.__cause__ or current.__context__
    return ERROR_CLASS_BACKEND
