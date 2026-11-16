from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import HTTPException, status

if TYPE_CHECKING:
    from af_mcp_broker.retry_after import RateLimiter


class CorrelatedHTTPException(HTTPException):
    """An ``HTTPException`` whose string ``detail`` is returned with the request's ``request_id`` in the body (issue #342).

    ``app._http_exception_handler`` adds the id to every 5xx on its own; a
    4xx opts in by raising this, for the cases where the broker cannot tell
    the user why the request failed and the id is what they quote to AF
    support.
    """


class RateLimitedHTTPException(HTTPException):
    """A 429 whose wait is ``Retry-After`` (whole seconds) and, in the body next to ``detail``, ``retry_after_seconds`` and ``retry_at``.

    Every ``/v1`` rate limit raises this (``app._http_exception_handler``
    renders the body), so a client backs off the same way whichever limit it
    hit. ``/mcp`` carries the same two values in the tool error message; see
    ``retry_after.py``. *limiter* names the limiter that refused, for the
    ``rate_limit.exceeded`` event the handler logs.
    """

    def __init__(
        self, detail: str, *, limiter: RateLimiter, retry_after_seconds: int
    ) -> None:
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers={"Retry-After": str(retry_after_seconds)},
        )
        self.limiter = limiter
        self.retry_after_seconds = retry_after_seconds
