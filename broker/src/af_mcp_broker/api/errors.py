from __future__ import annotations

from fastapi import HTTPException, status


class CorrelatedHTTPException(HTTPException):
    """An ``HTTPException`` whose string ``detail`` is returned with the request's ``correlation_id`` in the body (issue #342).

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
    ``retry_after.py``.
    """

    def __init__(self, detail: str, *, retry_after_seconds: int) -> None:
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers={"Retry-After": str(retry_after_seconds)},
        )
        self.retry_after_seconds = retry_after_seconds
