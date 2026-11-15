from __future__ import annotations

from fastapi import HTTPException


class CorrelatedHTTPException(HTTPException):
    """An ``HTTPException`` whose string ``detail`` is returned with the request's ``correlation_id`` in the body (issue #342).

    ``app._http_exception_handler`` adds the id to every 5xx on its own; a
    4xx opts in by raising this, for the cases where the broker cannot tell
    the user why the request failed and the id is what they quote to AF
    support.
    """
