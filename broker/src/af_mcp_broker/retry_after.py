"""``Retry-After`` handling shared by every rate-limit edge.

``/v1`` returns the wait as a ``Retry-After`` header plus ``retry_after_seconds``
and ``retry_at`` body fields (``api/errors.py``'s ``RateLimitedHTTPException``);
``/mcp`` puts the same two values in the tool error message
(``retry_after_sentence``). Both take whole seconds from here so a client sees
one wait whichever surface refused it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# Used when a rate-limiting backend answers 429 without a usable
# ``Retry-After`` (absent, or the HTTP-date form): a client still needs
# a wait to back off by, and a minute is the unit the broker's own windows use.
DEFAULT_RETRY_AFTER_SECONDS = 60


def retry_after_seconds(header: str | None) -> int:
    """Whole seconds from a backend's ``Retry-After`` header, or the default when it is absent or not a non-negative integer."""
    if header is not None and header.isdecimal():
        return int(header)
    return DEFAULT_RETRY_AFTER_SECONDS


def retry_at_timestamp(seconds: int) -> str:
    """UTC ISO-8601 time (``Z`` suffix, whole seconds) *seconds* from now."""
    retry_at = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=seconds)
    return retry_at.strftime("%Y-%m-%dT%H:%M:%SZ")


def retry_after_sentence(seconds: int) -> str:
    """Return the wait as one sentence for a ``/mcp`` tool error message."""
    return f"Retry-After: {seconds} seconds; retry_at: {retry_at_timestamp(seconds)}."
