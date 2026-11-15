"""Shared assertions for the one 429 shape every ``/v1`` rate limit returns."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx2

RATE_LIMITED_BODY_KEYS = {"detail", "retry_after_seconds", "retry_at"}


def assert_rate_limited_shape(
    resp: httpx2.Response, *, retry_after: int | None = None
) -> dict:
    """Assert *resp* is a 429 with ``Retry-After`` seconds and the JSON body ``{detail, retry_after_seconds, retry_at}``; return the body."""
    assert resp.status_code == 429, resp.text
    header = resp.headers["Retry-After"]
    assert header.isdecimal(), header
    body = resp.json()
    assert set(body) == RATE_LIMITED_BODY_KEYS
    assert isinstance(body["detail"], str)
    assert body["retry_after_seconds"] == int(header)
    if retry_after is not None:
        assert int(header) == retry_after
    # retry_at is a UTC ISO-8601 timestamp with a Z suffix, in the future.
    retry_at = datetime.strptime(body["retry_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=UTC
    )
    assert retry_at >= datetime.now(UTC).replace(microsecond=0)
    return body
