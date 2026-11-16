"""Fakes and constants shared with the tests of ``test_condor_token``."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2

SERVICE_URL = "http://condor-token-service.test"


class _FakeCondorClient:
    """Fake httpx2 client for the condor-token-service exchange.

    Records every POST (url + headers) so tests can assert the broker
    identity token actually presented, and returns a configurable
    ``httpx2.Response`` per call.
    """

    def __init__(self, responses: list[httpx2.Response] | None = None) -> None:
        self.responses = responses or [httpx2.Response(200, json=_token_response())]
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def post(
        self, url: str, headers: dict[str, str], **kwargs: Any
    ) -> httpx2.Response:
        self.calls.append((url, dict(headers)))
        return self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]


IDTOKEN = "fake-htcondor-idtoken"


def _token_response(
    *, expires_in_seconds: int = 3600, token: str = IDTOKEN
) -> dict[str, Any]:
    expires_at = datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
    return {
        "token": token,
        "identity": "auser@example.org",
        "expires_at": expires_at.isoformat(),
    }
