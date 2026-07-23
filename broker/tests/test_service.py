"""Unit tests for ServiceProvider.is_linked().

ServiceProvider uses the broker's own shared service credential, not any
per-user linkage, so is_linked() has exactly one behavior to verify: it is
always True regardless of the principal.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from af_mcp_broker.credentials.service import ServiceProvider
from af_mcp_broker.identity import Principal


def _principal() -> Principal:
    return Principal(
        subject="user-123",
        email="user@example.org",
        uid=50123,
        gid=5000,
        unixname="auser",
        groups=["af-atlas-users"],
        raw_token=SecretStr("fake-token"),
    )


@pytest.mark.asyncio
async def test_is_linked_always_true():
    provider = ServiceProvider(settings=SimpleNamespace())

    assert await provider.is_linked(_principal()) is True
