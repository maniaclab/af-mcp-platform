"""Fixtures and helpers shared by the unit and integration tests of ``test_mcp_auth_codes``."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest
from cryptography.fernet import Fernet

from af_mcp_broker.mcp_auth_codes import McpAuthCodeRecord, McpAuthCodeStore

if TYPE_CHECKING:
    from af_mcp_broker.shared_state import (
        SharedState,
    )

ISSUER = "https://mcp.example.test"


class _Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _record(**overrides: object) -> McpAuthCodeRecord:
    kwargs: dict[str, object] = {
        "principal_id": "sub-abc",
        "client_id": "https://client.example/.well-known/cimd",
        "redirect_uri": "http://localhost:12345/callback",
        "code_challenge": "challenge-abc",
        "client_name": "Test Client",
    }
    kwargs.update(overrides)
    return McpAuthCodeRecord(**kwargs)  # type: ignore[arg-type]


def _store(
    key: bytes,
    shared_state: SharedState,
    clock: _Clock | None = None,
    issuer: str = ISSUER,
) -> McpAuthCodeStore:
    return McpAuthCodeStore(
        Fernet(key),
        shared_state,
        issuer=issuer,
        clock=clock or time.time,
    )


@pytest.fixture(name="key")
def key_fixture() -> bytes:
    return Fernet.generate_key()
