"""Fixtures and helpers shared by the unit and integration tests of ``test_oauth21_vault``."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


KV_PATH_PREFIX = "mcp/tokens"
ALIAS = "rucio-mcp-atlas"


@pytest.fixture(name="_broker_signing_key", autouse=True)
def broker_signing_key_fixture(
    monkeypatch: pytest.MonkeyPatch, broker_signing_key_file: Path
) -> None:
    """The shipped "ami" service (covered by the x509 entry below) needs the broker signing key to boot."""
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(broker_signing_key_file))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
