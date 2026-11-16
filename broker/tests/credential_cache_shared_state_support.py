"""Fixtures and helpers shared by the unit and integration tests of ``test_credential_cache_shared_state``."""

from __future__ import annotations

import uuid

import pytest


@pytest.fixture(name="uid")
def uid_fixture() -> int:
    # The server outlives each test, so every test gets its own uid.
    return uuid.uuid4().int % 1_000_000_000
