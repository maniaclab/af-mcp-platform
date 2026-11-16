"""Fixtures and helpers shared by the unit and integration tests of ``test_pat_mint_shared_state``."""

from __future__ import annotations

import uuid

import pytest

_MAX_MINTS = 10


@pytest.fixture(name="subject")
def subject_fixture() -> str:
    # The server outlives each test, so every test gets its own subject.
    return f"sub-{uuid.uuid4()}"
