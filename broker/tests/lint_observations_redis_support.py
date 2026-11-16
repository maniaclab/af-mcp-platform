"""Fixtures and helpers shared by the unit and integration tests of ``test_lint_observations_redis``."""

from __future__ import annotations

import uuid

import pytest

from af_mcp_broker.service_registry import AnnotationMismatch


@pytest.fixture(name="service")
def service_fixture() -> str:
    # The server outlives each test, so every test gets its own service.
    return f"svc-{uuid.uuid4()}"


def _mismatch(service: str) -> AnnotationMismatch:
    return AnnotationMismatch(
        service=service,
        tool=f"{service}_tool",
        declared_read_only_hint=True,
        resolved_action_type="write",
        resolved_via="default",
        permission="read_data",
    )
