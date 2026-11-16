"""Unit tests for the area ``test_usage_postgres.py`` covers; the integration tests live in ``integration/test_usage_postgres.py``."""

from __future__ import annotations

from af_mcp_broker.usage import PostgresUsageStore, UsageStore


def test_postgres_store_satisfies_the_abc() -> None:
    assert issubclass(PostgresUsageStore, UsageStore)
