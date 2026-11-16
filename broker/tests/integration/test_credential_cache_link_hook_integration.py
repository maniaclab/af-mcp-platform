"""Integration tests for the area ``test_credential_cache_link_hook.py`` covers; the unit tests live in ``unit/test_credential_cache_link_hook.py``."""

from __future__ import annotations

import time
from typing import Any

from test_broker_issued_app import _find_service_provider

import af_mcp_broker.app as app_module
from af_mcp_broker.mcp import aggregator as aggregator_module


def _seed_negative_entry(provider: Any, subject: str) -> None:
    """Cache a failed tools listing for *subject*, as an unlinked caller's would be."""
    provider._subject_list_cache[("tools", subject)] = aggregator_module._CachedFailure(
        error=RuntimeError("not linked"), timestamp=time.monotonic()
    )


def test_lifespan_wires_on_link_to_the_targeted_service_and_subject_only(
    app_client_factory: Any,
) -> None:
    """The real lifespan's notify_linked drops the subject's cached listing and
    per-caller record for the targeted service, and nothing else."""
    with app_client_factory() as (client, _state):
        registry = client.app.state.broker.service_registry
        rucio = _find_service_provider(app_module.app.state, "rucio")
        ami = _find_service_provider(app_module.app.state, "ami")
        for provider in (rucio, ami):
            _seed_negative_entry(provider, "alice")
            _seed_negative_entry(provider, "bob")
            registry.record_list_failure(provider._service_name, "not_linked", "alice")
            registry.record_list_failure(provider._service_name, "not_linked", "bob")

        client.app.state.broker.credential_cache.notify_linked("alice", "rucio")

        assert ("tools", "alice") not in rucio._subject_list_cache
        assert registry.recent_list_failure("rucio", "alice") is None
        assert ("tools", "bob") in rucio._subject_list_cache
        assert registry.recent_list_failure("rucio", "bob") == "not_linked"
        assert ("tools", "alice") in ami._subject_list_cache
        assert registry.recent_list_failure("ami", "alice") == "not_linked"


async def test_lifespan_revoke_also_drops_the_per_caller_record(
    app_client_factory: Any,
) -> None:
    with app_client_factory() as (client, _state):
        registry = client.app.state.broker.service_registry
        rucio = _find_service_provider(app_module.app.state, "rucio")
        _seed_negative_entry(rucio, "alice")
        registry.record_list_failure("rucio", "unauthorized", "alice")

        await client.app.state.broker.credential_cache.revoke("alice", "rucio")

        assert ("tools", "alice") not in rucio._subject_list_cache
        assert registry.recent_list_failure("rucio", "alice") is None


async def test_lifespan_link_and_revoke_keep_the_service_wide_failure_record(
    app_client_factory: Any,
) -> None:
    with app_client_factory() as (client, _state):
        registry = client.app.state.broker.service_registry
        cache = client.app.state.broker.credential_cache
        registry.record_list_failure("rucio", "unavailable", None)
        registry.record_list_failure("rucio", "not_linked", "alice")

        cache.notify_linked("alice", "rucio")
        assert registry.recent_list_failure("rucio", "alice") == "unavailable"
        assert registry.recent_list_failure("rucio", "bob") == "unavailable"

        registry.record_list_failure("rucio", "not_linked", "alice")
        await cache.revoke("alice", "rucio")
        assert registry.recent_list_failure("rucio", "alice") == "unavailable"
        assert registry.recent_list_failure("rucio", "bob") == "unavailable"
