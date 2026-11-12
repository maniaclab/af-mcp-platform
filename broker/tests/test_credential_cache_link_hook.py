"""Tests for ``CredentialCache``'s ``on_link`` hook (issue #355).

Symmetric to ``on_revoke`` (see test_credential_cache_revoke_hook.py): when a
subject's credential for a service becomes usable through an explicit link
event, the aggregator's cached listing for that (subject, service) must not
outlive it. ``put()`` is deliberately NOT a link event -- every routine
token refresh goes through it, and firing the hook there would defeat the
per-(subject, service) listing cache (issue #320).
"""

from __future__ import annotations

import time
from typing import Any

from test_broker_issued_app import _find_service_provider

import af_mcp_broker.app as app_module
from af_mcp_broker.credentials.base import (
    CredentialKind,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.mcp import aggregator as aggregator_module

TARGET = "rucio"


def _cred(target: str) -> IssuedCredential:
    return IssuedCredential(
        cred_class="test",
        target=target,
        kind=CredentialKind.BEARER,
        expires_at=time.time() + 3600,
        payload={"access_token": "tok"},
        audit_id="test-audit",
        source="test",
        execution_model=ExecutionModel.DELEGATED,
    )


def test_notify_linked_calls_on_link_hook():
    calls: list[tuple[str, str]] = []
    cache = CredentialCache(
        on_link=lambda subject, target: calls.append((subject, target))
    )

    cache.notify_linked("sub-1", TARGET)

    assert calls == [("sub-1", TARGET)]


def test_notify_linked_without_hook_is_a_noop():
    CredentialCache().notify_linked("sub-1", TARGET)


async def test_put_does_not_call_on_link_hook():
    calls: list[tuple[str, str]] = []
    cache = CredentialCache(
        on_link=lambda subject, target: calls.append((subject, target))
    )

    await cache.put("sub-1", TARGET, _cred(TARGET))

    assert calls == []


async def test_revoke_does_not_call_on_link_hook():
    calls: list[tuple[str, str]] = []
    cache = CredentialCache(
        on_link=lambda subject, target: calls.append((subject, target))
    )

    await cache.revoke("sub-1", TARGET)

    assert calls == []


def _seed_negative_entry(provider: Any, subject: str) -> None:
    """Cache a failed tools listing for *subject*, as an unlinked caller's would be."""
    provider._subject_list_cache[("tools", subject)] = (
        aggregator_module._SubjectListCacheEntry(
            error=RuntimeError("not linked"), timestamp=time.monotonic()
        )
    )


def test_lifespan_wires_on_link_to_the_targeted_service_and_subject_only(
    app_client_factory: Any,
) -> None:
    """The real lifespan's notify_linked drops the subject's cached listing and
    per-caller record for the targeted service, and nothing else."""
    with app_client_factory() as (client, _state):
        registry = client.app.state.service_registry
        rucio = _find_service_provider(app_module._mcp_aggregator, "rucio")
        ami = _find_service_provider(app_module._mcp_aggregator, "ami")
        for provider in (rucio, ami):
            _seed_negative_entry(provider, "alice")
            _seed_negative_entry(provider, "bob")
            registry.record_list_failure(provider._service_name, "not_linked", "alice")
            registry.record_list_failure(provider._service_name, "not_linked", "bob")

        client.app.state.credential_cache.notify_linked("alice", "rucio")

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
        registry = client.app.state.service_registry
        rucio = _find_service_provider(app_module._mcp_aggregator, "rucio")
        _seed_negative_entry(rucio, "alice")
        registry.record_list_failure("rucio", "unauthorized", "alice")

        await client.app.state.credential_cache.revoke("alice", "rucio")

        assert ("tools", "alice") not in rucio._subject_list_cache
        assert registry.recent_list_failure("rucio", "alice") is None
