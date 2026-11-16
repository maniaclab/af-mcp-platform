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

from af_mcp_broker.credentials.base import (
    CredentialKind,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.credentials.cache import CredentialCache

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


async def test_notify_linked_without_hook_leaves_the_cache_untouched():
    cache = CredentialCache()
    cred = _cred(TARGET)
    await cache.put("sub-1", TARGET, cred)

    cache.notify_linked("sub-1", TARGET)

    assert await cache.peek("sub-1", TARGET) is cred


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
