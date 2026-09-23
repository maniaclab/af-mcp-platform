"""Tests for ``CredentialCache``'s ``on_revoke`` hook (issue #320).

The aggregator's per-(subject, service) ``tools/list`` cache
(``mcp/aggregator.py``'s ``_ObservableProxyProvider``) must not keep serving
a listing cached under a subject's now-revoked credential state. Rather than
wire that invalidation into every individual unlink/burn-credential call
site, ``CredentialCache.revoke()`` (and, by delegation, ``revoke_all()``)
calls an optional ``on_revoke(subject, target)`` callback -- app.py wires the
real one (``invalidate_subject_cache``); these tests use a plain recording
stub so the hook's firing conditions are pinned independently of the
aggregator.
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


async def test_revoke_calls_on_revoke_hook_when_something_was_cached():
    calls: list[tuple[str, str]] = []
    cache = CredentialCache(
        on_revoke=lambda subject, target: calls.append((subject, target))
    )
    await cache.put("sub-1", TARGET, _cred(TARGET))

    await cache.revoke("sub-1", TARGET)

    assert calls == [("sub-1", TARGET)]


async def test_revoke_calls_on_revoke_hook_even_when_nothing_was_cached():
    """A subject's linked identity can change even with nothing currently
    cached for it -- the hook must still fire, or a stale aggregator
    tools/list cache entry from an earlier credential state would survive
    the change."""
    calls: list[tuple[str, str]] = []
    cache = CredentialCache(
        on_revoke=lambda subject, target: calls.append((subject, target))
    )

    await cache.revoke("sub-1", TARGET)

    assert calls == [("sub-1", TARGET)]


async def test_revoke_all_calls_hook_once_per_cached_target():
    calls: list[tuple[str, str]] = []
    cache = CredentialCache(
        on_revoke=lambda subject, target: calls.append((subject, target))
    )
    await cache.put("sub-1", "rucio", _cred("rucio"))
    await cache.put("sub-1", "ami", _cred("ami"))
    await cache.put("sub-2", "rucio", _cred("rucio"))

    await cache.revoke_all("sub-1")

    assert sorted(calls) == [("sub-1", "ami"), ("sub-1", "rucio")]


async def test_no_on_revoke_configured_is_a_noop():
    """Every existing ``CredentialCache()`` call site omits ``on_revoke`` --
    revoke()/revoke_all() must keep working exactly as before."""
    cache = CredentialCache()
    await cache.put("sub-1", TARGET, _cred(TARGET))

    await cache.revoke("sub-1", TARGET)
    await cache.revoke_all("sub-1")
