"""Tests for ``CredentialCache``'s ``on_revoke`` hook (issue #320) and the
janitor's separate expiry path.

The aggregator's per-(subject, service) ``tools/list`` cache
(``mcp/aggregator.py``'s ``_ObservableProxyProvider``) must not keep serving
a listing cached under a subject's now-revoked credential state. Rather than
wire that invalidation into every individual unlink/burn-credential call
site, ``CredentialCache.revoke()`` (and, by delegation, ``revoke_all()``)
calls an optional ``on_revoke(subject, target)`` callback -- app.py wires the
real one (``invalidate_subject_cache``); these tests use a plain recording
stub so the hook's firing conditions are pinned independently of the
aggregator.

A cached credential simply expiring (the background janitor's sweep) is
bookkeeping, not an identity change, and must NOT fire ``on_revoke`` -- doing
so used to drop a subject's warm listing cache for no reason other than a
broker-issued token's 600s lifetime running out. The janitor sweeps through
``CredentialCache._expire()`` instead of ``revoke()`` for exactly this
reason; the tests below pin that split.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog.testing

from af_mcp_broker.credentials.base import (
    CredentialKind,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.credentials.cache import CredentialCache, ProxyMeta

if TYPE_CHECKING:
    from pathlib import Path

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


async def test_janitor_expiry_does_not_call_on_revoke_hook():
    """A credential merely expiring (background janitor sweep) is
    bookkeeping, not an identity change -- unlike an explicit revoke(), it
    must never fire on_revoke, or a subject's warm aggregator listing cache
    would be dropped every time a short-lived broker-issued token's 600s
    lifetime simply runs out."""
    calls: list[tuple[str, str]] = []
    cache = CredentialCache(
        on_revoke=lambda subject, target: calls.append((subject, target))
    )
    await cache.put("sub-1", TARGET, _cred(TARGET), expires_at=time.time() - 1)

    await cache.sweep_expired()

    assert calls == []


async def test_janitor_expiry_removes_the_entry():
    cache = CredentialCache()
    await cache.put("sub-1", TARGET, _cred(TARGET), expires_at=time.time() - 1)

    await cache.sweep_expired()

    assert await cache.peek("sub-1", TARGET, min_remaining=-(10**9)) is None


async def test_janitor_expiry_securely_deletes_x509_proxy_file(tmp_path: Path):
    """Expiry shares revoke()'s proxy-scrubbing cleanup -- an expired x509
    proxy's on-disk PEM must be zero-overwritten and unlinked exactly as it
    would be on an explicit revoke, even though on_revoke is never called."""
    proxy_file = tmp_path / "proxy.pem"
    proxy_file.write_text("FAKE PROXY PEM\n")
    meta = ProxyMeta(
        dn="/DC=ch/DC=cern/CN=Test User",
        voms_attributes=["/atlas/Role=NULL", "/atlas"],
        not_after=time.time() - 1,
        proxy_path=str(proxy_file),
    )
    cache = CredentialCache()
    await cache.put(
        "sub-1",
        TARGET,
        {"proxy_handle": "sub-1"},
        expires_at=time.time() - 1,
        proxy_meta=meta,
    )

    await cache.sweep_expired()

    assert not proxy_file.exists()


async def test_explicit_revoke_still_securely_deletes_x509_proxy_file(tmp_path: Path):
    """Same proxy-scrubbing cleanup, exercised via the explicit revoke() path
    -- pins that factoring the cleanup out for _expire() to share didn't
    change revoke()'s own behavior."""
    proxy_file = tmp_path / "proxy.pem"
    proxy_file.write_text("FAKE PROXY PEM\n")
    meta = ProxyMeta(
        dn="/DC=ch/DC=cern/CN=Test User",
        voms_attributes=["/atlas/Role=NULL", "/atlas"],
        not_after=time.time() + 3600,
        proxy_path=str(proxy_file),
    )
    cache = CredentialCache()
    await cache.put(
        "sub-1",
        TARGET,
        {"proxy_handle": "sub-1"},
        proxy_meta=meta,
    )

    await cache.revoke("sub-1", TARGET)

    assert not proxy_file.exists()


async def test_janitor_expiry_logs_expired_not_revoked():
    """Expiry must be distinguishable from an explicit revoke in the audit
    trail -- production diagnosis of issue #320's over-invalidation relied on
    telling the two apart."""
    cache = CredentialCache()
    await cache.put("sub-1", TARGET, _cred(TARGET), expires_at=time.time() - 1)

    with structlog.testing.capture_logs() as logs:
        await cache.sweep_expired()

    events = [entry["event"] for entry in logs]
    assert "credential_cache.expired" in events
    assert "credential_cache.revoked" not in events


async def test_revoke_logs_revoked_event_with_had_entry_true_when_cached():
    cache = CredentialCache()
    await cache.put("sub-1", TARGET, _cred(TARGET))

    with structlog.testing.capture_logs() as logs:
        await cache.revoke("sub-1", TARGET)

    revoked_logs = [
        entry for entry in logs if entry["event"] == "credential_cache.revoked"
    ]
    assert len(revoked_logs) == 1
    assert revoked_logs[0]["had_entry"] is True
    assert revoked_logs[0]["cred_class"] == "test"


async def test_revoke_logs_revoked_event_with_had_entry_false_when_nothing_cached():
    """Production diagnosis of issue #320's over-invalidation was made harder
    by revoke() staying silent whenever nothing happened to be cached -- it
    must now log every call, regardless."""
    cache = CredentialCache()

    with structlog.testing.capture_logs() as logs:
        await cache.revoke("sub-1", TARGET)

    revoked_logs = [
        entry for entry in logs if entry["event"] == "credential_cache.revoked"
    ]
    assert len(revoked_logs) == 1
    assert revoked_logs[0]["had_entry"] is False
    assert revoked_logs[0]["cred_class"] is None
