"""Tests for the credential-unlock rate-limit tunables (issue #21).

``CredentialCache`` rate-limits *actual failed unlock attempts* (bad
passphrase, or a minting-backend failure — recorded via
``record_failed_unlock()``) per uid to slow brute-force guessing against a
colocated user's ``~/.globus``. Plain cache misses from ``get()`` do not
count against this budget (issue #93) — see test_rate_limit_api.py for the
end-to-end regression test of that fix. The thresholds used to be hardcoded
module constants in ``cache.py``; these tests cover their promotion to
``Settings`` fields (env-overridable) while keeping ``CredentialCache()``'s
no-arg construction behaviourally unchanged.
"""

from __future__ import annotations

import pytest

from af_mcp_broker.config import Settings
from af_mcp_broker.credentials.cache import CredentialCache, RateLimitError

TARGET = "rucio"


def test_defaults_match_pre_lift_values():
    """Settings() without any env override reproduces the old hardcoded values."""
    settings = Settings()
    assert settings.credential_unlock_max_failures == 5
    assert settings.credential_unlock_window_seconds == 900


def test_env_var_overrides(monkeypatch: pytest.MonkeyPatch):
    """Env vars are reflected in Settings, and a cache built from those
    Settings raises on the 4th failed unlock (not the 6th default-derived
    one)."""
    monkeypatch.setenv("CREDENTIAL_UNLOCK_MAX_FAILURES", "3")
    monkeypatch.setenv("CREDENTIAL_UNLOCK_WINDOW_SECONDS", "60")
    settings = Settings()

    assert settings.credential_unlock_max_failures == 3
    assert settings.credential_unlock_window_seconds == 60

    cache = CredentialCache(
        max_failed_unlocks=settings.credential_unlock_max_failures,
        unlock_window_seconds=settings.credential_unlock_window_seconds,
    )
    uid = 12_345

    for _attempt in range(1, 4):
        cache.record_failed_unlock(uid)

    with pytest.raises(RateLimitError):
        cache.record_failed_unlock(uid)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"credential_unlock_max_failures": 0},
        {"credential_unlock_max_failures": -1},
        {"credential_unlock_window_seconds": 0},
        {"credential_unlock_window_seconds": -1},
    ],
)
def test_zero_or_negative_rejected(kwargs: dict[str, int]):
    with pytest.raises(ValueError, match="must be >= 1"):
        Settings(**kwargs)


def test_record_failed_unlock_defaults_unchanged():
    """``CredentialCache()`` with no args still raises on the 6th failed unlock.

    Backwards-compat guarantee for existing callers (test_oidc.py,
    spikes/credential-isolation/) that construct the cache directly without
    going through ``Settings``.
    """
    cache = CredentialCache()
    uid = 54_321

    for _attempt in range(1, 6):
        cache.record_failed_unlock(uid)

    with pytest.raises(RateLimitError):
        cache.record_failed_unlock(uid)


async def test_get_never_counts_against_rate_limit():
    """Plain cache misses via ``get()`` never consume unlock budget (issue #93).

    Before the fix, every miss -- including the ordinary "not cached yet, no
    passphrase given" probe -- counted the same as a bad passphrase attempt,
    so routine polling alone could exhaust the budget. Regardless of
    ``max_failed_unlocks``, ``get()`` must never raise ``RateLimitError``.
    """
    cache = CredentialCache(max_failed_unlocks=2, unlock_window_seconds=60)
    uid = 11_111

    for _ in range(50):
        assert await cache.get(uid, TARGET) is None


async def test_rate_limit_error_carries_retry_after_seconds():
    """``RateLimitError.retry_after_seconds`` reflects the fixed window's
    remaining time (issue #25) when tripped via ``record_failed_unlock()``."""
    cache = CredentialCache(max_failed_unlocks=2, unlock_window_seconds=60)
    uid = 99_999

    for _ in range(2):
        cache.record_failed_unlock(uid)

    with pytest.raises(RateLimitError) as excinfo:
        cache.record_failed_unlock(uid)

    assert 0 <= excinfo.value.retry_after_seconds <= 60


def test_check_unlock_rate_limit_carries_retry_after_seconds():
    """Same ``retry_after_seconds`` contract on the ``check_unlock_rate_limit``
    raise site (the guard called before minting, x509.py:279)."""
    cache = CredentialCache(max_failed_unlocks=1, unlock_window_seconds=30)
    uid = 88_888

    cache.record_failed_unlock(uid)  # 1st failure: attempts == limit, no raise
    with pytest.raises(RateLimitError):
        cache.record_failed_unlock(uid)  # 2nd failure: trips the limiter

    with pytest.raises(RateLimitError) as excinfo:
        cache.check_unlock_rate_limit(uid)  # already-tripped guard

    assert 0 <= excinfo.value.retry_after_seconds <= 30


async def test_failed_unlock_counter_resets_on_put_when_uid_given():
    """A successful ``put(..., uid=...)`` resets that uid's failed-unlock
    counter: otherwise a lockout could persist across a legitimate
    re-authentication. ``uid`` is keyword-only and opt-in (issue #148) --
    only X509Provider ever passes it; see CredentialCache's class docstring
    for why the credential-storage key (``subject``, the positional first
    arg below) and the uid-keyed rate limiter are deliberately separate."""
    cache = CredentialCache(max_failed_unlocks=2, unlock_window_seconds=60)
    uid = 22_222
    subject = "subject-22222"

    cache.record_failed_unlock(uid)  # 1 of 2 allowed failures

    await cache.put(subject, TARGET, "some-cred", uid=uid)

    # Counter reset by put() -- two more failures are allowed before tripping.
    cache.record_failed_unlock(uid)
    cache.record_failed_unlock(uid)
    with pytest.raises(RateLimitError):
        cache.record_failed_unlock(uid)


async def test_put_without_uid_does_not_reset_rate_limit():
    """A ``put()`` with no ``uid`` (every provider except X509Provider) must
    not reset any uid's failed-unlock counter -- issue #148 deliberately
    decoupled the credential-storage cache (keyed by subject, since uid may
    not exist) from the uid-keyed passphrase rate limiter."""
    cache = CredentialCache(max_failed_unlocks=2, unlock_window_seconds=60)
    uid = 33_333
    subject = "subject-33333"

    cache.record_failed_unlock(uid)  # 1 of 2 allowed failures

    await cache.put(subject, TARGET, "some-cred")  # no uid= passed

    # Counter NOT reset -- one more failure trips the limit, not two.
    cache.record_failed_unlock(uid)
    with pytest.raises(RateLimitError):
        cache.record_failed_unlock(uid)
