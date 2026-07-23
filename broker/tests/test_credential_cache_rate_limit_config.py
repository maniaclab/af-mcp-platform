"""Tests for the credential-unlock rate-limit tunables (issue #21).

``CredentialCache`` rate-limits failed cache lookups / bad passphrase attempts
per uid to slow brute-force guessing against a colocated user's ``~/.globus``.
The thresholds used to be hardcoded module constants in ``cache.py``; these
tests cover their promotion to ``Settings`` fields (env-overridable) while
keeping ``CredentialCache()``'s no-arg construction behaviourally unchanged.
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


async def test_env_var_overrides(monkeypatch: pytest.MonkeyPatch):
    """Env vars are reflected in Settings, and a cache built from those
    Settings raises on the 4th miss (not the 6th default-derived one)."""
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

    for attempt in range(1, 4):
        result = await cache.get(uid, TARGET)
        assert result is None, f"attempt {attempt}: expected None, got {result!r}"

    with pytest.raises(RateLimitError):
        await cache.get(uid, TARGET)


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


async def test_cache_defaults_unchanged():
    """``CredentialCache()`` with no args still raises on the 6th miss.

    Backwards-compat guarantee for existing callers (test_oidc.py,
    spikes/credential-isolation/) that construct the cache directly without
    going through ``Settings``.
    """
    cache = CredentialCache()
    uid = 54_321

    for attempt in range(1, 6):
        result = await cache.get(uid, TARGET)
        assert result is None, f"attempt {attempt}: expected None, got {result!r}"

    with pytest.raises(RateLimitError):
        await cache.get(uid, TARGET)
