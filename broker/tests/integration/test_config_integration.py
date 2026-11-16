from __future__ import annotations

from af_mcp_broker.config import Settings


def test_shared_state_defaults_to_in_memory_and_no_escape_hatch():
    settings = Settings()
    assert settings.shared_state_url is None
    assert settings.allow_per_replica_state is False


def test_shared_state_env_vars(monkeypatch):
    monkeypatch.setenv("SHARED_STATE_URL", "rediss://cache.example.org:6380/0")
    monkeypatch.setenv("ALLOW_PER_REPLICA_STATE", "true")
    settings = Settings()
    assert settings.shared_state_url == "rediss://cache.example.org:6380/0"
    assert settings.allow_per_replica_state is True
