"""App-level wiring for CondorTokenProvider (issue #169).

Covers: provider registration from an ``identity_providers`` condor-token
entry, the startup fail-closed check (a condor-token entry with no broker
signing key must refuse to boot -- the provider composes the same
``BrokerTokenIssuer`` as broker-issued), and /v1/identities listing the
provider as always linked. The provider unit tests (HTTP boundary stubbed)
live in test_condor_token.py.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest
from test_broker_issued import _make_rsa_key, _private_pem

from af_mcp_broker.credentials import CondorTokenProvider

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_CONDOR_TOKEN_PROVIDERS = [
    {
        "type": "condor-token",
        "alias": "condor",
        "display_name": "HTCondor",
        "targets": ["condor-mcp"],
        "service_url": "http://condor-token-service.invalid",
    }
]

_BACKENDS_YAML = (
    "backends:\n"
    "  - name: condor-mcp\n"
    "    prefix: condor\n"
    "    url: http://condor-mcp.invalid/mcp\n"
    "    auth_type: bearer\n"
    "    required_capability: read_data\n"
)


@pytest.fixture
def condor_token_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    """Point the app at a condor-token identity provider and (optionally) a real signing key on disk."""

    def _apply(*, with_signing_key: bool = True) -> None:
        backends_file = tmp_path / "backends.yaml"
        backends_file.write_text(_BACKENDS_YAML)
        monkeypatch.setenv("BACKENDS_FILE", str(backends_file))
        monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(_CONDOR_TOKEN_PROVIDERS))
        monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
        if with_signing_key:
            key_file = tmp_path / "signing-key.pem"
            key_file.write_bytes(_private_pem(_make_rsa_key()))
            monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))

    return _apply


def test_condor_token_provider_registered_from_config(
    condor_token_env, app_client_factory
) -> None:
    condor_token_env()

    with app_client_factory() as (client, _):
        state = client.app.state
        assert state.broker_token_issuer is not None
        assert isinstance(state.identity_providers["condor"], CondorTokenProvider)
        provider = asyncio.run(state.credential_registry.resolve("condor-mcp"))
        assert isinstance(provider, CondorTokenProvider)
        # issue #90's catalog join: the target maps to the configured alias.
        assert state.target_to_alias["condor-mcp"] == "condor"


def test_condor_token_entry_without_signing_key_refuses_to_start(
    condor_token_env, app_client_factory
) -> None:
    """Fail-closed, same as broker-issued: CondorTokenProvider mints its
    broker identity token through the shared BrokerTokenIssuer, so a
    condor-token entry with no signing key configured must refuse to boot
    rather than fail at first request."""
    condor_token_env(with_signing_key=False)

    with pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"):  # noqa: SIM117
        with app_client_factory():
            pass


def test_identities_lists_condor_token_provider_as_linked(
    condor_token_env, app_client_factory
) -> None:
    condor_token_env()

    with app_client_factory() as (client, _):
        resp = client.get("/v1/identities")

    assert resp.status_code == 200, resp.text
    rows: list[dict[str, Any]] = resp.json()["providers"]
    (row,) = [r for r in rows if r["id"] == "condor"]
    assert row["type"] == "condor-token"
    assert row["linked"] is True
    assert row["link_url"] is None
