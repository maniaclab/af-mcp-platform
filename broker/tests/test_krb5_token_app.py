"""App-level wiring for KrbTokenProvider (issue #274).

Covers: provider registration from an ``identity_providers`` krb5-token
entry, the startup fail-closed check (a krb5-token entry with no broker
signing key must refuse to boot -- the provider composes the same
``BrokerTokenIssuer`` as broker-issued/condor-token), and /v1/identities
listing the provider's is_linked() state. The provider unit tests (HTTP
boundary stubbed) live in test_krb5_token.py.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest
from test_broker_issued import _make_rsa_key, _private_pem

from af_mcp_broker.credentials import KrbTokenProvider

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_KRB5_TOKEN_PROVIDERS = [
    {
        "type": "krb5-token",
        "alias": "krb5",
        "display_name": "CERN Kerberos ticket",
        "targets": ["krb5-target"],
        "service_url": "http://krb5-token-service.invalid",
    }
]

_BACKENDS_YAML = (
    "services:\n"
    "  - name: krb5-target\n"
    "    prefix: krb5\n"
    "    url: http://krb5-target.invalid/mcp\n"
    "    auth_type: bearer\n"
    "    required_permission: read_data\n"
)


@pytest.fixture
def krb5_token_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[..., None]:
    """Point the app at a krb5-token identity provider and (optionally) a real signing key on disk."""

    def _apply(*, with_signing_key: bool = True) -> None:
        services_file = tmp_path / "services.yaml"
        services_file.write_text(_BACKENDS_YAML)
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(_KRB5_TOKEN_PROVIDERS))
        monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
        if with_signing_key:
            key_file = tmp_path / "signing-key.pem"
            key_file.write_bytes(_private_pem(_make_rsa_key()))
            monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))

    return _apply


def test_krb5_token_provider_registered_from_config(
    krb5_token_env, app_client_factory
) -> None:
    krb5_token_env()

    with app_client_factory() as (client, _):
        state = client.app.state
        assert state.broker_token_issuer is not None
        assert isinstance(state.identity_providers["krb5"], KrbTokenProvider)
        provider = asyncio.run(state.credential_registry.resolve("krb5-target"))
        assert isinstance(provider, KrbTokenProvider)
        # issue #90's catalog join: the target maps to the configured alias.
        assert state.target_to_alias["krb5-target"] == "krb5"


def test_krb5_token_entry_without_signing_key_refuses_to_start(
    krb5_token_env, app_client_factory
) -> None:
    """Fail-closed, same as broker-issued/condor-token: KrbTokenProvider mints
    its broker identity token through the shared BrokerTokenIssuer, so a
    krb5-token entry with no signing key configured must refuse to boot
    rather than fail at first request."""
    krb5_token_env(with_signing_key=False)

    with pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE"):  # noqa: SIM117
        with app_client_factory():
            pass


def test_identities_lists_krb5_token_provider_as_linked(
    krb5_token_env, app_client_factory
) -> None:
    krb5_token_env()

    with app_client_factory() as (client, _):
        resp = client.get("/v1/identities")

    assert resp.status_code == 200, resp.text
    rows: list[dict[str, Any]] = resp.json()["providers"]
    (row,) = [r for r in rows if r["id"] == "krb5"]
    assert row["type"] == "krb5-token"
    # Unlike CondorTokenProvider's unconditional True, KrbTokenProvider's
    # is_linked() reflects live cache state (see credentials/krb5.py's
    # module docstring) -- a freshly-started app with nothing minted yet
    # has no cached ticket for any of the entry's targets.
    assert row["linked"] is False
    assert row["link_url"] is None
