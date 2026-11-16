"""Startup validation for every service that needs a broker-issued token.

x509 mints only through voms-token-service, authenticated with an AF Broker
Identity Token, so an x509 entry needs the signing key and a ``service_url``
exactly like the other broker-token entries (broker-issued, condor-token,
krb5-token, servicex-token). Boot must fail naming the affected service(s)
instead of surfacing the gap at first request.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from test_broker_issued import _make_rsa_key, _private_pem

from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_SERVICES_YAML = (
    "services:\n"
    "  - name: ami\n"
    "    prefix: ami\n"
    "    url: http://ami-mcp.invalid/mcp\n"
    "    auth_type: x509\n"
    "    required_permission: read_data\n"
    "  - name: krb5-target\n"
    "    prefix: krb5\n"
    "    url: http://krb5-target.invalid/mcp\n"
    "    auth_type: bearer\n"
    "    required_permission: read_data\n"
)

_X509_ENTRY = {
    "type": "x509",
    "voms": "atlas",
    "alias": "x509",
    "targets": ["ami"],
    "service_url": "http://voms-token-service.invalid:8000",
}
_KRB5_ENTRY = {
    "type": "krb5-token",
    "alias": "krb5",
    "targets": ["krb5-target"],
    "service_url": "http://krb5-token-service.invalid",
}


async def _fake_authenticate(self: VaultKV) -> str:
    return "vault-test-token"


@pytest.fixture
def boot_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Callable[..., None]:
    """Point the app at *entries* with Vault stubbed, and a signing key only when asked.

    Applied from inside the test body so it runs after ``app_client_factory``'s
    own default environment.
    """

    def _apply(entries: list[dict], *, with_signing_key: bool) -> None:
        services_file = tmp_path / "services.yaml"
        services_file.write_text(_SERVICES_YAML)
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(entries))
        monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
        monkeypatch.setattr(VaultKV, "_authenticate", _fake_authenticate)
        monkeypatch.setenv("VAULT_ADDR", "https://vault.invalid")
        monkeypatch.setenv("VAULT_AUTH_ROLE", "af-mcp-broker")
        if with_signing_key:
            key_file = tmp_path / "signing-key.pem"
            key_file.write_bytes(_private_pem(_make_rsa_key()))
            monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
        else:
            monkeypatch.delenv("BROKER_SIGNING_KEY_FILE", raising=False)

    return _apply


def test_x509_entry_without_signing_key_refuses_to_boot_naming_the_service(
    boot_env: Callable[..., None], app_client_factory
) -> None:
    boot_env([_X509_ENTRY], with_signing_key=False)

    with (
        pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE") as excinfo,
        app_client_factory(),
    ):
        pass  # pragma: no cover - boot must fail before yielding

    assert "ami" in str(excinfo.value)


def test_every_broker_token_entry_without_signing_key_is_named(
    boot_env: Callable[..., None], app_client_factory
) -> None:
    boot_env([_X509_ENTRY, _KRB5_ENTRY], with_signing_key=False)

    with (
        pytest.raises(RuntimeError, match="BROKER_SIGNING_KEY_FILE") as excinfo,
        app_client_factory(),
    ):
        pass  # pragma: no cover - boot must fail before yielding

    message = str(excinfo.value)
    assert "ami" in message
    assert "krb5-target" in message


def test_x509_entry_with_signing_key_boots(
    boot_env: Callable[..., None], app_client_factory
) -> None:
    boot_env([_X509_ENTRY], with_signing_key=True)

    with app_client_factory() as (client, _):
        assert client.app.state.broker.broker_token_issuer is not None


def test_x509_entry_without_service_url_refuses_to_boot(
    boot_env: Callable[..., None], app_client_factory
) -> None:
    boot_env(
        [{"type": "x509", "alias": "x509", "targets": ["ami"]}],
        with_signing_key=True,
    )

    with (
        pytest.raises(ValueError, match="service_url"),
        app_client_factory(),
    ):
        pass  # pragma: no cover - boot must fail before yielding
