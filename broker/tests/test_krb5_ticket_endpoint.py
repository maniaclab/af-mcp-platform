"""HTTP-level tests for ``POST /v1/krb5/ticket`` (issue #274).

Mirrors test_x509_identity_provider.py's full-app pattern (specifically
TestPerTargetResolution): boot the real app via ``app_client_factory`` with a
krb5-token ``identity_providers`` entry, resolve the registered
``KrbTokenProvider`` from the credential registry, then replace its
underlying ``Krb5TokenServiceClient`` with an in-memory recording fake --
the same "swap the concrete client attribute post-boot" pattern
test_x509_service_mode.py's ``FakeVomsClient`` uses for
``VomsTokenServiceClient`` -- rather than mocking httpx at the wire level.

The provider's own error-mapping/NeedsUnlock behavior is unit-tested in
test_krb5_token.py; this file covers only the ``/v1/krb5/ticket`` route's
HTTP surface (status codes, response shape, and the pre-existing
``NeedsUnlock`` -> 409 mapping already exercised for x509 in test_api.py's
``test_credential_x509_needs_unlock_409``).
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any

import pytest
from test_broker_issued import _make_rsa_key, _private_pem

from af_mcp_broker.credentials import KrbTokenProvider
from af_mcp_broker.credentials.krb5_service import (
    Krb5TokenAccountError,
    Krb5TokenBadCredentialError,
    Krb5TokenInvalidRequestError,
    Krb5TokenRateLimitedError,
    MintedTicket,
)
from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_TARGET = "krb5-target"

_KRB5_TOKEN_PROVIDERS = [
    {
        "type": "krb5-token",
        "alias": "krb5",
        "display_name": "CERN Kerberos ticket",
        "targets": [_TARGET],
        "service_url": "http://krb5-token-service.invalid",
    }
]

# krb5-token has no `auth_type` variant in services.yaml (unlike x509) --
# the target backend is an ordinary bearer-auth entry, same as
# test_krb5_token_app.py's fixture.
_BACKENDS_YAML = (
    "services:\n"
    "  - name: krb5-target\n"
    "    prefix: krb5\n"
    "    url: http://krb5-target.invalid/mcp\n"
    "    auth_type: bearer\n"
    "    required_permission: read_data\n"
)


class FakeKrb5Client:
    """Recording fake for ``Krb5TokenServiceClient.mint``.

    ``outcome`` is a ``MintedTicket`` to return or an exception to raise;
    mutate it between requests to script the next mint's result. Every
    call's kwargs are recorded in ``calls``.
    """

    def __init__(self, outcome: MintedTicket | Exception | None = None) -> None:
        self.outcome = outcome or _minted()
        self.calls: list[dict[str, Any]] = []

    async def mint(self, **kwargs: Any) -> MintedTicket:
        self.calls.append(kwargs)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _minted(remaining: float = 3600.0, renewable: bool = True) -> MintedTicket:
    return MintedTicket(
        ccache_b64="ZmFrZS1jY2FjaGU=",
        principal="tuser@CERN.CH",
        realm="CERN.CH",
        not_after=time.time() + remaining,
        renew_until=(time.time() + remaining + 3600.0) if renewable else None,
    )


async def _fake_authenticate(self: VaultKV) -> str:
    return "vault-test-token"


@pytest.fixture
def krb5_app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
):
    """Boot the real app with a krb5-token entry, then swap the resolved
    provider's client for a scriptable fake -- see the module docstring."""
    services_file = tmp_path / "services.yaml"
    services_file.write_text(_BACKENDS_YAML)
    monkeypatch.setenv("SERVICES_FILE", str(services_file))
    monkeypatch.setenv("IDENTITY_PROVIDERS", json.dumps(_KRB5_TOKEN_PROVIDERS))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(_private_pem(_make_rsa_key()))
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
    # A krb5-token entry always requires Vault (config.py's
    # _validate_vault_config -- its optional "remember" feature persists
    # there with no in-memory fallback); stub the trial auth the same way
    # test_x509_service_mode.py's voms_service_env does for x509.
    monkeypatch.setattr(VaultKV, "_authenticate", _fake_authenticate)
    monkeypatch.setenv("VAULT_ADDR", "https://vault.invalid")
    monkeypatch.setenv("VAULT_AUTH_ROLE", "af-mcp-broker")

    with app_client_factory() as (client, state):
        provider = asyncio.run(client.app.state.credential_registry.resolve(_TARGET))
        assert isinstance(provider, KrbTokenProvider)
        fake_client = FakeKrb5Client()
        provider._client = fake_client
        yield client, state, fake_client


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_happy_path_returns_metadata_without_ccache(krb5_app) -> None:
    client, _state, fake_client = krb5_app

    resp = client.post(
        "/v1/krb5/ticket",
        json={"username": "tuser", "password": "hunter2"},
    )

    assert resp.status_code == 201, resp.text
    body = resp.json()
    # Assert on the actual JSON keys -- ccache_b64 must genuinely be absent
    # from the wire response, not merely from the pydantic model definition.
    assert set(body) == {
        "target",
        "principal",
        "realm",
        "expires_at",
        "remaining_seconds",
        "renew_until",
    }
    assert body["target"] == _TARGET
    assert body["principal"] == "tuser@CERN.CH"
    assert body["realm"] == "CERN.CH"
    assert body["renew_until"] is not None
    assert body["remaining_seconds"] == pytest.approx(3600, abs=5)

    assert len(fake_client.calls) == 1
    assert fake_client.calls[0]["username"] == "tuser"
    assert fake_client.calls[0]["password"].get_secret_value() == "hunter2"


def test_happy_path_null_renew_until_for_non_renewable_ticket(krb5_app) -> None:
    client, _state, fake_client = krb5_app
    fake_client.outcome = _minted(renewable=False)

    resp = client.post(
        "/v1/krb5/ticket",
        json={"username": "tuser", "password": "hunter2"},
    )

    assert resp.status_code == 201, resp.text
    assert resp.json()["renew_until"] is None


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


def test_bad_credential_maps_to_400(krb5_app) -> None:
    client, _state, fake_client = krb5_app
    fake_client.outcome = Krb5TokenBadCredentialError()

    resp = client.post(
        "/v1/krb5/ticket",
        json={"username": "tuser", "password": "wrong"},
    )

    assert resp.status_code == 400, resp.text


def test_account_error_maps_to_403(krb5_app) -> None:
    client, _state, fake_client = krb5_app
    fake_client.outcome = Krb5TokenAccountError()

    resp = client.post(
        "/v1/krb5/ticket",
        json={"username": "tuser", "password": "hunter2"},
    )

    assert resp.status_code == 403, resp.text


def test_invalid_request_maps_to_422(krb5_app) -> None:
    client, _state, fake_client = krb5_app
    fake_client.outcome = Krb5TokenInvalidRequestError()

    resp = client.post(
        "/v1/krb5/ticket",
        json={"username": "tuser", "password": "hunter2"},
    )

    assert resp.status_code == 422, resp.text


def test_rate_limited_maps_to_429_with_retry_after(krb5_app) -> None:
    client, _state, fake_client = krb5_app
    fake_client.outcome = Krb5TokenRateLimitedError("30")

    resp = client.post(
        "/v1/krb5/ticket",
        json={"username": "tuser", "password": "hunter2"},
    )

    assert resp.status_code == 429, resp.text
    assert resp.headers["retry-after"] == "30"


# ---------------------------------------------------------------------------
# NeedsUnlock -> 409, exercised via POST /v1/credential (provider-agnostic
# handler, no krb5-specific code -- see test_api.py's
# test_credential_x509_needs_unlock_409 for the x509 equivalent).
# ---------------------------------------------------------------------------


def test_credential_endpoint_needs_unlock_409_before_a_usable_ticket_is_cached(
    krb5_app,
) -> None:
    """Mint a ticket that's cached but inside issue()'s 300s staleness
    buffer: ``is_linked()``'s ``peek(min_remaining=0)`` still finds it (so
    the generic "not linked" 404 gate in ``issue_credential`` is bypassed --
    see ``KrbTokenProvider.is_linked``'s docstring on the two different
    staleness thresholds), but ``POST /v1/credential`` (which supplies no
    username/password) then hits ``issue()``'s cache miss and its
    ``NeedsUnlock`` raise, which ``issue_credential``'s existing generic
    ``except NeedsUnlock`` handler maps to 409 -- no krb5-specific code
    needed."""
    client, _state, fake_client = krb5_app
    fake_client.outcome = _minted(remaining=60.0)
    mint_resp = client.post(
        "/v1/krb5/ticket",
        json={"username": "tuser", "password": "hunter2"},
    )
    assert mint_resp.status_code == 201, mint_resp.text

    resp = client.post("/v1/credential", json={"target": _TARGET})

    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "proxy_unlock_required"
    assert detail["unlock_endpoint"] == "/v1/krb5/ticket"
