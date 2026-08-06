"""Tests for the public broker JWKS endpoint (issue #162).

``GET /.well-known/jwks.json`` serves the AF Broker Identity Token issuer's
public keys so AF-native backends (condor-token-service, future jupyter-mcp)
can verify broker-signed identity assertions locally with a standard
library. It must be reachable with no auth headers, publish public material
only, and degrade to a clear 503 when no signing key is configured -- the
same shape as the other well-known documents here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from test_broker_issued import (
    _make_rsa_key,
    _private_pem,
    _public_pem,
    _rfc7638_thumbprint,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest


def _configure_signing_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Any:
    key = _make_rsa_key()
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(_private_pem(key))
    monkeypatch.setenv("BROKER_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp.example.com")
    return key


def test_jwks_returns_200_without_auth_headers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    key = _configure_signing_key(monkeypatch, tmp_path)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/jwks.json", headers={})

    assert resp.status_code == 200, resp.text
    (jwk,) = resp.json()["keys"]
    assert jwk["kid"] == _rfc7638_thumbprint(key)


def test_jwks_content_type_is_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    _configure_signing_key(monkeypatch, tmp_path)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/jwks.json")

    assert resp.headers["content-type"].startswith("application/json")


def test_jwks_publishes_public_material_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    _configure_signing_key(monkeypatch, tmp_path)

    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/jwks.json")

    for jwk in resp.json()["keys"]:
        assert not ({"d", "p", "q", "dp", "dq", "qi"} & set(jwk))
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"


def test_jwks_includes_additional_rotation_keys(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_client_factory: Callable[..., Any],
) -> None:
    active_key = _configure_signing_key(monkeypatch, tmp_path)
    retiring_key = _make_rsa_key()
    extra_dir = tmp_path / "additional"
    extra_dir.mkdir()
    (extra_dir / "retiring.pem").write_bytes(_public_pem(retiring_key))
    monkeypatch.setenv("BROKER_ADDITIONAL_PUBLIC_KEYS_DIR", str(extra_dir))

    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/jwks.json")

    kids = {k["kid"] for k in resp.json()["keys"]}
    assert kids == {
        _rfc7638_thumbprint(active_key),
        _rfc7638_thumbprint(retiring_key),
    }


def test_jwks_degrades_to_503_when_unconfigured(
    app_client_factory: Callable[..., Any],
) -> None:
    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/jwks.json")

    assert resp.status_code == 503, resp.text
