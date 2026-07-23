"""Tests for the public CIMD endpoint (draft-ietf-oauth-client-id-metadata-document).

``GET /.well-known/cimd`` lets the broker identify itself to backend OAuth 2.1
authorization servers without per-backend Dynamic Client Registration. It must
be reachable with no auth headers, and ``client_id`` must be self-referential
(the exact URL the client used to fetch the document).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    import pytest


def test_cimd_returns_200_without_auth_headers(
    app_client_factory: Callable[..., Any],
) -> None:
    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/cimd", headers={})

    assert resp.status_code == 200, resp.text


def test_cimd_content_type_is_json(
    app_client_factory: Callable[..., Any],
) -> None:
    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/cimd")

    assert resp.headers["content-type"].startswith("application/json")


def test_cimd_token_endpoint_auth_method_is_none(
    app_client_factory: Callable[..., Any],
) -> None:
    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/cimd")

    assert resp.json()["token_endpoint_auth_method"] == "none"


def test_cimd_empty_idp_aliases_yields_empty_redirect_uris(
    app_client_factory: Callable[..., Any],
) -> None:
    # cimd_idp_aliases defaults to [] — no CIMD_IDP_ALIASES env var set.
    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/cimd")

    assert resp.status_code == 200, resp.text
    assert resp.json()["redirect_uris"] == []


def test_cimd_redirect_uris_derived_from_aliases_in_order(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setenv("OIDC_ISSUER", "https://kc.example.com/realms/foo")
    monkeypatch.setenv("CIMD_IDP_ALIASES", '["rucio-atlas", "rucio-escape"]')

    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/cimd")

    assert resp.status_code == 200, resp.text
    assert resp.json()["redirect_uris"] == [
        "https://kc.example.com/realms/foo/broker/rucio-atlas/endpoint",
        "https://kc.example.com/realms/foo/broker/rucio-escape/endpoint",
    ]


def test_cimd_client_id_is_self_referential(
    app_client_factory: Callable[..., Any],
) -> None:
    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/cimd")

    assert resp.status_code == 200, resp.text
    assert resp.json()["client_id"] == str(resp.request.url)


def test_cimd_client_name_from_settings(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
) -> None:
    monkeypatch.setenv("CIMD_CLIENT_NAME", "Test AF Broker")

    with app_client_factory() as (client, _):
        resp: Any = client.get("/.well-known/cimd")

    assert resp.status_code == 200, resp.text
    assert resp.json()["client_name"] == "Test AF Broker"
