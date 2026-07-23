"""Tests for GET /v1/identities' linked_accounts.

linked_accounts used to be built from JWT claims (principal.iam_sub/cern_sub)
that Keycloak was not actually populating — a verified-working
/broker/atlas-oidc/token call could retrieve a real ATLAS IAM token for a
user whose principal.iam_sub was None. These tests exercise the replacement:
probing OIDCProvider.is_linked() so the response reflects reality.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test"}


def test_linked_accounts_reflects_is_linked_true(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _linked(self, principal) -> bool:
        return True

    monkeypatch.setattr(OIDCProvider, "is_linked", _linked)

    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    linked_providers = {a["provider"] for a in body["linked_accounts"]}
    assert linked_providers == {"atlas-iam"}
    available_providers = {p["provider"] for p in body["available_providers"]}
    assert available_providers == {"cern"}


def test_linked_accounts_empty_when_not_linked(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _not_linked(self, principal) -> bool:
        return False

    monkeypatch.setattr(OIDCProvider, "is_linked", _not_linked)

    client, _ = app_client
    resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["linked_accounts"] == []
    available_providers = {p["provider"] for p in body["available_providers"]}
    assert available_providers == {"atlas-iam", "cern"}


def test_linked_accounts_probes_not_jwt_claims(
    app_client_factory: Callable[..., object], make_principal: Callable[..., object]
) -> None:
    """A principal has no JWT-derived sub claim to carry any more (the fields
    were removed from Principal entirely) — linked_accounts must still be
    accurate, built purely from the is_linked() probe."""
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _linked(self, principal) -> bool:
        return True

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(OIDCProvider, "is_linked", _linked)
        with app_client_factory() as (client, state):
            state["principal"] = make_principal(groups=[])
            resp = client.get("/v1/identities", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["linked_accounts"] == [{"provider": "atlas-iam", "sub": ""}]
