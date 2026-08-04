from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet

if TYPE_CHECKING:
    from collections.abc import Callable

    import pytest
    from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test"}


def _register_panda_backend(client: TestClient) -> None:
    """panda isn't in the shipped backends.yaml -- register it directly on
    the booted app's registry the same way test_catalog_action_type_reflects_
    target_action_type_overrides does for gitlab, so /v1/authorize (which now
    derives the required capability from the registry, not the request body
    -- issue #60) has a real backend to look up."""
    from af_mcp_broker.mcp.registry import BackendSpec

    client.app.state.backend_registry.register(
        BackendSpec(
            name="panda",
            prefix="panda",
            url="http://panda-mcp.mcp.svc.cluster.local/mcp",
            transport="http",
            required_capability="submit_jobs",
            auth_type="none",
        )
    )


def test_authorize_atlas_rucio_allow(app_client: tuple[TestClient, dict]) -> None:
    client, _ = app_client
    resp = client.post(
        "/v1/authorize",
        json={"target": "rucio", "action": "rucio_list_dids"},
        headers=_AUTH,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["allow"] is True
    assert body["action_type"] == "read"


def test_authorize_panda_submit_state_change(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"])
    _register_panda_backend(client)
    resp = client.post(
        "/v1/authorize",
        json={"target": "panda", "action": "submit_task"},
        headers=_AUTH,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["allow"] is True
    assert body["action_type"] == "state_change"


def test_authorize_no_groups_denied_panda(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    client, state = app_client
    state["principal"] = make_principal(groups=[])
    _register_panda_backend(client)
    resp = client.post(
        "/v1/authorize",
        json={"target": "panda", "action": "submit_task"},
        headers=_AUTH,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["allow"] is False


def test_authorize_unregistered_target_denied_without_leaking_internals(
    app_client: tuple[TestClient, dict],
) -> None:
    """A target absent from the backend registry must be denied cleanly --
    and the response must not be confused with a capability-based denial."""
    client, _ = app_client
    resp = client.post(
        "/v1/authorize",
        json={"target": "no-such-target", "action": "whatever"},
        headers=_AUTH,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["allow"] is False
    assert "no-such-target" in body["reason"]


def test_authorize_ignores_client_supplied_capability(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """The required capability is derived server-side from the registry
    (rucio -> read_data), not trusted from the request body -- a caller
    claiming an unrelated/higher capability for the same target must not
    change the outcome (issue #60)."""
    client, state = app_client
    state["principal"] = make_principal(groups=[])
    resp = client.post(
        "/v1/authorize",
        json={
            "target": "rucio",
            "action": "rucio_list_dids",
            "capability": "admin",
        },
        headers=_AUTH,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # __authenticated__ (no groups) lacks read_data -> denied, regardless of
    # the bogus "admin" capability the request body claimed.
    assert body["allow"] is False


def test_catalog_reflects_capabilities(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    client, state = app_client
    state["principal"] = make_principal(groups=[])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    servers = {s["name"] for s in resp.json()["servers"]}
    # __authenticated__ sees open + read_metadata/read_monitoring backends,
    # but not rucio (read_data) or panda (submit_jobs).
    assert "docs" in servers
    assert "ami" in servers
    assert "rucio" not in servers
    assert "panda" not in servers


def test_catalog_server_carries_display_metadata(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """Each server exposes display_name/description/auth_type from
    backends.yaml plus an (initially empty) tools placeholder — see #58 for
    populating it once the /mcp aggregator can enumerate real subtools."""
    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    servers = {s["name"]: s for s in resp.json()["servers"]}
    rucio = servers["rucio"]
    assert rucio["display_name"]
    assert rucio["description"]
    assert rucio["auth_type"] == "bearer"
    assert rucio["capability"] == "read_data"
    assert rucio["tools"] == []


def test_catalog_credential_provider_reflects_target_to_alias(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """credential_provider rides the identity<->backend join built at
    startup (issue #90): keycloak-brokered/oauth21-direct targets report
    their configured alias, x509 targets report the synthetic "x509" alias,
    and auth_type "none" backends report null (no user credential needed).
    """
    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    servers = {s["name"]: s for s in resp.json()["servers"]}
    # conftest's default identity_providers entry ("atlas-oidc") targets rucio.
    assert servers["rucio"]["credential_provider"] == "atlas-oidc"
    assert servers["ami"]["credential_provider"] == "x509"
    assert servers["atlasopenmagic"]["credential_provider"] is None
    assert servers["docs"]["credential_provider"] is None


def test_catalog_never_exposes_backend_url(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    assert "url" not in json.dumps(resp.json()["servers"])


def test_catalog_action_type_reflects_target_action_type_overrides(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """A backend whose capability defaults to "read" but whose
    target_action_types glob overrides include a "state_change" pattern
    (e.g. the shipped policy.yaml's gitlab entry) must report the
    server-level badge as "state_change" — the rollup rule for issue #89:
    any state-changing tool taints the whole server's badge until #58 lands
    per-tool enumeration.
    """
    from af_mcp_broker.app import app
    from af_mcp_broker.mcp.registry import BackendSpec

    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"])
    app.state.backend_registry.register(
        BackendSpec(
            name="gitlab",
            prefix="gitlab",
            url="http://gitlab-mcp.mcp.svc.cluster.local/mcp",
            transport="http",
            required_capability="read_gitlab",
            auth_type="bearer",
        )
    )
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    servers = {s["name"]: s for s in resp.json()["servers"]}
    assert servers["gitlab"]["action_type"] == "state_change"


def test_catalog_credential_provider_oauth21_direct(
    monkeypatch: pytest.MonkeyPatch, app_client_factory: Callable[..., object]
) -> None:
    """credential_provider surfaces oauth21-direct aliases too, not just
    keycloak-brokered ones (issue #90)."""
    monkeypatch.setenv("BROKER_STATE_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OAUTH21_CLIENT_ID", "https://mcp.example.com/.well-known/cimd")
    monkeypatch.setenv("BROKER_PUBLIC_ORIGIN", "https://mcp-portal.example.com")
    monkeypatch.setenv(
        "IDENTITY_PROVIDERS",
        json.dumps(
            [
                {
                    "type": "oauth21-direct",
                    "alias": "rucio-mcp-atlas",
                    "targets": ["rucio"],
                    "authorization_endpoint": "https://backend-as.example/authorize",
                    "token_endpoint": "https://backend-as.example/token",
                    "issuer": "https://backend-as.example",
                }
            ]
        ),
    )
    with app_client_factory() as (client, _state):
        resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    servers = {s["name"]: s for s in resp.json()["servers"]}
    assert servers["rucio"]["credential_provider"] == "rucio-mcp-atlas"


def test_credential_unknown_target_404(app_client: tuple[TestClient, dict]) -> None:
    client, _ = app_client
    resp = client.post(
        "/v1/credential", json={"target": "no-such-target"}, headers=_AUTH
    )
    assert resp.status_code == 404, resp.text


def test_credential_x509_needs_unlock_409(app_client: tuple[TestClient, dict]) -> None:
    client, _ = app_client
    # ami is x509; the app_client fixture pre-creates a fake usercert/userkey
    # pair so is_linked() reports True. With an empty cache and no passphrase
    # the provider then raises NeedsUnlock, which the endpoint maps to 409 +
    # unlock_endpoint.
    resp = client.post("/v1/credential", json={"target": "ami"}, headers=_AUTH)
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "proxy_unlock_required"
    assert detail["unlock_endpoint"] == "/v1/x509/proxy"


def test_credential_unlinked_provider_404(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A provider whose is_linked() reports False must 404 before issue()."""
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _not_linked(self, principal) -> bool:
        return False

    monkeypatch.setattr(OIDCProvider, "is_linked", _not_linked)

    client, _ = app_client
    resp = client.post("/v1/credential", json={"target": "rucio"}, headers=_AUTH)

    assert resp.status_code == 404, resp.text
    detail = resp.json()["detail"]
    assert "OIDCProvider not linked" in detail
    assert "Visit the portal Identities page to connect it." in detail


def test_credential_linked_provider_proceeds_to_issue(
    app_client: tuple[TestClient, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A provider whose is_linked() reports True must reach issue()."""
    from af_mcp_broker.credentials.base import CredentialKind, IssuedCredential
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _linked(self, principal) -> bool:
        return True

    async def _fake_issue(
        self,
        principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase=None,
    ) -> IssuedCredential:
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.BEARER,
            expires_at=time.time() + 3600,
            payload={"access_token": "fake-iam-token", "token_type": "Bearer"},
            audit_id="test-audit",
            source="test",
            execution_model=self.execution_model,
        )

    monkeypatch.setattr(OIDCProvider, "is_linked", _linked)
    monkeypatch.setattr(OIDCProvider, "issue", _fake_issue)

    client, _ = app_client
    resp = client.post("/v1/credential", json={"target": "rucio"}, headers=_AUTH)

    assert resp.status_code == 200, resp.text
    assert resp.json()["token"] == "fake-iam-token"
