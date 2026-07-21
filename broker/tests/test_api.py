from __future__ import annotations

from collections.abc import Callable

from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test"}


def test_authorize_atlas_rucio_allow(app_client: tuple[TestClient, dict]) -> None:
    client, _ = app_client
    resp = client.post(
        "/v1/authorize",
        json={
            "capability": "read_data",
            "target": "rucio",
            "action": "rucio_list_dids",
        },
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
    resp = client.post(
        "/v1/authorize",
        json={"capability": "submit_jobs", "target": "panda", "action": "submit_task"},
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
    resp = client.post(
        "/v1/authorize",
        json={"capability": "submit_jobs", "target": "panda", "action": "submit_task"},
        headers=_AUTH,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["allow"] is False


def test_catalog_reflects_capabilities(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    client, state = app_client
    state["principal"] = make_principal(groups=[])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    backends = {t["backend"] for t in resp.json()["tools"]}
    # __authenticated__ sees open + read_metadata/read_monitoring backends,
    # but not rucio (read_data) or panda (submit_jobs).
    assert "docs" in backends
    assert "ami" in backends
    assert "rucio" not in backends
    assert "panda" not in backends


def test_credential_unknown_target_404(app_client: tuple[TestClient, dict]) -> None:
    client, _ = app_client
    resp = client.post(
        "/v1/credential", json={"target": "no-such-target"}, headers=_AUTH
    )
    assert resp.status_code == 404, resp.text


def test_credential_x509_needs_unlock_409(app_client: tuple[TestClient, dict]) -> None:
    client, _ = app_client
    # ami is x509; with an empty cache and no passphrase the provider raises
    # NeedsUnlock, which the endpoint maps to 409 + unlock_endpoint.
    resp = client.post("/v1/credential", json={"target": "ami"}, headers=_AUTH)
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "proxy_unlock_required"
    assert detail["unlock_endpoint"] == "/v1/x509/proxy"
