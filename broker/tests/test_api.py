from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import pytest
from cryptography.fernet import Fernet

if TYPE_CHECKING:
    from collections.abc import Callable

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
    servers = {s["name"]: s for s in resp.json()["servers"]}
    # __authenticated__ holds read_metadata/read_monitoring but not read_data.
    # Every registered backend is still listed (issue #123: hiding a
    # capability-gated backend entirely left the portal unable to say *why*
    # it has no tools) -- rucio (read_data) now appears flagged
    # "capability_required" rather than being omitted.
    assert "docs" in servers
    assert servers["docs"]["status"] == "available"
    assert "ami" in servers
    assert servers["ami"]["status"] == "available"
    assert "rucio" in servers
    assert servers["rucio"]["status"] == "capability_required"
    # panda isn't in the shipped backends.yaml at all -- absent regardless.
    assert "panda" not in servers


def test_catalog_server_carries_display_metadata(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """Each server exposes display_name/description/auth_type from
    backends.yaml. Per-server tool enumeration is deliberately NOT part of
    the catalog payload — it lives at GET /v1/catalog/{backend}/tools (see
    test_catalog_tools.py), fetched on demand per backend."""
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
    assert "tools" not in rucio


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


# ---------------------------------------------------------------------------
# Per-backend availability status (issue #123) -- a machine-readable `status`
# plus a short human `status_detail`, so the portal's MCP Servers page can
# say *why* a backend contributes no tools instead of showing an
# unexplained empty list.
# ---------------------------------------------------------------------------


def test_catalog_status_available_for_open_backend(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """ "docs" opts into "__none__" (no capability gate) and auth_type "none"
    (no credential needed) -- always "available"."""
    client, state = app_client
    state["principal"] = make_principal(groups=[])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    docs = {s["name"]: s for s in resp.json()["servers"]}["docs"]
    assert docs["status"] == "available"
    assert docs["status_detail"]
    assert docs["correlation_id"] is None


def test_catalog_status_link_required_when_not_linked(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """ "rucio" needs read_data (held by "atlas") and a linked atlas-oidc
    identity; the default test principal isn't linked (OIDCProvider.
    is_linked() probes an unreachable issuer -- see test_credential_
    unlinked_provider_404), so the capability check passes but linkage
    doesn't -- "link_required", not "capability_required"."""
    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    rucio = {s["name"]: s for s in resp.json()["servers"]}["rucio"]
    assert rucio["status"] == "link_required"
    assert rucio["status_detail"]
    assert rucio["correlation_id"] is None


def test_catalog_status_available_when_capability_and_linked(
    app_client: tuple[TestClient, dict],
    make_principal: Callable[..., object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once linked (and entitled), "rucio" reports "available"."""
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _linked(self, principal) -> bool:
        return True

    monkeypatch.setattr(OIDCProvider, "is_linked", _linked)

    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    rucio = {s["name"]: s for s in resp.json()["servers"]}["rucio"]
    assert rucio["status"] == "available"
    assert rucio["correlation_id"] is None


def test_catalog_status_capability_required_includes_correlation_id(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """__authenticated__ lacks read_data -- "rucio" is flagged
    "capability_required" with a correlation id an admin can grep the audit
    log for, per issue #123's "never leak internals, but let an admin trace
    it" constraint."""
    client, state = app_client
    state["principal"] = make_principal(groups=[])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    rucio = {s["name"]: s for s in resp.json()["servers"]}["rucio"]
    assert rucio["status"] == "capability_required"
    assert rucio["status_detail"]
    assert rucio["correlation_id"]


def test_catalog_status_detail_names_the_diagnostic_tools(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """Close the loop (issue #153): both the "link_required" and
    "capability_required" status_detail sentences name the af_* diagnostic
    tool a model should call next, not just a human-facing instruction."""
    from af_mcp_broker.mcp.registry import LIST_IDENTITIES_TOOL_NAME, WHOAMI_TOOL_NAME

    client, state = app_client

    state["principal"] = make_principal(groups=["atlas"])
    resp = client.get("/v1/catalog", headers=_AUTH)
    rucio = {s["name"]: s for s in resp.json()["servers"]}["rucio"]
    assert rucio["status"] == "link_required"
    assert LIST_IDENTITIES_TOOL_NAME in rucio["status_detail"]

    state["principal"] = make_principal(groups=[])
    resp = client.get("/v1/catalog", headers=_AUTH)
    rucio = {s["name"]: s for s in resp.json()["servers"]}["rucio"]
    assert rucio["status"] == "capability_required"
    assert WHOAMI_TOOL_NAME in rucio["status_detail"]


def test_catalog_status_misconfigured_when_no_credential_provider_resolves(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """A backend that omits required_capability (credential layer is the
    gate -- issue #60) but has no credential provider resolving for it is a
    genuine platform misconfiguration, not a transient failure -- flagged
    "misconfigured" with a correlation id. (app.py's startup check normally
    refuses to boot with this config at all; registering it directly on an
    already-booted registry, as other tests here do for "panda"/"gitlab",
    exercises the defensive path.)"""
    from af_mcp_broker.app import app
    from af_mcp_broker.mcp.registry import BackendSpec

    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"])
    app.state.backend_registry.register(
        BackendSpec(
            name="orphan",
            prefix="orphan",
            url="http://orphan-mcp.mcp.svc.cluster.local/mcp",
            transport="http",
            auth_type="bearer",
        )
    )
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    orphan = {s["name"]: s for s in resp.json()["servers"]}["orphan"]
    assert orphan["status"] == "misconfigured"
    assert orphan["status_detail"]
    assert orphan["correlation_id"]


def test_catalog_status_unavailable_when_recent_list_failure_recorded(
    app_client: tuple[TestClient, dict],
    make_principal: Callable[..., object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recent tools/list failure the aggregator classified as "unavailable"
    (BackendRegistry.record_list_failure -- see aggregator.py's
    _ObservableProxyProvider) downgrades an otherwise-available backend to
    "unavailable" without an extra live probe."""
    from af_mcp_broker.app import app
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _linked(self, principal) -> bool:
        return True

    monkeypatch.setattr(OIDCProvider, "is_linked", _linked)
    app.state.backend_registry.record_list_failure("rucio", "unavailable")

    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    rucio = {s["name"]: s for s in resp.json()["servers"]}["rucio"]
    assert rucio["status"] == "unavailable"
    assert rucio["correlation_id"] is None


def test_catalog_status_unauthorized_failure_prompts_relink(
    app_client: tuple[TestClient, dict],
    make_principal: Callable[..., object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recorded "unauthorized" listing failure (the stored credential
    itself was rejected -- see aggregator.py's _classify_list_failure) means
    the user needs to re-link, not wait out a transient outage -- reported
    as "link_required", same actionable status as never having linked."""
    from af_mcp_broker.app import app
    from af_mcp_broker.credentials.oidc import OIDCProvider

    async def _linked(self, principal) -> bool:
        return True

    monkeypatch.setattr(OIDCProvider, "is_linked", _linked)
    app.state.backend_registry.record_list_failure("rucio", "unauthorized")

    client, state = app_client
    state["principal"] = make_principal(groups=["atlas"])
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    rucio = {s["name"]: s for s in resp.json()["servers"]}["rucio"]
    assert rucio["status"] == "link_required"


@pytest.mark.parametrize(
    ("required_capability", "groups", "expected_status"),
    [
        # Omitted (None) -- no capability gate, credential layer is the sole
        # gate (issue #60); auth_type "none" below means that gate is a
        # no-op too, so this reports "available" regardless of groups.
        (None, [], "available"),
        # "__none__" -- the explicit open-access opt-in; same as above.
        ("__none__", [], "available"),
        # An explicit capability the principal holds.
        ("read_data", ["atlas"], "available"),
        # An explicit capability the principal lacks.
        ("read_data", [], "capability_required"),
    ],
)
def test_catalog_status_required_capability_forms(
    app_client: tuple[TestClient, dict],
    make_principal: Callable[..., object],
    required_capability: str | None,
    groups: list[str],
    expected_status: str,
) -> None:
    """All three `required_capability` forms (declared / "__none__" /
    omitted) must be handled by the status derivation, not just the
    declared-string form (issue #127 made backends.yaml authoritative for
    all three)."""
    from af_mcp_broker.app import app
    from af_mcp_broker.mcp.registry import BackendSpec

    client, state = app_client
    state["principal"] = make_principal(groups=groups)
    app.state.backend_registry.register(
        BackendSpec(
            name="capform",
            prefix="capform",
            url="http://capform-mcp.mcp.svc.cluster.local/mcp",
            transport="http",
            required_capability=required_capability,
            auth_type="none",
        )
    )
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    capform = {s["name"]: s for s in resp.json()["servers"]}["capform"]
    assert capform["status"] == expected_status


def test_catalog_status_never_leaks_urls_or_upstream_errors(
    app_client: tuple[TestClient, dict], make_principal: Callable[..., object]
) -> None:
    """Across every status (capability_required, link_required,
    misconfigured, available), the catalog response must never carry a
    backend URL, an upstream error body, policy internals, or a group list
    -- issue #123's "never leak internals" constraint."""
    from af_mcp_broker.app import app
    from af_mcp_broker.mcp.registry import BackendSpec

    client, state = app_client
    state["principal"] = make_principal(groups=[])
    app.state.backend_registry.register(
        BackendSpec(
            name="orphan",
            prefix="orphan",
            url="http://orphan-mcp.mcp.svc.cluster.local/mcp",
            transport="http",
            auth_type="bearer",
        )
    )
    resp = client.get("/v1/catalog", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    body = json.dumps(resp.json()["servers"])
    assert "http://" not in body
    assert "https://" not in body
    assert "af-atlas-users" not in body


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
                },
                # This override replaces conftest's default entirely, but
                # the shipped backends.yaml's "ami" (auth_type: x509) still
                # needs an explicit entry or the broker refuses to start.
                {
                    "type": "x509",
                    "alias": "x509",
                    "targets": ["ami"],
                },
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
