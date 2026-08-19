"""Tests for GET /v1/x509/preflight (the portal's "Grid Certificates" checklist).

The route is a thin authenticated proxy: it resolves the caller's x509
``identity_providers`` entry (per-target, same resolution as the other
/v1/x509 routes), self-mints a broker-issued JWT via the entry's
``VomsTokenServiceClient``, calls the service's
``GET /v1/preflight/{unixname}``, and passes the JSON body through verbatim
— the checklist shape is voms-token-service's contract, not the broker's.

Status mapping: 404 when no x509 target is configured (or the caller has no
POSIX identity to preflight for), 501 for a legacy entry (no service_url —
there is no service to ask), 502 when the service is unreachable/timing
out/erroring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from test_x509_service_mode import FakeX509Store

from af_mcp_broker.credentials.voms_service import VomsServicePreflightError

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest
    from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test"}

_PREFLIGHT_BODY = {
    "unixname": "tuser",
    "root": "/home/tuser/.globus",
    "ok": False,
    "checks": [
        {
            "name": "globus_dir",
            "path": "/home/tuser/.globus",
            "exists": True,
            "ok": True,
        },
        {
            "name": "userkey",
            "path": "/home/tuser/.globus/userkey.pem",
            "exists": True,
            "mode": "0644",
            "readable_by_service": True,
            "ok": False,
            "detail": "run: chmod 400 ~/.globus/userkey.pem",
        },
    ],
}


class FakePreflightClient:
    """Recording fake for ``VomsTokenServiceClient.preflight``.

    ``outcome`` is the dict to pass through or an exception to raise; every
    call's kwargs are recorded in ``calls``.
    """

    def __init__(self, outcome: dict[str, Any] | Exception | None = None) -> None:
        self.outcome = outcome if outcome is not None else dict(_PREFLIGHT_BODY)
        self.calls: list[dict[str, Any]] = []

    async def preflight(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _enable_service_mode(
    client: TestClient, outcome: dict[str, Any] | Exception | None = None
) -> FakePreflightClient:
    """Flip the app's default legacy x509 provider into service mode with a scriptable fake client (same pattern as test_identities' service-mode test)."""
    fake = FakePreflightClient(outcome)
    provider = client.app.state.x509_provider
    provider._voms_client = fake
    provider._vault_store = FakeX509Store()
    assert provider.uses_voms_service is True
    return fake


class TestPreflightRoute:
    def test_passes_the_service_body_through_verbatim(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, _ = app_client
        _enable_service_mode(client)

        resp = client.get("/v1/x509/preflight", headers=_AUTH)

        assert resp.status_code == 200, resp.text
        assert resp.json() == _PREFLIGHT_BODY

    def test_preflights_for_the_principals_unixname(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, _ = app_client
        fake = _enable_service_mode(client)

        client.get("/v1/x509/preflight", headers=_AUTH)

        assert fake.calls == [{"subject": "sub-abc", "unixname": "tuser"}]

    def test_404_when_the_principal_has_no_posix_identity(
        self,
        app_client: tuple[TestClient, dict],
        make_principal: Callable[..., object],
    ) -> None:
        """No unixname means there is nothing to preflight — same actionable
        message as the mint path's PosixIdentityRequiredError."""
        client, state = app_client
        fake = _enable_service_mode(client)
        state["principal"] = make_principal(uid=None, gid=None, unixname=None)

        resp = client.get("/v1/x509/preflight", headers=_AUTH)

        assert resp.status_code == 404, resp.text
        assert "POSIX" in resp.json()["detail"]
        assert fake.calls == []

    def test_501_for_a_legacy_entry(self, app_client: tuple[TestClient, dict]) -> None:
        """conftest's default x509 entry has no service_url — there is no
        voms-token-service to ask, so the checklist cannot exist."""
        client, _ = app_client

        resp = client.get("/v1/x509/preflight", headers=_AUTH)

        assert resp.status_code == 501, resp.text
        assert "voms-token-service" in resp.json()["detail"]

    def test_502_when_the_service_is_unreachable(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, _ = app_client
        _enable_service_mode(
            client, VomsServicePreflightError("voms-token-service unreachable")
        )

        resp = client.get("/v1/x509/preflight", headers=_AUTH)

        assert resp.status_code == 502, resp.text

    def test_404_for_an_unknown_target(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, _ = app_client
        _enable_service_mode(client)

        resp = client.get(
            "/v1/x509/preflight", params={"target": "nope"}, headers=_AUTH
        )

        assert resp.status_code == 404, resp.text

    def test_404_when_no_x509_target_is_configured(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        app_client_factory: Callable[..., Any],
    ) -> None:
        """A deployment with no x509 providers at all answers 404, mirroring
        the other /v1/x509 routes' "No x509 target is configured"."""
        backends_file = tmp_path / "backends.yaml"
        backends_file.write_text(
            "backends:\n"
            "  - name: rucio\n"
            "    prefix: rucio\n"
            "    url: http://rucio-mcp.invalid/mcp\n"
            "    auth_type: bearer\n"
            "    required_capability: read_data\n"
        )
        monkeypatch.setenv("BACKENDS_FILE", str(backends_file))
        monkeypatch.setenv("IDENTITY_PROVIDERS", "[]")

        with app_client_factory() as (client, _state):
            resp = client.get("/v1/x509/preflight", headers=_AUTH)

        assert resp.status_code == 404, resp.text
        assert "No x509 target is configured" in resp.json()["detail"]
