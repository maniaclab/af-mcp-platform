"""Tests for GET /v1/x509/preflight (the portal's "Grid Certificates" checklist).

The route is a thin authenticated proxy: it resolves the caller's x509
``identity_providers`` entry (per-target, same resolution as the other
/v1/x509 routes), self-mints a broker-issued JWT via the entry's
``VomsTokenServiceClient``, calls the service's
``GET /v1/preflight/{unixname}``, and passes the JSON body through verbatim
— the checklist shape is voms-token-service's contract, not the broker's.

Status mapping: 404 when no x509 target is configured (or the caller has no
POSIX identity to preflight for), 502 when the service is unreachable/timing
out/erroring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from af_mcp_broker.credentials.errors import VomsServicePreflightError

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
            "detail": (
                "userkey.pem is 0644 but must be 0400 or 0600 (readable only "
                "by you). Fix: chmod 400 ~/.globus/userkey.pem"
            ),
            "required_modes": ["0400", "0600"],
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


def _use_preflight_client(
    client: TestClient, outcome: dict[str, Any] | Exception | None = None
) -> FakePreflightClient:
    """Point the app's default x509 provider at a scriptable fake voms-token-service client."""
    fake = FakePreflightClient(outcome)
    client.app.state.broker.x509_provider._voms_client = fake
    return fake


class TestPreflightRoute:
    def test_passes_the_service_body_through_verbatim(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, _ = app_client
        _use_preflight_client(client)

        resp = client.get("/v1/x509/preflight", headers=_AUTH)

        assert resp.status_code == 200, resp.text
        assert resp.json() == _PREFLIGHT_BODY

    def test_preflights_for_the_principals_unixname(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, _ = app_client
        fake = _use_preflight_client(client)

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
        fake = _use_preflight_client(client)
        state["principal"] = make_principal(uid=None, gid=None, unixname=None)

        resp = client.get("/v1/x509/preflight", headers=_AUTH)

        assert resp.status_code == 404, resp.text
        assert "POSIX" in resp.json()["detail"]
        assert fake.calls == []

    def test_502_when_the_service_is_unreachable(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, _ = app_client
        _use_preflight_client(
            client, VomsServicePreflightError("voms-token-service unreachable")
        )

        resp = client.get("/v1/x509/preflight", headers=_AUTH)

        assert resp.status_code == 502, resp.text

    def test_404_for_an_unknown_target(
        self, app_client: tuple[TestClient, dict]
    ) -> None:
        client, _ = app_client
        _use_preflight_client(client)

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
        services_file = tmp_path / "services.yaml"
        services_file.write_text(
            "services:\n"
            "  - name: rucio\n"
            "    prefix: rucio\n"
            "    url: http://rucio-mcp.invalid/mcp\n"
            "    auth_type: bearer\n"
            "    required_permission: read_data\n"
        )
        monkeypatch.setenv("SERVICES_FILE", str(services_file))
        monkeypatch.setenv("IDENTITY_PROVIDERS", "[]")

        with app_client_factory() as (client, _state):
            resp = client.get("/v1/x509/preflight", headers=_AUTH)

        assert resp.status_code == 404, resp.text
        assert "No x509 target is configured" in resp.json()["detail"]
