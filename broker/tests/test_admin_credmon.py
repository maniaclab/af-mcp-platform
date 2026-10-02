"""Tests for the credmon admin API -- GET /v1/admin/credmon and POST /v1/admin/credmon/sync (docs/credmon.md).

Both are admin-only. GET reports whether the integration is enabled and the
last sync cycle's status record (the same record on every replica, since
only the lease holder writes it); POST runs a cycle now, or 409s when
another replica holds the cycle lease. The sync service is injected on
``app.state.credmon_sync`` directly, the same way test_admin_api.py injects
its maintenance store.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from af_mcp_broker.credmon.state import InMemoryCredmonSyncState
from af_mcp_broker.credmon.storer import SyncReport
from af_mcp_broker.credmon.sync import CredmonSyncService


class _FakeStorer:
    kind_names: ClassVar[list[str]] = ["krb5"]

    def __init__(self) -> None:
        self.calls = 0

    async def run_once(self) -> SyncReport:
        self.calls += 1
        return SyncReport(
            started_at=1000.0,
            finished_at=1003.0,
            stored={"krb5": 2},
            failed={"krb5": 1},
            errors=["krb5: store failed for alice: denied"],
        )


@pytest.fixture
def credmon_client(app_client_factory, monkeypatch, make_principal):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):
        sync_state = InMemoryCredmonSyncState()
        storer = _FakeStorer()
        client.app.state.credmon_sync = CredmonSyncService(
            storer=storer,  # type: ignore[arg-type]
            state=sync_state,
            holder="broker-pod-a",
            interval_seconds=14400.0,
            lease_ttl_seconds=600.0,
            poll_seconds=60.0,
        )
        state["principal"] = make_principal(groups=["af-admins"], subject="admin-sub")
        yield client, state, sync_state, storer


def test_get_requires_admin(credmon_client, make_principal) -> None:
    client, state, _, _ = credmon_client
    state["principal"] = make_principal(groups=["users"])

    assert client.get("/v1/admin/credmon").status_code == 403


def test_get_reports_disabled_when_not_configured(
    app_client_factory, monkeypatch, make_principal
) -> None:
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["af-admins"])
        resp = client.get("/v1/admin/credmon")

    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False
    assert body["last_run"] is None


def test_get_before_first_cycle_has_no_last_run(credmon_client) -> None:
    client, _, _, _ = credmon_client

    body = client.get("/v1/admin/credmon").json()

    assert body["enabled"] is True
    assert body["interval_seconds"] == 14400.0
    assert body["last_run"] is None


def test_post_sync_runs_a_cycle_and_get_shows_it(credmon_client) -> None:
    client, _, _, storer = credmon_client

    post = client.post("/v1/admin/credmon/sync")

    assert post.status_code == 200, post.text
    assert storer.calls == 1
    run = client.get("/v1/admin/credmon").json()["last_run"]
    assert run["outcome"] == "partial"
    assert run["trigger"] == "manual"
    assert run["holder"] == "broker-pod-a"
    assert run["stored"] == {"krb5": 2}
    assert run["failed"] == {"krb5": 1}
    assert run["errors"] == ["krb5: store failed for alice: denied"]
    assert run["last_success_at"] == 1003.0


def test_post_sync_requires_admin(credmon_client, make_principal) -> None:
    client, state, _, storer = credmon_client
    state["principal"] = make_principal(groups=["users"])

    assert client.post("/v1/admin/credmon/sync").status_code == 403
    assert storer.calls == 0


async def test_post_sync_is_409_while_another_replica_holds_the_lease(
    credmon_client,
) -> None:
    client, _, sync_state, storer = credmon_client
    await sync_state.try_acquire_lease("broker-pod-b", ttl_seconds=600.0, now=1e12)

    resp = client.post("/v1/admin/credmon/sync")

    assert resp.status_code == 409
    assert storer.calls == 0


def test_post_sync_is_404_when_not_configured(
    app_client_factory, monkeypatch, make_principal
) -> None:
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["af-admins"])
        resp = client.post("/v1/admin/credmon/sync")

    assert resp.status_code == 404
