"""Tests for ``GET /v1/admin/users`` -- admin search over the users the platform has seen.

The population is the usage store's subjects; profiles come from a
test-controlled ``UserProfileDirectory``.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
from broker_state_helpers import set_broker_state

from af_mcp_broker.audit import AuditRecord
from af_mcp_broker.principal_directory import (
    PrincipalNotFoundError,
    UserProfile,
    UserProfileDirectory,
)
from af_mcp_broker.user_search import UserSearch

_ADMIN_SUB = "admin-sub"


class _Profiles(UserProfileDirectory):
    def __init__(self, profiles: dict[str, UserProfile]) -> None:
        self.profiles = profiles
        self.calls: list[str] = []

    async def profile(self, principal_id: str) -> UserProfile:
        self.calls.append(principal_id)
        try:
            return self.profiles[principal_id]
        except KeyError:
            raise PrincipalNotFoundError(principal_id) from None


def _record(subject: str, timestamp: float) -> AuditRecord:
    fields: dict[str, Any] = {
        "subject": subject,
        "uid": 1000,
        "permission": "read_data",
        "target": "rucio",
        "action": "rucio_list_dids",
        "action_type": "read",
        "args_summary": "scope=...",
        "timestamp": timestamp,
        "request_id": f"req-{subject}",
        "mcp_service": "rucio",
        "outcome": "success",
        "duration_ms": 10.0,
        "result_bytes": 100,
        "result_tokens_est": 1000,
    }
    return AuditRecord(**fields)


@pytest.fixture
def users_client(app_client_factory, make_principal, monkeypatch):
    """Yield ``(client, as_principal, profiles)`` with three seen users, grace most recent."""
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    profiles = _Profiles(
        {
            "sub-ada": UserProfile("ada", None, "ada@example.org", "Ada Lovelace"),
            "sub-grace": UserProfile(
                "grace", "ghopper", "grace@example.org", "Grace Hopper"
            ),
            "sub-alan": UserProfile("alan", None, "alan@example.org", "Alan Turing"),
        }
    )
    with app_client_factory() as (client, state):
        set_broker_state(client.app, user_search=UserSearch(profiles))
        store = client.app.state.broker.usage_store
        now = time.time()

        async def _seed() -> None:
            await store.record(_record("sub-alan", now - 7200))
            await store.record(_record("sub-ada", now - 3600))
            await store.record(_record("sub-grace", now))

        asyncio.run(_seed())

        def as_principal(*, admin: bool, subject: str = _ADMIN_SUB) -> None:
            groups = ["atlas", "af-admins"] if admin else ["atlas"]
            state["principal"] = make_principal(
                subject=subject, uid=1000, groups=groups
            )

        as_principal(admin=True)
        yield client, as_principal, profiles


def test_non_admin_is_403(users_client) -> None:
    client, as_principal, profiles = users_client
    as_principal(admin=False)

    resp = client.get("/v1/admin/users", params={"search": "ada"})

    assert resp.status_code == 403, resp.text
    assert profiles.calls == []


def test_search_matches_name_username_and_email_most_recent_first(users_client) -> None:
    client, _, _ = users_client

    by_name = client.get("/v1/admin/users", params={"search": "lovelace"}).json()
    by_unixname = client.get("/v1/admin/users", params={"search": "GHOPPER"}).json()
    by_email = client.get("/v1/admin/users", params={"search": "example.org"}).json()

    assert [u["subject"] for u in by_name["users"]] == ["sub-ada"]
    assert [u["subject"] for u in by_unixname["users"]] == ["sub-grace"]
    assert [u["subject"] for u in by_email["users"]] == [
        "sub-grace",
        "sub-ada",
        "sub-alan",
    ]


def test_row_shape(users_client) -> None:
    client, _, _ = users_client

    body = client.get("/v1/admin/users", params={"search": "grace"}).json()

    (row,) = body["users"]
    assert row["subject"] == "sub-grace"
    assert row["username"] == "ghopper"
    assert row["email"] == "grace@example.org"
    assert row["display_name"] == "Grace Hopper"
    assert row["last_seen"]
    assert row["pat_count"] == 0
    assert body["more"] is False
    assert body["partial"] is False


def test_limit_truncates_and_reports_more(users_client) -> None:
    client, _, _ = users_client

    body = client.get(
        "/v1/admin/users", params={"search": "example", "limit": 2}
    ).json()

    assert len(body["users"]) == 2
    assert body["more"] is True


@pytest.mark.parametrize("limit", [0, 51])
def test_limit_is_bounded(users_client, limit: int) -> None:
    client, _, _ = users_client

    resp = client.get("/v1/admin/users", params={"limit": limit})

    assert resp.status_code == 422


def test_pat_count_is_active_tokens_only(users_client) -> None:
    client, as_principal, _ = users_client
    as_principal(admin=False, subject="sub-ada")
    lookup_ids = [
        client.post("/v1/tokens", json={"name": name}).json()["lookup_id"]
        for name in ("a", "b", "c")
    ]
    client.delete(f"/v1/tokens/{lookup_ids[0]}")

    as_principal(admin=True)
    body = client.get("/v1/admin/users", params={"search": "ada"}).json()

    assert [(u["subject"], u["pat_count"]) for u in body["users"]] == [("sub-ada", 2)]


def test_empty_search_lists_most_recently_seen(users_client) -> None:
    client, _, _ = users_client

    body = client.get("/v1/admin/users", params={"limit": 2}).json()

    assert [u["subject"] for u in body["users"]] == ["sub-grace", "sub-ada"]
    assert body["more"] is True
