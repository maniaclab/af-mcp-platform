"""Tests for the admin PAT endpoints -- GET/DELETE /v1/admin/tokens (issue #336).

An admin can list and revoke another principal's PATs; revocation goes
through the same registry path as an owner's own, so it takes effect on the
owner's next request.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from af_mcp_broker.api import tokens as tokens_api

if TYPE_CHECKING:
    from af_mcp_broker.audit import AuditRecord

_ADMIN_SUB = "admin-sub"
_OWNER_SUB = "owner-sub"
_OTHER_SUB = "other-sub"


@pytest.fixture
def admin_tokens(app_client_factory, make_principal, monkeypatch):
    """Yield ``(client, as_principal)``; ``as_principal(sub, admin=False)`` switches the caller."""
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):

        def as_principal(subject: str, *, admin: bool = False) -> None:
            groups = ["atlas", "af-admins"] if admin else ["atlas"]
            state["principal"] = make_principal(
                subject=subject, uid=1000, groups=groups
            )

        yield client, as_principal


@pytest.fixture
def audited(monkeypatch: pytest.MonkeyPatch) -> list[AuditRecord]:
    records: list[AuditRecord] = []

    async def _capture(record: AuditRecord) -> None:
        records.append(record)

    monkeypatch.setattr(tokens_api, "write_audit", _capture)
    return records


def _mint_as(client, as_principal, subject: str, name: str) -> str:
    as_principal(subject)
    resp = client.post("/v1/tokens", json={"name": name})
    assert resp.status_code == 200, resp.text
    return resp.json()["lookup_id"]


def _listed(client, as_principal, subject: str) -> dict[str, dict]:
    as_principal(subject)
    return {r["lookup_id"]: r for r in client.get("/v1/tokens").json()}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", f"/v1/admin/tokens?subject={_OWNER_SUB}"),
        ("DELETE", "/v1/admin/tokens/some-lookup-id"),
        ("DELETE", f"/v1/admin/tokens?subject={_OWNER_SUB}"),
    ],
)
def test_non_admin_is_403(admin_tokens, method: str, path: str) -> None:
    client, as_principal = admin_tokens
    lookup_id = _mint_as(client, as_principal, _OWNER_SUB, "victim")
    as_principal(_OTHER_SUB)

    resp = client.request(method, path)

    assert resp.status_code == 403, resp.text
    assert _listed(client, as_principal, _OWNER_SUB)[lookup_id]["revoked_at"] is None


def test_admin_lists_another_principals_tokens(admin_tokens) -> None:
    client, as_principal = admin_tokens
    revoked = _mint_as(client, as_principal, _OWNER_SUB, "old")
    active = _mint_as(client, as_principal, _OWNER_SUB, "current")
    client.delete(f"/v1/tokens/{revoked}")
    _mint_as(client, as_principal, _OTHER_SUB, "not-listed")

    as_principal(_ADMIN_SUB, admin=True)
    resp = client.get(f"/v1/admin/tokens?subject={_OWNER_SUB}")

    assert resp.status_code == 200, resp.text
    rows = {r["lookup_id"]: r for r in resp.json()}
    assert set(rows) == {revoked, active}
    assert rows[active]["name"] == "current"
    assert rows[active]["revoked_at"] is None
    assert rows[revoked]["revoked_at"] is not None
    assert {"created_at", "expires_at", "last_used_at"} <= set(rows[active])


def test_admin_list_for_unknown_subject_is_empty(admin_tokens) -> None:
    client, as_principal = admin_tokens
    as_principal(_ADMIN_SUB, admin=True)

    resp = client.get("/v1/admin/tokens?subject=nobody")

    assert resp.status_code == 200, resp.text
    assert resp.json() == []


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_subject_is_required_on_the_collection(admin_tokens, method: str) -> None:
    client, as_principal = admin_tokens
    as_principal(_ADMIN_SUB, admin=True)

    assert client.request(method, "/v1/admin/tokens").status_code == 422


def test_admin_revokes_one_token_of_another_principal(
    admin_tokens, audited: list[AuditRecord]
) -> None:
    client, as_principal = admin_tokens
    target = _mint_as(client, as_principal, _OWNER_SUB, "target")
    sibling = _mint_as(client, as_principal, _OWNER_SUB, "sibling")
    audited.clear()

    as_principal(_ADMIN_SUB, admin=True)
    resp = client.delete(f"/v1/admin/tokens/{target}")

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"lookup_id": target, "revoked": True}
    rows = _listed(client, as_principal, _OWNER_SUB)
    assert rows[target]["revoked_at"] is not None
    assert rows[sibling]["revoked_at"] is None
    [event] = audited
    assert event.action == "token.revoked"
    assert event.principal_sub == _ADMIN_SUB
    assert event.request_id == target
    assert f"subject={_OWNER_SUB}" in event.args_summary


def test_admin_revoke_of_unknown_token_is_404(admin_tokens) -> None:
    client, as_principal = admin_tokens
    as_principal(_ADMIN_SUB, admin=True)

    assert client.delete("/v1/admin/tokens/does-not-exist").status_code == 404


def test_admin_revokes_all_active_tokens_of_a_principal(
    admin_tokens, audited: list[AuditRecord]
) -> None:
    client, as_principal = admin_tokens
    first = _mint_as(client, as_principal, _OWNER_SUB, "first")
    second = _mint_as(client, as_principal, _OWNER_SUB, "second")
    already = _mint_as(client, as_principal, _OWNER_SUB, "already-revoked")
    client.delete(f"/v1/tokens/{already}")
    bystander = _mint_as(client, as_principal, _OTHER_SUB, "bystander")
    audited.clear()

    as_principal(_ADMIN_SUB, admin=True)
    resp = client.delete(f"/v1/admin/tokens?subject={_OWNER_SUB}")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["subject"] == _OWNER_SUB
    assert sorted(body["revoked"]) == sorted([first, second])
    rows = _listed(client, as_principal, _OWNER_SUB)
    assert rows[first]["revoked_at"] is not None
    assert rows[second]["revoked_at"] is not None
    assert _listed(client, as_principal, _OTHER_SUB)[bystander]["revoked_at"] is None
    assert sorted(e.request_id for e in audited) == sorted([first, second])
    assert {e.action for e in audited} == {"token.revoked"}
    assert {e.principal_sub for e in audited} == {_ADMIN_SUB}
    assert all(f"subject={_OWNER_SUB}" in e.args_summary for e in audited)


def test_admin_revoke_all_for_principal_without_tokens_revokes_nothing(
    admin_tokens, audited: list[AuditRecord]
) -> None:
    client, as_principal = admin_tokens
    as_principal(_ADMIN_SUB, admin=True)

    resp = client.delete("/v1/admin/tokens?subject=nobody")

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"subject": "nobody", "revoked": []}
    assert audited == []


def test_admin_can_revoke_their_own_tokens_through_the_admin_routes(
    admin_tokens,
) -> None:
    client, as_principal = admin_tokens
    mine = _mint_as(client, as_principal, _ADMIN_SUB, "mine")
    as_principal(_ADMIN_SUB, admin=True)

    assert client.delete(f"/v1/admin/tokens/{mine}").status_code == 200
