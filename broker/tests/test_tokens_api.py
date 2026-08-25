"""Tests for POST/GET/DELETE /v1/tokens — broker-issued identity PAT bootstrap (issue #144 step 2a).

These exercise the real app through ``app_client``/``app_client_factory``
(see conftest.py). Unlike the RFC 8693 design this replaces, minting needs no
Keycloak call at all -- no fake HTTP client to install, no client-credential
env vars to set.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from af_mcp_broker.pat import PAT_PREFIX

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test"}

# A JWT looks like three base64url segments joined by dots. Used to assert
# list/detail payloads never carry a token-shaped string anywhere -- not
# just that the "token" key is absent.
_JWT_SHAPED = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _mint(
    client: TestClient,
    *,
    name: str | None = "claude-desktop",
    note: str | None = None,
    expires_in_days: int | None = None,
    never_expires: bool = False,
    capabilities: list[str] | None = None,
):
    body: dict = {}
    if name is not None:
        body["name"] = name
    if note is not None:
        body["note"] = note
    if expires_in_days is not None:
        body["expires_in_days"] = expires_in_days
    if never_expires:
        body["never_expires"] = True
    if capabilities is not None:
        body["capabilities"] = capabilities
    return client.post("/v1/tokens", json=body, headers=_AUTH)


def test_mint_happy_path(app_client: tuple[TestClient, dict]) -> None:
    client, _ = app_client
    resp = _mint(client, name="claude-desktop")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body["token"], str)
    assert body["token"].startswith(PAT_PREFIX)
    assert isinstance(body["lookup_id"], str)
    assert body["lookup_id"]
    assert body["name"] == "claude-desktop"
    assert "created_at" in body
    assert body["expires_at"] is not None


def test_mint_without_name_generates_a_default(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = _mint(client, name=None)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"].startswith("mcp-")
    assert body["lookup_id"][:8] in body["name"]


def test_mint_rejects_name_above_max_length(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = _mint(client, name="x" * 201)
    assert resp.status_code == 422, resp.text


def test_mint_duplicate_name_returns_409(app_client: tuple[TestClient, dict]) -> None:
    """`name` is a unique-per-principal identifier -- minting a second token
    with a name already in use by an active token for the same principal
    must fail clearly rather than silently creating two rows with the same
    displayed name."""
    client, _ = app_client
    first = _mint(client, name="claude-desktop")
    assert first.status_code == 200, first.text

    second = _mint(client, name="claude-desktop")
    assert second.status_code == 409, second.text
    assert "claude-desktop" in second.json()["detail"]


def test_mint_duplicate_name_is_case_insensitive(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    first = _mint(client, name="Claude-Desktop")
    assert first.status_code == 200, first.text

    second = _mint(client, name="claude-desktop")
    assert second.status_code == 409, second.text


def test_mint_duplicate_name_allowed_after_first_token_revoked(
    app_client: tuple[TestClient, dict],
) -> None:
    """Collisions with dead (revoked) tokens are allowed -- rejecting them
    would be confusing, since the old token can no longer be mistaken for
    the new one."""
    client, _ = app_client
    first = _mint(client, name="claude-desktop")
    lookup_id = first.json()["lookup_id"]
    revoke_resp = client.delete(f"/v1/tokens/{lookup_id}", headers=_AUTH)
    assert revoke_resp.status_code == 200, revoke_resp.text

    second = _mint(client, name="claude-desktop")
    assert second.status_code == 200, second.text


def test_mint_default_expiry_is_90_days(app_client: tuple[TestClient, dict]) -> None:
    import datetime as dt

    client, _ = app_client
    resp = _mint(client)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    expires_at = dt.datetime.fromisoformat(body["expires_at"])
    created_at = dt.datetime.fromisoformat(body["created_at"])
    delta_days = (expires_at - created_at).total_seconds() / 86400
    assert 89.9 < delta_days < 90.1


def test_mint_custom_expires_in_days(app_client: tuple[TestClient, dict]) -> None:
    import datetime as dt

    client, _ = app_client
    resp = _mint(client, expires_in_days=7)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    expires_at = dt.datetime.fromisoformat(body["expires_at"])
    created_at = dt.datetime.fromisoformat(body["created_at"])
    delta_days = (expires_at - created_at).total_seconds() / 86400
    assert 6.9 < delta_days < 7.1


def test_mint_never_expires_is_explicit_opt_in(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = _mint(client, never_expires=True)
    assert resp.status_code == 200, resp.text
    assert resp.json()["expires_at"] is None

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.json()[0]["expires_at"] is None


def test_mint_rejects_never_expires_and_expires_in_days_together(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = _mint(client, never_expires=True, expires_in_days=5)
    assert resp.status_code == 422, resp.text


def test_mint_rejects_expires_in_days_below_minimum(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = _mint(client, expires_in_days=0)
    assert resp.status_code == 422, resp.text


def test_mint_rejects_expires_in_days_above_maximum(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = _mint(client, expires_in_days=3651)
    assert resp.status_code == 422, resp.text


def test_mint_note_round_trips_through_list(
    app_client: tuple[TestClient, dict],
) -> None:
    """`note` (issue #116) is a free-text, purely self-descriptive field --
    not consumed by the broker, just stored and shown back."""
    client, _ = app_client
    mint_resp = _mint(client, name="claude-desktop", note="for the CI bot")
    assert mint_resp.status_code == 200, mint_resp.text
    assert mint_resp.json()["note"] == "for the CI bot"

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.status_code == 200, listed.text
    assert listed.json()[0]["note"] == "for the CI bot"


def test_mint_note_absent_by_default(app_client: tuple[TestClient, dict]) -> None:
    client, _ = app_client
    mint_resp = _mint(client, name="claude-desktop")
    assert mint_resp.status_code == 200, mint_resp.text
    assert mint_resp.json()["note"] is None

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.json()[0]["note"] is None


def test_mint_rejects_note_above_max_length(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    resp = _mint(client, note="x" * 257)
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# Capability PATs (issue #144 step 4). app_client_factory's default principal
# is in the "atlas" group, which the shipped policy.yaml maps to read_data,
# read_metadata, read_monitoring, submit_jobs, manage_jobs, launch_compute,
# manage_jupyter, read_files -- but never "admin" (that's af-admins only).
# ---------------------------------------------------------------------------


def test_mint_without_capabilities_returns_none_capability_grant(
    app_client: tuple[TestClient, dict],
) -> None:
    """Omitting `capabilities` (the default) mints an ordinary identity PAT
    -- capability_grant must be None, not an empty list, both in the mint
    response and the subsequent list."""
    client, _ = app_client
    mint_resp = _mint(client, name="claude-desktop")
    assert mint_resp.status_code == 200, mint_resp.text
    assert mint_resp.json()["capability_grant"] is None

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.json()[0]["capability_grant"] is None


def test_mint_with_capabilities_subset_of_current_succeeds(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _ = app_client
    mint_resp = _mint(client, name="ci-bot", capabilities=["read_data", "submit_jobs"])
    assert mint_resp.status_code == 200, mint_resp.text
    assert sorted(mint_resp.json()["capability_grant"]) == ["read_data", "submit_jobs"]

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert sorted(listed.json()[0]["capability_grant"]) == ["read_data", "submit_jobs"]


def test_mint_rejects_capability_the_caller_does_not_currently_hold(
    app_client: tuple[TestClient, dict],
) -> None:
    """ "admin" is not among atlas's group_capabilities -- requesting it must
    fail with a clear error naming it, and mint nothing at all."""
    client, _ = app_client
    resp = _mint(client, name="over-broad", capabilities=["read_data", "admin"])
    assert resp.status_code == 400, resp.text
    assert "admin" in resp.json()["detail"]
    # "read_data" is legitimately held -- it must not be named as offending.
    assert "read_data" not in resp.json()["detail"]

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.json() == []


def test_mint_empty_capabilities_list_mints_a_capability_pat_with_no_capabilities(
    app_client: tuple[TestClient, dict],
) -> None:
    """`capabilities: []` is a deliberate, if unusual, opt-in -- distinct
    from omitting the field entirely -- and must round-trip as an empty
    list, not None."""
    client, _ = app_client
    mint_resp = _mint(client, name="no-op-token", capabilities=[])
    assert mint_resp.status_code == 200, mint_resp.text
    assert mint_resp.json()["capability_grant"] == []


def test_mint_rate_limit_11th_call_429(app_client: tuple[TestClient, dict]) -> None:
    client, _ = app_client
    for i in range(10):
        resp = _mint(client, name=f"token-{i}")
        assert resp.status_code == 200, resp.text

    resp = _mint(client, name="eleventh")
    assert resp.status_code == 429, resp.text


def test_list_returns_own_tokens_only(
    app_client: tuple[TestClient, dict],
    make_principal: Callable[..., object],
) -> None:
    client, state = app_client
    mint_resp = _mint(client, name="mine")
    assert mint_resp.status_code == 200, mint_resp.text

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["name"] == "mine"
    assert "token" not in rows[0]  # never re-exposed

    # A different principal must never see the first user's tokens.
    state["principal"] = make_principal(
        uid=99999, groups=["atlas"], subject="sub-other"
    )
    listed_other = client.get("/v1/tokens", headers=_AUTH)
    assert listed_other.status_code == 200, listed_other.text
    assert listed_other.json() == []


def test_list_and_mint_responses_never_leak_a_jwt_shaped_string(
    app_client: tuple[TestClient, dict],
) -> None:
    """The registry never re-exposes anything a token could be
    reconstructed from. Scan the *raw* response bodies (not just specific
    keys) so a renamed or newly-added field can't silently smuggle a token
    value back out."""
    client, _ = app_client
    mint_resp = _mint(client, name="scan-me")
    assert mint_resp.status_code == 200, mint_resp.text
    minted_token = mint_resp.json()["token"]

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.status_code == 200, listed.text
    assert minted_token not in listed.text
    assert not _JWT_SHAPED.search(listed.text)

    lookup_id = mint_resp.json()["lookup_id"]
    revoke_resp = client.delete(f"/v1/tokens/{lookup_id}", headers=_AUTH)
    assert minted_token not in revoke_resp.text


def test_revoke_success_then_list_shows_revoked_row(
    app_client: tuple[TestClient, dict],
) -> None:
    """Revoking marks the row revoked rather than removing it (issue #115),
    so the portal can show a revoked/active/expired status."""
    client, _ = app_client
    mint_resp = _mint(client, name="to-revoke")
    lookup_id = mint_resp.json()["lookup_id"]

    revoke_resp = client.delete(f"/v1/tokens/{lookup_id}", headers=_AUTH)
    assert revoke_resp.status_code == 200, revoke_resp.text
    assert revoke_resp.json()["lookup_id"] == lookup_id
    assert revoke_resp.json()["revoked"] is True

    listed = client.get("/v1/tokens", headers=_AUTH)
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["lookup_id"] == lookup_id
    assert rows[0]["revoked_at"] is not None


def test_revoke_non_owned_lookup_id_403(
    app_client: tuple[TestClient, dict],
    make_principal: Callable[..., object],
) -> None:
    client, state = app_client
    mint_resp = _mint(client, name="owned-by-first-user")
    lookup_id = mint_resp.json()["lookup_id"]

    state["principal"] = make_principal(
        uid=99999, groups=["atlas"], subject="sub-other"
    )
    revoke_resp = client.delete(f"/v1/tokens/{lookup_id}", headers=_AUTH)
    assert revoke_resp.status_code == 403, revoke_resp.text


def test_revoke_unknown_lookup_id_404(app_client: tuple[TestClient, dict]) -> None:
    client, _ = app_client
    resp = client.delete("/v1/tokens/does-not-exist", headers=_AUTH)
    assert resp.status_code == 404, resp.text


def test_revoke_marks_lookup_id_in_the_apps_revoked_registry(
    app_client: tuple[TestClient, dict],
) -> None:
    """Confirms DELETE /v1/tokens/{lookup_id} actually reaches the same
    token_registry app.state wires into /mcp's PAT validation path --
    end-to-end enforcement itself (a revoked PAT rejecting a real request) is
    covered directly against pat_auth.resolve_pat_principal and
    test_mcp_middleware_identity.py."""
    from af_mcp_broker.app import app

    client, _ = app_client
    mint_resp = _mint(client, name="to-be-revoked")
    lookup_id = mint_resp.json()["lookup_id"]

    client.delete(f"/v1/tokens/{lookup_id}", headers=_AUTH)

    import asyncio

    revoked = asyncio.run(app.state.token_registry._backend.list_revoked_jtis())
    assert lookup_id in revoked


# ---------------------------------------------------------------------------
# /v1 stays Keycloak-JWT-only -- a PAT must never authenticate here (issue
# #144's security-load-bearing design point: a PAT minting further PATs
# would make a leaked credential self-renewing). keycloak_dependency is
# overridden by app_client_factory for every OTHER test in this module (so
# they can exercise the route logic without a real JWT) -- this test instead
# removes that override and asserts against the real dependency, since the
# whole point is proving a PAT-shaped bearer is rejected by the actual
# authentication path, not the test double.
# ---------------------------------------------------------------------------


def test_pat_is_rejected_on_v1(app_client: tuple[TestClient, dict]) -> None:
    import time

    from af_mcp_broker import identity
    from af_mcp_broker.app import app
    from af_mcp_broker.config import get_settings
    from af_mcp_broker.identity import keycloak_dependency

    client, _ = app_client
    mint_resp = _mint(client, name="for-v1-rejection-test")
    assert mint_resp.status_code == 200, mint_resp.text
    pat = mint_resp.json()["token"]

    # Prime the JWKS cache for the real Settings this app instance loaded
    # (app_client_factory points OIDC_ISSUER at an unreachable host) so
    # get_principal fails on "no key matches" rather than a network error --
    # the point of this test is that a PAT is rejected as an ordinary invalid
    # JWT, not that the JWKS endpoint happens to be unreachable in tests.
    settings = get_settings()
    identity._jwks_cache[settings.oidc_jwks_uri] = identity._JwksEntry(
        keys=[], fetched_at=time.monotonic()
    )

    # Remove app_client_factory's dependency_overrides so this request goes
    # through the REAL keycloak_dependency -- a PAT is not a valid JWT, so it
    # must be rejected by ordinary JWT decoding, not by any PAT-aware logic
    # (there is none on /v1).
    saved = app.dependency_overrides.pop(keycloak_dependency, None)
    try:
        resp = client.get("/v1/tokens", headers={"Authorization": f"Bearer {pat}"})
    finally:
        if saved is not None:
            app.dependency_overrides[keycloak_dependency] = saved
        identity._jwks_cache.pop(settings.oidc_jwks_uri, None)

    assert resp.status_code == 401, resp.text


def test_missing_bearer_still_401_on_v1(app_client: tuple[TestClient, dict]) -> None:
    """Sanity check that the override-removal technique above actually
    exercises the real dependency (i.e. isn't accidentally still bypassed)."""
    client, _ = app_client

    from af_mcp_broker.app import app
    from af_mcp_broker.identity import keycloak_dependency

    saved = app.dependency_overrides.pop(keycloak_dependency, None)
    try:
        resp = client.get("/v1/tokens")
    finally:
        if saved is not None:
            app.dependency_overrides[keycloak_dependency] = saved

    assert resp.status_code == 401, resp.text
