"""Tests for identity.require_admin -- the admin-gating dependency."""

from __future__ import annotations

from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from af_mcp_broker.config import get_settings
from af_mcp_broker.identity import Principal, keycloak_dependency, require_admin


@pytest.fixture
def admin_test_app(monkeypatch: pytest.MonkeyPatch, make_principal):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    get_settings.cache_clear()

    app = FastAPI()

    @app.get("/probe")
    async def probe(principal: Annotated[Principal, Depends(require_admin)]) -> dict:
        return {"subject": principal.subject}

    state = {"principal": make_principal(groups=["atlas"])}
    app.dependency_overrides[keycloak_dependency] = lambda: state["principal"]
    with TestClient(app) as client:
        yield client, state
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def test_admin_member_is_allowed(admin_test_app, make_principal):
    client, state = admin_test_app
    state["principal"] = make_principal(groups=["atlas", "af-admins"])
    resp = client.get("/probe")
    assert resp.status_code == 200


def test_non_admin_is_403(admin_test_app):
    client, _state = admin_test_app
    resp = client.get("/probe")
    assert resp.status_code == 403
