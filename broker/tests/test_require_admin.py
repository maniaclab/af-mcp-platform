"""Tests for identity.require_admin -- the admin-gating dependency."""

from __future__ import annotations

from typing import Annotated

import pytest
from broker_state_helpers import make_broker_state
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from af_mcp_broker.config import Settings, get_settings
from af_mcp_broker.identity import keycloak_dependency, require_admin
from af_mcp_broker.principal import Principal


@pytest.fixture
def admin_test_app(make_principal):
    app = FastAPI()
    app.state.broker = make_broker_state(settings=Settings(admin_group="af-admins"))

    @app.get("/probe")
    async def probe(principal: Annotated[Principal, Depends(require_admin)]) -> dict:
        return {"subject": principal.subject}

    state = {"principal": make_principal(groups=["atlas"])}
    app.dependency_overrides[keycloak_dependency] = lambda: state["principal"]
    with TestClient(app) as client:
        yield client, state
    app.dependency_overrides.clear()


def test_admin_member_is_allowed(admin_test_app, make_principal):
    client, state = admin_test_app
    state["principal"] = make_principal(groups=["atlas", "af-admins"])
    resp = client.get("/probe")
    assert resp.status_code == 200


def test_non_admin_is_403(admin_test_app):
    client, _state = admin_test_app
    resp = client.get("/probe")
    assert resp.status_code == 403


def test_admin_group_comes_from_the_state_settings_not_the_environment(
    admin_test_app, make_principal, monkeypatch
):
    """``BrokerState.settings`` is the single settings source in the running
    app: an environment that names a different admin group changes nothing."""
    monkeypatch.setenv("ADMIN_GROUP", "somebody-else")
    get_settings.cache_clear()
    client, state = admin_test_app
    state["principal"] = make_principal(groups=["af-admins"])

    resp = client.get("/probe")

    get_settings.cache_clear()
    assert resp.status_code == 200
