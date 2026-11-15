"""Unit tests for ``BrokerState`` (``broker_state.py``) and its assembly (``wiring/state.py``)."""

from __future__ import annotations

from dataclasses import fields
from types import SimpleNamespace
from typing import Any

import pytest
from broker_state_helpers import make_broker_state
from fastapi import FastAPI
from starlette.requests import Request

from af_mcp_broker.broker_state import BrokerState, broker_state_of, get_broker_state
from af_mcp_broker.wiring.state import build_broker_state

# Every field of BrokerState. Adding or removing a field is a deliberate act:
# update this set alongside the dataclass.
_FIELDS = {
    "settings",
    "entitlement_policy",
    "service_registry",
    "services",
    "services_loaded",
    "credential_cache",
    "credential_registry",
    "x509_provider",
    "x509_targets",
    "krb5_targets",
    "servicex_targets",
    "x509_audiences",
    "krb5_audiences",
    "servicex_audiences",
    "target_to_alias",
    "identity_providers",
    "identity_provider_configs",
    "oauth21_token_store",
    "oauth21_state_cipher",
    "token_registry",
    "principal_cache",
    "mcp_auth_code_store",
    "broker_token_issuer",
    "usage_store",
    "maintenance_mode_store",
    "lint_observations",
    "shared_state",
    "krb5_vault_store",
    "servicex_vault_store",
    "credmon_sync",
    "tool_listing_cache",
    "mcp_aggregator",
    "dev_bypass_principal",
    "metrics_port",
}

# Fields build_broker_state reads out of the catalog/targets/providers groups
# (or creates itself) rather than taking as arguments of their own.
_FROM_GROUPS_OR_CREATED = {
    "settings",
    "entitlement_policy",
    "service_registry",
    "services",
    "services_loaded",
    "x509_targets",
    "krb5_targets",
    "servicex_targets",
    "x509_audiences",
    "krb5_audiences",
    "servicex_audiences",
    "target_to_alias",
    "identity_providers",
    "identity_provider_configs",
    "credential_registry",
    "krb5_vault_store",
    "servicex_vault_store",
    "tool_listing_cache",
}


def test_fields_are_exactly_the_pinned_set() -> None:
    assert {field.name for field in fields(BrokerState)} == _FIELDS


def test_state_is_frozen() -> None:
    state = make_broker_state()

    with pytest.raises(AttributeError):
        state.settings = object()  # type: ignore[misc]


def test_accessor_returns_the_state_stored_on_the_app() -> None:
    app = FastAPI()
    state = make_broker_state()
    app.state.broker = state
    request = Request({"type": "http", "app": app})

    assert broker_state_of(app) is state
    assert get_broker_state(request) is state


def test_accessor_raises_when_no_state_is_stored() -> None:
    with pytest.raises(RuntimeError, match="BrokerState is not published"):
        broker_state_of(FastAPI())


def test_build_flattens_the_groups_the_lifespan_builds() -> None:
    marks: dict[str, Any] = {name: object() for name in _FIELDS}
    catalog = SimpleNamespace(
        entitlement_policy=marks["entitlement_policy"],
        service_registry=marks["service_registry"],
        services=marks["services"],
        services_loaded=marks["services_loaded"],
    )
    targets = SimpleNamespace(
        x509_targets=marks["x509_targets"],
        krb5_targets=marks["krb5_targets"],
        servicex_targets=marks["servicex_targets"],
        x509_audiences=marks["x509_audiences"],
        krb5_audiences=marks["krb5_audiences"],
        servicex_audiences=marks["servicex_audiences"],
        target_to_alias=marks["target_to_alias"],
    )
    providers = SimpleNamespace(
        registry=marks["credential_registry"],
        providers=marks["identity_providers"],
        configs=marks["identity_provider_configs"],
    )
    link_stores = SimpleNamespace(
        krb5=marks["krb5_vault_store"], servicex=marks["servicex_vault_store"]
    )
    passed_through = {name: marks[name] for name in _FIELDS - _FROM_GROUPS_OR_CREATED}

    state = build_broker_state(
        marks["settings"],
        catalog=catalog,  # type: ignore[arg-type]
        targets=targets,  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        link_stores=link_stores,  # type: ignore[arg-type]
        **passed_through,
    )

    for name in _FIELDS - {"tool_listing_cache"}:
        assert getattr(state, name) is marks[name], name
    assert state.tool_listing_cache.get("any", 60) is None
