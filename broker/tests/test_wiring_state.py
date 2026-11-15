"""Unit tests for ``BrokerState.publish`` (``wiring/state.py``): the ``app.state`` attribute names the routes and middleware read are a stable contract."""

from __future__ import annotations

from dataclasses import fields
from types import SimpleNamespace
from typing import Any

from starlette.datastructures import State

from af_mcp_broker.wiring.state import BrokerState

# The app.state attributes the lifespan publishes through BrokerState. The
# lifespan itself also sets dev_bypass_active, dev_bypass_principal and
# metrics_port.
_PUBLISHED = {
    "settings",
    "entitlement_policy",
    "service_registry",
    "services",
    "services_loaded",
    "credential_cache",
    "credential_registry",
    "x509_provider",
    "x509_targets",
    "x509_audiences",
    "krb5_audiences",
    "krb5_targets",
    "servicex_audiences",
    "servicex_targets",
    "identity_providers",
    "identity_provider_configs",
    "target_to_alias",
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
}


def _state() -> tuple[BrokerState, dict[str, Any]]:
    marks = {field.name: object() for field in fields(BrokerState)}
    marks["catalog"] = SimpleNamespace(
        entitlement_policy=object(),
        service_registry=object(),
        services=object(),
        services_loaded=object(),
    )
    marks["targets"] = SimpleNamespace(
        x509_targets=object(),
        krb5_targets=object(),
        servicex_targets=object(),
        x509_audiences=object(),
        krb5_audiences=object(),
        servicex_audiences=object(),
        target_to_alias=object(),
    )
    marks["providers"] = SimpleNamespace(
        registry=object(), providers=object(), configs=object()
    )
    marks["link_stores"] = SimpleNamespace(
        x509=object(), krb5=object(), servicex=object()
    )
    return BrokerState(**marks), marks


def test_publish_sets_exactly_the_attributes_the_request_path_reads() -> None:
    broker_state, _ = _state()
    state = State()

    broker_state.publish(state)

    assert set(vars(state)["_state"]) == _PUBLISHED


def test_publish_assigns_each_subsystem_to_its_attribute() -> None:
    broker_state, marks = _state()
    state = State()

    broker_state.publish(state)

    assert state.settings is marks["settings"]
    assert state.entitlement_policy is marks["catalog"].entitlement_policy
    assert state.credential_registry is marks["providers"].registry
    assert state.identity_providers is marks["providers"].providers
    assert state.identity_provider_configs is marks["providers"].configs
    assert state.x509_targets is marks["targets"].x509_targets
    assert state.target_to_alias is marks["targets"].target_to_alias
    assert state.krb5_vault_store is marks["link_stores"].krb5
    assert state.servicex_vault_store is marks["link_stores"].servicex
    assert state.token_registry is marks["token_registry"]
    assert state.credmon_sync is marks["credmon_sync"]
