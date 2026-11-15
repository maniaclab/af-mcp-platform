from __future__ import annotations

from typing import TYPE_CHECKING

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.credentials import CredentialRegistry
from af_mcp_broker.service_registry import ServiceRegistry

if TYPE_CHECKING:
    from fastapi import Request


def empty_policy() -> EntitlementPolicy:
    return EntitlementPolicy()


def get_policy(request: Request) -> EntitlementPolicy:
    return getattr(request.app.state, "entitlement_policy", None) or empty_policy()


def get_registry(request: Request) -> ServiceRegistry:
    return getattr(request.app.state, "service_registry", None) or ServiceRegistry()


def get_target_to_alias(request: Request) -> dict[str, str]:
    return getattr(request.app.state, "target_to_alias", None) or {}


def get_credential_registry(request: Request) -> CredentialRegistry:
    return (
        getattr(request.app.state, "credential_registry", None) or CredentialRegistry()
    )
