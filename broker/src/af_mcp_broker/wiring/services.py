"""Builders for the service catalog (policy + registry) and the identity-target maps derived from it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog
import yaml

from af_mcp_broker.authorization import EntitlementPolicy, load_policy
from af_mcp_broker.service_registry import ServiceRegistry
from af_mcp_broker.wiring.checks import (
    build_target_to_alias,
    validate_identity_token_auth_type_coverage,
    validate_service_permissions,
    validate_x509_provider_targets,
)

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.service_registry import ServiceSpec

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ServiceCatalog:
    """The entitlement policy and the services it gates, as loaded from ``policy.yaml`` and ``services.yaml``.

    *services* is the operator-configured services only: the registry always
    carries the builtin gateway service entry too (issue #240), which needs
    none of the startup validation (permission "__none__", no credential, no
    x509) and would otherwise mask an empty services.yaml from the
    non-empty check and inflate /readyz's services_count.
    """

    entitlement_policy: EntitlementPolicy
    service_registry: ServiceRegistry
    services: list[ServiceSpec]


def _load_nonempty_policy(path: str) -> EntitlementPolicy:
    """Load the policy at *path*, refusing one that is missing, unreadable or grants nothing.

    A broker whose policy grants nothing authenticates users and then denies
    every service, so it must never become ready.
    """
    try:
        policy = load_policy(path)
    except (OSError, yaml.YAMLError) as exc:
        msg = f"cannot read the entitlement policy at POLICY_FILE={path!r}: {exc}"
        raise RuntimeError(msg) from exc
    if not any(policy.group_permissions.values()):
        msg = (
            f"the entitlement policy at POLICY_FILE={path!r} grants no permissions "
            "(group_permissions has no group with a permission)"
        )
        raise RuntimeError(msg)
    return policy


def _load_nonempty_registry(path: str, builtin_service_name: str) -> ServiceRegistry:
    """Load the service registry at *path*, refusing a file that is missing, unreadable, invalid or defines no services.

    A broker with no services to route to authenticates users and then serves
    nothing, so it must never become ready.
    """
    registry = ServiceRegistry(builtin_service_name)
    try:
        registry.load(path)
    except (OSError, yaml.YAMLError, ValueError, KeyError, TypeError) as exc:
        msg = f"cannot read the service registry at SERVICES_FILE={path!r}: {exc!r}"
        raise RuntimeError(msg) from exc
    if not any(not spec.builtin for spec in registry.all_services()):
        msg = f"the service registry at SERVICES_FILE={path!r} defines no services"
        raise RuntimeError(msg)
    return registry


def build_service_catalog(settings: Settings) -> ServiceCatalog:
    """Load the policy and service registry and refuse to boot on a missing or empty policy or registry, or an undeclared or ungranted service permission."""
    # --- Authorization: the authorization/ engine matches the shipped policy.yaml.
    entitlement_policy = _load_nonempty_policy(settings.policy_file)
    # Observability for issue #125: the effective group -> permission mapping
    # is otherwise implicit (chart default vs. operator override vs. dev-only
    # fallback all merge into the same in-memory EntitlementPolicy), so an
    # operator reading pod logs has no other way to see which policy is
    # actually live. Group/permission names only -- no tokens or secrets ever
    # pass through here.
    logger.info(
        "policy.group_permissions_loaded",
        group_permissions={
            group: sorted(caps)
            for group, caps in sorted(entitlement_policy.group_permissions.items())
        },
    )

    # --- Service registry (config-only; adding a service needs no code change).
    service_registry = _load_nonempty_registry(
        settings.services_file, settings.builtin_service_name
    )
    services = [spec for spec in service_registry.all_services() if not spec.builtin]

    validate_service_permissions(services, entitlement_policy)
    return ServiceCatalog(
        entitlement_policy=entitlement_policy,
        service_registry=service_registry,
        services=services,
    )


@dataclass(frozen=True)
class IdentityTargets:
    """Per-credential-kind service targets, the audience -> target maps the redeem endpoints use, and the catalog's target -> provider-alias join."""

    x509_targets: list[str]
    krb5_targets: list[str]
    servicex_targets: list[str]
    x509_audiences: dict[str, str]
    krb5_audiences: dict[str, str]
    servicex_audiences: dict[str, str]
    target_to_alias: dict[str, str]

    @property
    def targets_by_kind(self) -> dict[str, list[str]]:
        """The identity targets each credmon kind redeems from."""
        return {
            "x509": self.x509_targets,
            "krb5": self.krb5_targets,
            "servicex": self.servicex_targets,
        }


def _entry_targets(settings: Settings, entry_type: str) -> list[str]:
    """Every target of every ``identity_providers`` entry of *entry_type*."""
    return [
        target
        for cfg in settings.identity_providers
        if cfg.type == entry_type
        for target in cfg.targets
    ]


def _audiences(services: list[ServiceSpec], auth_type: str) -> dict[str, str]:
    """Map each ``auth_type: <auth_type>`` service's effective audience to its name."""
    return {
        spec.effective_audience: spec.name
        for spec in services
        if spec.auth_type == auth_type
    }


def build_identity_targets(
    settings: Settings, services: list[ServiceSpec]
) -> IdentityTargets:
    """Collect each credential kind's targets and audiences, and refuse to boot when services and ``identity_providers`` disagree.

    x509 is an ordinary ``identity_providers`` type with no synthesized
    fallback -- every ``auth_type: x509`` service must be covered by an
    explicit entry, drift-checked both directions, fail-closed
    (``validate_x509_provider_targets``). Every surface downstream — provider
    registration, /v1/catalog's credential_provider alias, /v1/identities —
    works from these real, operator-declared entries.
    """
    x509_targets: list[str] = [
        spec.name for spec in services if spec.auth_type == "x509"
    ]
    # krb5-token has no analogous `auth_type` variant in services.yaml (its
    # targets are ordinary bearer-auth backends, resolved to a
    # KrbTokenProvider purely via `identity_providers`), so there is no
    # drift to validate here the way `validate_x509_provider_targets` does
    # for x509 -- just collect every krb5-token entry's targets.
    krb5_targets = _entry_targets(settings, "krb5-token")
    # Same reasoning as krb5_targets above: servicex-token has no analogous
    # `auth_type` variant in services.yaml either, so just collect every
    # servicex-token entry's targets -- used by /v1/servicex/link's
    # "no explicit target, use the first configured one" default.
    servicex_targets = _entry_targets(settings, "servicex-token")
    # Reverse maps from the aud a backend presents to a redeem endpoint (the
    # service's effective_audience -- what the broker mints, issue #257) back
    # to the target name the proxy/provider are keyed under. Without them the
    # redeem endpoint would keep assuming aud == target name, which the
    # name/audience split invalidated -- the 2026-08-27 x509 proxy 403. The
    # krb5 and servicex maps are plumbing for a future backend (no shipped
    # services.yaml declares one; see af-mcp-platform#295), mirrored
    # exactly so that endpoint's resolution works as soon as one does.
    x509_audiences = _audiences(services, "x509")
    krb5_audiences = _audiences(services, "krb5")
    servicex_audiences = _audiences(services, "servicex")
    # HTCondor credmon top tokens (docs/credmon.md): the credmon redeems a
    # user's *identity*, not any particular service's credential, so its
    # per-kind audience maps to that kind's first configured target -- the
    # same default the user-facing /v1 surfaces resolve to. No condor
    # service entry is involved; the identity just gains one more consumer.
    if settings.credmon_enabled:
        prefix = settings.credmon_audience_prefix
        for kind, audiences, targets in (
            ("x509", x509_audiences, x509_targets),
            ("krb5", krb5_audiences, krb5_targets),
            ("servicex", servicex_audiences, servicex_targets),
        ):
            if targets:
                audiences[f"{prefix}{kind}"] = targets[0]
    validate_x509_provider_targets(settings.identity_providers, set(x509_targets))
    validate_identity_token_auth_type_coverage(settings.identity_providers, services)
    return IdentityTargets(
        x509_targets=x509_targets,
        krb5_targets=krb5_targets,
        servicex_targets=servicex_targets,
        x509_audiences=x509_audiences,
        krb5_audiences=krb5_audiences,
        servicex_audiences=servicex_audiences,
        # Identity<->service join for /v1/catalog's credential_provider field
        # (issue #90): who services each target, from the same effective
        # config list the providers are wired from -- x509 targets get their
        # real entry's alias, no synthetic string.
        target_to_alias=build_target_to_alias(settings.identity_providers),
    )
