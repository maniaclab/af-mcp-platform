"""Startup checks that refuse to boot on an inconsistent config, and the helpers they share.

Each ``validate_*`` raises ``RuntimeError`` with an operator-actionable
message, so a Deployment rollout with a failing new pod leaves the previous
ReplicaSet serving traffic: a visible rollout failure with zero outage risk,
strictly better than a log line nobody is watching.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from af_mcp_broker.authorization import DISABLED_PERMISSION, PERMISSIONS

if TYPE_CHECKING:
    from collections.abc import Iterable

    from af_mcp_broker.authorization import EntitlementPolicy
    from af_mcp_broker.config import IdentityProviderConfig
    from af_mcp_broker.credentials import CredentialRegistry
    from af_mcp_broker.service_registry import ServiceSpec


def build_target_to_alias(
    identity_providers_cfgs: Iterable[IdentityProviderConfig],
) -> dict[str, str]:
    """Reverse map from service target name to the credential-provider alias that services it, surfaced on /v1/catalog as ``credential_provider`` (issue #90). Every target gets its entry's configured alias — x509 targets included, since x509 is an ordinary ``identity_providers`` type: every ``auth_type: x509`` service must be covered by an explicit entry (``validate_x509_provider_targets`` refuses to boot otherwise), so this helper never needs a hardcoded synthetic alias. Targets with ``auth_type: none`` need no user credential and are simply absent from the mapping."""
    target_to_alias: dict[str, str] = {}
    for cfg in identity_providers_cfgs:
        for target in cfg.targets:
            target_to_alias[target] = cfg.alias
    return target_to_alias


def validate_x509_provider_targets(
    identity_providers_cfgs: Iterable[IdentityProviderConfig],
    x509_service_names: set[str],
) -> None:
    """Fail-closed drift protection between ``auth_type: x509`` services and explicit x509 ``identity_providers`` entries (both directions) — same reasoning as issue #60's required_permission consolidation: a mismatch is a typo, a stale services.yaml, or a missing entry, and a startup RuntimeError surfaces it as a visible rollout failure with zero outage risk.

    Universal: there is no synthesized-entry escape hatch. Every
    ``auth_type: x509`` service must be named in some explicit entry's
    ``targets``, including deployments with zero x509 entries at all — an
    x509 service with no covering entry refuses to boot naming it, the same
    as one covered by the wrong entry.
    """
    x509_cfgs = [cfg for cfg in identity_providers_cfgs if cfg.type == "x509"]
    covered = {target for cfg in x509_cfgs for target in cfg.targets}
    uncovered = sorted(x509_service_names - covered)
    if uncovered:
        msg = (
            "The following auth_type: x509 services are not targeted by any "
            f"x509 identity_providers entry: {uncovered}. They would have no "
            "credential provider (and no catalog credential_provider alias) "
            "at all. Add an entry covering them, e.g.:\n"
            "  - type: x509\n"
            "    alias: x509\n"
            f"    targets: {uncovered}\n"
            "    service_url: <voms-token-service base URL>\n"
            "(voms/valid/audience are optional), or change their auth_type."
        )
        raise RuntimeError(msg)
    not_x509 = sorted(covered - x509_service_names)
    if not_x509:
        msg = (
            "The following x509 identity_providers targets are not "
            f"auth_type: x509 services: {not_x509}. The aggregator only "
            "injects the identity JWT (and the redeem endpoint only accepts "
            "the audience) for auth_type: x509 services, so the entry would "
            "silently do nothing for them. Fix the typo, set the service's "
            "auth_type to x509 in services.yaml, or remove the target."
        )
        raise RuntimeError(msg)


# auth_type -> the identity_providers entry type whose provider supplies that
# auth_type's credential. x509 has its own two-direction check
# (validate_x509_provider_targets); krb5 and servicex services are only
# validated for coverage, since a krb5-token/servicex-token entry may also
# target an ordinary bearer-auth backend.
_AUTH_TYPE_ENTRY_TYPES = {"krb5": "krb5-token", "servicex": "servicex-token"}


def validate_identity_token_auth_type_coverage(
    identity_providers_cfgs: Iterable[IdentityProviderConfig],
    services: Iterable[ServiceSpec],
) -> None:
    """Refuse to boot when an ``auth_type: krb5``/``servicex`` service is not targeted by an entry of the matching type.

    Such a service is authenticated with an AF Broker Identity Token, and its
    credential provider exists only through its entry. Without one the
    service could never be served, and the broker would have no reason to
    hold the signing key it needs, so the gap is reported here, naming the
    service, instead of at the first request.
    """
    cfgs = list(identity_providers_cfgs)
    specs = list(services)
    for auth_type, entry_type in _AUTH_TYPE_ENTRY_TYPES.items():
        covered = {
            target for cfg in cfgs if cfg.type == entry_type for target in cfg.targets
        }
        uncovered = sorted(
            spec.name
            for spec in specs
            if spec.auth_type == auth_type and spec.name not in covered
        )
        if uncovered:
            msg = (
                f"The following auth_type: {auth_type} services are not "
                f"targeted by any {entry_type} identity_providers entry: "
                f"{uncovered}. They would have no credential provider. Add "
                f"an entry covering them (type: {entry_type}, targets: "
                f"{uncovered}, service_url: <token service base URL>), or "
                "change their auth_type."
            )
            raise RuntimeError(msg)


# identity_providers types whose providers authenticate to their service with
# an AF Broker Identity Token minted by the broker's own signing key.
_BROKER_TOKEN_ENTRY_TYPES = frozenset(
    {"broker-issued", "condor-token", "krb5-token", "servicex-token", "x509"}
)


def broker_token_entries(
    identity_providers_cfgs: Iterable[IdentityProviderConfig],
) -> list[IdentityProviderConfig]:
    """Return the entries whose providers need the broker's signing key."""
    return [
        cfg for cfg in identity_providers_cfgs if cfg.type in _BROKER_TOKEN_ENTRY_TYPES
    ]


def describe_broker_token_entries(
    entries: Iterable[IdentityProviderConfig],
) -> str:
    """Name each target service of *entries* with the entry that serves it, for the missing-signing-key boot error."""
    described: list[str] = []
    for cfg in entries:
        targets = ", ".join(cfg.targets) if cfg.targets else "(no targets)"
        described.append(f"{targets} ({cfg.type} entry {cfg.alias!r})")
    return "; ".join(described)


def validate_service_permissions(
    services: Iterable[ServiceSpec], entitlement_policy: EntitlementPolicy
) -> None:
    """Refuse to boot on a service permission that is undeclared, or that no group grants."""
    specs = list(services)
    # A required_permission that is neither built-in nor declared under
    # custom_permissions has no action_type to resolve (get_action_type
    # would silently label it "read"), so refuse to start rather than
    # mislabel a state-changing tool. "__none__" is not a permission, and
    # "__disabled__" is the explicit opt-out sentinel.
    unknown_permissions: list[tuple[str, str]] = [
        (spec.name, permission)
        for spec in specs
        for permission in spec.all_required_permissions()
        if permission not in PERMISSIONS
        and permission not in entitlement_policy.custom_permissions
        and permission != DISABLED_PERMISSION
    ]
    if unknown_permissions:
        msg = (
            "The following services require a permission that is neither "
            "built-in nor declared in custom_permissions, so its action "
            "type (read vs. state_change) is unknown: "
            f"{sorted(unknown_permissions)}. Declare each in "
            "entitlements.custom_permissions (chart) / policy.yaml (local "
            "dev), e.g. `exec_jobs: state_change`, or fix the typo."
        )
        raise RuntimeError(msg)

    # A service's required_permission that no group in group_permissions
    # grants makes that service unusable by every principal -- e.g. the
    # operator never wrote a policy for it (a chart-rendered policy.yaml
    # with a stale key name the broker doesn't read, issue #59) or typo'd
    # the permission name. This is a hard startup failure, not a log line:
    # this is Kubernetes, so a Deployment rollout with a failing new pod
    # leaves the previous ReplicaSet serving traffic unaffected -- refusing
    # to start surfaces the misconfiguration as a visible rollout failure /
    # CrashLoopBackOff / k8s event with zero outage risk, which is strictly
    # better than a log line an operator has to be watching for. (Distinct
    # from the fail-closed check in ``validate_services_gated``, which guards
    # against a service with *no* gate at all -- this one guards against a
    # gate nobody can pass.)
    granted_permissions = {
        cap for caps in entitlement_policy.group_permissions.values() for cap in caps
    }
    # all_required_permissions() already excludes "__none__" and handles a
    # dict-form required_permission's multiple values (each checked
    # individually, so a typo in one per-tool entry is named without
    # flagging its correctly-spelled siblings).
    unreachable_permissions: list[tuple[str, str]] = [
        (spec.name, permission)
        for spec in specs
        for permission in spec.all_required_permissions()
        if permission not in granted_permissions
    ]
    if unreachable_permissions:
        msg = (
            "The following services require a permission that no group in "
            "group_permissions grants, so they are unreachable by every "
            "principal (a forgotten policy entry or a typo'd permission "
            f"name): {sorted(unreachable_permissions)}. Set "
            "entitlements.group_permissions (chart) / policy.yaml (local "
            "dev) so at least one group grants each missing permission."
        )
        raise RuntimeError(msg)


async def validate_services_gated(
    services: Iterable[ServiceSpec], credential_registry: CredentialRegistry
) -> None:
    """Fail-closed check (issue #60): refuse to boot on a service with no authorization gate at all.

    A service that omits ``required_permission`` in services.yaml relies on
    the credential layer as its sole authorization gate -- the user must have
    a linked identity / mintable credential for that target. If
    credential_registry can't resolve a provider for it either (e.g.
    ``auth_type: bearer`` with no ``identity_providers`` entry targeting it,
    or ``auth_type: none`` with no provider registered at all), there is no
    gate whatsoever: any authenticated principal could call it. Refuse to
    start rather than silently exposing an ungated service -- this must be
    based on whether credential_registry actually resolves the target, not
    the ``auth_type`` string, since ``auth_type: bearer`` alone doesn't
    guarantee a provider is wired up for this specific target.
    """
    ungated_services: list[str] = []
    for spec in services:
        if spec.required_permission is not None:
            continue
        try:
            await credential_registry.resolve(spec.name)
        except KeyError:
            ungated_services.append(spec.name)
    if ungated_services:
        msg = (
            "The following services omit `required_permission` in "
            "services.yaml and have no credential provider resolving for "
            "their target, so there is no authorization gate at all "
            f"(neither a declared permission nor a mintable credential): "
            f"{sorted(ungated_services)}. Either declare `required_permission` "
            "(or `__none__` to explicitly open it to any authenticated user), "
            "or configure a credential provider (identity_providers / x509) "
            "targeting this service."
        )
        raise RuntimeError(msg)
