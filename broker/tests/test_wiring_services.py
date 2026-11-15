"""Unit tests for the service-catalog and identity-target builders (``wiring/services.py``)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from af_mcp_broker.config import (
    KeycloakBrokeredProviderConfig,
    KrbTokenProviderConfig,
    ServiceXTokenProviderConfig,
    Settings,
    X509ProviderConfig,
)
from af_mcp_broker.wiring.services import (
    IdentityTargets,
    build_identity_targets,
    build_service_catalog,
)

if TYPE_CHECKING:
    from pathlib import Path

    from af_mcp_broker.service_registry import ServiceSpec

_POLICY = "group_permissions:\n  atlas: [read_data]\n"


def _service(name: str, auth_type: str, permission: str = "read_data") -> str:
    return (
        f"  - name: {name}\n"
        f"    prefix: {name}\n"
        f"    url: http://{name}.invalid/mcp\n"
        f"    auth_type: {auth_type}\n"
        f"    required_permission: {permission}\n"
    )


def _settings(tmp_path: Path, services: str | None, **overrides: Any) -> Settings:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_POLICY)
    services_file = tmp_path / "services.yaml"
    if services is not None:
        services_file.write_text(
            f"services:\n{services}" if services else "services: []"
        )
    return Settings(
        oidc_issuer="https://kc.invalid/realms/x",
        policy_file=str(policy_file),
        services_file=str(services_file),
        vault_addr="https://vault.invalid",
        vault_auth_role="r",
        **overrides,
    )


def _specs(tmp_path: Path, services: str, **overrides: Any) -> list[ServiceSpec]:
    return build_service_catalog(_settings(tmp_path, services, **overrides)).services


class TestBuildServiceCatalog:
    def test_loads_operator_services_without_the_builtin_entry(
        self, tmp_path: Path
    ) -> None:
        catalog = build_service_catalog(
            _settings(tmp_path, _service("rucio", "bearer"))
        )

        assert [spec.name for spec in catalog.services] == ["rucio"]
        assert catalog.services_loaded is True
        assert catalog.entitlement_policy.group_permissions == {"atlas": ["read_data"]}
        # The registry carries the builtin gateway service too; `services` does not.
        assert any(spec.builtin for spec in catalog.service_registry.all_services())

    def test_an_empty_services_file_is_loaded_not_missing(self, tmp_path: Path) -> None:
        catalog = build_service_catalog(_settings(tmp_path, ""))

        assert catalog.services == []
        assert catalog.services_loaded is True

    def test_missing_files_degrade_to_an_empty_policy_and_registry(
        self, tmp_path: Path
    ) -> None:
        settings = Settings(
            oidc_issuer="https://kc.invalid/realms/x",
            policy_file=str(tmp_path / "absent-policy.yaml"),
            services_file=str(tmp_path / "absent-services.yaml"),
        )

        catalog = build_service_catalog(settings)

        assert catalog.services == []
        assert catalog.services_loaded is False
        assert catalog.entitlement_policy.group_permissions == {}

    def test_refuses_a_permission_that_is_not_declared(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, _service("rucio", "bearer", "no_such_perm"))

        with pytest.raises(RuntimeError, match="neither built-in nor declared"):
            build_service_catalog(settings)

    def test_refuses_a_permission_no_group_grants(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, _service("rucio", "bearer", "manage_jobs"))

        with pytest.raises(RuntimeError, match="no group in group_permissions grants"):
            build_service_catalog(settings)


class TestBuildIdentityTargets:
    def test_collects_targets_audiences_and_alias_join_per_kind(
        self, tmp_path: Path
    ) -> None:
        services = (
            _service("ami", "x509")
            + _service("krbsvc", "krb5")
            + _service("sxsvc", "servicex")
        )
        settings = _settings(
            tmp_path,
            services,
            identity_providers=[
                KeycloakBrokeredProviderConfig(alias="oidc", targets=["rucio"]),
                X509ProviderConfig(
                    alias="x509", targets=["ami"], service_url="http://v.invalid"
                ),
                KrbTokenProviderConfig(
                    alias="krb", targets=["krbsvc"], service_url="http://k.invalid"
                ),
                ServiceXTokenProviderConfig(
                    alias="sx", targets=["sxsvc"], service_url="http://s.invalid"
                ),
            ],
        )

        targets = build_identity_targets(settings, _specs(tmp_path, services))

        assert targets.x509_targets == ["ami"]
        assert targets.krb5_targets == ["krbsvc"]
        assert targets.servicex_targets == ["sxsvc"]
        assert targets.x509_audiences == {"ami": "ami"}
        assert targets.krb5_audiences == {"krbsvc": "krbsvc"}
        assert targets.servicex_audiences == {"sxsvc": "sxsvc"}
        assert targets.target_to_alias == {
            "rucio": "oidc",
            "ami": "x509",
            "krbsvc": "krb",
            "sxsvc": "sx",
        }
        assert targets.targets_by_kind == {
            "x509": ["ami"],
            "krb5": ["krbsvc"],
            "servicex": ["sxsvc"],
        }

    def test_credmon_adds_a_per_kind_audience_for_the_first_target(
        self, tmp_path: Path
    ) -> None:
        settings = _settings(
            tmp_path,
            "",
            identity_providers=[
                KrbTokenProviderConfig(
                    alias="krb",
                    targets=["krbsvc", "other"],
                    service_url="http://k.invalid",
                ),
            ],
            credmon_enabled=True,
            credmon_htcondor_api_url="http://condor.invalid",
            credmon_htcondor_api_token_file="/token",
            credmon_user_domain="example.org",
        )

        targets = build_identity_targets(settings, [])

        assert targets.krb5_audiences == {
            f"{settings.credmon_audience_prefix}krb5": "krbsvc"
        }
        assert targets.x509_audiences == {}

    def test_refuses_an_x509_service_no_entry_covers(self, tmp_path: Path) -> None:
        services = _service("ami", "x509")
        settings = _settings(tmp_path, services, identity_providers=[])

        with pytest.raises(RuntimeError, match="not targeted by any x509"):
            build_identity_targets(settings, _specs(tmp_path, services))

    def test_refuses_a_krb5_service_no_entry_covers(self, tmp_path: Path) -> None:
        services = _service("krbsvc", "krb5")
        settings = _settings(tmp_path, services, identity_providers=[])

        with pytest.raises(RuntimeError, match="auth_type: krb5 services"):
            build_identity_targets(settings, _specs(tmp_path, services))

    def test_result_is_an_identity_targets(self, tmp_path: Path) -> None:
        targets = build_identity_targets(_settings(tmp_path, ""), [])

        assert isinstance(targets, IdentityTargets)
        assert targets.target_to_alias == {}
