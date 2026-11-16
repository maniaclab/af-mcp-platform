"""``values.schema.json`` rejects bad chart values before any template renders.

Each file in ``data/chart_values_schema`` is a deliberately bad overlay on
``ci/test-values.yaml``. The chart is rendered live with ``helm`` (a
dev-environment dependency) and must refuse it, naming the offending keys.
Helm's wording for a schema violation differs between releases, so the
assertions match key names, not sentences.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CHART = _REPO_ROOT / "charts" / "af-mcp-platform"
_BASE_VALUES = _CHART / "ci" / "test-values.yaml"
_EXAMPLES = _CHART / "examples"
_BAD_VALUES = Path(__file__).parent / "data" / "chart_values_schema"


def _helm_template(
    *overlays: Path,
    sets: tuple[str, ...] = (),
    set_jsons: tuple[str, ...] = (),
    base: Path = _BASE_VALUES,
) -> subprocess.CompletedProcess[str]:
    """Render the chart over *base* (the CI values by default) plus *overlays*, ``--set`` *sets* and ``--set-json`` *set_jsons*; never raises on failure."""
    command = [
        "helm",
        "template",
        "af-mcp-platform",
        str(_CHART),
        "--set",
        "image.broker.tag=sha-test",
        "--set",
        "image.portal.tag=sha-test",
        "-f",
        str(base),
    ]
    for overlay in overlays:
        command += ["-f", str(overlay)]
    for assignment in sets:
        command += ["--set", assignment]
    for assignment in set_jsons:
        command += ["--set-json", assignment]
    return subprocess.run(command, check=False, capture_output=True, text=True)


@pytest.mark.parametrize(
    ("overlay", "fragments"),
    [
        ("typo-key", ["keycloakAdmn"]),
        ("wrong-type", ["replicaCount"]),
        ("bad-backend", ["tokenRegistry", "backend"]),
        ("empty-services", ["aggregator", "services"]),
        ("empty-policy", ["entitlements", "group_permissions"]),
        ("service-typo", ["requried_permission"]),
        ("x509-without-service-url", ["serviceUrl"]),
        ("x509-without-voms", ["voms"]),
        ("ingress-without-hosts", ["mcpHost", "portalHost"]),
        ("missing-required", ["issuer", "clientId", "brokerOrigin"]),
        (
            "keycloak-admin-unset",
            ["keycloakAdmin", "clientId", "existingClientSecretSecret"],
        ),
        ("replicas-without-shared-state", ["sharedState"]),
        ("several-errors", ["keycloakAdmn", "replicaCount", "services"]),
    ],
)
def test_bad_values_are_rejected_by_the_schema(
    overlay: str, fragments: list[str]
) -> None:
    result = _helm_template(_BAD_VALUES / f"{overlay}.yaml")

    assert result.returncode != 0
    assert "values don't meet the specifications of the schema" in result.stderr
    for fragment in fragments:
        assert fragment in result.stderr


@pytest.mark.parametrize("key", ["endpoint", "networkPolicy"])
def test_removed_tracing_keys_are_unknown_to_the_schema(key: str) -> None:
    result = _helm_template(sets=(f"broker.tracing.{key}=x",))

    assert result.returncode != 0
    assert "values don't meet the specifications of the schema" in result.stderr
    assert f"additional properties '{key}' not allowed" in result.stderr


def test_base_values_pass_the_schema() -> None:
    result = _helm_template()

    assert result.returncode == 0, result.stderr


def test_ingress_disabled_needs_no_hosts() -> None:
    result = _helm_template(
        sets=(
            "ingress.enabled=false",
            "ingress.mcpHost=",
            "ingress.portalHost=",
            "broker.identityToken.issuer=https://mcp.example.com",
        )
    )

    assert result.returncode == 0, result.stderr


def test_default_render_carries_no_facility_content() -> None:
    # Template comments may cite an example; the rendered values must not.
    rendered = "\n".join(
        line
        for line in _helm_template().stdout.lower().splitlines()
        if not line.lstrip().startswith("#")
    )

    for facility_marker in ("uchicago", "letsencrypt", "mwt2"):
        assert facility_marker not in rendered


@pytest.mark.parametrize(
    "kind", ["kind: ServiceMonitor", "grafana_dashboard", "cert-manager.io"]
)
def test_optional_integrations_are_opt_in(kind: str) -> None:
    assert kind not in _helm_template().stdout


def test_tls_secret_names_derive_from_the_release() -> None:
    rendered = _helm_template().stdout

    assert 'secretName: "af-mcp-platform-mcp-tls"' in rendered
    assert 'secretName: "af-mcp-platform-portal-tls"' in rendered


def test_example_values_render_a_complete_deployment() -> None:
    result = _helm_template(_EXAMPLES / "example-values.yaml")

    assert result.returncode == 0, result.stderr
    for expected in (
        "kind: ServiceMonitor",
        "grafana_dashboard",
        "mcp.af.example.org",
        "cert-manager.io/cluster-issuer",
        "kind: NetworkPolicy",
        "192.0.2.0/24",
        "2001:db8::/32",
        "198.51.100.0/24",
    ):
        assert expected in result.stdout


_MINIMAL_BASE = _BAD_VALUES / "minimal-base.yaml"
_VAULT_CONNECTION = (
    "broker.oauth21.tokenStore.vault.addr=https://vault.example.com",
    "broker.oauth21.tokenStore.vault.authRole=example-role",
    "broker.vault.kvRoot=mcp",
)
_SIGNING_KEY = ("broker.identityToken.existingSigningKeySecret=example-signing-key",)
_STATE_KEY = ("broker.oauth21.existingStateKeySecret=example-state-key",)
_PUBLIC_ORIGIN = ("broker.publicOrigin=https://mcp.example.com",)
_USAGE_POSTGRES = (
    "broker.usage.backend=postgres",
    "broker.usage.postgres.existingSecret.name=example-usage-dsn",
    "broker.usage.postgres.networkPolicy.podSelector.app=postgres",
)
_X509_PROVIDER = (
    '[{"type": "x509", "alias": "x509-example", "serviceUrl": '
    '"https://voms.example.com", "voms": "example"}]'
)
_KRB5_PROVIDER = (
    '[{"type": "krb5-token", "alias": "krb5-example", "serviceUrl": '
    '"https://krb5.example.com"}]'
)
_SERVICEX_PROVIDER = (
    '[{"type": "servicex-token", "alias": "servicex-example", "serviceUrl": '
    '"https://servicex.example.com"}]'
)
_BROKER_ISSUED_PROVIDER = '[{"type": "broker-issued", "alias": "af-native-example"}]'
_OAUTH21_PROVIDER = (
    '[{"type": "oauth21-direct", "alias": "rucio-example", '
    '"authorizationEndpoint": "https://rucio.example.com/authorize", '
    '"tokenEndpoint": "https://rucio.example.com/token", '
    '"issuer": "https://rucio.example.com"}]'
)


def _render_minimal(
    *sets: str, set_jsons: tuple[str, ...] = ()
) -> subprocess.CompletedProcess[str]:
    return _helm_template(sets=sets, set_jsons=set_jsons, base=_MINIMAL_BASE)


def test_minimal_values_pass_the_schema() -> None:
    result = _render_minimal()

    assert result.returncode == 0, result.stderr


def _assert_rejected_naming(
    result: subprocess.CompletedProcess[str], fragments: list[str]
) -> None:
    assert result.returncode != 0
    for fragment in fragments:
        assert fragment in result.stderr


_VAULT_KEYS = ["tokenStore", "addr", "authRole", "kvRoot"]


@pytest.mark.parametrize(
    "selector",
    [
        "broker.oauth21.tokenStore.backend=vault",
        "broker.tokenRegistry.backend=vault",
        "broker.principalCache.backend=vault",
        "broker.maintenanceMode.backend=vault",
    ],
)
def test_vault_backend_without_connection_is_rejected(selector: str) -> None:
    _assert_rejected_naming(_render_minimal(selector), _VAULT_KEYS)


@pytest.mark.parametrize(
    "providers",
    [_X509_PROVIDER, _KRB5_PROVIDER, _SERVICEX_PROVIDER],
    ids=["x509", "krb5-token", "servicex-token"],
)
def test_vault_persisting_provider_without_connection_is_rejected(
    providers: str,
) -> None:
    result = _render_minimal(
        *_SIGNING_KEY, set_jsons=(f"broker.identityProviders={providers}",)
    )

    _assert_rejected_naming(result, _VAULT_KEYS)


def test_vault_backend_with_connection_renders() -> None:
    result = _render_minimal("broker.tokenRegistry.backend=vault", *_VAULT_CONNECTION)

    assert result.returncode == 0, result.stderr


def test_vault_connection_reports_every_missing_key_in_one_error() -> None:
    result = _render_minimal(
        "broker.tokenRegistry.backend=vault", "broker.vault.kvRoot=mcp"
    )

    _assert_rejected_naming(result, ["addr", "authRole"])
    assert "kvRoot" not in result.stderr


def test_postgres_usage_without_secret_is_rejected() -> None:
    result = _render_minimal(
        "broker.usage.backend=postgres",
        "broker.usage.postgres.networkPolicy.podSelector.app=postgres",
    )

    _assert_rejected_naming(result, ["usage", "postgres", "existingSecret"])


def test_postgres_usage_with_secret_renders() -> None:
    result = _render_minimal(*_USAGE_POSTGRES)

    assert result.returncode == 0, result.stderr


def test_postgres_maintenance_mode_without_any_dsn_is_rejected() -> None:
    result = _render_minimal("broker.maintenanceMode.backend=postgres")

    _assert_rejected_naming(result, ["broker.maintenanceMode.postgres.existingSecret"])


@pytest.mark.parametrize(
    "sets",
    [
        ("broker.maintenanceMode.postgres.existingSecret.name=example-dsn",),
        _USAGE_POSTGRES,
    ],
    ids=["own-secret", "usage-secret-fallback"],
)
def test_postgres_maintenance_mode_with_a_dsn_renders(sets: tuple[str, ...]) -> None:
    result = _render_minimal("broker.maintenanceMode.backend=postgres", *sets)

    assert result.returncode == 0, result.stderr


def test_credmon_without_its_settings_is_rejected() -> None:
    result = _render_minimal("broker.credmon.enabled=true")

    _assert_rejected_naming(
        result,
        ["htcondorApiUrl", "userDomain", "existingHtcondorApiTokenSecret"],
    )


@pytest.mark.parametrize(
    "signal",
    [
        "broker.tracing.enabled=true",
        "broker.metrics.otlp.enabled=true",
        "broker.usageEvents.otlp.enabled=true",
    ],
)
def test_otlp_signal_without_endpoint_is_rejected(signal: str) -> None:
    _assert_rejected_naming(_render_minimal(signal), ["otlp", "endpoint"])


def test_otlp_signal_with_endpoint_renders() -> None:
    result = _render_minimal(
        "broker.tracing.enabled=true",
        "broker.otlp.endpoint=http://collector.example.com:4318",
    )

    assert result.returncode == 0, result.stderr


def test_oauth21_provider_without_its_settings_is_rejected() -> None:
    result = _render_minimal(
        set_jsons=(f"broker.identityProviders={_OAUTH21_PROVIDER}",)
    )

    _assert_rejected_naming(result, ["publicOrigin", "existingStateKeySecret"])


def test_oauth21_provider_with_its_settings_renders() -> None:
    result = _render_minimal(
        *_PUBLIC_ORIGIN,
        *_STATE_KEY,
        set_jsons=(f"broker.identityProviders={_OAUTH21_PROVIDER}",),
    )

    assert result.returncode == 0, result.stderr


def test_token_mint_client_without_its_settings_is_rejected() -> None:
    result = _render_minimal("broker.tokenMint.clientId=example-client")

    _assert_rejected_naming(
        result,
        ["publicOrigin", "existingStateKeySecret", "existingClientSecretSecret"],
    )


def test_token_mint_client_with_its_settings_renders() -> None:
    result = _render_minimal(
        "broker.tokenMint.clientId=example-client",
        "broker.tokenMint.existingClientSecretSecret=example-client-secret",
        *_PUBLIC_ORIGIN,
        *_STATE_KEY,
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "provider",
    [
        _BROKER_ISSUED_PROVIDER,
        '[{"type": "condor-token", "alias": "condor-example", "serviceUrl": "https://condor.example.com"}]',
    ],
    ids=["broker-issued", "condor-token"],
)
def test_broker_signed_provider_without_signing_key_is_rejected(provider: str) -> None:
    result = _render_minimal(set_jsons=(f"broker.identityProviders={provider}",))

    _assert_rejected_naming(result, ["existingSigningKeySecret"])


def test_broker_signed_provider_with_signing_key_renders() -> None:
    result = _render_minimal(
        *_SIGNING_KEY,
        set_jsons=(f"broker.identityProviders={_BROKER_ISSUED_PROVIDER}",),
    )

    assert result.returncode == 0, result.stderr


def test_credmon_with_its_settings_renders() -> None:
    result = _render_minimal(
        "broker.credmon.enabled=true",
        "broker.credmon.htcondorApiUrl=http://condor.example.com:8080",
        "broker.credmon.userDomain=example.org",
        "broker.credmon.existingHtcondorApiTokenSecret=example-token",
        *_SIGNING_KEY,
        *_VAULT_CONNECTION,
        "broker.tokenRegistry.backend=vault",
        set_jsons=(f"broker.identityProviders={_KRB5_PROVIDER}",),
    )

    assert result.returncode == 0, result.stderr


def _token_issuer(result: subprocess.CompletedProcess[str]) -> str | None:
    """The BROKER_TOKEN_ISSUER env value in the render, or None when it is not set."""
    lines = result.stdout.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "- name: BROKER_TOKEN_ISSUER":
            return lines[index + 1].split("value:", 1)[1].strip().strip('"')
    return None


def test_unset_token_issuer_defaults_to_the_mcp_origin() -> None:
    result = _render_minimal(
        *_SIGNING_KEY, "broker.publicOrigin=https://portal.example.com"
    )

    assert result.returncode == 0, result.stderr
    assert _token_issuer(result) == "https://mcp.example.com"


def test_explicit_token_issuer_wins_over_the_mcp_origin() -> None:
    result = _render_minimal(
        *_SIGNING_KEY, "broker.identityToken.issuer=https://issuer.example.org"
    )

    assert result.returncode == 0, result.stderr
    assert _token_issuer(result) == "https://issuer.example.org"


def test_unset_token_issuer_without_ingress_is_rejected() -> None:
    result = _render_minimal(
        *_SIGNING_KEY,
        "ingress.enabled=false",
        "ingress.mcpHost=",
        "ingress.portalHost=",
    )

    _assert_rejected_naming(result, ["identityToken", "issuer"])


def test_token_issuer_without_ingress_renders_when_set() -> None:
    result = _render_minimal(
        *_SIGNING_KEY,
        "ingress.enabled=false",
        "ingress.mcpHost=",
        "ingress.portalHost=",
        "broker.identityToken.issuer=https://mcp.example.com",
    )

    assert result.returncode == 0, result.stderr
    assert _token_issuer(result) == "https://mcp.example.com"
