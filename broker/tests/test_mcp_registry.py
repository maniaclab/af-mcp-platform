from __future__ import annotations

from pathlib import Path

import pytest

from af_mcp_broker.config import Settings
from af_mcp_broker.mcp.registry import (
    BUILTIN_SERVICE_NAME,
    DIAGNOSTIC_TOOL_NAMES,
    DISABLED_PERMISSION,
    LINK_IDENTITY_TOOL_NAME,
    RESERVED_PREFIX,
    ServiceRegistry,
    ServiceSpec,
    identity_provider_url,
    namespaced_tool_name,
)

# The shipped services.yaml is the authoritative source for the apply_namespace
# behavior this file tests (rucio is self-prefixed; everything else is not).
_SRC = Path(__file__).resolve().parents[1] / "src" / "af_mcp_broker"
SHIPPED_SERVICES = _SRC / "mcp" / "services.yaml"


def test_backend_spec_apply_namespace_defaults_true() -> None:
    spec = ServiceSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
    )
    assert spec.apply_namespace is True


def test_load_defaults_apply_namespace_true_when_absent(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.apply_namespace is True


def test_load_respects_apply_namespace_false(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
    apply_namespace: false
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.apply_namespace is False


def test_shipped_backends_rucio_apply_namespace_false() -> None:
    """rucio-mcp's tools are already self-prefixed (rucio_list_dids, ...);
    namespacing again would produce rucio_rucio_*."""
    registry = ServiceRegistry()
    registry.load(str(SHIPPED_SERVICES))
    rucio = registry.get("rucio")
    assert rucio is not None
    assert rucio.apply_namespace is False


@pytest.mark.parametrize(
    "name", ["ami", "atlasopenmagic", "af-jupyterlab-mcp", "monitoring", "docs"]
)
def test_shipped_backends_others_apply_namespace_true(name: str) -> None:
    registry = ServiceRegistry()
    registry.load(str(SHIPPED_SERVICES))
    spec = registry.get(name)
    assert spec is not None
    assert spec.apply_namespace is True


def test_shipped_backends_af_filesystem_mcp_apply_namespace_false() -> None:
    """af-filesystem-mcp's tools are already self-prefixed (fs_list, fs_stat,
    fs_read, fs_grep, ...); namespacing again would produce fs_fs_*."""
    registry = ServiceRegistry()
    registry.load(str(SHIPPED_SERVICES))
    fs = registry.get("af-filesystem-mcp")
    assert fs is not None
    assert fs.apply_namespace is False


def test_backend_spec_timeout_seconds_defaults_to_30() -> None:
    spec = ServiceSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
    )
    assert spec.timeout_seconds == 30.0


def test_load_defaults_timeout_seconds_when_absent(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.timeout_seconds == 30.0


def test_load_respects_custom_timeout_seconds(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
    timeout_seconds: 5
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.timeout_seconds == 5.0


# ---------------------------------------------------------------------------
# The builtin af-mcp service (issue #240): the registry self-registers the
# broker's own af_* methods as a first-class service so the catalog,
# af_list_mcp_servers, and the middleware authorization path all see it --
# and operators can never define, replace, or unregister it via services.yaml.
# ---------------------------------------------------------------------------


def test_registry_self_registers_the_builtin_gateway_service() -> None:
    registry = ServiceRegistry()
    spec = registry.get(BUILTIN_SERVICE_NAME)
    assert spec is not None
    assert spec.builtin is True
    assert spec.name == "gateway_service"
    assert spec.prefix == RESERVED_PREFIX
    # Open to any authenticated principal: af_whoami/af_link_identity are the
    # bootstrap methods a caller with zero permissions needs.
    assert spec.required_permission == "__none__"
    # No per-user credential concept at all -- keeps _service_status
    # (api/permissions.py) reporting it "available" unconditionally.
    assert spec.auth_type == "none"
    assert spec in registry.all_services()


def test_builtin_gateway_service_owns_the_af_tool_prefix() -> None:
    """Tool routing by prefix must map every af_* method to the builtin
    service, so EntitlementMiddleware/AuthorizationMiddleware handle them on
    the normal path instead of a name-based bypass."""
    registry = ServiceRegistry()
    for tool_name in sorted(DIAGNOSTIC_TOOL_NAMES):
        spec = registry.get_by_tool_prefix(tool_name)
        assert spec is not None
        assert spec.name == BUILTIN_SERVICE_NAME


def test_builtin_service_name_is_configurable() -> None:
    """The builtin gateway service's name is deployment-configurable (default
    gateway_service): a custom name registers the builtin under it, keeps the
    reserved `af` prefix, and is itself reserved against operator services."""
    registry = ServiceRegistry(builtin_service_name="mygw_service")
    spec = registry.get("mygw_service")
    assert spec is not None
    assert spec.builtin is True
    assert spec.name == "mygw_service"
    assert spec.prefix == RESERVED_PREFIX
    # The default name is no longer special once overridden.
    assert registry.get(BUILTIN_SERVICE_NAME) is None
    # An af_* method still routes to the (renamed) builtin by prefix.
    assert registry.get_by_tool_prefix(LINK_IDENTITY_TOOL_NAME) is spec


def test_register_rejects_the_configured_builtin_service_name() -> None:
    """The reservation follows the configured name, not the default -- an
    operator entry claiming the custom builtin name is refused."""
    registry = ServiceRegistry(builtin_service_name="mygw_service")
    with pytest.raises(ValueError, match="mygw_service"):
        registry.register(
            ServiceSpec(
                name="mygw_service",
                prefix="mygw",
                url="http://shadow.invalid/mcp",
                transport="http",
                required_permission="__none__",
            )
        )


def test_operator_spec_defaults_to_not_builtin() -> None:
    spec = ServiceSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
    )
    assert spec.builtin is False


def test_register_rejects_the_builtin_service_name() -> None:
    """An operator entry named af-mcp (even under a different prefix) would
    silently replace the builtin entry -- refuse it with a clear error."""
    registry = ServiceRegistry()
    with pytest.raises(ValueError, match="gateway_service"):
        registry.register(
            ServiceSpec(
                name=BUILTIN_SERVICE_NAME,
                prefix="shadow",
                url="http://shadow.invalid/mcp",
                transport="http",
                required_permission="__none__",
            )
        )


def test_load_rejects_the_builtin_service_name_in_services_yaml(
    tmp_path: Path,
) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: gateway_service
    prefix: shadow
    url: "http://shadow.invalid/mcp"
    required_permission: __none__
"""
    )
    registry = ServiceRegistry()
    with pytest.raises(ValueError, match="gateway_service"):
        registry.load(str(services_file))


def test_load_cannot_mark_an_operator_service_builtin(tmp_path: Path) -> None:
    """`builtin` is not a services.yaml key -- an operator entry carrying it
    is simply ignored, never honored."""
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
    builtin: true
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.builtin is False


def test_register_rejects_reserved_diagnostic_prefix() -> None:
    """issue #153: no backend may be configured under the "af" prefix -- it's
    reserved for the broker-native af_whoami/af_list_identities/
    af_list_mcp_servers diagnostic tools (mcp/diagnostics.py), which must
    stay impossible to shadow."""
    registry = ServiceRegistry()
    with pytest.raises(ValueError, match="af"):
        registry.register(
            ServiceSpec(
                name="shadow",
                prefix="af",
                url="http://shadow.invalid/mcp",
                transport="http",
                required_permission="__none__",
            )
        )


def test_load_rejects_reserved_diagnostic_prefix_in_backends_yaml(
    tmp_path: Path,
) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: shadow
    prefix: af
    url: "http://shadow.invalid/mcp"
    required_permission: __none__
"""
    )
    registry = ServiceRegistry()
    with pytest.raises(ValueError, match="af"):
        registry.load(str(services_file))


def test_get_by_tool_prefix_unaffected_by_apply_namespace() -> None:
    """apply_namespace only controls FastMCP's namespace= wiring; the
    registry's own prefix matching used for entitlement filtering is
    unchanged regardless of its value."""
    registry = ServiceRegistry()
    registry.register(
        ServiceSpec(
            name="rucio",
            prefix="rucio",
            url="http://rucio.invalid/mcp",
            transport="http",
            required_permission="read_data",
            apply_namespace=False,
        )
    )
    assert registry.get_by_tool_prefix("rucio_list_dids") is not None
    assert registry.get_by_tool_prefix("rucio_list_dids").name == "rucio"


# ---------------------------------------------------------------------------
# Trust tier (Elwood v5 / Shannon) as structured data -- docs/architecture.md's
# "Trust tiers" section defines the vocabulary; ServiceSpec.trust_tier lets
# services.yaml/the chart *declare* a service's posture machine-checkably
# (re-review finding #5). The authoritative per-deployment assignment still
# lives in the GitOps repo (maniaclab/flux_apps#32); this field is the
# declaration, not the policy.
# ---------------------------------------------------------------------------


def test_trust_tier_defaults_to_none() -> None:
    spec = ServiceSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
    )
    assert spec.trust_tier is None


def test_load_parses_trust_tier(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
    trust_tier: service-tier
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.trust_tier == "service-tier"


def test_load_defaults_trust_tier_none_when_absent(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.trust_tier is None


def test_spec_rejects_unknown_trust_tier() -> None:
    """A typo'd tier must fail loudly, not silently stick -- __post_init__
    validates against the closed Elwood vocabulary."""
    with pytest.raises(ValueError, match="trust_tier"):
        ServiceSpec(
            name="example",
            prefix="example",
            url="http://example.invalid/mcp",
            transport="http",
            required_permission="__none__",
            trust_tier="platform-tier",  # type: ignore[arg-type]  # not an Elwood tier
        )


def test_load_rejects_unknown_trust_tier(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
    trust_tier: bogus-tier
"""
    )
    registry = ServiceRegistry()
    with pytest.raises(ValueError, match="trust_tier"):
        registry.load(str(services_file))


def test_builtin_gateway_service_is_infrastructure_tier() -> None:
    """The broker is infrastructure-tier (docs/architecture.md's "The broker
    is infrastructure-tier"): it holds the identity-token signing key and the
    token store, so its own builtin service entry declares that posture as the
    first concrete instance of the field."""
    registry = ServiceRegistry()
    spec = registry.get(BUILTIN_SERVICE_NAME)
    assert spec is not None
    assert spec.trust_tier == "infrastructure-tier"


@pytest.mark.parametrize(
    ("name", "tier"),
    [
        ("rucio", "user-tier"),
        ("ami", "user-tier"),
        ("atlasopenmagic", "service-tier"),
        ("af-jupyterlab-mcp", "service-tier"),
        ("af-filesystem-mcp", "user-tier"),
        ("monitoring", "service-tier"),
        ("docs", "user-tier"),
    ],
)
def test_shipped_services_declare_trust_tier(name: str, tier: str) -> None:
    """The reference services.yaml classifies each entry per the Trust tiers
    doc: external-fronting / shared-infrastructure backends are service-tier;
    per-user own-resource read (filesystem) and __none__ read-only (docs) are
    user-tier."""
    registry = ServiceRegistry()
    registry.load(str(SHIPPED_SERVICES))
    spec = registry.get(name)
    assert spec is not None
    assert spec.trust_tier == tier


# ---------------------------------------------------------------------------
# Model-facing per-service policy (agent_policy) -- the "dual enforcement"
# (Elwood v5 re-review finding #6) model-facing half. DISTINCT from the
# technical permission gate: agent_policy is guidance the LLM agent reads and
# reasons over, NOT an access-control boundary. It is also distinct from
# `description` (user-facing catalog UX).
# ---------------------------------------------------------------------------


def test_agent_policy_defaults_to_none() -> None:
    spec = ServiceSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
    )
    assert spec.agent_policy is None


def test_load_parses_agent_policy(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
    agent_policy: "Read-only; safe to call without confirmation."
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.agent_policy == "Read-only; safe to call without confirmation."


def test_load_defaults_agent_policy_none_when_absent(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.agent_policy is None


def test_builtin_gateway_service_declares_an_agent_policy() -> None:
    """The builtin af-mcp service is the model's entry point for the identity
    and catalog methods, so it carries model-facing guidance of its own."""
    registry = ServiceRegistry()
    spec = registry.get(BUILTIN_SERVICE_NAME)
    assert spec is not None
    assert spec.agent_policy is not None
    assert spec.agent_policy.strip() != ""


@pytest.mark.parametrize(
    "name",
    ["rucio", "ami", "af-jupyterlab-mcp", "af-filesystem-mcp", "docs"],
)
def test_shipped_services_declare_agent_policy(name: str) -> None:
    """The reference services.yaml carries model-facing guidance for each
    service the agent should reason over before calling its tools."""
    registry = ServiceRegistry()
    registry.load(str(SHIPPED_SERVICES))
    spec = registry.get(name)
    assert spec is not None
    assert spec.agent_policy is not None
    assert spec.agent_policy.strip() != ""


def test_link_identity_tool_name_is_reserved_diagnostic_tool() -> None:
    """af_link_identity (stage 1 of the elicitation/link-identity design) is
    a broker-native diagnostic tool like the other af_* methods -- it must be
    in DIAGNOSTIC_TOOL_NAMES so middleware special-cases it as always-callable,
    no credential, no ProxyProvider, the same as af_whoami/af_list_identities/
    af_list_mcp_servers/af_usage."""
    assert LINK_IDENTITY_TOOL_NAME == "af_link_identity"
    assert LINK_IDENTITY_TOOL_NAME in DIAGNOSTIC_TOOL_NAMES


def test_identity_provider_url_builds_portal_deep_link() -> None:
    settings = Settings(
        oidc_issuer="https://issuer.example", oidc_audience="test-audience"
    )
    url = identity_provider_url(settings, "atlas-iam")
    assert url == f"{settings.portal_url}/identities#identity-card-atlas-iam"


def test_identity_provider_url_strips_trailing_slash_from_portal_url() -> None:
    settings = Settings(
        oidc_issuer="https://issuer.example",
        oidc_audience="test-audience",
        portal_url="https://mcp-portal.af.uchicago.edu/",
    )
    url = identity_provider_url(settings, "x509")
    assert url == "https://mcp-portal.af.uchicago.edu/identities#identity-card-x509"


# ---------------------------------------------------------------------------
# Audience (issue #257): the `aud` an AF-native backend validates the broker
# identity token against. Split from `name` so a service can be renamed (its
# registry/catalog/audit identity) without moving the cross-system wire
# contract every backend checks. `effective_audience` is `audience or name`,
# so an omitted audience keeps the historical name-is-audience behavior.
# ---------------------------------------------------------------------------


def test_audience_defaults_to_none_and_effective_falls_back_to_name() -> None:
    spec = ServiceSpec(
        name="ami_service",
        prefix="ami",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
    )
    assert spec.audience is None
    assert spec.effective_audience == "ami_service"


def test_effective_audience_uses_explicit_audience_when_set() -> None:
    spec = ServiceSpec(
        name="ami_service",
        prefix="ami",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
        audience="ami-mcp",
    )
    assert spec.effective_audience == "ami-mcp"


def test_load_parses_audience(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: ami_service
    prefix: ami
    url: "http://example.invalid/mcp"
    required_permission: __none__
    audience: ami-mcp
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("ami_service")
    assert spec is not None
    assert spec.audience == "ami-mcp"
    assert spec.effective_audience == "ami-mcp"


def test_load_defaults_audience_none_when_absent(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: example
    prefix: example
    url: "http://example.invalid/mcp"
    required_permission: __none__
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("example")
    assert spec is not None
    assert spec.audience is None
    assert spec.effective_audience == "example"


# ---------------------------------------------------------------------------
# requires_posix (issue #257): does the broker stamp the caller's
# directory-resolved uid/gid/unixname into this backend's identity token (and
# 404 if the caller has none)? A per-service backend requirement -- moved here
# from the broker-issued provider's targetOptions so every token property of a
# service lives on the service entry.
# ---------------------------------------------------------------------------


def test_requires_posix_defaults_false() -> None:
    spec = ServiceSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
    )
    assert spec.requires_posix is False


def test_load_parses_requires_posix(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: filesystem_service
    prefix: fs
    url: "http://example.invalid/mcp"
    required_permission: __none__
    requires_posix: true
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("filesystem_service")
    assert spec is not None
    assert spec.requires_posix is True


@pytest.mark.parametrize("name", ["af-jupyterlab-mcp", "af-filesystem-mcp"])
def test_shipped_posix_backends_require_posix(name: str) -> None:
    """The reference broker-issued backends that act as the POSIX user
    (filesystem reads home dirs; jupyterlab launches as the user) declare
    requires_posix; a metadata backend must not, to avoid leaking uid/gid."""
    registry = ServiceRegistry()
    registry.load(str(SHIPPED_SERVICES))
    spec = registry.get(name)
    assert spec is not None
    assert spec.requires_posix is True


def test_shipped_metadata_backend_does_not_require_posix() -> None:
    registry = ServiceRegistry()
    registry.load(str(SHIPPED_SERVICES))
    spec = registry.get("ami")
    assert spec is not None
    assert spec.requires_posix is False


# ---------------------------------------------------------------------------
# Per-tool required_permission: services.yaml's required_permission may be a
# dict mapping a tool's *native* (pre-namespace) name to a permission, so a
# service can require different permissions for different tools instead of
# one blanket value. `__default__` is an optional fallback for any tool not
# explicitly listed -- if it's absent, an unlisted tool is disabled entirely
# (opt-in only, so a forgotten entry can never silently under-gate a new
# tool). See docs/adding-a-service.md.
# ---------------------------------------------------------------------------


def test_namespaced_tool_name_applies_prefix_when_apply_namespace_true() -> None:
    spec = ServiceSpec(
        name="condor_service",
        prefix="condor",
        url="http://condor.invalid/mcp",
        transport="http",
        required_permission="submit_jobs",
        apply_namespace=True,
    )
    assert namespaced_tool_name(spec, "query_jobs") == "condor_query_jobs"


def test_namespaced_tool_name_returns_native_name_when_apply_namespace_false() -> None:
    spec = ServiceSpec(
        name="rucio",
        prefix="rucio",
        url="http://rucio.invalid/mcp",
        transport="http",
        required_permission="read_data",
        apply_namespace=False,
    )
    assert namespaced_tool_name(spec, "list_dids") == "list_dids"


def test_all_required_permissions_empty_when_omitted() -> None:
    spec = ServiceSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
    )
    assert spec.all_required_permissions() == set()


def test_all_required_permissions_excludes_none_sentinel_for_string_form() -> None:
    spec = ServiceSpec(
        name="example",
        prefix="example",
        url="http://example.invalid/mcp",
        transport="http",
        required_permission="__none__",
    )
    assert spec.all_required_permissions() == set()


def test_all_required_permissions_returns_single_value_for_string_form() -> None:
    spec = ServiceSpec(
        name="rucio",
        prefix="rucio",
        url="http://rucio.invalid/mcp",
        transport="http",
        required_permission="read_data",
    )
    assert spec.all_required_permissions() == {"read_data"}


def test_all_required_permissions_returns_every_dict_value() -> None:
    spec = ServiceSpec(
        name="condor_service",
        prefix="condor",
        url="http://condor.invalid/mcp",
        transport="http",
        required_permission={
            "__default__": "manage_jobs",
            "query_jobs": "read_monitoring",
        },
    )
    assert spec.all_required_permissions() == {"manage_jobs", "read_monitoring"}


def test_all_required_permissions_excludes_none_sentinel_values_in_dict_form() -> None:
    spec = ServiceSpec(
        name="condor_service",
        prefix="condor",
        url="http://condor.invalid/mcp",
        transport="http",
        required_permission={
            "__default__": "manage_jobs",
            "condor_doc_search": "__none__",
        },
    )
    assert spec.all_required_permissions() == {"manage_jobs"}


def test_load_parses_dict_form_required_permission(tmp_path: Path) -> None:
    services_file = tmp_path / "services.yaml"
    services_file.write_text(
        """
services:
  - name: condor_service
    prefix: condor
    url: "http://condor.invalid/mcp"
    required_permission:
      __default__: manage_jobs
      query_jobs: read_monitoring
"""
    )
    registry = ServiceRegistry()
    registry.load(str(services_file))
    spec = registry.get("condor_service")
    assert spec is not None
    assert spec.required_permission == {
        "__default__": "manage_jobs",
        "query_jobs": "read_monitoring",
    }


# ---------------------------------------------------------------------------
# ServiceRegistry.required_permission_for: O(1) exact-match resolution
# (tool name, else the service's own default/scalar, else disabled/open).
# ---------------------------------------------------------------------------


def _condor_spec(required_permission: object, **overrides: object) -> ServiceSpec:
    return ServiceSpec(
        name="condor_service",
        prefix="condor",
        url="http://condor.invalid/mcp",
        transport="http",
        required_permission=required_permission,  # type: ignore[arg-type]
        **overrides,  # type: ignore[arg-type]
    )


def test_required_permission_for_exact_tool_match() -> None:
    registry = ServiceRegistry()
    spec = _condor_spec({"__default__": "manage_jobs", "query_jobs": "read_monitoring"})
    registry.register(spec)
    assert (
        registry.required_permission_for("condor_query_jobs", spec) == "read_monitoring"
    )


def test_required_permission_for_falls_back_to_default() -> None:
    registry = ServiceRegistry()
    spec = _condor_spec({"__default__": "manage_jobs", "query_jobs": "read_monitoring"})
    registry.register(spec)
    assert registry.required_permission_for("condor_submit_job", spec) == "manage_jobs"


def test_required_permission_for_disabled_without_default_or_match() -> None:
    """No __default__ and this tool isn't listed -- opt-in-only means it's
    disabled, not silently open."""
    registry = ServiceRegistry()
    spec = _condor_spec({"query_jobs": "read_monitoring"})
    registry.register(spec)
    assert (
        registry.required_permission_for("condor_submit_job", spec)
        == DISABLED_PERMISSION
    )


def test_required_permission_for_open_when_field_omitted_entirely() -> None:
    """Distinct from the disabled case above: an omitted required_permission
    (not a dict at all) means the credential layer is the gate -- always
    open at the permission-check step, exactly as today."""
    registry = ServiceRegistry()
    spec = _condor_spec(None)
    registry.register(spec)
    assert registry.required_permission_for("condor_submit_job", spec) is None


def test_required_permission_for_string_form_applies_to_every_tool() -> None:
    registry = ServiceRegistry()
    spec = _condor_spec("submit_jobs")
    registry.register(spec)
    assert registry.required_permission_for("condor_query_jobs", spec) == "submit_jobs"
    assert registry.required_permission_for("condor_submit_job", spec) == "submit_jobs"


def test_required_permission_for_dict_keys_are_native_names_regardless_of_apply_namespace() -> (
    None
):
    """The same config key (the tool's native name) resolves correctly
    whether or not the service namespaces its tools -- the operator never
    has to think about the prefix when writing per-tool overrides."""
    registry = ServiceRegistry()
    namespaced = _condor_spec({"query_jobs": "read_monitoring"}, apply_namespace=True)
    registry.register(namespaced)
    assert (
        registry.required_permission_for("condor_query_jobs", namespaced)
        == "read_monitoring"
    )

    registry2 = ServiceRegistry()
    unnamespaced = ServiceSpec(
        name="rucio",
        prefix="rucio",
        url="http://rucio.invalid/mcp",
        transport="http",
        required_permission={"list_dids": "read_data"},
        apply_namespace=False,
    )
    registry2.register(unnamespaced)
    assert registry2.required_permission_for("list_dids", unnamespaced) == "read_data"


def test_register_rejects_colliding_tool_permission_keys_across_services() -> None:
    """Two services whose merged per-tool/default keys collide would make one
    service's permission silently win over the other's -- fail loud instead."""
    registry = ServiceRegistry()
    registry.register(_condor_spec("manage_jobs"))
    # A dict-form entry whose literal (already-namespaced) key collides with
    # another service's own name-as-default-key.
    other = ServiceSpec(
        name="collider",
        prefix="other",
        url="http://other.invalid/mcp",
        transport="http",
        required_permission={"condor_service": "read_data"},
        apply_namespace=False,
    )
    with pytest.raises(ValueError, match="condor_service"):
        registry.register(other)
