"""Tests for ServiceSpec/ServiceRegistry — the config-driven backend catalog
that both /v1/catalog and the /mcp aggregator's routing read from.
"""

from __future__ import annotations

from pathlib import Path

from af_mcp_broker.mcp.registry import (
    _MAX_CALLER_LIST_FAILURES,
    ServiceRegistry,
    ServiceSpec,
)

SHIPPED_SERVICES = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "af_mcp_broker"
    / "mcp"
    / "services.yaml"
)


def test_backend_spec_description_and_display_name_default_to_empty() -> None:
    spec = ServiceSpec(
        name="rucio",
        prefix="rucio",
        url="http://rucio-mcp/mcp",
        transport="http",
        required_permission="read_data",
    )
    assert spec.description == ""
    assert spec.display_name == ""


def test_registry_load_reads_description_and_display_name_from_yaml(
    tmp_path: Path,
) -> None:
    backends_yaml = tmp_path / "services.yaml"
    backends_yaml.write_text(
        "services:\n"
        "  - name: rucio\n"
        "    prefix: rucio\n"
        "    url: http://rucio-mcp/mcp\n"
        "    required_permission: read_data\n"
        "    display_name: Rucio\n"
        "    description: ATLAS distributed data management\n"
    )
    registry = ServiceRegistry()
    registry.load(str(backends_yaml))
    spec = registry.get("rucio")
    assert spec is not None
    assert spec.display_name == "Rucio"
    assert spec.description == "ATLAS distributed data management"


def test_shipped_backends_carry_display_name_and_description() -> None:
    """The shipped services.yaml must not ship description-less entries
    forever — every entry gets a real display_name/description."""
    registry = ServiceRegistry()
    registry.load(str(SHIPPED_SERVICES))
    for spec in registry.all_services():
        assert spec.display_name, f"{spec.name} is missing display_name"
        assert spec.description, f"{spec.name} is missing description"


def test_backend_spec_required_permission_defaults_to_none() -> None:
    """Omitted required_permission means "no permission gate; the credential
    layer is the gate instead" (issue #60) -- distinct from the "__none__"
    sentinel, which is an explicit open-access opt-in."""
    spec = ServiceSpec(
        name="rucio",
        prefix="rucio",
        url="http://rucio-mcp/mcp",
        transport="http",
    )
    assert spec.required_permission is None


def test_registry_load_omitted_required_permission_is_none(tmp_path: Path) -> None:
    """services.yaml entries that omit required_permission must load as None,
    not silently default to "__none__" (open access) -- that would collapse
    the "credential layer is the gate" case into the "no gate at all" case."""
    backends_yaml = tmp_path / "services.yaml"
    backends_yaml.write_text(
        "services:\n  - name: rucio\n    prefix: rucio\n    url: http://rucio-mcp/mcp\n"
    )
    registry = ServiceRegistry()
    registry.load(str(backends_yaml))
    spec = registry.get("rucio")
    assert spec is not None
    assert spec.required_permission is None


def test_recent_list_failure_absent_by_default() -> None:
    """A backend with no recorded tools/list failure reports None -- the
    common case for a healthy backend (issue #123's /v1/catalog status)."""
    registry = ServiceRegistry()
    assert registry.recent_list_failure("rucio", "alice") is None


def test_recent_list_failure_reflects_last_recorded_reason() -> None:
    """record_list_failure() is how the aggregator's _ObservableProxyProvider
    (see aggregator.py's _classify_list_failure) reports a classified
    tools/list failure so /v1/catalog can factor it into a backend's status
    without an extra live probe (issue #123). Last write wins -- no history
    is kept, only the most recent reason."""
    registry = ServiceRegistry()
    registry.record_list_failure("rucio", "unauthorized", "alice")
    assert registry.recent_list_failure("rucio", "alice") == "unauthorized"
    registry.record_list_failure("rucio", "unavailable", "alice")
    assert registry.recent_list_failure("rucio", "alice") == "unavailable"


def test_clear_list_failure_removes_a_recorded_reason() -> None:
    """clear_list_failure() is how a successful tools/list (aggregator.py's
    _ObservableProxyProvider) un-records a stale failure once a backend
    recovers -- without it, recent_list_failure() would report a backend
    "unavailable" forever after a single transient blip."""
    registry = ServiceRegistry()
    registry.record_list_failure("rucio", "unavailable", "alice")
    registry.clear_list_failure("rucio", "alice")
    assert registry.recent_list_failure("rucio", "alice") is None


def test_clear_list_failure_is_a_noop_when_nothing_was_recorded() -> None:
    registry = ServiceRegistry()
    registry.clear_list_failure("rucio", "alice")  # must not raise
    assert registry.recent_list_failure("rucio", "alice") is None


def test_caller_specific_list_failure_is_not_visible_to_other_subjects() -> None:
    """ "unauthorized"/"not_linked" describe one caller's credential, so a
    record made for alice must never be reported for bob."""
    registry = ServiceRegistry()
    registry.record_list_failure("rucio", "unauthorized", "alice")
    assert registry.recent_list_failure("rucio", "alice") == "unauthorized"
    assert registry.recent_list_failure("rucio", "bob") is None


def test_caller_specific_list_failure_is_scoped_to_its_service() -> None:
    registry = ServiceRegistry()
    registry.record_list_failure("rucio", "not_linked", "alice")
    assert registry.recent_list_failure("panda", "alice") is None


def test_service_wide_list_failure_is_visible_to_every_subject() -> None:
    """ "unavailable" is about the backend, true for every caller."""
    registry = ServiceRegistry()
    registry.record_list_failure("rucio", "unavailable", "alice")
    assert registry.recent_list_failure("rucio", "alice") == "unavailable"
    assert registry.recent_list_failure("rucio", "bob") == "unavailable"


def test_successful_listing_clears_only_that_subjects_caller_specific_record() -> None:
    registry = ServiceRegistry()
    registry.record_list_failure("rucio", "unauthorized", "alice")
    registry.record_list_failure("rucio", "unauthorized", "bob")
    registry.clear_list_failure("rucio", "alice")
    assert registry.recent_list_failure("rucio", "alice") is None
    assert registry.recent_list_failure("rucio", "bob") == "unauthorized"


def test_successful_listing_clears_the_service_wide_record_for_everyone() -> None:
    registry = ServiceRegistry()
    registry.record_list_failure("rucio", "unavailable", "alice")
    registry.clear_list_failure("rucio", "bob")
    assert registry.recent_list_failure("rucio", "alice") is None


def test_caller_specific_list_failure_without_a_subject_is_not_recorded() -> None:
    """A listing with no identifiable caller has nobody to show a
    caller-specific reason to; recording it service-wide would reintroduce
    the cross-caller leak."""
    registry = ServiceRegistry()
    registry.record_list_failure("rucio", "unauthorized", None)
    assert registry.recent_list_failure("rucio", "alice") is None


def test_caller_specific_list_failures_are_bounded() -> None:
    """Per-subject records are in-process memory keyed by subject, so they
    are capped; the least recently recorded entry is evicted first."""
    registry = ServiceRegistry()
    for i in range(_MAX_CALLER_LIST_FAILURES + 1):
        registry.record_list_failure("rucio", "unauthorized", f"user-{i}")
    assert registry.recent_list_failure("rucio", "user-0") is None
    assert (
        registry.recent_list_failure("rucio", f"user-{_MAX_CALLER_LIST_FAILURES}")
        == "unauthorized"
    )
    assert registry.recent_list_failure("rucio", "user-1") == "unauthorized"
