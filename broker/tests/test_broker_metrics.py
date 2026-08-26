"""Unit tests for the custom Prometheus metrics defined in ``metrics.py``.

These tests check the *shape* of each metric (name, label set) rather than
who increments it -- increment behavior is covered where each metric is
actually incremented (``test_mcp_middleware_authorization.py``,
``test_credential_cache.py``, ``test_x509.py``). The label-set assertions
here exist specifically to catch a regression where someone adds an
unbounded label (a token, jti, request_id, or raw tool argument) to one of
these counters -- see the cardinality policy in ``metrics.py``'s module
docstring.
"""

from __future__ import annotations

from af_mcp_broker import metrics

# Label names that must never appear on any custom metric -- each is either
# unbounded (attacker- or session-influenced), a secret, or identifies a
# specific user. Per-user labels are forbidden outright (not just unbounded
# ones): the audit log already records every invocation with the caller's
# identity attached, at full fidelity and behind access control, whereas
# Prometheus series are long-retained and broadly readable via Grafana -- a
# per-user label here would duplicate the audit log at worse fidelity while
# adding storage cost and a privacy surface. See metrics.py's module
# docstring.
_FORBIDDEN_LABEL_NAMES = {
    "jti",
    "token",
    "access_token",
    "request_id",
    "sub",
    "subject",
    "password",
    "passphrase",
    "secret",
    "args",
    "args_summary",
    "identity",
    "username",
    "unixname",
}


def _all_counters() -> list:
    return [
        metrics.tool_invocations_total,
        metrics.tool_invocations_denied_total,
        metrics.tool_invocations_unmapped_total,
        metrics.credential_cache_hits_total,
        metrics.credential_cache_misses_total,
        metrics.x509_proxy_mints_total,
        metrics.metering_queue_overflow_total,
        metrics.metering_worker_processed_total,
        metrics.metering_worker_errors_total,
        metrics.metering_records_missing_measurements_total,
    ]


def _full_name(counter) -> str:
    """The name as actually scraped -- prometheus_client's Counter strips a
    trailing ``_total`` off ``_name`` internally and re-appends it when
    collecting samples, so ``_name`` alone is not what shows up on the wire.
    """
    return counter._name + "_total"


def test_no_metric_carries_a_forbidden_label():
    for counter in _all_counters():
        offending = _FORBIDDEN_LABEL_NAMES & set(counter._labelnames)
        assert not offending, (
            f"{_full_name(counter)} has forbidden label(s): {offending}"
        )


def test_tool_invocations_total_labeled_by_service_tool_action_type():
    """No identity label -- per-user counting was dropped in favor of the
    audit log; see the module docstring's cardinality policy."""
    assert _full_name(metrics.tool_invocations_total) == "af_mcp_tool_invocations_total"
    assert set(metrics.tool_invocations_total._labelnames) == {
        "service",
        "tool",
        "action_type",
    }


def test_tool_invocations_denied_total_labeled_by_service_action_type():
    assert (
        _full_name(metrics.tool_invocations_denied_total)
        == "af_mcp_tool_invocations_denied_total"
    )
    assert set(metrics.tool_invocations_denied_total._labelnames) == {
        "service",
        "action_type",
    }


def test_tool_invocations_unmapped_total_has_no_labels():
    """Tool name is client-supplied and unbounded when it matches no
    registered service prefix -- this counter must never be labeled by it."""
    assert (
        _full_name(metrics.tool_invocations_unmapped_total)
        == "af_mcp_tool_invocations_unmapped_total"
    )
    assert metrics.tool_invocations_unmapped_total._labelnames == ()


def test_credential_cache_counters_labeled_by_target():
    assert (
        _full_name(metrics.credential_cache_hits_total)
        == "af_mcp_credential_cache_hits_total"
    )
    assert metrics.credential_cache_hits_total._labelnames == ("target",)
    assert (
        _full_name(metrics.credential_cache_misses_total)
        == "af_mcp_credential_cache_misses_total"
    )
    assert metrics.credential_cache_misses_total._labelnames == ("target",)


def test_tool_duration_seconds_labeled_by_service_tool_action_type():
    """Same label set as tool_invocations_total -- and deliberately NOT
    outcome (the audit log is the per-outcome source of truth) and never an
    identity label; see the module docstring's cardinality policy."""
    assert metrics.tool_duration_seconds._name == "af_mcp_tool_duration_seconds"
    assert set(metrics.tool_duration_seconds._labelnames) == {
        "service",
        "tool",
        "action_type",
    }
    assert not _FORBIDDEN_LABEL_NAMES & set(metrics.tool_duration_seconds._labelnames)
    # Buckets sized for tool calls that can include credential minting via
    # ephemeral k8s Jobs (tens of seconds to minutes), plus the implicit +Inf.
    assert metrics.tool_duration_seconds._upper_bounds == [
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
        30.0,
        60.0,
        120.0,
        300.0,
        float("inf"),
    ]


def test_metering_metrics_have_no_labels():
    """Every metering pipeline metric (counters and worker-health gauges
    alike) is deliberately unlabeled -- per-record dimensions live in the
    audit log; see the module docstring's cardinality policy."""
    for metric in (
        metrics.metering_queue_overflow_total,
        metrics.metering_queue_depth,
        metrics.metering_queue_delay_seconds,
        metrics.metering_worker_processed_total,
        metrics.metering_worker_errors_total,
        metrics.metering_records_missing_measurements_total,
    ):
        assert metric._labelnames == ()


def test_x509_proxy_mints_total_has_no_labels():
    """No username label -- mints are rare/expensive but still per-user
    events, and per-user labels are forbidden outright; see the module
    docstring's cardinality policy."""
    assert _full_name(metrics.x509_proxy_mints_total) == "af_mcp_x509_proxy_mints_total"
    assert metrics.x509_proxy_mints_total._labelnames == ()
