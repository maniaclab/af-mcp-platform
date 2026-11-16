"""Every structlog call in ``broker/src`` follows the logging conventions in CLAUDE.md.

Operators query on event names and field names, so the rules are checked
statically over every ``logger.<level>("event", field=...)`` call:

- the event is a dotted ``component.action`` literal;
- no field uses a name the conventions replace (``principal_id`` for
  ``subject``, ``message`` for ``detail``, ...) or that could carry a secret;
- an event named ``*failed`` is never logged below ``warning``.

The ``_*_OUTLIERS`` sets hold the calls that do not follow the rules yet.
Each set must equal what the scan finds, so a new outlier fails the test and
a fixed one must leave the set.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "af_mcp_broker"

_LEVELS = {"debug", "info", "warning", "warn", "error", "exception", "critical"}
# Levels below which a ``*failed`` event may not be logged.
_BELOW_WARNING = {"debug", "info"}

_EVENT_PATTERN = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")

# The audit line's shape is the audit contract; its event is the bare word.
_AUDIT_EVENT = "audit"

# Names the conventions replace, and names that could carry a secret or a
# payload. ``subject``, ``detail``, ``correlation_id`` etc. are the standard
# fields (CLAUDE.md, "Logging conventions").
_FORBIDDEN_FIELDS = frozenset(
    {
        "principal_id",
        "principal_sub",
        "user",
        "message",
        "request_id",
        "token",
        "access_token",
        "refresh_token",
        "password",
        "passphrase",
        "secret",
        "authorization",
        "cookie",
        "keytab",
        "body",
        "headers",
        "query",
        "query_string",
    }
)

# Calls whose event is built at runtime. ``(file, source of the first
# argument)``. ``self._event`` is ``f"{component}.shared_state_unavailable"``,
# which follows the pattern by construction.
_DYNAMIC_EVENTS = frozenset({("shared_state.py", "self._event")})

_EVENT_OUTLIERS: frozenset[str] = frozenset(
    {
        "af_mcp_broker_started",
        "af_mcp_broker_stopped",
        "authorize_decision",
        "cimd_client_resolved",
        "credmon_config_invalid",
        "dev_auth_bypass_active",
        "dev_auth_bypass_used",
        "http_exception",
        "identity_unlink_completed",
        "identity_unlink_requested",
        "image_dimensions_unreadable",
        "internal_validation_error",
        "jwks_cache_prime_failed",
        "jwks_cache_primed",
        "jwks_cache_refreshed",
        "jwks_fetch_failed",
        "jwks_refresh_failed_serving_stale",
        "jwt_audience_mismatch",
        "jwt_expired",
        "jwt_validation_failed",
        "krb5_vault_store_wired",
        "maintenance_mode_changed",
        "maintenance_mode_config_invalid",
        "maintenance_mode_in_memory_multi_replica",
        "maintenance_store_unavailable",
        "mcp_identity_validation_failed",
        "mcp_oauth_config_invalid",
        "mcp_principal_directory_unavailable",
        "mcp_stateful_multi_replica",
        "metering_audit_write_failed",
        "metering_measurement_failed",
        "metrics_server_started",
        "oauth21_config_invalid",
        "otel_metrics_initialized",
        "otel_metrics_record_failed",
        "otel_metrics_shutdown_failed",
        "pat_minted_without_expiry",
        "per_replica_state",
        "prometheus_instrumentator_not_installed",
        "rate_limit_exceeded",
        "readyz_jwks_check_failed",
        "servicex_vault_store_wired",
        "token_estimate_encoding_unavailable",
        "token_mint_duplicate_name",
        "tool_result_measurement_failed",
        "tracing_initialized",
        "unknown_content_type",
        "usage_event_emit_failed",
        "usage_event_shutdown_failed",
        "usage_record_batch_failed",
        "usage_record_failed",
        "usage_rollup_completed",
        "usage_rollup_failed",
        "usage_store_config_invalid",
        "vault_config_invalid",
        "x509_voms_service_mode",
    }
)
# event -> fields of it that use a forbidden name
_FIELD_OUTLIERS: dict[str, frozenset[str]] = {
    "catalog.service_status_flagged": frozenset({"request_id"}),
    "dev_auth_bypass_active": frozenset({"message"}),
    "htcondor_api.store.failed": frozenset({"user"}),
    "htcondor_api.store.unreachable": frozenset({"user"}),
    "maintenance_mode_in_memory_multi_replica": frozenset({"message"}),
    "mcp_oauth.keycloak_login_succeeded": frozenset({"principal_id"}),
    "mcp_oauth.pat_minted": frozenset({"principal_id"}),
    "mcp_stateful_multi_replica": frozenset({"message"}),
    "metering_audit_write_failed": frozenset({"principal_sub"}),
    "pat_minted_without_expiry": frozenset({"principal_id"}),
    "per_replica_state": frozenset({"message"}),
    "principal_cache.backend_read_failed_treated_as_miss": frozenset({"principal_id"}),
    "principal_cache.persist_failed": frozenset({"principal_id"}),
    "principal_cache.principal_rejected": frozenset({"principal_id"}),
    "principal_cache.refresh_failed_serving_stale": frozenset({"principal_id"}),
    "principal_cache.rejection_persist_failed": frozenset({"principal_id"}),
    "principal_cache.resolve_failed_no_cached_value": frozenset({"principal_id"}),
    "principal_cache.stale_past_max_serving_failed_closed": frozenset({"principal_id"}),
    "token_mint_duplicate_name": frozenset({"principal_id"}),
    "token_registry.deleted": frozenset({"principal_id"}),
    "token_registry.minted": frozenset({"principal_id"}),
    "token_registry.revoked": frozenset({"principal_id"}),
    "token_registry.touch_last_used_retry_budget_exceeded": frozenset({"principal_id"}),
}
_LEVEL_OUTLIERS: frozenset[str] = frozenset({"catalog.tools_list_failed"})


@dataclass(frozen=True)
class LogCall:
    file: str
    line: int
    level: str | None  # None when the level is chosen at runtime
    event: str | None  # None when the event is not a literal
    event_source: str
    fields: tuple[str, ...]


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    return {
        node.targets[0].id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }


def _is_log_call(call: ast.Call) -> tuple[bool, str | None]:
    """Return (is a log call, its level). ``log(...)`` is a logger method chosen into a local, so its level is unknown."""
    func = call.func
    if isinstance(func, ast.Name) and func.id in {"log", "_log"}:
        return True, None
    if (
        isinstance(func, ast.Attribute)
        and func.attr in _LEVELS
        and "log" in ast.unparse(func.value).lower()
    ):
        return True, func.attr
    return False, None


def scan_source(source: str, file: str = "<memory>") -> list[LogCall]:
    """Return every structlog call in *source* that passes an event as its first argument."""
    tree = ast.parse(source)
    constants = _module_string_constants(tree)
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        is_log, level = _is_log_call(node)
        if not is_log:
            continue
        first = node.args[0]
        event: str | None = None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            event = first.value
        elif isinstance(first, ast.Name) and first.id in constants:
            event = constants[first.id]
        calls.append(
            LogCall(
                file=file,
                line=node.lineno,
                level=level,
                event=event,
                event_source=ast.unparse(first),
                fields=tuple(k.arg for k in node.keywords if k.arg is not None),
            )
        )
    return calls


def _all_calls() -> list[LogCall]:
    return [
        call
        for path in sorted(_SRC.rglob("*.py"))
        for call in scan_source(path.read_text(), str(path.relative_to(_SRC)))
    ]


def _event_violations(calls: list[LogCall]) -> set[str]:
    return {
        call.event if call.event is not None else f"{call.file}: {call.event_source}"
        for call in calls
        if call.event != _AUDIT_EVENT
        and (call.event is None or not _EVENT_PATTERN.fullmatch(call.event))
        and (call.file, call.event_source) not in _DYNAMIC_EVENTS
    }


def _field_violations(calls: list[LogCall]) -> dict[str, frozenset[str]]:
    found: dict[str, set[str]] = {}
    for call in calls:
        bad = _FORBIDDEN_FIELDS.intersection(call.fields)
        if bad:
            found.setdefault(call.event or call.event_source, set()).update(bad)
    return {event: frozenset(fields) for event, fields in found.items()}


def _level_violations(calls: list[LogCall]) -> set[str]:
    return {
        call.event
        for call in calls
        if call.event is not None
        and call.level in _BELOW_WARNING
        and call.event.rsplit(".", 1)[-1].endswith("failed")
    }


def test_scan_finds_the_calls() -> None:
    calls = _all_calls()
    assert len(calls) > 150
    assert any(call.event == "http.request.finished" for call in calls)


def test_event_names_are_dotted_literals() -> None:
    assert _event_violations(_all_calls()) == _EVENT_OUTLIERS


def test_fields_use_standard_names() -> None:
    assert _field_violations(_all_calls()) == _FIELD_OUTLIERS


def test_failed_events_log_at_warning_or_above() -> None:
    assert _level_violations(_all_calls()) == _LEVEL_OUTLIERS


def test_scanner_flags_each_kind_of_outlier() -> None:
    calls = scan_source(
        """
EVENT = 'flat_event'
logger.info('flat_name', subject=s)
logger.info(EVENT)
logger.warning(f'{x}.thing')
logger.info('jwks.fetch_failed', principal_id=p, message='m')
log('http.exception', status_code=500)
logger.error('audit')
"""
    )
    assert _event_violations(calls) == {
        "flat_name",
        "flat_event",
        "<memory>: f'{x}.thing'",
    }
    assert _field_violations(calls) == {
        "jwks.fetch_failed": frozenset({"principal_id", "message"})
    }
    assert _level_violations(calls) == {"jwks.fetch_failed"}
