"""Cross-replica record of what the tool-listing lint last observed per service.

``EntitlementMiddleware`` lints a service's tool listing (annotation/policy
mismatches, tool-mapping drift) only when a caller lists that service through
one replica's ``/mcp``. Each replica therefore knew only what it had seen
itself, and the admin tables disagreed from one refresh to the next (#332).
``LintObservationStore`` keeps one record per service in ``SharedState``, so
whichever replica answers the admin page shows the same thing.

A record carries the time of the last observation, which distinguishes
"observed and clean" from "not observed" -- an empty table alone cannot. It
expires after ``retention_seconds``: a service nobody has listed for that long
reads as not observed rather than as clean on stale evidence. While the store
is down, writes and reads fall back to this replica's own observations
(``FallbackSharedState``), which is what the admin tables showed before.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

import structlog

from af_mcp_broker.mcp.registry import AnnotationMismatch, ToolMappingDrift
from af_mcp_broker.shared_state import FallbackSharedState

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from af_mcp_broker.shared_state import SharedState

# How long an observation stays readable without being refreshed.
LINT_OBSERVATION_TTL_SECONDS = 24 * 60 * 60

# An unchanged observation is rewritten at most this often, to refresh its
# timestamp and TTL without a store write on every tools/list.
_REFRESH_SECONDS = 5 * 60

logger = structlog.get_logger(__name__)


def _key(service: str) -> str:
    return f"lint-observation:{service}"


@dataclass(frozen=True)
class ServiceLintObservation:
    """What the lint found in one service's tool listing, and when."""

    service: str
    # Wall-clock epoch seconds of the last observation: it is compared across
    # replicas, so it cannot be a monotonic reading.
    observed_at: float
    annotation_mismatches: tuple[AnnotationMismatch, ...]
    tool_mapping_drift: ToolMappingDrift | None


class LintObservationStore:
    """Reads and writes ``ServiceLintObservation`` records in the shared store."""

    def __init__(
        self,
        shared_state: SharedState,
        *,
        ttl_seconds: float = LINT_OBSERVATION_TTL_SECONDS,
        refresh_seconds: float = _REFRESH_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._shared_state = FallbackSharedState(
            shared_state,
            component="lint_observations",
            effect=(
                "admin lint tables show only what this replica observed "
                "until the store recovers"
            ),
        )
        self._ttl_seconds = ttl_seconds
        self._refresh_seconds = refresh_seconds
        self._clock = clock
        # service -> (payload last written, when). Lets an unchanged
        # observation skip the write until it is due for a refresh.
        self._last_written: dict[str, tuple[str, float]] = {}

    @property
    def retention_seconds(self) -> float:
        """How long an observation stays readable without being refreshed."""
        return self._ttl_seconds

    async def observe(
        self,
        service: str,
        annotation_mismatches: Sequence[AnnotationMismatch],
        tool_mapping_drift: ToolMappingDrift | None,
    ) -> None:
        """Record that *service*'s listing was just linted with these findings."""
        findings = json.dumps(
            {
                "annotation_mismatches": [asdict(m) for m in annotation_mismatches],
                "tool_mapping_drift": (
                    asdict(tool_mapping_drift) if tool_mapping_drift else None
                ),
            },
            sort_keys=True,
        )
        now = self._clock()
        previous = self._last_written.get(service)
        if (
            previous is not None
            and previous[0] == findings
            and now - previous[1] < self._refresh_seconds
        ):
            return
        record = json.dumps({"observed_at": now, "findings": json.loads(findings)})
        await self._shared_state.set(_key(service), record, self._ttl_seconds)
        self._last_written[service] = (findings, now)

    async def get(self, service: str) -> ServiceLintObservation | None:
        """Return *service*'s last observation, or None if none is recorded (never observed, or expired)."""
        raw = await self._shared_state.get(_key(service))
        if raw is None:
            return None
        try:
            record = json.loads(raw)
            findings = record["findings"]
            drift = findings["tool_mapping_drift"]
            return ServiceLintObservation(
                service=service,
                observed_at=float(record["observed_at"]),
                annotation_mismatches=tuple(
                    AnnotationMismatch(**m) for m in findings["annotation_mismatches"]
                ),
                tool_mapping_drift=_drift_from_dict(drift) if drift else None,
            )
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning(
                "lint_observations.bad_record", service=service, error=str(exc)
            )
            return None


def _drift_from_dict(raw: dict[str, object]) -> ToolMappingDrift:
    # JSON has no tuples; the dataclass's list-valued fields are tuples.
    return ToolMappingDrift(
        **{k: tuple(v) if isinstance(v, list) else v for k, v in raw.items()}  # type: ignore[arg-type]
    )
