"""Integration tests: the admin lint tables answer the same from any replica (issue #332).

The real app boots with ``SHARED_STATE_URL`` pointing at a real redis server
(see the ``shared_state_url`` fixture). The "other replica" is a second
``LintObservationStore`` on its own store client.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from af_mcp_broker.mcp.lint_observations import LintObservationStore
from af_mcp_broker.mcp.registry import AnnotationMismatch
from af_mcp_broker.shared_state import RedisSharedState

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.usefixtures("unpinned_loggers")

_MISMATCH = AnnotationMismatch(
    service="rucio",
    tool="rucio_list_dids",
    declared_read_only_hint=False,
    resolved_action_type="read",
    resolved_via="permission",
    permission="read_data",
)


def test_an_observation_made_by_another_replica_shows_on_this_replicas_admin_page(
    monkeypatch: pytest.MonkeyPatch,
    app_client_factory: Callable[..., Any],
    shared_state_url: str,
    make_principal: Callable[..., Any],
) -> None:
    monkeypatch.setenv("SHARED_STATE_URL", shared_state_url)
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")

    async def observe_on_another_replica(*, clean: bool) -> None:
        state = RedisSharedState(shared_state_url)
        try:
            await LintObservationStore(state).observe(
                "rucio", () if clean else (_MISMATCH,), None
            )
        finally:
            await state.close()

    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["af-admins"])

        before = client.get("/v1/admin/annotation-mismatches").json()
        assert before["mismatches"] == []
        assert {s["last_observed"] for s in before["services"]} == {None}

        asyncio.run(observe_on_another_replica(clean=False))
        after = client.get("/v1/admin/annotation-mismatches").json()

        asyncio.run(observe_on_another_replica(clean=True))  # leave no finding behind

    assert [m["tool"] for m in after["mismatches"]] == ["rucio_list_dids"]
    rucio = next(s for s in after["services"] if s["service"] == "rucio")
    assert rucio["last_observed"] is not None
