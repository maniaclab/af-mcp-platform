from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from af_mcp_broker.authorization import EntitlementPolicy
from af_mcp_broker.mcp.aggregator import _require_entitled_list_principal
from af_mcp_broker.mcp.errors import NotEntitledForListingError
from af_mcp_broker.mcp.registry import ServiceSpec
from af_mcp_broker.principal import Principal


class _StateContext:
    """The slice of fastmcp's Context the list-time preamble reads."""

    def __init__(self, principal: Principal | None) -> None:
        self._principal = principal

    async def get_state(self, key: str) -> Any:
        assert key == "principal"
        return self._principal


_SPEC = ServiceSpec(
    name="redeemer",
    prefix="redeemer",
    url="http://localhost:1/mcp",
    transport="http",
    required_permission="read_data",
    auth_type="krb5",
)
_POLICY = EntitlementPolicy(group_permissions={"atlas": ["read_data"]})


def _principal(groups: list[str]) -> Principal:
    return Principal(
        subject="user-erin",
        email="erin@example.com",
        uid=None,
        gid=None,
        unixname=None,
        groups=groups,
        raw_token=SecretStr("unused"),
    )


async def test_missing_principal_is_an_internal_error_not_a_bare_request() -> None:
    with pytest.raises(RuntimeError, match=r"redeemer.*no authenticated principal"):
        await _require_entitled_list_principal(_StateContext(None), _SPEC, _POLICY)  # type: ignore[arg-type]


async def test_unentitled_principal_raises_not_entitled() -> None:
    with pytest.raises(NotEntitledForListingError, match="redeemer"):
        await _require_entitled_list_principal(
            _StateContext(_principal([])),  # type: ignore[arg-type]
            _SPEC,
            _POLICY,
        )


async def test_entitled_principal_is_returned() -> None:
    principal = _principal(["atlas"])
    assert (
        await _require_entitled_list_principal(
            _StateContext(principal),  # type: ignore[arg-type]
            _SPEC,
            _POLICY,
        )
        is principal
    )
