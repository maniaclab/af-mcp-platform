"""An absent entitlement policy is never replaced by an empty one."""

from __future__ import annotations

from dataclasses import fields

import pytest
from broker_state_helpers import make_broker_state

from af_mcp_broker.broker_state import BrokerState


def test_broker_state_cannot_be_built_without_a_policy() -> None:
    complete = make_broker_state()
    without_policy = {
        field.name: getattr(complete, field.name)
        for field in fields(BrokerState)
        if field.name != "entitlement_policy"
    }

    with pytest.raises(TypeError, match="entitlement_policy"):
        BrokerState(**without_policy)
