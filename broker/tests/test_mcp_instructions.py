from __future__ import annotations

from typing import Any

from af_mcp_broker.mcp.instructions import compose_agent_instructions
from af_mcp_broker.mcp.registry import ServiceRegistry, ServiceSpec


def _spec(**overrides: Any) -> ServiceSpec:
    defaults: dict[str, Any] = {
        "name": "example",
        "prefix": "example",
        "url": "http://example.invalid/mcp",
        "transport": "http",
        "required_permission": "__none__",
    }
    defaults.update(overrides)
    return ServiceSpec(**defaults)


def test_compose_includes_platform_preamble() -> None:
    """The composed instructions always carry the platform preamble, even for
    a bare registry (the builtin af-mcp service is always present)."""
    text = compose_agent_instructions(ServiceRegistry())
    assert text.strip() != ""
    # The core conceptual deliverable: a denial is a policy decision, not a
    # transient error the agent should retry.
    lowered = text.lower()
    assert "retry" in lowered
    assert "af_link_identity" in text


def test_compose_includes_a_services_agent_policy() -> None:
    registry = ServiceRegistry()
    registry.register(
        _spec(name="widgets", prefix="widgets", agent_policy="Widgets are read-only.")
    )
    text = compose_agent_instructions(registry)
    assert "widgets" in text
    assert "Widgets are read-only." in text


def test_compose_omits_services_without_agent_policy() -> None:
    registry = ServiceRegistry()
    registry.register(_spec(name="withpolicy", prefix="wp", agent_policy="Say hi."))
    registry.register(_spec(name="nopolicy", prefix="np", agent_policy=None))
    text = compose_agent_instructions(registry)
    assert "Say hi." in text
    # A service with no agent_policy contributes no per-service policy line.
    assert "nopolicy" not in text


def test_compose_is_deterministic() -> None:
    registry = ServiceRegistry()
    registry.register(_spec(name="a", prefix="a", agent_policy="Policy A."))
    registry.register(_spec(name="b", prefix="b", agent_policy="Policy B."))
    assert compose_agent_instructions(registry) == compose_agent_instructions(registry)
