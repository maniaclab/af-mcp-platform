"""Compose the aggregator's model-facing instructions (dual enforcement, #6).

Enforcement on this platform is dual: a *technical* gate (the group-derived
permission check in the authorization middleware, which denies unauthorized
calls outright and remains authoritative) AND a *model-facing* policy layer --
guidance the LLM agent itself reads and reasons over. This module builds that
second layer: a platform preamble plus one policy line per service that
declares an ``agent_policy`` (mcp/registry.py's ``ServiceSpec.agent_policy``).
The result is passed as FastMCP's ``instructions`` on the aggregator (see
mcp/aggregator.py's ``build_aggregator``/``populate_aggregator``), which surface
it to clients in the MCP ``initialize`` response.

The model-facing layer is guidance, NOT an access-control boundary -- a
capable-but-adversarial model can ignore it. The technical gate is what
actually stops an unauthorized call; the instructions exist so a *cooperative*
agent behaves well (does not retry a denial, routes the user to link an
identity, confirms before mutating real facility state).

Kept a pure function of the registry so it is unit-testable without building a
whole server.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from af_mcp_broker.mcp.registry import ServiceRegistry

# The platform preamble: guidance that applies to every call through the
# gateway, independent of which service is targeted. The deny-is-policy and
# missing-credential-is-policy paragraphs are the actual conceptual deliverable
# of finding #6 -- they tell a cooperative agent how to interpret the two
# failure modes the technical gate produces.
_PLATFORM_PREAMBLE = """\
You are connected to the AF MCP gateway: a credential-brokering Model Context \
Protocol gateway that fronts many backend services (data management, metadata, \
filesystem, compute, documentation) behind a single endpoint. Each service's \
tools are namespaced by a service prefix (for example rucio_, fs_, jlab_).

Access to each service is authorization-gated by the caller's group-derived \
permissions, and some services additionally require the caller to have a \
linked identity or credential. Two failure modes are policy decisions, not \
transient errors -- do not retry them:

- A denial (the caller lacks the required permission) means the user is not \
authorized for that service. Tell them they lack access; do not retry the call.
- A missing-credential or not-linked failure means the user must link an \
identity first. Route them to the af_link_identity tool or the portal; do not \
retry the call.

Services also declare a trust tier: user-tier services act only with the \
caller's own per-user credentials, while service-tier and infrastructure-tier \
services touch shared facility infrastructure and warrant more caution. The \
per-service policies below are guidance you must respect when deciding whether \
and how to call each service's tools -- in particular, which operations are \
safe reads and which change real facility state and should be confirmed with \
the user first."""


def compose_agent_instructions(registry: ServiceRegistry) -> str:
    """Compose the aggregator's model-facing instructions from *registry*.

    Returns the platform preamble followed by one policy line per service that
    declares an ``agent_policy``; services with ``agent_policy=None`` are
    omitted. Pure function of the registry so ``build_aggregator`` can compose
    at construction and ``populate_aggregator`` can recompose once the real
    registry is loaded (the eager build starts with an empty one -- see app.py).
    """
    sections = [_PLATFORM_PREAMBLE]
    policy_lines = [
        f"- {spec.name}: {spec.agent_policy}"
        for spec in registry.all_services()
        if spec.agent_policy is not None
    ]
    if policy_lines:
        sections.append("Per-service policies:\n" + "\n".join(policy_lines))
    return "\n\n".join(sections)
