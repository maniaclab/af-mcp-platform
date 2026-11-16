"""Settings parsing for the e2e flow in tests/e2e/test_mcp_flow.py."""

from __future__ import annotations

from typing import Final


class BearerToken:
    """A bearer token that never appears in a repr, a str or a traceback.

    pytest prints a failing fixture's arguments in its traceback, so a plain
    ``str`` token would be written to the operator's terminal and CI logs.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value: Final = value

    def __repr__(self) -> str:
        return "BearerToken('<redacted>')"

    __str__ = __repr__

    def authorization_header(self) -> dict[str, str]:
        """The Authorization header that presents this token."""
        return {"Authorization": f"Bearer {self._value}"}


def broker_origin(configured: str) -> str:
    """The broker's base URL from either it or its /mcp endpoint URL.

    Operators copy the MCP endpoint from their client config, which ends in
    /mcp/; the flow appends /mcp/ itself, so a trailing /mcp is dropped.
    """
    url = configured.rstrip("/")
    return url.removesuffix("/mcp")
