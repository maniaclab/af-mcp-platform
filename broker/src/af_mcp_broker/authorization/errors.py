from __future__ import annotations

from af_mcp_broker.errors import BrokerError


class ToolRateLimitError(BrokerError):
    """A principal exceeded a ``rate_limits`` budget for a tool call.

    ``limit`` and ``window_seconds`` describe the rule that was exceeded
    (when several were, the one whose window closes last).
    *retry_after_seconds* is how long until every exceeded window has
    closed, so a retry after it cannot hit the same rule again. The MCP
    middleware turns it into a tool error carrying that wait.
    """

    def __init__(
        self,
        message: str,
        *,
        limit: int,
        window_seconds: int,
        retry_after_seconds: int,
    ) -> None:
        super().__init__(message)
        self.limit = limit
        self.window_seconds = window_seconds
        self.retry_after_seconds = retry_after_seconds
