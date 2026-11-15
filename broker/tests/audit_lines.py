"""Parse the audit lines out of captured stdout."""

from __future__ import annotations

import json
from typing import Any


def audit_lines(captured_stdout: str) -> list[dict[str, Any]]:
    """Return every ``event: "audit"`` JSON line in *captured_stdout*."""
    return [
        json.loads(line)
        for line in captured_stdout.splitlines()
        if line.startswith("{") and '"event": "audit"' in line
    ]
