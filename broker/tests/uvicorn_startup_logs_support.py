"""Fixtures and helpers shared by the unit and integration tests of ``test_uvicorn_startup_logs``."""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTAINERFILE = REPO_ROOT / "Containerfile.broker"


def _container_log_config_args() -> list[str]:
    """The ``--log-config <file>`` arguments of the Containerfile's CMD, with the file resolved to this checkout."""
    cmd_line = next(
        line
        for line in CONTAINERFILE.read_text().splitlines()
        if line.startswith("CMD")
    )
    cmd = json.loads(cmd_line.removeprefix("CMD "))
    path = Path(cmd[cmd.index("--log-config") + 1])
    # The image keeps the sources at /app/broker/src.
    checkout_path = REPO_ROOT / path.relative_to("/app")
    assert checkout_path.is_file(), f"{path} in the CMD is not shipped"
    return ["--log-config", str(checkout_path)]
