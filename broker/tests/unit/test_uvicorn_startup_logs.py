"""The real uvicorn server, started the way ``Containerfile.broker`` starts it, emits only JSON lines.

The log pipeline parses every line a broker pod writes. uvicorn's lifecycle
lines (server process start, application startup, the listening address, and
the shutdown counterparts) are written by uvicorn's own loggers, which
uvicorn configures before the broker's code runs, so only uvicorn's
``--log-config`` can make them JSON from the first line.
"""

from __future__ import annotations

from uvicorn_startup_logs_support import (
    _container_log_config_args,
)


def test_containerfile_cmd_points_uvicorn_at_the_json_log_config() -> None:
    assert _container_log_config_args()
