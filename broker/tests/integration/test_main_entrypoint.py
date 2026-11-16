"""``python -m af_mcp_broker`` starts uvicorn with the same log config the container image does."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import uvicorn
from uvicorn_startup_logs_support import _container_log_config_args

from af_mcp_broker import __main__ as entrypoint

if TYPE_CHECKING:
    import pytest


def test_main_starts_uvicorn_with_the_container_log_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.append(kwargs))

    entrypoint.main()

    [kwargs] = calls
    assert ["--log-config", kwargs["log_config"]] == _container_log_config_args()
