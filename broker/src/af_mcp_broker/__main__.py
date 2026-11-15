from __future__ import annotations

from pathlib import Path

import uvicorn

# The file Containerfile.broker's CMD passes as --log-config: uvicorn's own
# lifecycle lines are JSON like the broker's, whichever way it is started.
UVICORN_LOG_CONFIG = Path(__file__).with_name("uvicorn_log_config.json")


def main() -> None:
    uvicorn.run(
        "af_mcp_broker.app:app",
        host="0.0.0.0",  # noqa: S104 -- container entrypoint; network exposure is restricted by the chart's NetworkPolicy
        port=8080,
        log_config=str(UVICORN_LOG_CONFIG),
    )


if __name__ == "__main__":
    main()
