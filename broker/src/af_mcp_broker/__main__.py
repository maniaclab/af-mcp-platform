from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run(
        "af_mcp_broker.app:app",
        host="0.0.0.0",  # noqa: S104 -- container entrypoint; network exposure is restricted by the chart's NetworkPolicy
        port=8080,
        log_config=None,  # structlog owns log formatting
    )


if __name__ == "__main__":
    main()
