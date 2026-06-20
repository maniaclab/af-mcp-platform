from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run(
        "af_mcp_broker.app:app",
        host="0.0.0.0",
        port=8080,
        log_config=None,  # structlog owns log formatting
    )


if __name__ == "__main__":
    main()
