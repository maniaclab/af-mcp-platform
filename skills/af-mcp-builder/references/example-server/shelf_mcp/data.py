"""A tiny in-memory stand-in for the service's native client library (I1)."""

from __future__ import annotations

from fnmatch import fnmatch
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

_DATASETS: dict[str, dict[str, Any]] = {
    "mc23_ttbar": {
        "name": "mc23_ttbar",
        "status": "complete",
        "size_gb": 12.5,
        "events": 2_000_000,
    },
    "mc23_zee": {
        "name": "mc23_zee",
        "status": "complete",
        "size_gb": 4.1,
        "events": 800_000,
    },
    "data23_physics": {
        "name": "data23_physics",
        "status": "transferring",
        "size_gb": 310.0,
        "events": 90_000_000,
    },
}


class ShelfNotFoundError(KeyError):
    """The dataset does not exist."""


class ShelfUnavailableError(ConnectionError):
    """The service could not be reached; a repeat may succeed."""


class ShelfClient:
    """Fake client. A real one takes an explicit timeout on every call (X5)."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def iter_datasets(self, pattern: str) -> Iterator[dict[str, Any]]:
        """Yield matching rows lazily, so a caller can stop after one page (B1)."""
        for name, row in _DATASETS.items():
            if fnmatch(name, pattern):
                yield row

    def get_dataset(self, name: str) -> dict[str, Any]:
        """Return one row or raise ShelfNotFoundError."""
        try:
            return _DATASETS[name]
        except KeyError as exc:
            raise ShelfNotFoundError(name) from exc
