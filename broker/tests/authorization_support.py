"""Fixtures and helpers shared by the unit and integration tests of ``test_authorization``."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def _write_policy(tmp_path: Path, text: str) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(text)
    return str(path)
