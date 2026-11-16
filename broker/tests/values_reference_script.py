"""Loads ``scripts/gen-values-reference.py``, whose hyphenated name is not importable."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "gen-values-reference.py"


def load_generator() -> ModuleType:
    """Import the values-reference generator script as a module."""
    spec = importlib.util.spec_from_file_location("gen_values_reference", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
