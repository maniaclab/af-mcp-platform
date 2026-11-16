"""Helpers shared between test modules live in support modules, never in another test module."""

from __future__ import annotations

import ast
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parents[1]


def _cross_test_imports(tests_dir: Path) -> dict[str, list[str]]:
    """Map each module under *tests_dir* to the ``test_*`` modules it imports from."""
    offenders: dict[str, list[str]] = {}
    for path in sorted(tests_dir.rglob("*.py")):
        imported: list[str] = []
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
            elif isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
        modules = [m for m in imported if m.rsplit(".", 1)[-1].startswith("test_")]
        if modules:
            offenders[str(path.relative_to(tests_dir))] = modules
    return offenders


def test_no_module_imports_from_a_test_module() -> None:
    assert _cross_test_imports(_TESTS_DIR) == {}


def test_the_guard_flags_an_import_from_a_test_module(tmp_path: Path) -> None:
    (tmp_path / "test_a.py").write_text("from test_b import helper\nimport test_c\n")
    (tmp_path / "test_b.py").write_text("from a_support import helper\n")
    assert _cross_test_imports(tmp_path) == {"test_a.py": ["test_b", "test_c"]}
