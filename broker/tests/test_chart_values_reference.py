"""``docs/values-reference.md`` is the generated table of every chart value.

The table is rendered from ``values.yaml`` and ``values.schema.json`` by
``scripts/gen-values-reference.py``. A change to either file must come with a
regenerated table: ``pixi run -e dev python scripts/gen-values-reference.py``.
"""

from __future__ import annotations

from values_reference_script import REPO_ROOT, load_generator

_CHART = REPO_ROOT / "charts" / "af-mcp-platform"
_REFERENCE = REPO_ROOT / "docs" / "values-reference.md"


def test_committed_reference_matches_the_chart() -> None:
    expected = load_generator().render_reference(
        _CHART / "values.yaml", _CHART / "values.schema.json"
    )

    assert _REFERENCE.read_text() == expected, (
        "docs/values-reference.md is stale: run "
        "`pixi run -e dev python scripts/gen-values-reference.py`"
    )


def test_every_row_has_a_type_from_the_schema() -> None:
    table = _REFERENCE.read_text()
    untyped = [
        line.split("|")[1].strip()
        for line in table.splitlines()
        if line.startswith("| `") and not line.split("|")[2].strip()
    ]

    assert untyped == []
