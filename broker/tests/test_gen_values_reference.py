"""Unit tests for the chart values-reference generator (``scripts/gen-values-reference.py``).

Each test renders a tiny values file and schema, so what the table says about a
key is pinned down independently of the real chart.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from values_reference_script import load_generator

if TYPE_CHECKING:
    from pathlib import Path

_VALUES = """\
# Section banner
# ---------------------------------------------------------------------------
replicaCount: 2

# Cluster-wide switch that turns every part of the feature on or off at once.
# Second sentence is not in the table.
enabled: true

oidc:
  # The issuer URL, shared by
  # the broker and the portal.
  issuer: ""

env: {}
ipFamilies: [IPv4, IPv6]
mode: "a|b"  # trailing comment
# Endpoint such as http://svc.example.svc:8080, or `https://quoted.example.org`.
endpoint: ""
nothing:

# Master switch. Everything below hangs off it.
group:
  # group_permissions:
  #   example: [read]
  # The grants of each group.
  grants: {}
  # The list of hosts, for example:
  #   - a.example.org
  hostList: []
  child: 1
  # Example block directly above the key.
  # group_permissions:
  #   example: [read]
  other: 1
bigList:
  - {name: one, value: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
  - {name: two, value: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}
"""

_SCHEMA = {
    "type": "object",
    "required": ["oidc"],
    "properties": {
        "replicaCount": {"type": "integer"},
        "enabled": {"type": "boolean"},
        "oidc": {
            "type": "object",
            "required": ["issuer"],
            "properties": {"issuer": {"type": "string"}},
        },
        "env": {"type": "object"},
        "ipFamilies": {"type": "array"},
        "mode": {"enum": ["a|b", "c"]},
        "hosts": {"type": "string"},
        "group": {"type": "object"},
        "bigList": {"type": "array"},
        "removed": {},
    },
    "allOf": [
        {
            "if": {"properties": {"enabled": {"const": True}}, "required": ["enabled"]},
            "then": {"required": ["hosts"]},
        }
    ],
}


@pytest.fixture(name="table")
def _table(tmp_path: Path) -> str:
    values = tmp_path / "values.yaml"
    values.write_text(_VALUES)
    schema = tmp_path / "values.schema.json"
    schema.write_text(json.dumps(_SCHEMA))
    return load_generator().render_reference(values, schema)


def _row(table: str, key: str) -> list[str]:
    for line in table.splitlines():
        if line.startswith(f"| `{key}` "):
            return [cell.strip() for cell in line.strip("|").split(" | ")]
    pytest.fail(f"no row for {key}:\n{table}")


def test_scalar_row_carries_type_default_and_first_sentence(table: str) -> None:
    assert _row(table, "enabled") == [
        "`enabled`",
        "boolean",
        "`true`",
        "no",
        "Cluster-wide switch that turns every part of the feature on or off at once.",
    ]


def test_banner_comments_are_not_descriptions(table: str) -> None:
    assert _row(table, "replicaCount")[-1] == ""


def test_nested_key_uses_dotted_path_and_joins_a_wrapped_comment(table: str) -> None:
    assert _row(table, "oidc.issuer") == [
        "`oidc.issuer`",
        "string",
        '`""`',
        "yes",
        "The issuer URL, shared by the broker and the portal.",
    ]


def test_container_that_only_has_children_gets_no_row(table: str) -> None:
    assert "| `oidc` " not in table


def test_empty_map_and_list_defaults_are_rows(table: str) -> None:
    assert _row(table, "env")[2] == "`{}`"
    assert _row(table, "ipFamilies")[2] == "`[IPv4, IPv6]`"


def test_enum_type_and_escaped_pipes(table: str) -> None:
    row = _row(table, "mode")
    assert row[1] == r"`a\|b`, `c`"
    assert row[2] == r'`"a\|b"`'


def test_null_default_is_shown(table: str) -> None:
    assert _row(table, "nothing")[2] == "`null`"


def test_key_required_by_a_conditional_is_listed_with_its_condition(
    table: str,
) -> None:
    row = _row(table, "hosts")
    assert row[1] == "string"
    assert row[2] == ""
    assert row[3] == "when `enabled` is `true`"


def test_output_is_deterministic(tmp_path: Path) -> None:
    values = tmp_path / "values.yaml"
    values.write_text(_VALUES)
    schema = tmp_path / "values.schema.json"
    schema.write_text(json.dumps(_SCHEMA))
    generator = load_generator()

    assert generator.render_reference(values, schema) == generator.render_reference(
        values, schema
    )


def test_example_lines_do_not_become_the_description(table: str) -> None:
    assert _row(table, "group.grants")[-1] == "The grants of each group."
    assert _row(table, "group.hostList")[-1] == "The list of hosts, for example"


def test_a_key_without_a_comment_takes_the_nearest_commented_ancestor(
    table: str,
) -> None:
    assert (
        _row(table, "group.child")[-1]
        == "Master switch. Everything below hangs off it."
    )


def test_a_long_list_default_is_not_inlined(table: str) -> None:
    assert _row(table, "bigList")[2] == "see `values.yaml`"


def test_schema_key_that_accepts_anything_gets_no_row(table: str) -> None:
    assert "`removed`" not in table


def test_bare_urls_in_a_description_are_code_so_they_are_not_linked(
    table: str,
) -> None:
    assert (
        _row(table, "endpoint")[-1]
        == "Endpoint such as `http://svc.example.svc:8080`, or `https://quoted.example.org`."
    )
