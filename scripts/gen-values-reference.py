#!/usr/bin/env python3
"""Render docs/values-reference.md: one row per chart value.

The table is derived from the chart's own files so it cannot drift from them:

* key path, default and description come from ``values.yaml`` (the description
  is the first sentence of the comment above the key);
* type and required-ness come from ``values.schema.json``.

A key the schema lists but ``values.yaml`` omits also gets a row, with no
default. ``broker/tests/unit/test_chart_values_reference.py`` fails when the
committed table differs from what this script renders.

Usage:
    pixi run -e dev python scripts/gen-values-reference.py
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CHART = _REPO_ROOT / "charts" / "af-mcp-platform"
_DEFAULT_OUTPUT = _REPO_ROOT / "docs" / "values-reference.md"

_HEADER = """\
# Chart Values Reference

Every value of the `af-mcp-platform` Helm chart: its key path, type, default,
whether it must be set, and a one-line description. The full explanation of a
value is the comment above it in
[`values.yaml`](https://github.com/maniaclab/af-mcp-platform/blob/main/charts/af-mcp-platform/values.yaml).
For the order in which to set them, see the
[Deployment Runbook](deployment-runbook.md).

This page is generated from `values.yaml` and `values.schema.json`; do not edit
it. Regenerate it with `pixi run -e dev python scripts/gen-values-reference.py`.
A test fails when it is stale.

"Required" is what `values.schema.json` enforces at `helm template`/`helm install`
time. Values that are required only by a combination of other values (for
example `broker.vault.kvRoot` once a Vault-backed store is selected) are
explained in the Deployment Runbook.
"""

_KEY_LINE = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z0-9_.\-]+):(?:\s|$)")
_BANNER_LINE = re.compile(r"^#\s*[-=]{3,}\s*$")
# A sentence ends at a period followed by whitespace, except in "e.g." / "i.e.".
_SENTENCE_END = re.compile(r"(?<!e\.g)(?<!i\.e)\.(?:\s|$)")


# A URL not already in a code span; markdown would otherwise link it (and the
# docs link check would try to fetch placeholder hosts).
_BARE_URL = re.compile(r"(?<![`\w])(\w+://[^\s`\"']*[^\s`\"'.,;:)])")
_MIN_DESCRIPTION = 40
_MAX_DESCRIPTION = 200
_MAX_DEFAULT = 80


def _description(lines: list[str]) -> str:
    """The comment's first sentence, extended to the next while it is very short."""
    text = re.sub(r"\s+", " ", " ".join(lines)).strip()
    sentence = ""
    while text and len(sentence) < _MIN_DESCRIPTION:
        match = _SENTENCE_END.search(text)
        end = match.start() + 1 if match else len(text)
        sentence = f"{sentence} {text[:end]}".strip()
        text = text[end:].strip()
    if len(sentence) > _MAX_DESCRIPTION:
        sentence = sentence[:_MAX_DESCRIPTION].rsplit(" ", 1)[0] + " ..."
    return _BARE_URL.sub(r"`\1`", sentence.rstrip(":")).replace("|", r"\|")


def _comment_text(line: str) -> str:
    return line.lstrip()[1:].strip()


def _is_prose(line: str) -> bool:
    # A commented-out example is indented past "# " or starts a list item.
    body = line.lstrip()[1:]
    return not (body.startswith("  ") or body.lstrip().startswith("-"))


def _prose(block: list[str]) -> list[str]:
    """The comment lines that describe the key below *block*, without examples.

    A block is prose runs split by indented example lines. A lone ``key:`` line
    opens an example, so a run that is only that is skipped; the first run left
    is the description.
    """
    runs: list[list[str]] = [[]]
    for line in block:
        if _is_prose(line):
            runs[-1].append(_comment_text(line))
        elif runs[-1]:
            runs.append([])
    for run in runs:
        if run and not (len(run) == 1 and re.fullmatch(r"[\w.\-]+:", run[0])):
            return run
    return []


def descriptions(values_text: str) -> dict[str, str]:
    """Map each dotted key path in *values_text* to the first sentence of its comment."""
    found: dict[str, str] = {}
    stack: list[tuple[int, str]] = []
    pending: list[str] = []
    for line in values_text.splitlines():
        stripped = line.strip()
        if _BANNER_LINE.match(stripped) or not stripped:
            pending = []
        elif stripped.startswith("#"):
            pending.append(line)
        else:
            match = _KEY_LINE.match(line)
            if match:
                indent = len(match["indent"])
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                stack.append((indent, match["key"]))
                keys = [key for _, key in stack]
                inline = line.partition(" #")[2].strip()
                own = _description(_prose(pending)) or _description([inline])
                found[".".join(keys)] = own
            pending = []
    return found


def _described(described: dict[str, str], path: str) -> str:
    """The description of *path*, else of its nearest commented ancestor."""
    keys = path.split(".")
    return next(
        (
            described[prefix]
            for depth in range(len(keys), 0, -1)
            if described.get(prefix := ".".join(keys[:depth]))
        ),
        "",
    )


def _flatten(node: Any, prefix: str = "") -> dict[str, Any]:
    """Leaf defaults by dotted path; an empty or non-mapping value is a leaf."""
    if isinstance(node, dict) and node:
        leaves: dict[str, Any] = {}
        for key, child in node.items():
            leaves.update(_flatten(child, f"{prefix}.{key}" if prefix else str(key)))
        return leaves
    return {prefix: node}


def _schema_children(schema: dict[str, Any], key: str) -> dict[str, Any] | None:
    child = schema.get("properties", {}).get(key)
    if child is not None:
        return child
    extra = schema.get("additionalProperties")
    return extra if isinstance(extra, dict) else None


def _schema_leaves(schema: dict[str, Any], prefix: str = "") -> list[str]:
    properties = schema.get("properties")
    if not properties:
        return [prefix] if prefix else []
    leaves: list[str] = []
    for key, child in properties.items():
        leaves += _schema_leaves(child, f"{prefix}.{key}" if prefix else key)
    return leaves


def _schema_node(schema: dict[str, Any], path: str) -> dict[str, Any] | None:
    node: dict[str, Any] | None = schema
    for key in path.split("."):
        if node is None:
            return None
        node = _schema_children(node, key)
    return node


def _type_cell(node: dict[str, Any] | None, default: Any) -> str:
    if node is not None and "enum" in node:
        return ", ".join(f"`{value}`" for value in node["enum"]).replace("|", r"\|")
    if node is not None and "type" in node:
        declared = node["type"]
        return " / ".join(declared) if isinstance(declared, list) else declared
    return {
        bool: "boolean",
        int: "integer",
        float: "number",
        str: "string",
        list: "array",
        dict: "object",
        type(None): "null",
    }[type(default)]


def _default_cell(default: Any) -> str:
    if default is None:
        text = "null"
    elif isinstance(default, list) and default:
        text = yaml.safe_dump(default, default_flow_style=True, width=10**6).strip()
    else:
        text = json.dumps(default)
    if len(text) > _MAX_DEFAULT:
        return "see `values.yaml`"
    return f"`{text}`".replace("|", r"\|")


def _required_paths(schema: dict[str, Any]) -> tuple[set[str], dict[str, str]]:
    """Unconditionally required key paths, and the condition of conditionally required ones."""
    always: set[str] = set()
    conditional: dict[str, str] = {}

    def walk(node: dict[str, Any], prefix: str, chain_required: bool) -> None:
        def join(key: str) -> str:
            return f"{prefix}.{key}" if prefix else key

        required = set(node.get("required", ()))
        for key in required:
            if chain_required:
                always.add(join(key))
        for clause in node.get("allOf", ()):
            condition = clause.get("if", {}).get("properties", {})
            then_required = clause.get("then", {}).get("required", ())
            described = " and ".join(
                f"`{join(key)}` is `{json.dumps(rule['const'])}`"
                for key, rule in condition.items()
                if "const" in rule
            )
            for key in then_required:
                if described:
                    conditional[join(key)] = f"when {described}"
        for key, child in node.get("properties", {}).items():
            walk(child, join(key), chain_required and key in required)

    walk(schema, "", chain_required=True)
    return always, conditional


def render_reference(values_path: Path, schema_path: Path) -> str:
    """Render the values-reference page for the chart files at the given paths."""
    values_text = values_path.read_text()
    schema = json.loads(schema_path.read_text())
    defaults = _flatten(yaml.safe_load(values_text))
    described = descriptions(values_text)
    always, conditional = _required_paths(schema)

    schema_only = [
        path
        for path in _schema_leaves(schema)
        if not any(path == leaf or leaf.startswith(f"{path}.") for leaf in defaults)
        # An empty schema constrains nothing: the key is only listed so a
        # template guard can refuse it (a removed value), not a setting.
        and _schema_node(schema, path)
    ]
    rows: dict[str, list[str]] = {}
    for path in [*defaults, *schema_only]:
        has_default = path in defaults
        default = defaults.get(path)
        if path in always:
            required = "yes"
        else:
            required = conditional.get(path, "no")
        rows.setdefault(path.split(".")[0], []).append(
            "| "
            + " | ".join(
                [
                    f"`{path}`",
                    _type_cell(_schema_node(schema, path), default),
                    _default_cell(default) if has_default else "",
                    required,
                    _described(described, path),
                ]
            )
            + " |"
        )

    sections = [_HEADER]
    for group, group_rows in rows.items():
        sections.append(
            f"## `{group}`\n\n"
            "| Key | Type | Default | Required | Description |\n"
            "| --- | --- | --- | --- | --- |\n" + "\n".join(group_rows) + "\n"
        )
    return "\n".join(sections)


def main() -> None:
    """Write the rendered reference to the output path (docs/values-reference.md by default)."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    args = parser.parse_args()
    args.output.write_text(
        render_reference(_CHART / "values.yaml", _CHART / "values.schema.json")
    )


if __name__ == "__main__":
    main()
