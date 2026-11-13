"""Unit tests for the check functions in scripts/audit_tools.py.

Tools are real ``mcp.types.Tool`` objects, results are the fastmcp result
shape; nothing is mocked.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.types import TextContent, Tool, ToolAnnotations

RO = ToolAnnotations(read_only_hint=True)
OBJ = {"type": "object", "properties": {}}


def make_tool(
    name: str = "fx_get_thing",
    description: str | None = "Get a thing.",
    properties: dict[str, Any] | None = None,
    *,
    input_type: str = "object",
    output_schema: dict[str, Any] | None = OBJ,
    annotations: ToolAnnotations | None = RO,
) -> Tool:
    return Tool(
        name=name,
        description=description,
        input_schema={"type": input_type, "properties": properties or {}},
        output_schema=output_schema,
        annotations=annotations,
    )


def items(findings: list[Any], item: str) -> list[Any]:
    return [f for f in findings if f.item == item]


def desc(text: str = "An argument.") -> dict[str, str]:
    return {"type": "string", "description": text}


class TestCompliantTool:
    def test_no_findings(self, audit: Any) -> None:
        tool = make_tool(properties={"thing_id": desc()})
        assert audit.audit_tool(tool, "fx") == []


class TestN1Names:
    @pytest.mark.parametrize(
        ("name", "prefix", "n_findings"),
        [
            ("fx_get_thing", "fx", 0),
            ("fx_get_thing", None, 0),
            ("get_thing", "fx", 1),
            ("fxx_get_thing", "fx", 1),  # shares letters, not the 'fx_' prefix
            ("fx get thing", "fx", 2),  # space is outside the character set and breaks the prefix
            ("fx_" + "a" * 130, "fx", 1),  # over 128 characters
        ],
    )
    def test_name_and_prefix(self, audit: Any, name: str, prefix: str | None, n_findings: int) -> None:
        found = items(audit.audit_tool(make_tool(name=name), prefix), "N1")
        assert len(found) == n_findings
        assert all(f.level == "MUST" for f in found)


class TestN2N3Descriptions:
    @pytest.mark.parametrize(
        ("description", "expected"),
        [
            ("Get a thing.", []),
            ("Get a thing.\n\nDetails and caveats.", []),
            (None, ["no description"]),
            ("   ", ["no description"]),
            ("W" * 121, ["first line is 121 chars"]),
            ("fx get thing", ["only restates the tool name"]),
        ],
    )
    def test_n2(self, audit: Any, description: str | None, expected: list[str]) -> None:
        found = items(audit.audit_tool(make_tool(description=description), "fx"), "N2")
        assert len(found) == len(expected)
        assert all(e in f.message for f, e in zip(found, expected, strict=True))
        assert all(f.level == "MUST" for f in found)

    def test_n3_flags_one_line_description_with_many_arguments(self, audit: Any) -> None:
        props = {k: desc() for k in "abc"}
        found = items(audit.audit_tool(make_tool(properties=props), "fx"), "N3")
        assert [f.level for f in found] == ["SHOULD"]

    @pytest.mark.parametrize(
        ("description", "n_props"),
        [("Get a thing.\n\nMore.", 3), ("Get a thing.", 2)],
    )
    def test_n3_not_flagged(self, audit: Any, description: str, n_props: int) -> None:
        props = {k: desc() for k in "abc"[:n_props]}
        found = items(audit.audit_tool(make_tool(description=description, properties=props), "fx"), "N3")
        assert found == []


class TestS1InputSchema:
    def test_non_object_schema(self, audit: Any) -> None:
        found = items(audit.audit_tool(make_tool(input_type="array"), "fx"), "S1")
        assert [f.message for f in found] == ["inputSchema is not a JSON object schema"]

    @pytest.mark.parametrize(
        ("prop", "flagged"),
        [
            (desc(), False),
            ({"type": "string"}, True),
            ({"type": "string", "description": ""}, True),
            ({"type": "string", "description": "  "}, True),
        ],
    )
    def test_argument_description(self, audit: Any, prop: dict[str, Any], flagged: bool) -> None:
        found = items(audit.audit_tool(make_tool(properties={"thing_id": prop}), "fx"), "S1")
        assert bool(found) is flagged
        if flagged:
            assert "thing_id" in found[0].message
            assert found[0].level == "MUST"


class TestU3Credentials:
    @pytest.mark.parametrize(
        ("arg", "flagged"),
        [
            ("thing_id", False),
            ("password", True),
            ("api_token", True),
            ("x509_proxy", True),
            ("Private_Key", True),
            ("credential", True),
        ],
    )
    def test_argument_names(self, audit: Any, arg: str, flagged: bool) -> None:
        found = items(audit.audit_tool(make_tool(properties={arg: desc()}), "fx"), "U3")
        assert bool(found) is flagged


class TestO1OutputSchema:
    @pytest.mark.parametrize(
        ("schema", "expected"),
        [
            (OBJ, []),
            (None, ["no outputSchema"]),
            ({"type": "array", "items": {}}, ["outputSchema is not a JSON object schema"]),
        ],
    )
    def test_output_schema(self, audit: Any, schema: dict[str, Any] | None, expected: list[str]) -> None:
        found = items(audit.audit_tool(make_tool(output_schema=schema), "fx"), "O1")
        assert [f.message for f in found] == expected


class TestA1A2Annotations:
    def test_missing_annotations(self, audit: Any) -> None:
        found = items(audit.audit_tool(make_tool(annotations=None), "fx"), "A1")
        assert [(f.level, f.message) for f in found] == [("MUST", "readOnlyHint is not set")]

    def test_annotations_without_read_only_hint(self, audit: Any) -> None:
        tool = make_tool(annotations=ToolAnnotations(title="t"))
        assert len(items(audit.audit_tool(tool, "fx"), "A1")) == 1

    def test_read_only_tool_is_clean(self, audit: Any) -> None:
        assert items(audit.audit_tool(make_tool(annotations=RO), "fx"), "A1") == []

    def test_destructive_hint_on_read_only_tool(self, audit: Any) -> None:
        ann = ToolAnnotations(read_only_hint=True, destructive_hint=False)
        found = items(audit.audit_tool(make_tool(annotations=ann), "fx"), "A1")
        assert [f.level for f in found] == ["SHOULD"]

    @pytest.mark.parametrize(
        ("ann", "missing"),
        [
            (ToolAnnotations(read_only_hint=False), "destructiveHint, idempotentHint, openWorldHint"),
            (
                ToolAnnotations(read_only_hint=False, destructive_hint=True),
                "idempotentHint, openWorldHint",
            ),
            (
                ToolAnnotations(
                    read_only_hint=False,
                    destructive_hint=False,
                    idempotent_hint=True,
                    open_world_hint=False,
                ),
                None,
            ),
        ],
    )
    def test_write_tool_hints(self, audit: Any, ann: ToolAnnotations, missing: str | None) -> None:
        found = items(audit.audit_tool(make_tool(annotations=ann), "fx"), "A2")
        if missing is None:
            assert found == []
        else:
            assert [(f.level, f.message) for f in found] == [
                ("SHOULD", f"write tool does not set {missing}")
            ]


class TestB1Listings:
    @pytest.mark.parametrize(
        ("name", "props", "n_must"),
        [
            ("fx_list_things", {}, 1),
            ("fx_search_things", {"query": desc()}, 1),
            ("fx_query_jobs", {}, 1),
            ("fx_find_things", {}, 1),
            ("fx_get_all_things", {}, 1),
            ("fx_list_things", {"limit": {"type": "integer", "description": "n", "maximum": 5}}, 0),
            ("fx_list_things", {"cursor": desc()}, 0),
            ("fx_get_thing", {}, 0),  # not a listing verb
        ],
    )
    def test_limit_argument_required(
        self, audit: Any, name: str, props: dict[str, Any], n_must: int
    ) -> None:
        found = [f for f in items(audit.audit_tool(make_tool(name=name, properties=props), "fx"), "B1") if f.level == "MUST"]
        assert len(found) == n_must

    @pytest.mark.parametrize(
        ("limit_schema", "flagged"),
        [
            ({"type": "integer", "description": "n"}, True),
            ({"type": "integer", "description": "n", "maximum": 100}, False),
            ({"type": "string", "description": "n"}, False),  # a cursor, not a count
        ],
    )
    def test_limit_needs_maximum(self, audit: Any, limit_schema: dict[str, Any], flagged: bool) -> None:
        tool = make_tool(name="fx_list_things", properties={"limit": limit_schema})
        found = items(audit.audit_tool(tool, "fx"), "B1")
        assert [f.level for f in found] == (["SHOULD"] if flagged else [])

    def test_prefix_is_stripped_before_matching_the_verb(self, audit: Any) -> None:
        # 'list_things' without a prefix is still a listing tool.
        found = items(audit.audit_tool(make_tool(name="list_things"), None), "B1")
        assert len(found) == 1


def result(
    text: str = "",
    structured: dict[str, Any] | None = None,
    *,
    is_error: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        content=[TextContent(type="text", text=text)] if text else [],
        structured_content=structured,
        is_error=is_error,
    )


OUT_SCHEMA = {
    "type": "object",
    "properties": {"size": {"type": "integer"}},
    "required": ["size"],
}


class TestAuditCall:
    def tool(self, audit: Any) -> Tool:
        return make_tool(output_schema=OUT_SCHEMA)

    def run(self, audit: Any, res: SimpleNamespace, *, expect_error: bool = False, max_bytes: int = 50_000) -> list[Any]:
        return audit.audit_call(self.tool(audit), res, expect_error=expect_error, max_bytes=max_bytes)

    def test_valid_call_is_clean(self, audit: Any) -> None:
        assert self.run(audit, result("size is 3", {"size": 3})) == []

    def test_oversized_result(self, audit: Any) -> None:
        found = self.run(audit, result("x" * 100, {"size": 3}), max_bytes=50)
        assert [(f.item, f.level) for f in found] == [("B1", "MUST")]

    def test_structured_content_violating_schema(self, audit: Any) -> None:
        found = self.run(audit, result("bad", {"size": "three"}))
        assert [(f.item, f.level) for f in found] == [("O1", "MUST")]
        assert "structuredContent invalid" in found[0].message

    def test_missing_structured_content(self, audit: Any) -> None:
        found = self.run(audit, result("text only"))
        assert [(f.item, f.message) for f in found] == [
            ("O1", "outputSchema declared but no structuredContent")
        ]

    def test_text_that_is_a_json_dump(self, audit: Any) -> None:
        payload = {"size": 3}
        found = self.run(audit, result(json.dumps(payload), payload))
        assert [(f.item, f.level) for f in found] == [("O2", "SHOULD")]

    def test_unexpected_error_on_a_good_input(self, audit: Any) -> None:
        found = self.run(audit, result("boom", is_error=True))
        assert [(f.item, f.level) for f in found] == [("E1", "SHOULD")]

    @pytest.mark.parametrize(
        ("res", "expected"),
        [
            (result("No thing. Next step: call fx_list_things.", is_error=True), []),
            (result("error-shaped text, no flag"), [("E1", "failing input did not set isError")]),
            (result("", is_error=True), [("E2", "error result has no text")]),
            (
                result("Traceback (most recent call last):\n  File x", is_error=True),
                [("E2", "error text contains a stack trace")],
            ),
            (
                result("goroutine 7 [running]:\nmain.go", is_error=True),
                [("E2", "error text contains a stack trace")],
            ),
        ],
    )
    def test_expected_error(self, audit: Any, res: SimpleNamespace, expected: list[tuple[str, str]]) -> None:
        found = self.run(audit, res, expect_error=True)
        assert [(f.item, f.message) for f in found] == expected
        assert all(f.level == "MUST" for f in found)


class TestRender:
    def test_no_findings(self, audit: Any) -> None:
        assert audit.render([], 3) == "Audited 3 tools.\n\nNo findings."

    def test_table_orders_must_before_should_and_counts(self, audit: Any) -> None:
        F = audit.Finding
        findings = [
            F("N3", "SHOULD", "fx_b", "short"),
            F("S1", "MUST", "fx_b", "arg"),
            F("A1", "MUST", "fx_a", "ro"),
        ]
        lines = audit.render(findings, 2).splitlines()
        rows = [ln for ln in lines if ln.startswith("| ") and "Item" not in ln and "---" not in ln]
        assert rows == [
            "| A1 | MUST | `fx_a` | ro |",
            "| S1 | MUST | `fx_b` | arg |",
            "| N3 | SHOULD | `fx_b` | short |",
        ]
        assert lines[-1] == "2 MUST, 1 SHOULD."


class TestCheck401:
    @pytest.mark.parametrize(("code", "n_findings"), [(401, 0), (200, 1), (403, 1), (500, 1)])
    def test_status_codes(
        self, audit: Any, serve: Any, code: int, n_findings: int
    ) -> None:
        port = serve("status", str(code))
        found = audit.check_401(f"http://127.0.0.1:{port}/mcp")
        assert len(found) == n_findings
        if found:
            assert (found[0].item, found[0].level) == ("X2", "MUST")
            assert f"HTTP {code}" in found[0].message
