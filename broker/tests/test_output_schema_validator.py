from __future__ import annotations

import copy

import pytest
from jsonschema.validators import validator_for

from af_mcp_broker.mcp.middleware import output_schema_mw
from af_mcp_broker.mcp.middleware.output_schema_mw import OutputSchemaValidator

_SCHEMA = {
    "type": "object",
    "properties": {"n": {"type": "integer"}},
    "required": ["n"],
}


class TestOutputSchemaValidator:
    def test_conforming_content_passes(self) -> None:
        OutputSchemaValidator().validate("t", _SCHEMA, {"n": 1})

    def test_violation_names_the_tool_and_the_reason(self) -> None:
        with pytest.raises(
            RuntimeError,
            match="Invalid structured content returned by tool t: 'x' is not of type 'integer'",
        ):
            OutputSchemaValidator().validate("t", _SCHEMA, {"n": "x"})

    def test_missing_structured_content_is_an_error_when_a_schema_exists(self) -> None:
        with pytest.raises(
            RuntimeError,
            match="Tool t has an output schema but did not return structured content",
        ):
            OutputSchemaValidator().validate("t", _SCHEMA, None)

    def test_a_tool_without_an_output_schema_is_never_checked(self) -> None:
        OutputSchemaValidator().validate("t", None, None)
        OutputSchemaValidator().validate("t", None, {"anything": object()})

    def test_an_invalid_schema_is_reported(self) -> None:
        with pytest.raises(RuntimeError, match="Invalid schema for tool t"):
            OutputSchemaValidator().validate("t", {"type": "nonsense"}, {})

    def test_an_unresolvable_ref_is_reported(self) -> None:
        schema = {"$ref": "#/$defs/missing"}

        with pytest.raises(RuntimeError, match="Invalid schema for tool t"):
            OutputSchemaValidator().validate("t", schema, {})

    def test_a_schema_is_compiled_once_across_calls_and_equal_copies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        compiled = 0

        def counting_validator_for(schema):
            nonlocal compiled
            compiled += 1
            return validator_for(schema)

        monkeypatch.setattr(output_schema_mw, "validator_for", counting_validator_for)
        validator = OutputSchemaValidator()

        for _ in range(3):
            validator.validate("t", _SCHEMA, {"n": 1})
        validator.validate("t", copy.deepcopy(_SCHEMA), {"n": 2})

        assert compiled == 1

    def test_distinct_schemas_get_distinct_validators(self) -> None:
        validator = OutputSchemaValidator()
        other = {"type": "object", "properties": {"n": {"type": "string"}}}

        validator.validate("t", _SCHEMA, {"n": 1})
        validator.validate("u", other, {"n": "s"})
        with pytest.raises(RuntimeError):
            validator.validate("u", other, {"n": 1})
