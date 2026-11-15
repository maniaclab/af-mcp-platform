"""``_parse_callback_outcome`` classifies a backend AS redirect's query parameters."""

from __future__ import annotations

import pytest
from starlette.exceptions import (
    HTTPException,  # noqa: TID251 -- the api edge raises it; the test asserts its status
)

from af_mcp_broker.api.oauth21 import (
    _CallbackFailure,
    _CallbackSuccess,
    _parse_callback_outcome,
)


def test_a_code_alone_is_a_success() -> None:
    assert _parse_callback_outcome("abc", None, None, None) == _CallbackSuccess("abc")


def test_an_error_carries_its_description_and_uri() -> None:
    assert _parse_callback_outcome(
        None, "access_denied", "user said no", "https://as.example/err"
    ) == _CallbackFailure("access_denied", "user said no", "https://as.example/err")


def test_an_error_wins_over_a_code() -> None:
    outcome = _parse_callback_outcome("abc", "server_error", None, None)

    assert outcome == _CallbackFailure("server_error", None, None)


def test_neither_code_nor_error_is_a_bad_request() -> None:
    with pytest.raises(HTTPException) as excinfo:
        _parse_callback_outcome(None, None, "ignored", "ignored")

    assert excinfo.value.status_code == 400
    assert excinfo.value.detail == "Missing code or error in callback"
