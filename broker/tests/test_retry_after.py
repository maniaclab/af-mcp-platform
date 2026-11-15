"""Unit tests for the shared ``Retry-After`` helpers every rate-limit edge uses."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from af_mcp_broker.retry_after import (
    DEFAULT_RETRY_AFTER_SECONDS,
    retry_after_seconds,
    retry_after_sentence,
    retry_at_timestamp,
)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("17", 17),
        ("0", 0),
        (None, DEFAULT_RETRY_AFTER_SECONDS),
        ("", DEFAULT_RETRY_AFTER_SECONDS),
        # HTTP-date form is valid per RFC 9110 but the service's value is
        # only ever relayed as seconds.
        ("Wed, 21 Oct 2026 07:28:00 GMT", DEFAULT_RETRY_AFTER_SECONDS),
        ("-5", DEFAULT_RETRY_AFTER_SECONDS),
    ],
)
def test_retry_after_seconds_parses_a_service_header(
    header: str | None, expected: int
) -> None:
    assert retry_after_seconds(header) == expected


def test_retry_at_timestamp_is_utc_iso_with_z_suffix() -> None:
    before = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=30)
    stamp = retry_at_timestamp(30)
    parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert before <= parsed <= before + timedelta(seconds=2)


def test_retry_after_sentence_names_seconds_and_timestamp() -> None:
    sentence = retry_after_sentence(30)
    assert sentence.startswith("Retry-After: 30 seconds; retry_at: ")
    assert sentence.endswith("Z.")
