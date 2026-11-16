"""Tests for the PAT format/hashing primitives (issue #144 step 2a)."""

from __future__ import annotations

from af_mcp_broker.pat import (
    PAT_PREFIX,
    hash_secret,
    mint_pat,
    parse_pat,
    verify_secret,
)


def test_mint_pat_round_trips_through_parse_pat() -> None:
    plaintext, lookup_id, secret_hash = mint_pat()

    parsed = parse_pat(plaintext)

    assert parsed is not None
    parsed_lookup_id, parsed_secret = parsed
    assert parsed_lookup_id == lookup_id
    assert verify_secret(parsed_secret, secret_hash) is True


def test_mint_pat_has_stable_prefix() -> None:
    plaintext, _, _ = mint_pat()
    assert plaintext.startswith(PAT_PREFIX)


def test_mint_pat_never_repeats() -> None:
    """Sanity check on the entropy source -- two mints must never collide."""
    first = mint_pat()
    second = mint_pat()
    assert first[0] != second[0]
    assert first[1] != second[1]


def test_mint_pat_lookup_id_has_no_underscore() -> None:
    """lookup_id is hex-encoded specifically so it can never contain '_' --
    parse_pat's split-on-first-underscore logic depends on this."""
    _, lookup_id, _ = mint_pat()
    assert "_" not in lookup_id


def test_secret_hash_is_not_the_plaintext_secret() -> None:
    plaintext, _, secret_hash = mint_pat()
    assert secret_hash not in plaintext
    assert secret_hash != plaintext


def test_verify_secret_rejects_wrong_secret() -> None:
    _, _, secret_hash = mint_pat()
    assert verify_secret("not-the-right-secret", secret_hash) is False


def test_hash_secret_is_deterministic() -> None:
    assert hash_secret("abc") == hash_secret("abc")


def test_hash_secret_differs_for_different_secrets() -> None:
    assert hash_secret("abc") != hash_secret("abd")


def test_parse_pat_rejects_wrong_prefix() -> None:
    assert parse_pat("not_a_pat_at_all") is None


def test_parse_pat_rejects_missing_secret() -> None:
    assert parse_pat(f"{PAT_PREFIX}onlylookupid") is None


def test_parse_pat_rejects_empty_lookup_id() -> None:
    assert parse_pat(f"{PAT_PREFIX}_secretvalue") is None


def test_parse_pat_rejects_empty_secret() -> None:
    assert parse_pat(f"{PAT_PREFIX}lookupid_") is None


def test_parse_pat_secret_may_contain_underscores() -> None:
    """secret's own alphabet (urlsafe-base64) can contain '_' -- parsing
    must split on the FIRST '_' only, keeping the rest as the secret."""
    parsed = parse_pat(f"{PAT_PREFIX}abc123_sec_ret_with_underscores")
    assert parsed == ("abc123", "sec_ret_with_underscores")


def test_parse_pat_rejects_empty_string() -> None:
    assert parse_pat("") is None
