from __future__ import annotations

import dataclasses

import pytest

from af_mcp_broker.principal import PosixPrincipal, Principal


def test_from_principal_with_full_posix_identity_keeps_every_field(make_principal):
    principal = make_principal(
        groups=["atlas"],
        uid=50123,
        gid=50124,
        unixname="auser",
        permission_grant=frozenset({"read_data"}),
        token_id="lookup-1",
    )

    posix = PosixPrincipal.from_principal(principal)

    assert isinstance(posix, PosixPrincipal)
    assert isinstance(posix, Principal)
    assert (posix.uid, posix.gid, posix.unixname) == (50123, 50124, "auser")
    assert posix.subject == principal.subject
    assert posix.email == principal.email
    assert posix.groups == ["atlas"]
    assert posix.raw_token.get_secret_value() == "fake-token"
    assert posix.permission_grant == frozenset({"read_data"})
    assert posix.token_id == "lookup-1"


@pytest.mark.parametrize(
    "missing", [{"uid": None}, {"gid": None}, {"unixname": None}], ids=str
)
def test_from_principal_is_none_when_any_posix_field_is_missing(
    make_principal, missing
):
    assert PosixPrincipal.from_principal(make_principal(**missing)) is None


def test_posix_principal_is_immutable(make_principal):
    posix = PosixPrincipal.from_principal(make_principal())
    assert posix is not None

    with pytest.raises(dataclasses.FrozenInstanceError):
        posix.uid = 1  # type: ignore[misc]
