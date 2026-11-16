"""Unit tests for the helpers that narrow a validated Optional or a provider type without an ``assert``."""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest
from broker_state_helpers import make_broker_state

from af_mcp_broker.api.credentials import _krb5_expires_at
from af_mcp_broker.api.identities import _typed_provider
from af_mcp_broker.credentials import (
    CredentialKind,
    ExecutionModel,
    IssuedCredential,
    KrbTokenProvider,
    OIDCProvider,
    ServiceXProvider,
)
from af_mcp_broker.mcp.aggregator import _CachedFailure, _CachedItems


def _request(providers: dict[str, Any]) -> Any:
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                broker=make_broker_state(identity_providers=providers)
            )
        )
    )


class TestTypedProvider:
    def test_returns_the_provider_when_it_is_of_the_expected_kind(self) -> None:
        krb = object.__new__(KrbTokenProvider)

        assert _typed_provider(_request({"krb": krb}), "krb", KrbTokenProvider) is krb

    def test_raises_a_type_error_naming_both_types_on_a_mismatch(self) -> None:
        other = object.__new__(OIDCProvider)

        with pytest.raises(
            TypeError, match="'oidc' is a OIDCProvider, not a ServiceXProvider"
        ):
            _typed_provider(_request({"oidc": other}), "oidc", ServiceXProvider)

    def test_an_unknown_alias_is_a_key_error(self) -> None:
        with pytest.raises(KeyError):
            _typed_provider(_request({}), "missing", KrbTokenProvider)


class TestKrb5ExpiresAt:
    @staticmethod
    def _cred(expires_at: float | None) -> IssuedCredential:
        return IssuedCredential(
            cred_class="user_krb5",
            target="krb",
            kind=CredentialKind.KRB5_CCACHE,
            expires_at=expires_at,
            payload={},
            audit_id="audit",
            source="test",
            execution_model=ExecutionModel.DELEGATED,
        )

    def test_returns_the_end_time(self) -> None:
        assert _krb5_expires_at(self._cred(123.0)) == pytest.approx(123.0)

    def test_a_credential_without_an_end_time_is_an_invariant_error(self) -> None:
        with pytest.raises(RuntimeError, match="always has an end time"):
            _krb5_expires_at(self._cred(None))


class TestCachedListingServe:
    def test_a_cached_failure_is_re_raised(self) -> None:
        entry = _CachedFailure(error=ValueError("backend down"), timestamp=0.0)

        with pytest.raises(ValueError, match="backend down"):
            entry.serve()

    def test_a_cached_success_returns_its_items(self) -> None:
        entry = _CachedItems(items=["tool"], timestamp=0.0)

        assert entry.serve() == ["tool"]

    def test_a_failure_stays_fresh_for_the_negative_ttl_whatever_the_success_ttl(
        self,
    ) -> None:
        now = time.monotonic()

        assert _CachedFailure(error=ValueError(), timestamp=now).is_fresh(0.0)
        assert not _CachedItems(items=[], timestamp=now).is_fresh(0.0)
