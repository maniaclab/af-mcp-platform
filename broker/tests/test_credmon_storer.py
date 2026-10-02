"""Unit tests for the HTCondor credmon storer (docs/credmon.md).

``CredmonStorer.run_once`` is one sync cycle: for every subject that has a
linked identity of a credmon kind and a POSIX unixname, mint a top token
(an AF Broker Identity Token with aud ``af-credmon/<kind>``) and push it to
credd -- through a ``CredentialStoreClient`` -- as service ``af_<kind>``
for that unixname. These tests drive it with in-memory fakes; the
htcondor-api HTTP client is covered separately.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import jwt
import pytest
from test_broker_issued import ISSUER_URL, _make_rsa_key, _private_pem

from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
from af_mcp_broker.credmon import storer as storer_module
from af_mcp_broker.credmon.storer import (
    CredentialStoreClient,
    CredentialStoreError,
    CredmonKind,
    CredmonStorer,
    SubjectSource,
)

if TYPE_CHECKING:
    from af_mcp_broker.audit import AuditRecord
    from af_mcp_broker.identity import Principal

_TTL = 86400


class _FakeSubjects(SubjectSource):
    def __init__(self, by_kind: dict[str, list[str]]) -> None:
        self.by_kind = by_kind

    async def list_subjects(self, kind: str) -> list[str]:
        return list(self.by_kind.get(kind, []))


class _FakeStoreClient(CredentialStoreClient):
    def __init__(self, fail_for_users: set[str] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail_for_users = fail_for_users or set()

    async def store_service_credential(
        self, *, user: str, service: str, credential: dict[str, str]
    ) -> None:
        if user in self.fail_for_users:
            raise CredentialStoreError(f"credd rejected store for {user} (test)")
        self.calls.append({"user": user, "service": service, "credential": credential})


def _linked(subjects: set[str]):  # type: ignore[no-untyped-def]
    async def _is_linked(principal: Principal) -> bool:
        return principal.subject in subjects

    return _is_linked


@pytest.fixture
def issuer() -> BrokerTokenIssuer:
    return BrokerTokenIssuer(
        private_key_pem=_private_pem(_make_rsa_key()), issuer=ISSUER_URL
    )


@pytest.fixture
def captured_audits(monkeypatch: pytest.MonkeyPatch) -> list[AuditRecord]:
    records: list[AuditRecord] = []

    async def _fake_write_audit(record: AuditRecord) -> None:
        records.append(record)

    monkeypatch.setattr(storer_module, "write_audit", _fake_write_audit)
    return records


def _storer(
    issuer: BrokerTokenIssuer,
    principal_cache: Any,
    *,
    kinds: list[CredmonKind],
    subjects: dict[str, list[str]],
    client: _FakeStoreClient,
) -> CredmonStorer:
    return CredmonStorer(
        issuer=issuer,
        kinds=kinds,
        subjects=_FakeSubjects(subjects),
        principal_cache=principal_cache,
        client=client,
        audience_prefix="af-credmon/",
        service_prefix="af_",
        top_token_ttl_seconds=_TTL,
    )


async def test_stores_top_token_for_linked_subject_with_unixname(
    issuer, static_principal_cache, captured_audits
) -> None:
    cache, directory = static_principal_cache
    directory.posix_by_subject["sub-a"] = {
        "uid": 1001,
        "gid": 1001,
        "unixname": "alice",
    }
    client = _FakeStoreClient()
    storer = _storer(
        issuer,
        cache,
        kinds=[CredmonKind("krb5", _linked({"sub-a"}))],
        subjects={"krb5": ["sub-a"]},
        client=client,
    )

    report = await storer.run_once()

    assert report.stored == {"krb5": 1}
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["user"] == "alice"
    assert call["service"] == "af_krb5"
    claims = issuer.verify(call["credential"]["access_token"])
    assert claims is not None
    assert claims["sub"] == "sub-a"
    assert claims["aud"] == "af-credmon/krb5"
    assert claims["exp"] - claims["iat"] == _TTL
    # The audit line records who/what, never the token itself.
    assert len(captured_audits) == 1
    assert captured_audits[0].outcome == "success"
    assert captured_audits[0].principal_sub == "sub-a"
    assert call["credential"]["access_token"] not in captured_audits[0].args_summary


async def test_each_kind_gets_its_own_audience(
    issuer, static_principal_cache, captured_audits
) -> None:
    cache, directory = static_principal_cache
    directory.posix_by_subject["sub-a"] = {"unixname": "alice"}
    client = _FakeStoreClient()
    storer = _storer(
        issuer,
        cache,
        kinds=[
            CredmonKind("krb5", _linked({"sub-a"})),
            CredmonKind("x509", _linked({"sub-a"})),
        ],
        subjects={"krb5": ["sub-a"], "x509": ["sub-a"]},
        client=client,
    )

    report = await storer.run_once()

    assert report.stored == {"krb5": 1, "x509": 1}
    by_service = {c["service"]: c for c in client.calls}
    assert set(by_service) == {"af_krb5", "af_x509"}
    for kind in ("krb5", "x509"):
        token = by_service[f"af_{kind}"]["credential"]["access_token"]
        assert jwt.decode(token, options={"verify_signature": False})["aud"] == (
            f"af-credmon/{kind}"
        )


async def test_skips_subject_without_unixname(
    issuer, static_principal_cache, captured_audits
) -> None:
    """credd keys credentials by the POSIX owner of the job -- a subject with
    no unixname has no condor user to store for."""
    cache, _ = static_principal_cache
    client = _FakeStoreClient()
    storer = _storer(
        issuer,
        cache,
        kinds=[CredmonKind("krb5", _linked({"sub-a"}))],
        subjects={"krb5": ["sub-a"]},
        client=client,
    )

    report = await storer.run_once()

    assert client.calls == []
    assert report.stored == {"krb5": 0}
    assert report.skipped_no_posix == {"krb5": 1}


async def test_skips_subject_whose_identity_is_not_linked(
    issuer, static_principal_cache, captured_audits
) -> None:
    """A Vault record can outlive a usable link (e.g. an expired proxy with no
    stored passphrase) -- the provider's own is_linked is authoritative."""
    cache, directory = static_principal_cache
    directory.posix_by_subject["sub-a"] = {"unixname": "alice"}
    client = _FakeStoreClient()
    storer = _storer(
        issuer,
        cache,
        kinds=[CredmonKind("krb5", _linked(set()))],
        subjects={"krb5": ["sub-a"]},
        client=client,
    )

    report = await storer.run_once()

    assert client.calls == []
    assert report.not_linked == {"krb5": 1}


async def test_store_failure_is_isolated_to_that_subject(
    issuer, static_principal_cache, captured_audits
) -> None:
    cache, directory = static_principal_cache
    directory.posix_by_subject["sub-a"] = {"unixname": "alice"}
    directory.posix_by_subject["sub-b"] = {"unixname": "bob"}
    client = _FakeStoreClient(fail_for_users={"alice"})
    storer = _storer(
        issuer,
        cache,
        kinds=[CredmonKind("krb5", _linked({"sub-a", "sub-b"}))],
        subjects={"krb5": ["sub-a", "sub-b"]},
        client=client,
    )

    report = await storer.run_once()

    assert [c["user"] for c in client.calls] == ["bob"]
    assert report.stored == {"krb5": 1}
    assert report.failed == {"krb5": 1}
    assert any("alice" in err for err in report.errors)
    outcomes = sorted(r.outcome for r in captured_audits)
    assert outcomes == ["error", "success"]


async def test_directory_outage_for_one_subject_is_isolated(
    issuer, static_principal_cache, captured_audits
) -> None:
    cache, directory = static_principal_cache
    directory.unavailable_subjects.add("sub-a")
    directory.posix_by_subject["sub-b"] = {"unixname": "bob"}
    client = _FakeStoreClient()
    storer = _storer(
        issuer,
        cache,
        kinds=[CredmonKind("krb5", _linked({"sub-a", "sub-b"}))],
        subjects={"krb5": ["sub-a", "sub-b"]},
        client=client,
    )

    report = await storer.run_once()

    assert [c["user"] for c in client.calls] == ["bob"]
    assert report.failed == {"krb5": 1}
