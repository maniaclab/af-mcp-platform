"""Unit tests for the typed link/ticket/proxy records the Vault stores return.

The stored record keeps both halves optional (a fresh link has no proxy yet).
Each store getter returns a narrowed record whose required fields are
non-Optional, validated once when the record is read, so callers need no
``assert ... is not None``.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from af_mcp_broker.credentials.krb5_vault import (
    Krb5Link,
    Krb5Ticket,
    StoredKrb5Credential,
)
from af_mcp_broker.credentials.servicex_vault import (
    ServiceXLink,
    ServiceXToken,
    StoredServiceXCredential,
)
from af_mcp_broker.credentials.x509_vault import (
    StoredX509Credential,
    X509Link,
    X509Proxy,
)


class TestX509Records:
    def test_a_complete_link_half_narrows_to_x509_link(self) -> None:
        record = StoredX509Credential(
            passphrase=SecretStr("pw"), unixname="alice", uid=1000, gid=1001
        )

        link = record.as_link()

        assert isinstance(link, X509Link)
        assert (link.passphrase.get_secret_value(), link.unixname) == ("pw", "alice")
        assert (link.uid, link.gid) == (1000, 1001)

    @pytest.mark.parametrize("missing", ["passphrase", "unixname", "uid", "gid"])
    def test_an_incomplete_link_half_is_not_a_link(self, missing: str) -> None:
        fields = {
            "passphrase": SecretStr("pw"),
            "unixname": "alice",
            "uid": 1000,
            "gid": 1001,
        }
        fields[missing] = None  # type: ignore[assignment]

        assert StoredX509Credential(**fields).as_link() is None

    def test_a_proxy_narrows_to_x509_proxy_keeping_the_metadata(self) -> None:
        record = StoredX509Credential(
            proxy_pem=SecretStr("PEM"),
            dn="/DC=ch/CN=alice",
            voms_attributes=["/atlas"],
            not_after=1234.5,
            nickname="alice",
        )

        proxy = record.as_proxy()

        assert isinstance(proxy, X509Proxy)
        assert proxy.not_after == pytest.approx(1234.5)
        assert (proxy.dn, proxy.voms_attributes, proxy.nickname) == (
            "/DC=ch/CN=alice",
            ["/atlas"],
            "alice",
        )

    def test_a_record_without_a_proxy_is_not_a_proxy(self) -> None:
        record = StoredX509Credential(
            passphrase=SecretStr("pw"), unixname="a", uid=1, gid=1
        )

        assert record.as_proxy() is None

    def test_the_narrowed_types_reject_missing_required_fields(self) -> None:
        with pytest.raises(ValidationError):
            X509Link.model_validate({"passphrase": None})
        with pytest.raises(ValidationError):
            X509Proxy.model_validate({"proxy_pem": "PEM", "not_after": None})


class TestKrb5Records:
    def test_a_complete_link_half_narrows_to_krb5_link(self) -> None:
        record = StoredKrb5Credential(username="alice", keytab_b64=SecretStr("kt"))

        link = record.as_link()

        assert link == Krb5Link(username="alice", keytab_b64=SecretStr("kt"))

    @pytest.mark.parametrize(
        "record",
        [
            StoredKrb5Credential(username="alice"),
            StoredKrb5Credential(keytab_b64=SecretStr("kt")),
            StoredKrb5Credential(),
        ],
    )
    def test_an_incomplete_link_half_is_not_a_link(
        self, record: StoredKrb5Credential
    ) -> None:
        assert record.as_link() is None

    def test_a_complete_ticket_half_narrows_to_krb5_ticket(self) -> None:
        record = StoredKrb5Credential(
            username="alice",
            ccache_b64=SecretStr("cc"),
            principal="alice@CERN.CH",
            realm="CERN.CH",
            not_after=100.0,
            renew_until=200.0,
        )

        ticket = record.as_ticket()

        assert ticket == Krb5Ticket(
            ccache_b64=SecretStr("cc"),
            not_after=100.0,
            principal="alice@CERN.CH",
            realm="CERN.CH",
            renew_until=200.0,
        )

    @pytest.mark.parametrize(
        "record",
        [
            StoredKrb5Credential(ccache_b64=SecretStr("cc")),
            StoredKrb5Credential(not_after=100.0),
            StoredKrb5Credential(username="alice", keytab_b64=SecretStr("kt")),
        ],
    )
    def test_an_incomplete_ticket_half_is_not_a_ticket(
        self, record: StoredKrb5Credential
    ) -> None:
        assert record.as_ticket() is None


class TestServiceXRecords:
    def test_a_refresh_token_narrows_to_servicex_link(self) -> None:
        record = StoredServiceXCredential(refresh_token=SecretStr("rt"))

        link = record.as_link()

        assert isinstance(link, ServiceXLink)
        assert link.refresh_token.get_secret_value() == "rt"

    def test_no_refresh_token_is_not_a_link(self) -> None:
        assert StoredServiceXCredential().as_link() is None

    def test_an_access_token_narrows_to_servicex_token(self) -> None:
        record = StoredServiceXCredential(
            refresh_token=SecretStr("rt"),
            access_token=SecretStr("at"),
            expires_at=50.0,
        )

        token = record.as_token()

        assert isinstance(token, ServiceXToken)
        assert token.access_token.get_secret_value() == "at"
        assert token.expires_at == pytest.approx(50.0)

    @pytest.mark.parametrize(
        "record",
        [
            StoredServiceXCredential(access_token=SecretStr("at")),
            StoredServiceXCredential(expires_at=50.0),
            StoredServiceXCredential(refresh_token=SecretStr("rt")),
        ],
    )
    def test_an_incomplete_token_half_is_not_a_token(
        self, record: StoredServiceXCredential
    ) -> None:
        assert record.as_token() is None
