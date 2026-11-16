"""Fakes and builders shared by the tests of ``test_krb5_token``."""

from __future__ import annotations

import time
from dataclasses import replace
from typing import TYPE_CHECKING

from af_mcp_broker.credentials.krb5_service import MintedTicket
from af_mcp_broker.credentials.krb5_vault import (
    Krb5Link,
    Krb5Ticket,
    StoredKrb5Credential,
)

if TYPE_CHECKING:
    from pydantic import SecretStr


class _FakeClient:
    """Recording fake for ``Krb5TokenServiceClient``'s mint/renew.

    Each method's outcome is scripted independently via the constructor
    (a success value, or an exception to raise) and every call's kwargs are
    recorded in that method's own ``*_calls`` list -- ``mint``'s list keeps
    the pre-existing name ``calls`` so the original tests need no changes.
    """

    def __init__(
        self,
        ticket: MintedTicket | None = None,
        error: Exception | None = None,
        renew_ticket: MintedTicket | None = None,
        renew_error: Exception | None = None,
    ):
        self._ticket = ticket
        self._error = error
        self._renew_ticket = renew_ticket
        self._renew_error = renew_error
        self.calls: list[dict] = []
        self.renew_calls: list[dict] = []

    async def mint(
        self,
        *,
        subject,
        username,
        password=None,
        keytab_b64=None,
        lifetime=None,
        renewable_lifetime=None,
    ):
        self.calls.append(
            {
                "subject": subject,
                "username": username,
                "password": password.get_secret_value()
                if password is not None
                else None,
                "keytab_b64": (
                    keytab_b64.get_secret_value() if keytab_b64 is not None else None
                ),
                "lifetime": lifetime,
                "renewable_lifetime": renewable_lifetime,
            }
        )
        if self._error is not None:
            raise self._error
        assert self._ticket is not None
        return self._ticket

    async def renew(self, *, subject, ccache_b64):
        self.renew_calls.append({"subject": subject, "ccache_b64": ccache_b64})
        if self._renew_error is not None:
            raise self._renew_error
        assert self._renew_ticket is not None
        return self._renew_ticket


class FakeKrb5VaultStore:
    """In-memory stand-in for ``Krb5VaultStore`` (same public API).

    Mirrors test_x509_service_mode.py's ``FakeX509Store`` convention: a
    plain dict keyed by subject, holding the same frozen record dataclass
    the real store round-trips.
    """

    def __init__(self) -> None:
        self.records: dict[str, StoredKrb5Credential] = {}
        self.deleted: list[str] = []

    async def store_link(
        self, subject: str, *, username: str, keytab_b64: SecretStr
    ) -> None:
        base = self.records.get(subject, StoredKrb5Credential())
        self.records[subject] = replace(base, username=username, keytab_b64=keytab_b64)

    async def get_link(self, subject: str) -> Krb5Link | None:
        record = self.records.get(subject)
        return record.as_link() if record is not None else None

    async def store_ticket(
        self,
        subject: str,
        *,
        ccache_b64: SecretStr,
        principal: str,
        realm: str,
        not_after: float,
        renew_until: float | None,
    ) -> None:
        base = self.records.get(subject, StoredKrb5Credential())
        self.records[subject] = replace(
            base,
            ccache_b64=ccache_b64,
            principal=principal,
            realm=realm,
            not_after=not_after,
            renew_until=renew_until,
        )

    async def get_ticket(
        self, subject: str, min_remaining: float = 0.0
    ) -> Krb5Ticket | None:
        record = self.records.get(subject)
        ticket = record.as_ticket() if record is not None else None
        if ticket is None or ticket.not_after - time.time() < min_remaining:
            return None
        return ticket

    async def get_renewable_ticket(self, subject: str) -> Krb5Ticket | None:
        record = self.records.get(subject)
        ticket = record.as_ticket() if record is not None else None
        if ticket is None:
            return None
        if ticket.renew_until is None or ticket.renew_until <= time.time():
            return None
        return ticket

    async def clear_ticket(self, subject: str) -> None:
        record = self.records.get(subject)
        if record is None:
            return
        self.records[subject] = replace(
            record,
            ccache_b64=None,
            principal=None,
            realm=None,
            not_after=None,
            renew_until=None,
        )

    async def delete(self, subject: str) -> None:
        self.records.pop(subject, None)
        self.deleted.append(subject)


def _ticket(not_after=None, renew_until=None, ccache_b64="ZmFrZQ==") -> MintedTicket:
    return MintedTicket(
        ccache_b64=ccache_b64,
        principal="alice@CERN.CH",
        realm="CERN.CH",
        not_after=not_after if not_after is not None else time.time() + 3600,
        renew_until=renew_until,
    )
