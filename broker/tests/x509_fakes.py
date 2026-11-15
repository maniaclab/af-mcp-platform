"""In-memory fakes of the x509 Vault store and the voms-token-service client.

``FakeX509Store`` implements ``VaultX509Store``'s public API (its Vault wire
behavior is covered by test_x509_vault.py); ``FakeVomsClient`` records every
mint call and returns or raises a scriptable outcome. Shared by conftest's
default app wiring and the x509 test modules.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from pydantic import SecretStr

from af_mcp_broker.credentials.voms_service import MintedProxy
from af_mcp_broker.credentials.x509_vault import (
    StoredX509Credential,
    X509Link,
    X509Proxy,
)

PEM = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
DN = "/DC=ch/DC=cern/CN=Test User"
VOMS_ATTRS = ["/atlas/Role=NULL", "/atlas"]


class FakeX509Store:
    """In-memory stand-in for ``VaultX509Store`` (same public API)."""

    def __init__(self) -> None:
        self.records: dict[str, StoredX509Credential] = {}
        self.deleted: list[str] = []

    async def store_link(
        self,
        subject: str,
        *,
        passphrase: SecretStr | None,
        unixname: str,
        uid: int,
        gid: int,
    ) -> None:
        self.records[subject] = StoredX509Credential(
            passphrase=passphrase, unixname=unixname, uid=uid, gid=gid
        )

    async def get_link(self, subject: str) -> X509Link | None:
        record = self.records.get(subject)
        return record.as_link() if record is not None else None

    async def get(self, subject: str) -> StoredX509Credential | None:
        return self.records.get(subject)

    async def store_proxy(
        self,
        subject: str,
        *,
        pem: str,
        dn: str,
        voms_attributes: list[str],
        not_after: float,
        nickname: str | None = None,
    ) -> None:
        base = self.records.get(subject, StoredX509Credential())
        self.records[subject] = base.model_copy(
            update={
                "proxy_pem": SecretStr(pem),
                "dn": dn,
                "voms_attributes": list(voms_attributes),
                "not_after": not_after,
                "nickname": nickname,
            }
        )

    async def get_proxy(
        self, subject: str, min_remaining: float = 0.0
    ) -> X509Proxy | None:
        record = self.records.get(subject)
        proxy = record.as_proxy() if record is not None else None
        if proxy is None or proxy.not_after - time.time() < min_remaining:
            return None
        return proxy

    async def clear_proxy(self, subject: str) -> None:
        record = self.records.get(subject)
        if record is None:
            return
        self.records[subject] = record.model_copy(
            update={
                "proxy_pem": None,
                "dn": None,
                "voms_attributes": [],
                "not_after": None,
            }
        )

    async def delete(self, subject: str) -> None:
        self.records.pop(subject, None)
        self.deleted.append(subject)


class FakeVomsClient:
    """Recording fake for ``VomsTokenServiceClient.mint``.

    ``outcome`` is a ``MintedProxy`` to return or an exception to raise;
    every call's kwargs are recorded in ``calls``.
    """

    def __init__(
        self, outcome: MintedProxy | Exception | None = None, delay: float = 0.0
    ) -> None:
        self.outcome = outcome or minted()
        self.delay = delay
        self.calls: list[dict[str, Any]] = []

    async def mint(self, **kwargs: Any) -> MintedProxy:
        self.calls.append(kwargs)
        if self.delay:
            await asyncio.sleep(self.delay)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def minted(remaining: float = 3600.0, nickname: str | None = None) -> MintedProxy:
    return MintedProxy(
        pem=PEM,
        dn=DN,
        voms_attributes=list(VOMS_ATTRS),
        not_after=time.time() + remaining,
        nickname=nickname,
    )


def seed_x509_link(
    store: FakeX509Store,
    subject: str = "sub-abc",
    *,
    passphrase: str | None = "stored-passphrase",
) -> None:
    """Store a Globus link for *subject* (the default test principal's identity) in *store*.

    ``passphrase=None`` stores only the POSIX identity, the shape a
    ``remember=false`` link leaves behind.
    """
    asyncio.run(
        store.store_link(
            subject,
            passphrase=SecretStr(passphrase) if passphrase is not None else None,
            unixname="tuser",
            uid=1000,
            gid=1000,
        )
    )


def seed_x509_proxy(
    store: FakeX509Store, subject: str = "sub-abc", *, remaining: float = 3600.0
) -> float:
    """Store a proxy valid for *remaining* seconds for *subject* in *store* and return its expiry (epoch seconds)."""
    proxy = minted(remaining)
    asyncio.run(
        store.store_proxy(
            subject,
            pem=proxy.pem,
            dn=proxy.dn,
            voms_attributes=proxy.voms_attributes,
            not_after=proxy.not_after,
        )
    )
    return proxy.not_after
