"""Fakes and builders shared by the tests of ``test_servicex``."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from pydantic import SecretStr

from af_mcp_broker.credentials.servicex_service import RedeemedServiceXToken
from af_mcp_broker.credentials.servicex_vault import (
    ServiceXLink,
    ServiceXToken,
    StoredServiceXCredential,
)


class FakeServiceXStore:
    """In-memory stand-in for ``VaultServiceXStore`` (same public API)."""

    def __init__(self) -> None:
        self.records: dict[str, StoredServiceXCredential] = {}
        self.deleted: list[str] = []

    async def store_link(self, subject: str, *, refresh_token: SecretStr) -> None:
        self.records[subject] = StoredServiceXCredential(refresh_token=refresh_token)

    async def get_link(self, subject: str) -> ServiceXLink | None:
        record = self.records.get(subject)
        return record.as_link() if record is not None else None

    async def store_token(
        self, subject: str, *, access_token: str, expires_at: float
    ) -> None:
        base = self.records.get(subject, StoredServiceXCredential())
        self.records[subject] = base.model_copy(
            update={
                "access_token": SecretStr(access_token),
                "expires_at": expires_at,
            }
        )

    async def get_token(
        self, subject: str, min_remaining: float = 0.0
    ) -> ServiceXToken | None:
        record = self.records.get(subject)
        token = record.as_token() if record is not None else None
        if token is None or token.expires_at - time.time() < min_remaining:
            return None
        return token

    async def clear_token(self, subject: str) -> None:
        record = self.records.get(subject)
        if record is None:
            return
        self.records[subject] = record.model_copy(
            update={"access_token": None, "expires_at": None}
        )

    async def delete(self, subject: str) -> None:
        self.records.pop(subject, None)
        self.deleted.append(subject)


class FakeServiceXClient:
    """Recording fake for ``ServiceXTokenServiceClient.redeem``.

    ``outcome`` is a ``RedeemedServiceXToken`` to return or an exception to
    raise; every call's kwargs are recorded in ``calls``.
    """

    def __init__(
        self,
        outcome: RedeemedServiceXToken | Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        self.outcome = outcome or _redeemed()
        self.delay = delay
        self.calls: list[dict[str, Any]] = []

    async def redeem(self, **kwargs: Any) -> RedeemedServiceXToken:
        self.calls.append(kwargs)
        if self.delay:
            await asyncio.sleep(self.delay)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _redeemed(remaining: float = 3600.0) -> RedeemedServiceXToken:
    return RedeemedServiceXToken(
        access_token=_ACCESS_TOKEN, expires_at=time.time() + remaining
    )


_ACCESS_TOKEN = "fresh-access-token"
