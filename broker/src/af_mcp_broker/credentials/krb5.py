"""Kerberos tickets via krb5-token-service (issue #274).

Unlike ``CondorTokenProvider`` (broker-authoritative, no external secret),
krb5-token-service needs a live CERN username+password on every mint --
there is no standing linkage the broker can redeem on its own. This
provider therefore raises ``NeedsUnlock`` (pointing at ``POST
/v1/krb5/ticket``, the credentials API's new endpoint) whenever no fresh
username/password was supplied and nothing valid is cached, mirroring
``X509Provider``'s passphrase-unlock doctrine rather than
``CondorTokenProvider``'s unconditional ``is_linked() -> True``.

Nothing is persisted at rest: no Vault record, no "remember" option. The
CERN password is a live, non-recoverable secret (not a passphrase that
merely unlocks an already-stored credential the way x509's Globus
passphrase does), so ``is_linked()`` reports whether a still-valid ticket
happens to be cached for one of this entry's targets -- not a durable
linkage state.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, ClassVar

import structlog
from pydantic import SecretStr

from af_mcp_broker import metrics
from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
    NeedsUnlock,
)

if TYPE_CHECKING:
    from pydantic import SecretBytes

    from af_mcp_broker.credentials.cache import CredentialCache
    from af_mcp_broker.credentials.krb5_service import Krb5TokenServiceClient
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)


class KrbTokenProvider(CredentialProvider):
    """Issues per-user Kerberos tickets by exchanging a caller-supplied CERN username/password at krb5-token-service.

    ``is_linked()`` reflects live cache state (True iff any of this entry's
    targets has an unexpired cached ticket) rather than a durable linkage --
    see the module docstring.
    """

    cred_class: ClassVar[str] = "krb5_ticket"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.DELEGATED

    def __init__(
        self,
        client: Krb5TokenServiceClient,
        cache: CredentialCache,
        alias: str,
        targets: frozenset[str],
    ) -> None:
        self._client = client
        self._cache = cache
        self._alias = alias
        self._targets = targets
        self._log = structlog.get_logger(__name__).bind(
            provider="KrbTokenProvider", alias=alias
        )

    async def is_linked(self, principal: Principal) -> bool:
        """True iff a still-valid ticket happens to be cached for one of this entry's targets — see the module docstring.

        Uses ``CredentialCache.peek()``, not ``get()``, so this status probe
        doesn't skew the credential-cache hit/miss metrics that ``get()``
        records. Note this checks with ``min_remaining=0`` while ``issue()``
        defaults to a 300s buffer (``min_remaining_seconds``) -- a ticket
        reported as "linked" here can still trigger ``NeedsUnlock`` from an
        immediately-following ``issue()`` call using that default buffer,
        since the two use different staleness thresholds.
        """
        for target in self._targets:
            if (
                await self._cache.peek(principal.subject, target, min_remaining=0)
                is not None
            ):
                return True
        return False

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,
        *,
        username: str | None = None,
        lifetime: str | None = None,
        renewable_lifetime: str | None = None,
    ) -> IssuedCredential:
        """Return a cached ticket, or mint a fresh one when *username*/*passphrase* (the CERN password) are supplied.

        Raises:
            NeedsUnlock: nothing valid is cached and no fresh
                username/password was supplied — the caller should POST
                both to ``/v1/krb5/ticket``.
            Krb5TokenBadCredentialError / Krb5TokenAccountError /
                Krb5TokenInvalidRequestError / Krb5TokenRateLimitedError /
                Krb5TokenMintError: see ``Krb5TokenServiceClient.mint``.

        """
        cached = await self._cache.get(
            principal.subject, target, min_remaining=min_remaining_seconds
        )
        if cached is not None:
            self._log.debug(
                "krb5_token.issue.cache_hit", subject=principal.subject, target=target
            )
            return cached

        if passphrase is None or username is None:
            raise NeedsUnlock(
                target,
                "Kerberos ticket not yet minted or expired",
                unlock_endpoint="/v1/krb5/ticket",
            )

        async def _do_mint() -> IssuedCredential:
            ticket = await self._client.mint(
                subject=principal.subject,
                username=username,
                password=SecretStr(passphrase.get_secret_value().decode()),
                lifetime=lifetime,
                renewable_lifetime=renewable_lifetime,
            )
            audit_id = uuid.uuid4().hex
            cred = IssuedCredential(
                cred_class=self.cred_class,
                target=target,
                kind=CredentialKind.KRB5_CCACHE,
                expires_at=ticket.not_after,
                payload={
                    "ccache_b64": ticket.ccache_b64,
                    "principal": ticket.principal,
                    "realm": ticket.realm,
                    "renew_until": ticket.renew_until,
                },
                audit_id=audit_id,
                source="krb5_token_service",
                execution_model=self.execution_model,
            )
            await self._cache.put(
                principal.subject, target, cred, expires_at=ticket.not_after
            )
            metrics.krb5_tickets_issued_total.labels(target=target).inc()
            # Never log ccache/password material -- subject/target/audit only.
            self._log.info(
                "krb5_token.issue.success",
                subject=principal.subject,
                target=target,
                audit_id=audit_id,
                expires_at=ticket.not_after,
            )
            return cred

        # Single-flighted like every other provider (issue #94's pattern).
        return await self._cache.get_or_mint(
            principal.subject, target, min_remaining_seconds, _do_mint
        )

    async def revoke(self, principal: Principal, target: str) -> None:
        """Drop the cached ticket; ccaches are not server-side revocable, so the short lifetime is the actual revocation bound."""
        await self._cache.revoke(principal.subject, target)
