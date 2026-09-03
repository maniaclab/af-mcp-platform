"""Kerberos tickets via krb5-token-service (issue #274, remember/keytab follow-up).

Unlike ``CondorTokenProvider`` (broker-authoritative, no external secret),
krb5-token-service needs a live CERN username+password to mint a ticket from
scratch -- there is no standing linkage the broker can redeem on its own
UNLESS the user has opted in to "remember" (below). ``issue()`` therefore
works through a five-tier fallback, mirroring ``X509Provider``'s
Vault-as-source-of-truth design, before ever raising ``NeedsUnlock``
(pointing at ``POST /v1/krb5/ticket``):

1. **Cache** -- an unexpired ticket already sits in the in-process
   ``CredentialCache``.
2. **Vault repopulation** -- a fresh-enough ticket sits in Vault even though
   the in-process cache was evicted or the pod restarted; served straight
   from there with no network call.
3. **Renew** -- the Vault-stored ticket is past its ``not_after`` but still
   within its own ``renew_until`` window: ``client.renew()`` extends it with
   no credential at all. An expected ``Krb5TokenRenewalWindowClosedError``
   falls through to the next tier; any other failure is a genuine infra
   problem and propagates uncaught, rather than being silently downgraded to
   demanding a password from the user.
4. **Keytab remint** -- a keytab was previously bootstrapped and stored
   (only when the user opted in to "remember" on an earlier mint):
   ``client.mint(keytab_b64=...)`` mints a fresh ticket with no live
   password. A rejected keytab (``Krb5TokenBadCredentialError`` -- e.g. the
   CERN password was rotated) proactively unlinks the identity
   (``vault_store.delete``, mirroring ``X509Provider.renew_from_stored_
   link``'s auto-unlink-on-bad-stored-passphrase behavior) and falls through
   to asking for a fresh password; any other failure propagates uncaught.
5. **Interactive password** -- nothing above worked: raise ``NeedsUnlock``
   unless a fresh username/passphrase was supplied, in which case mint via
   the live CERN password. ``remember=True`` additionally bootstraps and
   stores a keytab from that SAME password (one prompt, not two).

The ticket half (last-minted ccache + its own renewal deadline) is persisted
to Vault on EVERY successful mint or renewal, regardless of "remember" --
that is what makes tier 3 (renew) possible for every user, not just ones who
opted into durable keytab custody. Only the keytab (link) half is
custody-gated behind "remember".
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, ClassVar, Literal

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
from af_mcp_broker.credentials.krb5_service import (
    Krb5TokenBadCredentialError,
    Krb5TokenRenewalWindowClosedError,
)

if TYPE_CHECKING:
    from pydantic import SecretBytes

    from af_mcp_broker.credentials.cache import CredentialCache
    from af_mcp_broker.credentials.krb5_service import (
        Krb5TokenServiceClient,
        MintedTicket,
    )
    from af_mcp_broker.credentials.krb5_vault import (
        Krb5VaultStore,
        StoredKrb5Credential,
    )
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)

# The three tiers that persist a freshly minted/renewed ticket -- kept as a
# Literal (rather than a bare str) so a typo or an unlisted future value is
# caught by mypy at the _persist_and_cache() call sites, not at runtime.
_MintTier = Literal["renew", "keytab_remint", "password_mint"]


class KrbTokenProvider(CredentialProvider):
    """Issues per-user Kerberos tickets, falling back through Vault-backed renewal/remint tiers before ever prompting for a password -- see the module docstring."""

    cred_class: ClassVar[str] = "krb5_ticket"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.DELEGATED

    def __init__(
        self,
        client: Krb5TokenServiceClient,
        cache: CredentialCache,
        vault_store: Krb5VaultStore,
        alias: str,
        targets: frozenset[str],
    ) -> None:
        self._client = client
        self._cache = cache
        self._vault_store = vault_store
        self._alias = alias
        self._targets = targets
        self._log = structlog.get_logger(__name__).bind(
            provider="KrbTokenProvider", alias=alias
        )

    async def is_linked(self, principal: Principal) -> bool:
        """True iff a usable ticket can be produced right now with no password prompt.

        Checks, in order, whether any of this entry's targets has a live
        cached ticket (``CredentialCache.peek()``, so this status probe
        doesn't skew the cache hit/miss metrics ``get()`` records), then
        whether Vault holds a stored keytab, then whether Vault holds a
        still-renewable ticket half -- returning True on the first hit.
        Note this checks the cache with ``min_remaining=0`` while ``issue()``
        defaults to a 300s buffer (``min_remaining_seconds``) -- a ticket
        reported as "linked" here can still trigger a further fallback tier
        from an immediately-following ``issue()`` call, since the two use
        different staleness thresholds.
        """
        for target in self._targets:
            if (
                await self._cache.peek(principal.subject, target, min_remaining=0)
                is not None
            ):
                return True
        if await self._vault_store.get_link(principal.subject) is not None:
            return True
        return (
            await self._vault_store.get_renewable_ticket(principal.subject) is not None
        )

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
        remember: bool = False,
    ) -> IssuedCredential:
        """Return a ticket via the first tier that can produce one -- see the module docstring for the full fallback order.

        ``remember`` only matters on the tier-5 fresh-password path: when
        True, the same already-captured password additionally bootstraps and
        stores a keytab (one prompt, not two) so future calls can skip
        straight to tier 4 without the user re-entering anything.

        Raises:
            NeedsUnlock: nothing usable is cached or stored, and no fresh
                username/password was supplied -- the caller should POST
                both to ``/v1/krb5/ticket``.
            Krb5TokenBadCredentialError / Krb5TokenAccountError /
                Krb5TokenInvalidRequestError / Krb5TokenRateLimitedError /
                Krb5TokenMintError: a genuine service failure on the tier-5
                fresh mint, or on tier 3/4 when it isn't the expected
                window-closed / bad-stored-keytab signal those tiers already
                handle -- see ``Krb5TokenServiceClient``.

        """
        # Tier 1: in-process cache.
        cached = await self._cache.get(
            principal.subject, target, min_remaining=min_remaining_seconds
        )
        if cached is not None:
            self._log.debug(
                "krb5_token.issue.cache_hit", subject=principal.subject, target=target
            )
            return cached

        # Tier 2: repopulate from Vault -- the in-process cache may have been
        # evicted or the pod restarted, but Vault still has a ticket with
        # enough validity left.
        stored_ticket = await self._vault_store.get_ticket(
            principal.subject, min_remaining=min_remaining_seconds
        )
        if stored_ticket is not None:
            self._log.debug(
                "krb5_token.issue.vault_hit", subject=principal.subject, target=target
            )
            return await self._serve_stored_ticket(principal, target, stored_ticket)

        # Tier 3: renew a ticket that's past not_after but still within its
        # own renew_until window -- no credential needed.
        renewable = await self._vault_store.get_renewable_ticket(principal.subject)
        if renewable is not None:
            assert renewable.ccache_b64 is not None  # has_ticket guarantees this
            try:
                ticket = await self._client.renew(
                    subject=principal.subject,
                    ccache_b64=renewable.ccache_b64.get_secret_value(),
                )
            except Krb5TokenRenewalWindowClosedError:
                # Expected, recoverable: the renewable window has closed --
                # fall through to the next tier rather than surfacing this.
                self._log.info(
                    "krb5_token.issue.renewal_window_closed",
                    subject=principal.subject,
                    target=target,
                )
            else:
                return await self._persist_and_cache(
                    principal, target, ticket, tier="renew"
                )
            # Any OTHER exception from client.renew() propagates uncaught
            # here -- a genuine infra failure must surface as one, not be
            # silently downgraded to demanding a password.

        # Tier 4: remint from a previously-bootstrapped, stored keytab.
        link = await self._vault_store.get_link(principal.subject)
        if link is not None:
            assert link.username is not None  # has_link guarantees this
            assert link.keytab_b64 is not None  # has_link guarantees this
            try:
                ticket = await self._client.mint(
                    subject=principal.subject,
                    username=link.username,
                    keytab_b64=link.keytab_b64,
                    lifetime=lifetime,
                    renewable_lifetime=renewable_lifetime,
                )
            except Krb5TokenBadCredentialError:
                # The stored keytab is dead (e.g. the CERN password was
                # rotated since it was bootstrapped) -- unlink proactively,
                # mirroring X509Provider.renew_from_stored_link's
                # auto-unlink-on-bad-stored-passphrase behavior, then fall
                # through as if no link had ever existed.
                await self._vault_store.delete(principal.subject)
                self._log.info(
                    "krb5_token.issue.stored_keytab_rejected",
                    subject=principal.subject,
                )
            else:
                return await self._persist_and_cache(
                    principal, target, ticket, tier="keytab_remint"
                )
            # Any OTHER exception from client.mint() propagates uncaught here.

        # Tier 5: nothing usable without a password.
        if passphrase is None or username is None:
            raise NeedsUnlock(
                target,
                "Kerberos ticket not yet minted or expired",
                unlock_endpoint="/v1/krb5/ticket",
            )

        async def _do_mint() -> IssuedCredential:
            password = SecretStr(passphrase.get_secret_value().decode())
            ticket = await self._client.mint(
                subject=principal.subject,
                username=username,
                password=password,
                lifetime=lifetime,
                renewable_lifetime=renewable_lifetime,
            )
            cred = await self._persist_and_cache(
                principal, target, ticket, tier="password_mint"
            )
            if remember:
                # Reuses the SAME already-captured password -- never a
                # second prompt, never persisted anywhere but this one call.
                keytab_b64, keytab_principal = await self._client.mint_keytab(
                    subject=principal.subject, username=username, password=password
                )
                await self._vault_store.store_link(
                    principal.subject,
                    username=username,
                    keytab_b64=SecretStr(keytab_b64),
                )
                self._log.info(
                    "krb5_token.issue.keytab_remembered",
                    subject=principal.subject,
                    principal=keytab_principal,
                )
            return cred

        # Single-flighted like every other provider (issue #94's pattern).
        return await self._cache.get_or_mint(
            principal.subject, target, min_remaining_seconds, _do_mint
        )

    async def revoke(self, principal: Principal, target: str) -> None:
        """Drop the cached ticket and the Vault-stored ticket half; a stored keytab (the link) is untouched.

        ccaches are not server-side revocable, so the short lifetime is the
        actual revocation bound. Mirrors ``X509Provider.revoke()``'s
        revoke/unlink distinction: burning a ticket must not unlink the
        identity -- the next ``issue()`` can still remint via the stored
        keytab (tier 4).
        """
        await self._cache.revoke(principal.subject, target)
        await self._vault_store.clear_ticket(principal.subject)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _cred_from_ticket(self, ticket: MintedTicket, target: str) -> IssuedCredential:
        return IssuedCredential(
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
            audit_id=uuid.uuid4().hex,
            source="krb5_token_service",
            execution_model=self.execution_model,
        )

    async def _persist_and_cache(
        self,
        principal: Principal,
        target: str,
        ticket: MintedTicket,
        *,
        tier: _MintTier,
    ) -> IssuedCredential:
        """Build the credential for a freshly minted/renewed *ticket*, persist it to Vault, cache it, and return it."""
        cred = self._cred_from_ticket(ticket, target)
        await self._vault_store.store_ticket(
            principal.subject,
            ccache_b64=SecretStr(ticket.ccache_b64),
            principal=ticket.principal,
            realm=ticket.realm,
            not_after=ticket.not_after,
            renew_until=ticket.renew_until,
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
            audit_id=cred.audit_id,
            expires_at=ticket.not_after,
            tier=tier,
        )
        return cred

    async def _serve_stored_ticket(
        self, principal: Principal, target: str, record: StoredKrb5Credential
    ) -> IssuedCredential:
        """Build a credential from a Vault-stored ticket *record* and repopulate the in-process cache with it -- no service call, since Vault already has a ticket with enough validity left."""
        assert record.ccache_b64 is not None  # has_ticket guarantees this
        assert record.not_after is not None  # has_ticket guarantees this
        cred = IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.KRB5_CCACHE,
            expires_at=record.not_after,
            payload={
                "ccache_b64": record.ccache_b64.get_secret_value(),
                "principal": record.principal,
                "realm": record.realm,
                "renew_until": record.renew_until,
            },
            audit_id=uuid.uuid4().hex,
            source="krb5_token_service",
            execution_model=self.execution_model,
        )
        await self._cache.put(
            principal.subject, target, cred, expires_at=record.not_after
        )
        return cred
