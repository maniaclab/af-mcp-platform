"""Kerberos tickets via krb5-token-service (issue #274; keytab auto-bootstrap replaced by user-provided upload).

Unlike ``CondorTokenProvider`` (broker-authoritative, no external secret),
krb5-token-service needs a live CERN username+password to mint a ticket from
scratch -- there is no standing linkage the broker can redeem on its own
unless a keytab has already been linked (see ``link_keytab()`` below).
``issue()`` therefore works through a five-tier fallback, mirroring
``X509Provider``'s Vault-as-source-of-truth design, before ever raising
``NeedsUnlock`` (pointing at ``POST /v1/krb5/ticket``):

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
4. **Keytab remint** -- a keytab was previously linked via ``link_keytab()``:
   ``client.mint(keytab_b64=...)`` mints a fresh ticket with no live
   password. A rejected keytab (``Krb5TokenBadCredentialError`` -- e.g. the
   CERN password backing it was rotated) proactively unlinks the identity
   (``vault_store.delete``, mirroring ``X509Provider.renew_from_stored_
   link``'s auto-unlink-on-bad-stored-passphrase behavior) and falls through
   to asking for a fresh password; any other failure propagates uncaught.
5. **Interactive password** -- nothing above worked: raise ``NeedsUnlock``
   unless a fresh username/passphrase was supplied, in which case mint via
   the live CERN password.

The ticket half (last-minted ccache + its own renewal deadline) is persisted
to Vault on EVERY successful mint or renewal -- that is what makes tier 3
(renew) possible for every user, not just ones with a linked keytab. Only
the keytab (link) half requires a separate, explicit action.

The broker cannot mint that keytab itself. The obvious approach --
bootstrapping one from the same password a tier-5 caller just typed, via
krb5-token-service's ``cern-get-keytab``-backed ``mint_keytab()`` -- is
unreachable from this facility's network: ``cern-get-keytab``'s
``msktutil`` backend needs CERN-internal LDAP/AD reachability (to
``cerndc.cern.ch``, on ports other than the KDC's 88) plus an HTTPS call to
``lxkerbwin.cern.ch``, and neither host is reachable from here (confirmed by
testing: the call hangs and times out). An SSH-tunnel-through-lxplus
workaround was investigated and ruled out: lxplus enforces mandatory
multi-factor SSH (Kerberos plus a registered SSH key plus an interactive
2FA prompt), and that interactive step cannot be satisfied by an unattended
service. Tier 4 (remint from an already-linked keytab) is UNAFFECTED by any
of this: ``kinit -kt`` only needs the CERN KDC on port 88, already open and
already used by every other tier.

Instead, ``link_keytab()`` (below, parallel to ``revoke()``/``unlink()``,
not part of ``issue()``'s tier fallback) accepts a keytab the user generated
themselves -- e.g. on lxplus, which has no such reachability problem, since
it runs directly on CERN's network -- validates it by minting a ticket with
it (the exact same ``Krb5TokenServiceClient.mint(..., keytab_b64=...)`` call
tier 4 already uses), and on success stores it via the exact same
``Krb5VaultStore.store_link()`` schema tier 4 already reads from. Only how
the link gets INTO Vault has changed -- upload instead of auto-bootstrap.
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
_MintTier = Literal["renew", "keytab_remint", "password_mint", "keytab_link"]


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
        """Return True iff a usable ticket can be produced right now with no password prompt.

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

    async def has_keytab_link(self, principal: Principal) -> bool:
        """Whether *principal* has a durably linked keytab (tier 4 can remint hands-free forever), independent of ``is_linked()``.

        ``is_linked()`` also returns True for a principal with nothing but a
        live cached ticket or a still-renewable ticket half and no keytab at
        all -- that link is bounded (it lasts only until the ticket's own
        ``renew_until``), whereas a keytab link is durable. Exposed for
        ``/v1/identities``' status display (``IdentityProvider.
        krb5_has_keytab``), mirroring ``X509Provider.link_status()``'s
        ``mode`` distinction between "auto-renew" and "until-expiry".
        """
        return await self._vault_store.get_link(principal.subject) is not None

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
        """Return a ticket via the first tier that can produce one -- see the module docstring for the full fallback order.

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
            return await self._serve_stored_ticket(
                principal.subject, target, stored_ticket
            )

        # Tier 3: renew a ticket that's past not_after but still within its
        # own renew_until window -- no credential needed.
        renewable = await self._vault_store.get_renewable_ticket(principal.subject)
        if renewable is not None:
            assert renewable.ccache_b64 is not None  # has_ticket guarantees this
            ccache_b64 = renewable.ccache_b64.get_secret_value()

            async def _do_renew() -> IssuedCredential:
                ticket = await self._client.renew(
                    subject=principal.subject,
                    ccache_b64=ccache_b64,
                )
                return await self._persist_and_cache(
                    principal, target, ticket, tier="renew"
                )

            # Single-flighted like X509Provider._do_renew (issue #94's
            # pattern): unlike tier 5 below, this carries no consent flag,
            # so a concurrent caller reusing the first caller's renewal is
            # exactly what should happen, not a bug. The try/except sits
            # OUTSIDE get_or_mint rather than inside _do_renew, so the
            # expected Krb5TokenRenewalWindowClosedError propagates through
            # get_or_mint uninterrupted to this tier-dispatch logic instead
            # of being swallowed by the single-flight machinery.
            try:
                return await self._cache.get_or_mint(
                    principal.subject, target, min_remaining_seconds, _do_renew
                )
            except Krb5TokenRenewalWindowClosedError:
                # Expected, recoverable: the renewable window has closed --
                # fall through to the next tier rather than surfacing this.
                self._log.info(
                    "krb5_token.issue.renewal_window_closed",
                    subject=principal.subject,
                    target=target,
                )
            # Any OTHER exception from client.renew() propagates uncaught
            # here -- a genuine infra failure must surface as one, not be
            # silently downgraded to demanding a password.

        # Tier 4: remint from a previously-bootstrapped, stored keytab.
        link = await self._vault_store.get_link(principal.subject)
        if link is not None:
            assert link.username is not None  # has_link guarantees this
            assert link.keytab_b64 is not None  # has_link guarantees this
            link_username = link.username
            link_keytab_b64 = link.keytab_b64

            async def _do_remint() -> IssuedCredential:
                ticket = await self._client.mint(
                    subject=principal.subject,
                    username=link_username,
                    keytab_b64=link_keytab_b64,
                    lifetime=lifetime,
                    renewable_lifetime=renewable_lifetime,
                )
                return await self._persist_and_cache(
                    principal, target, ticket, tier="keytab_remint"
                )

            # Single-flighted for the same reason as tier 3 above: no
            # consent flag here either, so deduping concurrent remints is
            # strictly a win. Same try/except-outside-get_or_mint structure
            # so the expected Krb5TokenBadCredentialError still reaches this
            # tier-dispatch logic instead of the single-flight machinery.
            try:
                return await self._cache.get_or_mint(
                    principal.subject, target, min_remaining_seconds, _do_remint
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
            return await self._persist_and_cache(
                principal, target, ticket, tier="password_mint"
            )

        # Deliberately NOT single-flighted through get_or_mint (unlike every
        # other provider's cache-miss mint, issue #94's pattern) -- this is
        # an explicit password mint, and get_or_mint's in-flight re-check
        # only looks at the in-process cache: a concurrent caller supplying
        # a DIFFERENT password would silently get back the first caller's
        # mint result instead of its own. Mirrors
        # X509Provider._issue_via_service's own explicit-passphrase path
        # (see its comment on why THAT call is not deduped through
        # get_or_mint either) -- tiers 1-4 above (cache, Vault repopulation,
        # renew, keytab remint) carry no live credential and remain
        # unwrapped/direct as they always were.
        return await _do_mint()

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

    async def unlink(self, principal: Principal) -> None:
        """Delete the stored keytab (link), fully forgetting this identity.

        Distinct from ``revoke()``, which only drops a single target's
        cached/Vault-stored ticket and leaves the keytab in place so tier 4
        can remint from it -- ``unlink()`` is the stronger, user-initiated
        "forget me" operation: it deletes the entire Vault record (keytab
        AND any ticket half), mirroring ``X509Provider``'s auto-unlink-on-
        bad-stored-passphrase (``renew_from_stored_link``) but triggered by
        the user rather than a rejected credential. Called by ``DELETE
        /v1/identities/link/{provider}``'s krb5-token branch.
        """
        await self._vault_store.delete(principal.subject)

    async def link_keytab(
        self,
        principal: Principal,
        target: str,
        *,
        username: str,
        keytab_b64: str,
        lifetime: str | None = None,
        renewable_lifetime: str | None = None,
    ) -> IssuedCredential:
        """Validate a user-supplied keytab by minting a ticket with it, then store it as this principal's link.

        The broker cannot generate a keytab itself (see the module docstring
        for why ``cern-get-keytab`` is unreachable from this facility's
        network) -- the user generates one themselves (e.g. on lxplus) and
        uploads it here. Validation IS the mint: a bad keytab surfaces as
        the exact same ``Krb5TokenBadCredentialError`` tier 4's remint
        already handles, from the exact same underlying ``kinit -kt`` check
        (krb5-token-service's own mint endpoint, keytab_b64 branch) -- there
        is no separate "just check, don't use" call.

        Nothing is stored if validation fails: this mints (and thus proves
        the keytab works) BEFORE calling store_link, not after -- a caller
        must never end up with a bad keytab persisted to Vault.
        """
        keytab_secret = SecretStr(keytab_b64)
        ticket = await self._client.mint(
            subject=principal.subject,
            username=username,
            keytab_b64=keytab_secret,
            lifetime=lifetime,
            renewable_lifetime=renewable_lifetime,
        )
        await self._vault_store.store_link(
            principal.subject,
            username=username,
            keytab_b64=keytab_secret,
        )
        return await self._persist_and_cache(
            principal, target, ticket, tier="keytab_link"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_credential(
        self,
        target: str,
        *,
        ccache_b64: str,
        principal: str | None,
        realm: str | None,
        not_after: float,
        renew_until: float | None,
    ) -> IssuedCredential:
        """Build an ``IssuedCredential`` from a ticket's primitive fields, shared by ``_cred_from_ticket`` (a freshly minted/renewed ``MintedTicket``) and ``_serve_stored_ticket`` (a Vault-stored ``StoredKrb5Credential``, whose ``SecretStr`` fields the caller must unwrap first)."""
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.KRB5_CCACHE,
            expires_at=not_after,
            payload={
                "ccache_b64": ccache_b64,
                "principal": principal,
                "realm": realm,
                "renew_until": renew_until,
            },
            audit_id=uuid.uuid4().hex,
            source="krb5_token_service",
            execution_model=self.execution_model,
        )

    def _cred_from_ticket(self, ticket: MintedTicket, target: str) -> IssuedCredential:
        return self._build_credential(
            target,
            ccache_b64=ticket.ccache_b64,
            principal=ticket.principal,
            realm=ticket.realm,
            not_after=ticket.not_after,
            renew_until=ticket.renew_until,
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
        self, subject: str, target: str, record: StoredKrb5Credential
    ) -> IssuedCredential:
        """Build a credential from a Vault-stored ticket *record* and repopulate the in-process cache with it -- no service call, since Vault already has a ticket with enough validity left.

        Takes *subject* directly (not a ``Principal``) since the cache key is
        all this needs -- shared by ``issue()``'s tier 2 and the read-only
        ``peek_ticket()`` below, neither of which has any other use here for
        a full ``Principal``.
        """
        assert record.ccache_b64 is not None  # has_ticket guarantees this
        assert record.not_after is not None  # has_ticket guarantees this
        cred = self._build_credential(
            target,
            ccache_b64=record.ccache_b64.get_secret_value(),
            principal=record.principal,
            realm=record.realm,
            not_after=record.not_after,
            renew_until=record.renew_until,
        )
        await self._cache.put(subject, target, cred, expires_at=record.not_after)
        return cred

    async def peek_ticket(
        self, subject: str, target: str, min_remaining_seconds: int = 300
    ) -> IssuedCredential | None:
        """Return whatever ticket is currently available for *(subject, target)*, without minting, renewing, or ever prompting for a password.

        The read-only subset of ``issue()``'s tiers 1-2 (cache, then Vault
        repopulation) -- see the module docstring for the full tier order.
        Deliberately stops there: tiers 3-5 (renew, keytab remint, password
        mint) each require a synchronous krb5-token-service network round
        trip (tier 3's renew included -- it needs no credential, but still
        calls out to the service), which this route must never perform at
        redeem time; it only serves whatever is already resolved and
        cached/stored. Tiers 4-5 additionally require a password, which a
        synchronous backend-to-backend call has no way to prompt a user for.
        Used by ``POST /v1/credentials/krb5/redeem``
        (api/credentials.py) -- the krb5 analogue of
        ``X509Provider.vault_store``'s direct read for
        ``POST /v1/credentials/x509/redeem``.
        """
        # Tier 1: in-process cache.
        cached = await self._cache.get(
            subject, target, min_remaining=min_remaining_seconds
        )
        if cached is not None:
            return cached

        # Tier 2: repopulate from Vault -- the in-process cache may have been
        # evicted or the pod restarted, but Vault still has a ticket with
        # enough validity left.
        record = await self._vault_store.get_ticket(
            subject, min_remaining=min_remaining_seconds
        )
        if record is None:
            return None
        return await self._serve_stored_ticket(subject, target, record)
