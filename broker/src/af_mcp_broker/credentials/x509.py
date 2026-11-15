from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Literal

import structlog
from pydantic import SecretStr

from af_mcp_broker import metrics
from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
)
from af_mcp_broker.credentials.cache import ProxyMeta
from af_mcp_broker.credentials.errors import (
    NeedsUnlockError,
    PosixIdentityRequiredError,
    VomsServiceBadPassphraseError,
)
from af_mcp_broker.credentials.x509_vault import X509Proxy
from af_mcp_broker.principal import PosixPrincipal

if TYPE_CHECKING:
    from pydantic import SecretBytes

    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials.cache import CredentialCache
    from af_mcp_broker.credentials.voms_service import (
        MintedProxy,
        VomsTokenServiceClient,
    )
    from af_mcp_broker.credentials.x509_vault import VaultX509Store
    from af_mcp_broker.principal import Principal

log = structlog.get_logger(__name__)

# Targets served by the x509 provider
_DEFAULT_X509_TARGETS: frozenset[str] = frozenset({"ami"})


# ------------------------------------------------------------------
# X509Provider
# ------------------------------------------------------------------


@dataclass(frozen=True)
class X509LinkStatus:
    """How an x509 identity is linked, for surfaces that render custody.

    ``mode`` distinguishes the two custody choices (issue #112's follow-up
    consent toggle): ``"auto-renew"`` — a passphrase is stored, proxies
    re-mint hands-free; ``"until-expiry"`` — only the proxy is stored (the
    user declined passphrase custody), so the link lasts exactly as long as
    the proxy does. ``None`` when not linked.

    ``proxy_not_after`` is the expiry (epoch seconds) of the currently-valid
    stored proxy, or None when no valid proxy is stored — including the
    auto-renew case where the proxy has lapsed but the link survives.
    """

    linked: bool
    mode: Literal["auto-renew", "until-expiry"] | None
    proxy_not_after: float | None


class X509Provider(CredentialProvider):
    """Issues delegated x509 proxy credentials via voms-token-service.

    Minting is delegated to the service (the only component that mounts user
    homes), and both the proxy and the Globus passphrase persist in Vault
    (``VaultX509Store``, issue #112's custodianship model): the passphrase
    enables hands-free renewal when the stored proxy nears expiry, with a
    bad-passphrase failure on renewal unlinking the identity so the portal
    prompts a re-link. Backends fetch the PEM via
    ``POST /v1/credentials/x509/redeem``
    (``CredentialKind.X509_PROXY_REDEEM``) — no local file exists.

    Passphrase rules:
    - Never logged, never stored in the in-memory cache; persisted only in
      Vault, as the deliberate custodianship choice.
    - Revealed only at the HTTP call boundary (see voms_service.py's module
      docstring).
    - Rate-limited per uid; see ``Settings.credential_unlock_max_failures``
      and ``Settings.credential_unlock_window_seconds`` for the defaults
      (5 attempts / 15 minutes). Only genuine bad-passphrase failures count;
      infra failures never do.
    """

    cred_class: ClassVar[str] = "user_x509"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.DELEGATED

    def __init__(
        self,
        settings: Settings,
        cache: CredentialCache,
        voms_client: VomsTokenServiceClient,
        vault_store: VaultX509Store,
        targets: frozenset[str] = _DEFAULT_X509_TARGETS,
    ) -> None:
        self._settings = settings
        self._cache = cache
        self._targets = targets
        # The client to mint with and the store to persist in; app.py wires
        # both for every x509 entry.
        self._voms_client = voms_client
        self._vault_store = vault_store
        self._log = structlog.get_logger(__name__).bind(provider="X509Provider")

    @property
    def voms_client(self) -> VomsTokenServiceClient:
        """The voms-token-service client.

        Exposed so ``api/credentials.py``'s preflight route can proxy the
        service's credential-readiness checklist through the same
        authenticated client the mint path uses.
        """
        return self._voms_client

    @property
    def vault_store(self) -> VaultX509Store:
        """The Vault-backed link/proxy store.

        Exposed so ``api/credentials.py``'s redeem endpoint can serve/renew
        the Vault-stored proxy.
        """
        return self._vault_store

    @property
    def settings(self) -> Settings:
        """The ``Settings`` this provider was constructed with.

        Exposed so ``api/credentials.py`` can build the same actionable
        ``PosixIdentityRequiredError`` message ``issue()`` would raise,
        before its own ``is_linked()`` pre-check gate would otherwise hide it
        behind a generic "not linked" 404 (issue #148).
        """
        return self._settings

    async def is_linked(self, principal: Principal) -> bool:
        """Return True when the x509 identity currently works without re-entering anything.

        This covers BOTH custody choices (see ``link_status``): a stored
        passphrase (auto-renew — proxies re-mint hands-free) or a
        still-valid stored proxy with no passphrase (until-expiry — the link
        lasts exactly as long as the proxy). The filesystem is never
        consulted, since minting happens in the service's pod, not the
        broker's.

        Returns False (rather than raising) when *principal* has no POSIX
        identity at all: this method is used for best-effort status probing
        (the portal catalog, `/mcp` tools/list credential attempts) that must
        never crash for a principal without one (issue #148) -- the
        actionable ``PosixIdentityRequiredError`` instead surfaces from
        ``issue()``, at the point an x509 credential is actually minted.
        """
        return (await self.link_status(principal)).linked

    async def link_status(self, principal: Principal) -> X509LinkStatus:
        """Return *principal*'s linkage plus its custody mode and proxy expiry.

        The single source ``is_linked`` and ``/v1/identities`` both read: one
        Vault read decides linked-with-renewal (passphrase stored),
        linked-until-expiry (valid proxy, no passphrase), or unlinked — an
        expired proxy with no passphrase reads as UNLINKED, which is the
        bounded consequence remember=false users consented to.
        """
        record = await self._vault_store.get(principal.subject)
        if record is None:
            return X509LinkStatus(linked=False, mode=None, proxy_not_after=None)
        proxy_valid = (
            record.proxy_pem is not None
            and record.not_after is not None
            and record.not_after > time.time()
        )
        if record.has_link:
            return X509LinkStatus(
                linked=True,
                mode="auto-renew",
                proxy_not_after=record.not_after if proxy_valid else None,
            )
        if proxy_valid:
            return X509LinkStatus(
                linked=True, mode="until-expiry", proxy_not_after=record.not_after
            )
        return X509LinkStatus(linked=False, mode=None, proxy_not_after=None)

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,
        *,
        remember: bool = True,
    ) -> IssuedCredential:
        """Return an x509 proxy redeem credential.

        If a valid proxy is already cached, returns immediately without
        touching the service -- POSIX identity isn't needed just to serve an
        already-minted credential, so this check comes before the guard
        below. If there is no cached proxy and *principal* has no POSIX
        identity at all, raises ``PosixIdentityRequiredError`` naming
        *target*: minting can never succeed for such a principal, and saying
        so immediately is clearer than asking for a passphrase first only to
        fail after it's given. Otherwise, if no passphrase was provided,
        raises ``NeedsUnlockError`` so the caller can guide the user to POST their
        passphrase to ``/v1/x509/proxy``.

        ``remember`` is the custody consent captured alongside an explicit
        *passphrase*: False mints and stores the proxy but NOT the
        passphrase, making the link last exactly the proxy's validity window
        (see ``link_status``). Meaningless without a passphrase, and True
        (the hands-free-renewal default) is the standard custody choice.
        """
        cached = await self._cache.get(
            principal.subject, target, min_remaining=min_remaining_seconds
        )
        # An EXPLICIT passphrase is a linking act (the user may have just
        # changed their Globus password): it must reach the service and
        # update the stored passphrase, never short-circuit on a still-valid
        # cached credential.
        if cached is not None and passphrase is None:
            self._log.debug(
                "x509.issue.cache_hit", subject=principal.subject, target=target
            )
            return cached

        return await self._issue_via_service(
            principal, target, min_remaining_seconds, passphrase, remember=remember
        )

    async def revoke(self, principal: Principal, target: str) -> None:
        """Clear the cache entry and the Vault-stored proxy, so the redeem endpoint stops serving it.

        The LINK (passphrase) stays: burning a proxy must not unlink the
        identity, the next issue() simply renews hands-free. Unlinking is a
        separate, deliberate act (a bad-passphrase renewal, or a portal
        unlink).
        """
        # Read before revoke() pops the entry, for the audit log only.
        had_cached_proxy = (
            self._cache.get_proxy_meta(principal.subject, target) is not None
        )
        await self._cache.revoke(principal.subject, target)
        await self._vault_store.clear_proxy(principal.subject)
        if had_cached_proxy:
            self._log.info("x509.revoked", subject=principal.subject, target=target)

    def _posix_identity(self, principal: Principal, target: str) -> PosixPrincipal:
        """Return *principal* with its POSIX identity narrowed, or raise ``PosixIdentityRequiredError`` naming *target* when any field is missing."""
        posix = PosixPrincipal.from_principal(principal)
        if posix is None:
            raise PosixIdentityRequiredError(target, settings=self._settings)
        return posix

    # ------------------------------------------------------------------
    # Minting via voms-token-service
    # ------------------------------------------------------------------

    async def _issue_via_service(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int,
        passphrase: SecretBytes | None,
        *,
        remember: bool = True,
    ) -> IssuedCredential:
        """Serve the Vault-stored proxy, or mint via voms-token-service.

        Three paths, in order:

        1. A stored proxy with enough validity left is served directly.
           POSIX identity isn't needed just to serve an already-minted
           credential — same rule as the in-memory cache hit. (Skipped
           when a passphrase was explicitly given: that is a linking act,
           see ``issue()``.)
        2. A passphrase was given (the portal unlock/link flow): mint via
           the service, then persist BOTH the passphrase (the link enabling
           hands-free renewal) and the proxy in Vault.
        3. No passphrase: renew hands-free with the stored link, or raise
           ``NeedsUnlockError`` when there is none.
        """
        store = self._vault_store

        if passphrase is None:
            served = await self._serve_stored_proxy(
                principal, target, min_remaining_seconds
            )
            if served is not None:
                return served

            link = await store.get_link(principal.subject)
            if link is None:
                # An unlinked principal with no POSIX identity can never
                # complete a link — say that instead of asking for a
                # passphrase.
                self._posix_identity(principal, target)
                raise NeedsUnlockError(
                    target=target,
                    reason="not_linked",
                    unlock_endpoint="/v1/x509/proxy",
                )

            async def _do_renew() -> IssuedCredential:
                # Re-check under the single-flight lock: another caller may
                # have completed a renewal while this one waited.
                served = await self._serve_stored_proxy(
                    principal, target, min_remaining_seconds
                )
                if served is not None:
                    return served
                record = await self.renew_from_stored_link(principal.subject, target)
                return await self._cache_stored_record(principal, target, record)

            return await self._cache.get_or_mint(
                principal.subject, target, min_remaining_seconds, _do_renew
            )

        # Link/unlock flow: an explicit passphrase always reaches the
        # service — deliberately NOT deduped through get_or_mint, whose
        # cache re-check would swallow a re-link (the whole point is storing
        # a possibly-new passphrase). Link POSTs are one-off portal acts,
        # not the thundering-herd renewal path single-flighted above.
        posix = self._posix_identity(principal, target)
        return await self._link_and_mint(
            principal, posix, target, passphrase, remember=remember
        )

    async def _serve_stored_proxy(
        self, principal: Principal, target: str, min_remaining_seconds: int
    ) -> IssuedCredential | None:
        """Return a credential for the Vault-stored proxy if one with at least *min_remaining_seconds* of validity exists, else None."""
        record = await self._vault_store.get_proxy(
            principal.subject, min_remaining=min_remaining_seconds
        )
        if record is None:
            return None
        self._log.debug(
            "x509.issue.vault_hit", subject=principal.subject, target=target
        )
        return await self._cache_stored_record(principal, target, record)

    async def _link_and_mint(
        self,
        principal: Principal,
        posix: PosixPrincipal,
        target: str,
        passphrase: SecretBytes,
        *,
        remember: bool = True,
    ) -> IssuedCredential:
        """Mint via voms-token-service with a user-supplied passphrase, then persist the link and the proxy in Vault.

        *remember* is the custody consent: True stores the passphrase (the
        link enabling hands-free renewal); False stores only the POSIX
        identity alongside the proxy — the passphrase is used once for this
        mint and never persisted.

        A bad passphrase counts against the unlock rate limiter (the user
        typed it); an infra failure does not. Nothing is persisted on any
        failure.
        """
        await self._cache.check_unlock_rate_limit(posix.uid)
        # The service speaks JSON, so the passphrase crosses as str;
        # SecretStr keeps it out of repr/logs (see voms_service.py).
        passphrase_str = SecretStr(passphrase.get_secret_value().decode())
        try:
            minted = await self._voms_client.mint(
                subject=principal.subject,
                unixname=posix.unixname,
                uid=posix.uid,
                gid=posix.gid,
                passphrase=passphrase_str,
            )
        except VomsServiceBadPassphraseError:
            await self._cache.record_failed_unlock(posix.uid)
            raise

        await self._vault_store.store_link(
            principal.subject,
            passphrase=passphrase_str if remember else None,
            unixname=posix.unixname,
            uid=posix.uid,
            gid=posix.gid,
        )
        record = await self._store_minted_proxy(principal.subject, minted)
        self._log.info(
            "x509.linked",
            subject=principal.subject,
            target=target,
            dn=minted.dn,
            not_after=minted.not_after,
        )
        return await self._cache_stored_record(principal, target, record)

    async def renew_from_stored_link(self, subject: str, target: str) -> X509Proxy:
        """Mint a fresh proxy with *subject*'s Vault-stored passphrase and persist it — the hands-free renewal step.

        Public (also called by the redeem endpoint's renewal path, which
        holds only a broker-token subject, not a live ``Principal``).

        Raises:
            NeedsUnlockError: no link is stored, or the stored passphrase was
                rejected — in which case the identity is UNLINKED first (the
                user changed their Globus password; the stored passphrase is
                dead weight) so the portal prompts a re-link. A stored-
                passphrase failure is not a user brute-force attempt, so it
                does not count against the unlock rate limiter.
            VomsServiceMintError: the service failed for an infra reason —
                the link is kept and nothing is unlinked.

        """
        link = await self._vault_store.get_link(subject)
        if link is None:
            raise NeedsUnlockError(
                target=target, reason="not_linked", unlock_endpoint="/v1/x509/proxy"
            )
        try:
            minted = await self._voms_client.mint(
                subject=subject,
                unixname=link.unixname,
                uid=link.uid,
                gid=link.gid,
                passphrase=link.passphrase,
            )
        except VomsServiceBadPassphraseError as exc:
            await self._vault_store.delete(subject)
            self._log.info("x509.unlinked_stored_passphrase_rejected", subject=subject)
            raise NeedsUnlockError(
                target=target,
                reason="stored_passphrase_rejected",
                unlock_endpoint="/v1/x509/proxy",
            ) from exc
        return await self._store_minted_proxy(subject, minted)

    async def _store_minted_proxy(self, subject: str, minted: MintedProxy) -> X509Proxy:
        """Persist *minted* in Vault and return it as a stored record."""
        await self._vault_store.store_proxy(
            subject,
            pem=minted.pem,
            dn=minted.dn,
            voms_attributes=minted.voms_attributes,
            not_after=minted.not_after,
            nickname=minted.nickname,
        )
        # Single choke point for every successful mint (link, hands-free
        # renewal), so each counts exactly once. No username label --
        # per-user labels are forbidden outright; see metrics.py's
        # cardinality policy.
        metrics.x509_proxy_mints_total.inc()
        self._log.info(
            "x509.proxy_minted",
            subject=subject,
            dn=minted.dn,
            not_after=minted.not_after,
            source="voms_token_service",
        )
        return X509Proxy(
            proxy_pem=SecretStr(minted.pem),
            dn=minted.dn,
            voms_attributes=list(minted.voms_attributes),
            not_after=minted.not_after,
            nickname=minted.nickname,
        )

    async def _cache_stored_record(
        self, principal: Principal, target: str, record: X509Proxy
    ) -> IssuedCredential:
        """Build the redeem-kind credential for *record* and cache it in memory.

        ``uid`` is passed to ``cache.put`` only on link/renewal mints via
        the caller's principal — but a successful put after ANY correct-
        passphrase mint legitimately resets the failed-unlock counter, and
        serving an already-stored proxy involves no passphrase at all, so
        passing the principal's uid unconditionally is harmless: the
        counter only ever holds entries for genuine failures.
        """
        meta = ProxyMeta(
            dn=record.dn or "",
            voms_attributes=list(record.voms_attributes),
            not_after=record.not_after,
        )
        cred = self._build_credential(principal, target, meta)
        await self._cache.put(
            principal.subject,
            target,
            cred,
            expires_at=record.not_after,
            proxy_meta=meta,
            uid=principal.uid,
        )
        return cred

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_credential(
        self, principal: Principal, target: str, meta: ProxyMeta
    ) -> IssuedCredential:
        proxy_handle = f"px_{principal.uid}_{uuid.uuid4().hex[:8]}"
        audit_id = uuid.uuid4().hex
        # No local file exists — the backend fetches the PEM from Vault
        # via POST /v1/credentials/x509/redeem.
        payload: dict = {"proxy_handle": proxy_handle, "delivery": "redeem"}
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.X509_PROXY_REDEEM,
            expires_at=meta.not_after,
            payload=payload,
            audit_id=audit_id,
            source="voms_token_service",
            execution_model=self.execution_model,
        )
