"""ServiceX access tokens via servicex-token-service (issue #295).

``ServiceXProvider`` is the third "vaulted secret, redeemed via a dedicated
microservice" provider (after ``X509Provider``'s voms-token-service mode and
``KrbTokenProvider``'s renewable-ticket mode), but the simplest of the
three: ServiceX's refresh token needs no POSIX identity to redeem (unlike
x509's home-directory-scoped mint) and is supplied once via a portal paste,
never re-entered per call (unlike krb5's live-password-per-call default) --
it is always the "hands-free renewal from a stored link" shape.

A stale/revoked refresh token is a link problem, not a redeem problem: on
``ServiceXBadRefreshTokenError`` the identity is unlinked (mirrors
``X509Provider.renew_from_stored_link``'s bad-passphrase-unlink) so the
portal prompts a re-paste, rather than repeatedly failing the same stale
token on every call.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, ClassVar

from pydantic import SecretStr

from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
    NeedsUnlock,
)
from af_mcp_broker.credentials.servicex_service import ServiceXBadRefreshTokenError

if TYPE_CHECKING:
    from pydantic import SecretBytes

    from af_mcp_broker.credentials.cache import CredentialCache
    from af_mcp_broker.credentials.servicex_service import ServiceXTokenServiceClient
    from af_mcp_broker.credentials.servicex_vault import (
        StoredServiceXCredential,
        VaultServiceXStore,
    )
    from af_mcp_broker.identity import Principal

_LINK_ENDPOINT = "/v1/servicex/link"


class ServiceXProvider(CredentialProvider):
    """Issues delegated ServiceX access-token credentials, redeemed via servicex-token-service.

    Unlike ``X509Provider``, there is no legacy/local mint path and no POSIX
    identity requirement -- every instance of this provider redeems via a
    configured ``ServiceXTokenServiceClient`` against a Vault-stored refresh
    token (``VaultServiceXStore``). Backends fetch the access token via
    ``POST /v1/credentials/servicex/redeem`` (``CredentialKind.
    SERVICEX_ACCESS_TOKEN_REDEEM``) -- no local file exists, no token ever
    transits to the LLM or client.
    """

    cred_class: ClassVar[str] = "user_servicex"
    execution_model: ClassVar[ExecutionModel] = ExecutionModel.DELEGATED

    def __init__(
        self,
        *,
        servicex_client: ServiceXTokenServiceClient,
        vault_store: VaultServiceXStore,
        cache: CredentialCache,
        alias: str = "",
        targets: frozenset[str] = frozenset(),
    ) -> None:
        self._servicex_client = servicex_client
        self._vault_store = vault_store
        self._cache = cache
        self._alias = alias
        self._targets = targets

    @property
    def vault_store(self) -> VaultServiceXStore:
        """The Vault-backed link/token store.

        Exposed so ``api/credentials.py``'s redeem endpoint can serve/renew
        the Vault-stored access token the same way the mint path does.
        """
        return self._vault_store

    async def is_linked(self, principal: Principal) -> bool:
        """Return True when *principal* has a stored ServiceX refresh token."""
        link = await self._vault_store.get_link(principal.subject)
        return link is not None

    async def link(self, subject: str, refresh_token: SecretStr) -> None:
        """Store *subject*'s ServiceX refresh token, verifying it with one redeem first.

        A bad refresh token at link time must not be silently stored --
        ``redeem_from_link`` propagates ``ServiceXBadRefreshTokenError``
        (never unlinking here, since there is nothing to unlink yet) so the
        caller (the ``/v1/servicex/link`` route) can surface a 400 before
        anything is persisted.
        """
        redeemed = await self._servicex_client.redeem(
            subject=subject, refresh_token=refresh_token
        )
        await self._vault_store.store_link(subject, refresh_token=refresh_token)
        await self._vault_store.store_token(
            subject,
            access_token=redeemed.access_token,
            expires_at=redeemed.expires_at,
        )

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,  # noqa: ARG002 (interface)
    ) -> IssuedCredential:
        """Return a redeem-kind credential for *(principal, target)*.

        Serves the Vault-stored access token if it has enough validity
        left; else redeems hands-free from the stored refresh token. Raises
        ``NeedsUnlock`` when there is no stored link at all, or when the
        stored refresh token has been rejected (in which case the identity
        is unlinked first, so the portal prompts a re-paste rather than
        repeating the same rejected token on every call).
        """
        served = await self._serve_stored_token(
            principal.subject, target, min_remaining_seconds
        )
        if served is not None:
            return served

        link = await self._vault_store.get_link(principal.subject)
        if link is None:
            raise NeedsUnlock(
                target=target, reason="not_linked", unlock_endpoint=_LINK_ENDPOINT
            )

        async def _do_redeem() -> IssuedCredential:
            # Re-check under the single-flight lock: another caller may
            # have completed a redeem while this one waited.
            served = await self._serve_stored_token(
                principal.subject, target, min_remaining_seconds
            )
            if served is not None:
                return served
            record = await self.redeem_from_link(principal.subject, target)
            return self._build_credential(target, record)

        # Single-flighted (issue #94's pattern, mirroring X509Provider):
        # concurrent misses for this (subject, target) await one redeem
        # instead of each independently hitting servicex-token-service.
        return await self._cache.get_or_mint(
            principal.subject, target, min_remaining_seconds, _do_redeem
        )

    async def redeem_from_link(
        self, subject: str, target: str
    ) -> StoredServiceXCredential:
        """Redeem a fresh access token with *subject*'s Vault-stored refresh token and persist it -- the hands-free renewal step.

        Public (also called by the redeem endpoint's renewal path, which
        holds only a broker-token subject, not a live ``Principal``).

        Raises:
            NeedsUnlock: no link is stored, or the stored refresh token was
                rejected -- in which case the identity is UNLINKED first
                (the token was revoked/expired; the stored value is dead
                weight) so the portal prompts a re-paste. A stored-token
                rejection is not a user brute-force attempt, so there is no
                rate limiter to count it against.
            ServiceXServiceMintError: the service failed for an infra
                reason -- the link is kept and nothing is unlinked.

        """
        link = await self._vault_store.get_link(subject)
        if link is None:
            raise NeedsUnlock(
                target=target, reason="not_linked", unlock_endpoint=_LINK_ENDPOINT
            )
        # get_link() guarantees the link half is complete; narrow for mypy.
        assert link.refresh_token is not None
        try:
            redeemed = await self._servicex_client.redeem(
                subject=subject, refresh_token=link.refresh_token
            )
        except ServiceXBadRefreshTokenError as exc:
            await self._vault_store.delete(subject)
            raise NeedsUnlock(
                target=target,
                reason="stored_refresh_token_rejected",
                unlock_endpoint=_LINK_ENDPOINT,
            ) from exc
        await self._vault_store.store_token(
            subject,
            access_token=redeemed.access_token,
            expires_at=redeemed.expires_at,
        )
        # Built directly from the redeem result rather than re-reading Vault
        # (same shortcut X509Provider._store_minted_proxy takes).
        return link.model_copy(
            update={
                "access_token": SecretStr(redeemed.access_token),
                "expires_at": redeemed.expires_at,
            }
        )

    async def revoke(self, principal: Principal, target: str) -> None:  # noqa: ARG002 (interface)
        """Clear the Vault-stored access token; the link (refresh token) stays.

        Burning an access token must not unlink the identity: the next
        issue() simply redeems hands-free. Unlinking is a separate,
        deliberate act (a rejected refresh token, or a portal unlink).
        """
        await self._vault_store.clear_token(principal.subject)

    async def _serve_stored_token(
        self, subject: str, target: str, min_remaining_seconds: int
    ) -> IssuedCredential | None:
        record = await self._vault_store.get_token(
            subject, min_remaining=min_remaining_seconds
        )
        if record is None:
            return None
        return self._build_credential(target, record)

    def _build_credential(
        self, target: str, record: StoredServiceXCredential
    ) -> IssuedCredential:
        assert record.access_token is not None  # only called with a token present
        assert record.expires_at is not None
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.SERVICEX_ACCESS_TOKEN_REDEEM,
            expires_at=record.expires_at,
            payload={"delivery": "redeem"},
            audit_id=uuid.uuid4().hex,
            source="servicex_token_service",
            execution_model=self.execution_model,
        )
