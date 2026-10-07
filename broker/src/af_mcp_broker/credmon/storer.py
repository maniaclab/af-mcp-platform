"""One credmon sync cycle: push a per-(user, kind) broker top token into HTCondor's credd.

The broker never stores these tokens itself. Each cycle it mints a fresh
AF Broker Identity Token with aud ``{audience_prefix}{kind}`` (e.g.
``af-credmon/krb5``) and a long TTL, and hands it to credd as the OAuth
service credential ``{service_prefix}{kind}`` (e.g. ``af_krb5``) owned by
the user's POSIX unixname. credd writes it to ``<user>/af_krb5.top``; the
AP-side credmon presents it to ``POST /v1/credentials/krb5/redeem`` (which
accepts that audience when ``CREDMON_ENABLED`` -- see app.py) and writes
the redeemed credential to ``af_krb5.use`` for HTCondor to ship to jobs.

Revocation is by expiry plus the redeem endpoint's own live checks: a user
who unlinks stops getting new top tokens here, and their existing one stops
redeeming the moment the identity is gone.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog
from pydantic import SecretStr

from af_mcp_broker.audit.logger import AuditRecord, write_audit
from af_mcp_broker.identity import Principal
from af_mcp_broker.principal_cache import PrincipalUnavailableError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from af_mcp_broker.credentials.broker_issued import BrokerTokenIssuer
    from af_mcp_broker.principal_cache import PrincipalCache

log = structlog.get_logger(__name__)


class CredentialStoreError(Exception):
    """The credential store (credd, via htcondor-api) rejected or failed a store call."""


class CredentialStoreClient(ABC):
    """Stores an OAuth service credential in credd on behalf of a POSIX user."""

    @abstractmethod
    async def store_service_credential(
        self, *, user: str, service: str, credential: dict[str, str]
    ) -> None:
        """Store *credential* (JSON object) as *service* for *user*; raise ``CredentialStoreError`` on failure."""


class SubjectSource(ABC):
    """Enumerates the subjects that may hold an identity of a given credmon kind."""

    @abstractmethod
    async def list_subjects(self, kind: str) -> list[str]:
        """Return candidate subjects for *kind* -- each is still checked with ``CredmonKind.is_linked``."""


@dataclass(frozen=True)
class CredmonKind:
    """A credential kind the credmon serves (``x509``/``krb5``/``servicex``), with the provider-owned linkage check for it."""

    name: str
    is_linked: Callable[[Principal], Awaitable[bool]]


@dataclass
class SyncReport:
    """Per-kind outcome counts of one ``CredmonStorer.run_once`` cycle."""

    started_at: float
    finished_at: float = 0.0
    stored: dict[str, int] = field(default_factory=dict)
    not_linked: dict[str, int] = field(default_factory=dict)
    skipped_no_posix: dict[str, int] = field(default_factory=dict)
    failed: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class CredmonStorer:
    """Mints and stores credmon top tokens for every linked subject, one cycle per ``run_once``."""

    def __init__(
        self,
        *,
        issuer: BrokerTokenIssuer,
        kinds: Sequence[CredmonKind],
        subjects: SubjectSource,
        principal_cache: PrincipalCache,
        client: CredentialStoreClient,
        audience_prefix: str,
        service_prefix: str,
        top_token_ttl_seconds: int,
    ) -> None:
        self._issuer = issuer
        self._kinds = list(kinds)
        self._subjects = subjects
        self._principal_cache = principal_cache
        self._client = client
        self._audience_prefix = audience_prefix
        self._service_prefix = service_prefix
        self._ttl = top_token_ttl_seconds

    @property
    def kind_names(self) -> list[str]:
        return [kind.name for kind in self._kinds]

    async def run_once(self) -> SyncReport:
        """Run one full sync cycle; per-subject failures are recorded, never raised."""
        report = SyncReport(started_at=time.time())
        for kind in self._kinds:
            outcomes: Counter[str] = Counter()
            for subject in await self._subjects.list_subjects(kind.name):
                outcomes[await self._sync_one(kind, subject, report)] += 1
            report.stored[kind.name] = outcomes["stored"]
            if outcomes["not_linked"]:
                report.not_linked[kind.name] = outcomes["not_linked"]
            if outcomes["no_posix"]:
                report.skipped_no_posix[kind.name] = outcomes["no_posix"]
            if outcomes["failed"]:
                report.failed[kind.name] = outcomes["failed"]
        report.finished_at = time.time()
        log.info(
            "credmon_sync.completed",
            stored=report.stored,
            not_linked=report.not_linked,
            skipped_no_posix=report.skipped_no_posix,
            failed=report.failed,
            duration_seconds=round(report.finished_at - report.started_at, 3),
        )
        return report

    async def _sync_one(
        self, kind: CredmonKind, subject: str, report: SyncReport
    ) -> str:
        """Sync *subject*'s top token for *kind*; return the outcome key counted by ``run_once``."""
        try:
            attrs = await self._principal_cache.get(subject)
        except PrincipalUnavailableError as exc:
            report.errors.append(
                f"{kind.name}: directory unavailable for {subject}: {exc}"
            )
            return "failed"
        if not attrs.unixname:
            return "no_posix"

        principal = Principal(
            subject=subject,
            email=attrs.email,
            uid=attrs.uid,
            gid=attrs.gid,
            unixname=attrs.unixname,
            groups=list(attrs.groups),
            # No inbound request: this principal exists only to ask the
            # provider whether the identity is linked.
            raw_token=SecretStr(""),
        )
        if not await kind.is_linked(principal):
            return "not_linked"

        service = f"{self._service_prefix}{kind.name}"
        token, _ = self._issuer.mint(
            subject, f"{self._audience_prefix}{kind.name}", ttl_seconds=self._ttl
        )
        try:
            await self._client.store_service_credential(
                user=attrs.unixname, service=service, credential={"access_token": token}
            )
        except CredentialStoreError as exc:
            report.errors.append(
                f"{kind.name}: store failed for {attrs.unixname}: {exc}"
            )
            await self._audit(
                subject, attrs.uid, service, attrs.unixname, error=str(exc)
            )
            return "failed"
        await self._audit(subject, attrs.uid, service, attrs.unixname, error=None)
        return "stored"

    async def _audit(
        self,
        subject: str,
        uid: int | None,
        service: str,
        unixname: str,
        *,
        error: str | None,
    ) -> None:
        await write_audit(
            AuditRecord(
                principal_sub=subject,
                principal_uid=uid,
                permission=None,
                target=service,
                action="credmon_top_token_store",
                action_type="state_change",
                args_summary=f"top token for {service!r} stored in credd as user {unixname!r}"
                if error is None
                else f"storing top token for {service!r} as user {unixname!r} failed",
                timestamp=time.time(),
                request_id="",
                outcome="success" if error is None else "error",
                error=error,
            )
        )
