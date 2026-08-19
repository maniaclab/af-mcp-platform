from __future__ import annotations

# requires: kubernetes_asyncio>=30.0
import asyncio
import base64
import binascii
import os
import stat
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Literal, cast

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
from af_mcp_broker.credentials.cache import ProxyMeta
from af_mcp_broker.credentials.voms_service import VomsServiceBadPassphraseError
from af_mcp_broker.credentials.x509_vault import StoredX509Credential

if TYPE_CHECKING:
    from pydantic import SecretBytes

    from af_mcp_broker.config import Settings
    from af_mcp_broker.credentials.cache import CredentialCache
    from af_mcp_broker.credentials.voms_service import (
        MintedProxy,
        VomsTokenServiceClient,
    )
    from af_mcp_broker.credentials.x509_vault import VaultX509Store
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)

# Targets served by the x509 provider
_DEFAULT_X509_TARGETS: frozenset[str] = frozenset({"ami"})

# Default voms-proxy-init validity in hours
_DEFAULT_PROXY_VALID_HOURS = "192:00"  # 8 days

# Sentinel lines that delimit the base64-encoded proxy in the mint pod's log.
# The proxy is harvested by reading the pod log after the Job completes (a
# completed pod cannot be exec'd into), so the payload must be unambiguous.
# Base64's alphabet ([A-Za-z0-9+/=] plus newlines) never contains the literal
# "-----...-----" sentinel text, so voms-proxy-init's own output cannot be
# mistaken for the payload.
_PROXY_B64_BEGIN = "-----BEGIN-PROXY-B64-----"
_PROXY_B64_END = "-----END-PROXY-B64-----"


class PosixIdentityRequiredError(RuntimeError):
    """Raised when x509 proxy minting is attempted for a principal with no POSIX identity.

    Issue #148 made ``Principal.uid``/``gid``/``unixname`` optional -- almost
    nothing in the broker needs them, but x509 genuinely does (the mint
    Job's NFS home subPath and ``runAsUser``/``runAsGroup`` all require real
    values). Rather than reject such a principal at the door for every
    backend (the old JWT-level behavior this issue removes), the requirement
    moves to this point of use, naming *target* so the resulting error is
    actionable: "this backend needs a grid identity your account doesn't
    have" rather than an opaque failure.
    """

    def __init__(self, target: str, *, settings: Settings) -> None:
        self.target = target
        super().__init__(
            f"Backend {target!r} requires an x509/VOMS proxy, which needs a "
            "POSIX (grid) identity your account does not have. The broker "
            "looked for the Keycloak profile attributes "
            f"{settings.posix_uid_attribute!r}/{settings.posix_gid_attribute!r}/"
            f"{settings.posix_unixname_attribute!r} and found none of them "
            "set. Contact your Analysis Facility operator to request a grid "
            "identity."
        )


class ProxyHarvestError(ValueError):
    """Raised when a mint Job SUCCEEDED but its proxy could not be harvested from the pod log (truncated log, kubelet log-size limits, transient read issue).

    This is an infra failure, not a bad-passphrase signal, so callers
    must NOT count it against the passphrase rate limiter the way a genuine
    Job failure is. Subclasses ``ValueError`` so existing ``except
    ValueError`` call sites still catch it; callers that need to tell the two
    apart (see ``_mint_kubernetes``) catch this first.
    """


def _zero_bytearray(buf: bytearray) -> None:
    """Overwrite *buf* in place with NUL bytes.

    Unlike rebinding an immutable ``bytes`` object, mutating a ``bytearray``
    genuinely clears the underlying buffer, so a secret held in one is erased
    once this returns.
    """
    for i in range(len(buf)):
        buf[i] = 0


def _extract_proxy_from_log(log_text: str) -> bytes:
    """Extract and base64-decode the proxy payload from a mint pod's log.

    The mint container prints the proxy between :data:`_PROXY_B64_BEGIN` and
    :data:`_PROXY_B64_END`; any voms-proxy-init noise appears before the begin
    sentinel.  Raises :class:`ProxyHarvestError` if either sentinel is missing
    or the payload does not decode — the Job having reached this point means
    it already succeeded, so this is an infra failure, not a bad passphrase.
    """
    begin = log_text.find(_PROXY_B64_BEGIN)
    if begin == -1:
        raise ProxyHarvestError("proxy begin sentinel not found in mint pod log")
    payload_start = begin + len(_PROXY_B64_BEGIN)
    end = log_text.find(_PROXY_B64_END, payload_start)
    if end == -1:
        raise ProxyHarvestError("proxy end sentinel not found in mint pod log")
    b64 = log_text[payload_start:end]
    try:
        # validate=False discards the newlines base64 wraps its output with.
        decoded = base64.b64decode(b64, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise ProxyHarvestError(
            "failed to decode proxy payload from mint pod log"
        ) from exc
    if not decoded:
        raise ProxyHarvestError("proxy payload in mint pod log was empty")
    return decoded


# ------------------------------------------------------------------
# X509Backend ABC
# ------------------------------------------------------------------


class X509Backend(ABC):
    """Pluggable backend for minting x509 proxies.

    Implementations are tried in order by X509Provider.  Only the first
    backend that reports available() == True is used.  This lets operators
    swap HomeDirVomsBackend for RCauthBackend via config without code changes.
    """

    @abstractmethod
    async def available(self, principal: Principal) -> bool:
        """Return True if this backend can mint a proxy for *principal*."""

    @abstractmethod
    async def mint(
        self,
        principal: Principal,
        passphrase: SecretBytes,
        valid: str,
        voms: str,
        cache: CredentialCache,
    ) -> ProxyMeta:
        """Mint a new proxy and return its metadata.

        Implementations MUST:
        - Call cache.check_unlock_rate_limit(principal.uid) first.
        - Copy the passphrase into a mutable bytearray and zero it (in a finally
          block) immediately after transmission. The SecretBytes original is
          owned by pydantic and cannot be zeroed here.
        - Store the resulting proxy at the path returned in ProxyMeta.proxy_path.
        - Delete any intermediate files / Jobs created during minting.
        """


# ------------------------------------------------------------------
# HomeDirVomsBackend
# ------------------------------------------------------------------

# Kubernetes Job spec template for isolated proxy minting.
#
# Security context notes:
# - runAsUser/runAsGroup: set to principal's uid/gid so the Job can read
#   the NFS-mounted home directory (which is mode 0700 / owned by uid).
# - readOnlyRootFilesystem: true — proxy output goes to tmpfs emptyDir.
# - allowPrivilegeEscalation: false, drop ALL capabilities.
# - No automountServiceAccountToken: the Job needs no Kubernetes API access.
# - NetworkPolicy (applied separately via ConfigMap-driven VOMS allowlist)
#   restricts egress to the VOMS server(s) only.
_K8S_JOB_SPEC_TEMPLATE: dict = {
    "apiVersion": "batch/v1",
    "kind": "Job",
    "metadata": {
        # name and namespace are filled in at runtime
        "name": "",
        "namespace": "",
        "labels": {"app.kubernetes.io/component": "voms-proxy-mint"},
    },
    "spec": {
        # Comfortably above the harvest window so the pod log survives long
        # enough to read after completion.  The broker also deletes the Job
        # explicitly in the mint finally block, so this is only a backstop.
        "ttlSecondsAfterFinished": 120,
        "backoffLimit": 0,
        "template": {
            "spec": {
                "restartPolicy": "Never",
                "automountServiceAccountToken": False,
                "securityContext": {
                    # runAsUser / runAsGroup filled in at runtime
                    "runAsNonRoot": True,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "volumes": [
                    {
                        "name": "home",
                        "nfs": {
                            # server and path filled in at runtime
                            "server": "",
                            "path": "",
                            "readOnly": True,
                        },
                    },
                    {
                        "name": "proxy-out",
                        "emptyDir": {"medium": "Memory"},  # tmpfs
                    },
                ],
                "containers": [
                    {
                        "name": "voms-proxy-init",
                        # Image must have voms-proxy-init and the ATLAS VOMS config
                        "image": "ghcr.io/atlas-af/voms-client:latest",
                        # Command is filled in at runtime
                        "command": [],
                        "stdin": True,
                        "stdinOnce": True,
                        "securityContext": {
                            # runAsUser / runAsGroup filled in at runtime
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "volumeMounts": [
                            {
                                "name": "home",
                                "mountPath": "/mnt/home",
                                "readOnly": True,
                            },
                            {
                                "name": "proxy-out",
                                "mountPath": "/run/proxy",
                            },
                        ],
                        "resources": {
                            "requests": {"cpu": "100m", "memory": "64Mi"},
                            "limits": {"cpu": "200m", "memory": "128Mi"},
                        },
                    }
                ],
            }
        },
    },
}


class HomeDirVomsBackend(X509Backend):
    """Mint a proxy from the user's ``~/.globus/usercert.pem`` via voms-proxy-init.

    In production the minting runs in an ephemeral Kubernetes Job that:
    - Mounts the user's NFS home directory read-only, scoped to their subPath.
    - Writes the proxy to a tmpfs emptyDir (never touches persistent storage).
    - Runs as the user's uid/gid (no privilege escalation, all capabilities dropped).
    - Has network egress restricted to the VOMS server(s) via NetworkPolicy.
    - Is deleted immediately after the proxy is harvested.

    In development (``DEV_MODE_LOCAL_VOMS=true``) voms-proxy-init is run in a
    subprocess locally — useful for workstations with a ~/.globus directory.
    """

    def __init__(
        self,
        settings: Settings,
        namespace: str = "af-mcp",
        nfs_server: str = "",
        nfs_home_root: str = "/data/homes",
        voms: str = "atlas",
        valid_hours: str = _DEFAULT_PROXY_VALID_HOURS,
        job_timeout_seconds: int = 60,
    ) -> None:
        self._settings = settings
        self._namespace = namespace
        self._nfs_server = nfs_server
        self._nfs_home_root = nfs_home_root
        self._voms = voms
        self._valid_hours = valid_hours
        self._job_timeout_seconds = job_timeout_seconds
        self._dev_mode = os.environ.get("DEV_MODE_LOCAL_VOMS", "").lower() == "true"
        self._log = structlog.get_logger(__name__).bind(backend="HomeDirVomsBackend")

    async def available(self, principal: Principal) -> bool:
        """Return True if the user's certificate exists and is readable as a public cert (no passphrase needed for this check).

        Returns False (rather than raising) when *principal* has no POSIX
        identity at all -- this backend genuinely cannot serve such a
        principal, which is exactly what "not available" already means here
        (issue #148).
        """
        if principal.unixname is None:
            return False
        cert_path = (
            Path(self._settings.home_root)
            / principal.unixname
            / ".globus"
            / "usercert.pem"
        )
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: cert_path.exists() and os.access(cert_path, os.R_OK)
            )
        except OSError:
            return False

    async def mint(
        self,
        principal: Principal,
        passphrase: SecretBytes,
        valid: str,
        voms: str,
        cache: CredentialCache,
    ) -> ProxyMeta:
        """Mint a proxy using an ephemeral Job (or local subprocess in dev mode)."""
        # X509Provider.issue() already rejects a principal with no POSIX
        # identity (PosixIdentityRequiredError) before ever reaching here --
        # this assert only narrows the type for mypy in the rest of this
        # call chain, it is never expected to actually fail.
        assert principal.uid is not None
        assert principal.gid is not None
        assert principal.unixname is not None
        cache.check_unlock_rate_limit(principal.uid)

        if self._dev_mode:
            return await self._mint_local(principal, passphrase, valid, voms, cache)
        return await self._mint_kubernetes(principal, passphrase, valid, voms, cache)

    # ------------------------------------------------------------------
    # Kubernetes minting path (production)
    # ------------------------------------------------------------------

    async def _mint_kubernetes(
        self,
        principal: Principal,
        passphrase: SecretBytes,
        valid: str,
        voms: str,
        cache: CredentialCache,
    ) -> ProxyMeta:
        import copy

        # See mint()'s matching asserts -- HomeDirVomsBackend.mint() is the
        # only caller of this method, and it already validated this.
        assert principal.uid is not None
        assert principal.gid is not None
        assert principal.unixname is not None

        try:
            from kubernetes_asyncio import client as k8s_client  # type: ignore[import]
            from kubernetes_asyncio import config as k8s_config  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "kubernetes_asyncio package is required for Kubernetes-based proxy "
                "minting. Install it or set DEV_MODE_LOCAL_VOMS=true."
            ) from exc

        # load_incluster_config is synchronous in kubernetes_asyncio; awaiting
        # it raises TypeError.
        k8s_config.load_incluster_config()

        job_name = f"voms-mint-{principal.uid}-{uuid.uuid4().hex[:8]}"
        spec = copy.deepcopy(_K8S_JOB_SPEC_TEMPLATE)

        # Metadata
        spec["metadata"]["name"] = job_name
        spec["metadata"]["namespace"] = self._namespace

        pod_spec = spec["spec"]["template"]["spec"]

        # Security context — pod level
        pod_spec["securityContext"]["runAsUser"] = principal.uid
        pod_spec["securityContext"]["runAsGroup"] = principal.gid

        # NFS volume: scope to principal's home subpath
        nfs_vol = pod_spec["volumes"][0]["nfs"]
        nfs_vol["server"] = self._nfs_server
        nfs_vol["path"] = f"{self._nfs_home_root}/{principal.unixname}"

        # Container: security context + command.
        #
        # A shell wrapper runs voms-proxy-init and, only on success (&&), prints
        # the proxy as base64 between sentinel lines.  The proxy is harvested
        # from the pod LOG after completion — you cannot exec into a completed
        # pod whose only container has terminated.
        #
        # - voms/valid are passed as positional args ($1/$2) to avoid injection.
        # - voms-proxy-init reads the passphrase from stdin (-pwstdin) and never
        #   echoes it; its own stdout is redirected to stderr (1>&2) so it can
        #   never be confused with the base64 payload between the sentinels.
        container = pod_spec["containers"][0]
        container["securityContext"]["runAsUser"] = principal.uid
        container["securityContext"]["runAsGroup"] = principal.gid
        script = (
            'voms-proxy-init -pwstdin -voms "$1" '
            "-cert /mnt/home/.globus/usercert.pem "
            "-key /mnt/home/.globus/userkey.pem "
            '-out /run/proxy/proxy.pem -valid "$2" 1>&2 && '
            f"echo '{_PROXY_B64_BEGIN}' && "
            "base64 /run/proxy/proxy.pem && "
            f"echo '{_PROXY_B64_END}'"
        )
        container["command"] = ["sh", "-c", script, "sh", voms, valid]

        async with k8s_client.ApiClient() as api_client:
            batch_v1 = k8s_client.BatchV1Api(api_client)
            core_v1 = k8s_client.CoreV1Api(api_client)

            try:
                self._log.info(
                    "x509.kubernetes_job.creating",
                    job=job_name,
                    uid=principal.uid,
                )
                await batch_v1.create_namespaced_job(
                    namespace=self._namespace, body=cast("Any", spec)
                )

                # Transmit the passphrase via pod stdin. It lives in a mutable
                # bytearray that _send_stdin_to_pod genuinely zeros before it
                # returns; only the SecretBytes original (owned by pydantic) is
                # out of reach.
                passphrase_buf = bytearray(passphrase.get_secret_value())
                await self._send_stdin_to_pod(core_v1, job_name, passphrase_buf)

                # Wait for Job completion and read the proxy from the pod log.
                # A failed Job most likely means a bad passphrase, so count it
                # against the rate limiter just like the local path does. A
                # Job that SUCCEEDED but whose log couldn't be harvested is an
                # infra failure, not a passphrase signal, so it must NOT count
                # against that same rate limiter — check ProxyHarvestError
                # (a ValueError subclass) before the general ValueError case.
                try:
                    proxy_pem = await self._wait_for_job_and_harvest(
                        batch_v1, core_v1, job_name, principal
                    )
                except ProxyHarvestError:
                    raise
                except ValueError:
                    cache.record_failed_unlock(principal.uid)
                    raise

            finally:
                # Always delete the Job — best effort
                try:
                    await batch_v1.delete_namespaced_job(
                        name=job_name,
                        namespace=self._namespace,
                        body=k8s_client.V1DeleteOptions(
                            propagation_policy="Foreground"
                        ),
                    )
                    self._log.debug("x509.kubernetes_job.deleted", job=job_name)
                except Exception as cleanup_err:  # noqa: BLE001  # best-effort cleanup
                    self._log.warning(
                        "x509.kubernetes_job.delete_failed",
                        job=job_name,
                        error=str(cleanup_err),
                    )

        return await self._store_proxy_and_parse(proxy_pem, principal)

    async def _wait_for_running_pod(self, core_v1, job_name: str) -> str:
        """Return the name of the Job's pod once it reaches ``Running``.

        Immediately after the Job is created the pod usually does not exist yet,
        and attaching stdin requires the container to be Running.  Poll until a
        pod for the Job exists and its phase is Running, bounded by
        ``job_timeout_seconds``.
        """
        deadline = time.monotonic() + self._job_timeout_seconds
        while time.monotonic() < deadline:
            pods = await core_v1.list_namespaced_pod(
                namespace=self._namespace,
                label_selector=f"job-name={job_name}",
            )
            if pods.items:
                pod = pods.items[0]
                phase = pod.status.phase if pod.status else None
                if phase == "Running":
                    return pod.metadata.name
                if phase == "Failed":
                    raise ValueError(
                        f"mint pod for Job {job_name!r} failed before stdin "
                        "could be attached."
                    )
            await asyncio.sleep(1)
        raise TimeoutError(
            f"mint pod for Job {job_name!r} did not reach Running within "
            f"{self._job_timeout_seconds}s."
        )

    async def _send_stdin_to_pod(
        self,
        core_v1,
        job_name: str,
        passphrase_buf: bytearray,
    ) -> None:
        """Stream the passphrase in *passphrase_buf* to the pod's stdin.

        Waits for the pod to be Running (voms-proxy-init blocks reading stdin,
        so the pod stays Running until the passphrase arrives) before attaching.
        Takes ownership of *passphrase_buf* and zeros it — plus the transient
        copy built at the I/O boundary — before returning, on success or error.
        """
        # kubernetes_asyncio drives exec/attach over a websocket client.
        from kubernetes_asyncio import client as k8s_client  # type: ignore[import]
        from kubernetes_asyncio.stream import WsApiClient  # type: ignore[import]

        try:
            pod_name = await self._wait_for_running_pod(core_v1, job_name)

            # Convert to bytes only at the write boundary; zero the copy after.
            payload = bytearray(passphrase_buf)
            payload.extend(b"\n")
            async with WsApiClient() as ws_api:
                ws_core = k8s_client.CoreV1Api(ws_api)
                # Stubs type this as str; _preload_content=False yields a
                # websocket client instead.
                ws_client: Any = await ws_core.connect_get_namespaced_pod_attach(
                    name=pod_name,
                    namespace=self._namespace,
                    container="voms-proxy-init",
                    stdin=True,
                    stdout=False,
                    stderr=False,
                    _preload_content=False,
                )
                try:
                    await ws_client.write_stdin(bytes(payload))
                finally:
                    _zero_bytearray(payload)
                    await ws_client.close()
        finally:
            _zero_bytearray(passphrase_buf)

    async def _wait_for_job_and_harvest(
        self,
        batch_v1,
        core_v1,
        job_name: str,
        principal: Principal,  # noqa: ARG002 (interface)
    ) -> bytes:
        """Poll until the Job succeeds, then read the proxy from the pod log.

        The mint container prints the proxy as base64 between sentinel lines on
        success.  We read the pod log (``read_namespaced_pod_log``) after the
        Job completes — a completed pod cannot be exec'd into — and decode the
        payload.  Raises ``ValueError`` on Job failure (likely a bad passphrase)
        or :class:`ProxyHarvestError` if the Job succeeded but the log lacks a
        valid payload (infra failure, not a bad passphrase).
        """
        deadline = time.monotonic() + self._job_timeout_seconds
        while time.monotonic() < deadline:
            job = await batch_v1.read_namespaced_job(
                name=job_name, namespace=self._namespace
            )
            if job.status.succeeded:
                break
            if job.status.failed:
                # Likely bad passphrase
                raise ValueError(
                    f"voms-proxy-init Job {job_name!r} failed — check passphrase "
                    "or certificate validity."
                )
            await asyncio.sleep(2)
        else:
            raise TimeoutError(
                f"voms-proxy-init Job {job_name!r} did not complete within "
                f"{self._job_timeout_seconds}s."
            )

        pods = await core_v1.list_namespaced_pod(
            namespace=self._namespace,
            label_selector=f"job-name={job_name}",
        )
        if not pods.items:
            raise ProxyHarvestError(
                f"no pod found for completed Job {job_name!r} — cannot harvest "
                "proxy (TTL may have reaped it)."
            )
        pod_name = pods.items[0].metadata.name

        log_text = await core_v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=self._namespace,
            container="voms-proxy-init",
        )
        if isinstance(log_text, bytes):
            log_text = log_text.decode(errors="replace")
        return _extract_proxy_from_log(log_text)

    # ------------------------------------------------------------------
    # Local / dev minting path
    # ------------------------------------------------------------------

    async def _mint_local(
        self,
        principal: Principal,
        passphrase: SecretBytes,
        valid: str,
        voms: str,
        cache: CredentialCache,
    ) -> ProxyMeta:
        """Run voms-proxy-init locally as a subprocess — dev/testing only."""
        # See mint()'s matching asserts -- HomeDirVomsBackend.mint() is the
        # only caller of this method, and it already validated this.
        assert principal.uid is not None
        assert principal.gid is not None
        assert principal.unixname is not None
        proxy_dir = Path(self._settings.proxy_dir) / str(principal.uid)
        proxy_dir.mkdir(parents=True, exist_ok=True)
        proxy_path = proxy_dir / "proxy.pem"

        cert_path = (
            Path(self._settings.home_root)
            / principal.unixname
            / ".globus"
            / "usercert.pem"
        )
        key_path = (
            Path(self._settings.home_root)
            / principal.unixname
            / ".globus"
            / "userkey.pem"
        )

        cmd = [
            "voms-proxy-init",
            "-pwstdin",
            "-voms",
            voms,
            "-cert",
            str(cert_path),
            "-key",
            str(key_path),
            "-out",
            str(proxy_path),
            "-valid",
            valid,
        ]

        # Mutable copy so the secret is genuinely zeroed after the subprocess
        # returns; input= converts to bytes only at the call boundary.
        passphrase_buf = bytearray(passphrase.get_secret_value())
        passphrase_buf.extend(b"\n")
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    input=bytes(passphrase_buf),
                    capture_output=True,
                    check=False,
                    timeout=30,
                ),
            )
        finally:
            _zero_bytearray(passphrase_buf)

        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace")
            self._log.warning(
                "x509.local_mint.failed", uid=principal.uid, stderr=stderr
            )
            cache.record_failed_unlock(principal.uid)
            raise ValueError(
                f"voms-proxy-init failed (rc={result.returncode}): {stderr[:200]}"
            )

        proxy_pem = proxy_path.read_bytes()
        return await self._store_proxy_and_parse(proxy_pem, principal)

    # ------------------------------------------------------------------
    # Shared: store proxy and parse metadata
    # ------------------------------------------------------------------

    async def _store_proxy_and_parse(
        self, proxy_pem: bytes, principal: Principal
    ) -> ProxyMeta:
        """Write *proxy_pem* to the broker's per-uid tmpfs and parse its metadata."""
        # See mint()'s matching asserts -- reached only via _mint_kubernetes/
        # _mint_local, both of which already validated this.
        assert principal.uid is not None
        proxy_dir = Path(self._settings.proxy_dir) / str(principal.uid)
        proxy_dir.mkdir(parents=True, exist_ok=True)
        proxy_path = proxy_dir / "proxy.pem"

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, lambda: _write_proxy_file(proxy_path, proxy_pem)
        )

        dn, voms_attributes, not_after = await loop.run_in_executor(
            None, lambda: _parse_proxy_pem(proxy_pem)
        )

        meta = ProxyMeta(
            dn=dn,
            voms_attributes=voms_attributes,
            not_after=not_after,
            proxy_path=str(proxy_path),
        )
        self._log.info(
            "x509.proxy_minted",
            uid=principal.uid,
            dn=dn,
            not_after=not_after,
            proxy_path=str(proxy_path),
        )
        # Single choke point for both the Kubernetes and local-dev mint
        # paths (_mint_kubernetes / _mint_local both funnel here on
        # success), so this counts every successful mint exactly once
        # regardless of backend. No username label -- per-user labels are
        # forbidden outright; see metrics.py's cardinality policy.
        metrics.x509_proxy_mints_total.inc()
        return meta


def _write_proxy_file(proxy_path: Path, proxy_pem: bytes) -> None:
    """Write *proxy_pem* to *proxy_path* with mode 0600."""
    proxy_path.write_bytes(proxy_pem)
    proxy_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600


def _parse_proxy_pem(proxy_pem: bytes) -> tuple[str, list[str], float]:
    """Parse a PEM proxy file and extract DN, VOMS attributes, and notAfter.

    Uses the ``cryptography`` library which ships with most Python environments.
    Returns ``(dn, voms_attributes, not_after_epoch)``.
    """
    from cryptography import x509 as cx509

    # The proxy PEM may contain multiple certs (proxy chain); parse the first
    pem_blocks = proxy_pem.split(b"-----END CERTIFICATE-----")
    first_cert_pem = pem_blocks[0] + b"-----END CERTIFICATE-----\n"

    cert = cx509.load_pem_x509_certificate(first_cert_pem)

    # DN — build RFC 4514 string from issuer (the EEC/previous proxy is the issuer)
    dn = cert.issuer.rfc4514_string()

    # notAfter
    not_after: float = cert.not_valid_after_utc.timestamp()

    # VOMS attributes are encoded in the proxyCertInfo or custom VOMS extension.
    # For now we extract them from the Subject Alternative Name extension if present,
    # or fall back to an empty list (full VOMS AC parsing requires voms-api-python).
    voms_attributes: list[str] = []
    try:
        # VOMS AC OID: 1.3.6.1.4.1.8005.100.100.5
        voms_oid = cx509.ObjectIdentifier("1.3.6.1.4.1.8005.100.100.5")
        ext = cert.extensions.get_extension_for_oid(voms_oid)
        # Raw value — production code would parse the ASN.1 AC here.
        # Returning the raw bytes as a placeholder avoids a hard voms-api dependency.
        raw_ext = cast("cx509.UnrecognizedExtension", ext.value)
        voms_attributes = [f"<voms_ac_bytes:{len(raw_ext.value)}b>"]
    except cx509.ExtensionNotFound:
        pass

    return dn, voms_attributes, not_after


# ------------------------------------------------------------------
# X509Provider
# ------------------------------------------------------------------


@dataclass(frozen=True)
class X509LinkStatus:
    """How an x509 identity is linked, for surfaces that render custody.

    ``mode`` distinguishes the two service-mode custody choices (issue
    #112's follow-up consent toggle): ``"auto-renew"`` — a passphrase is
    stored, proxies re-mint hands-free; ``"until-expiry"`` — only the proxy
    is stored (the user declined passphrase custody), so the link lasts
    exactly as long as the proxy does. ``None`` when not linked, and in
    legacy mode, where linkage is a filesystem fact with no custody concept.

    ``proxy_not_after`` is the expiry (epoch seconds) of the currently-valid
    stored proxy, or None when no valid proxy is stored — including the
    auto-renew case where the proxy has lapsed but the link survives.
    """

    linked: bool
    mode: Literal["auto-renew", "until-expiry"] | None
    proxy_not_after: float | None


class X509Provider(CredentialProvider):
    """Issues delegated x509 proxy credentials.

    Two mint paths coexist behind whether the entry that constructed this
    provider has a ``service_url`` (``X509ProviderConfig.service_url``; see
    ``uses_voms_service``):

    * **Legacy (k8s Job / local dev)** — the proxy file is stored on the
      broker's tmpfs (``/run/broker/proxies/{uid}/proxy.pem``) and never
      transmitted to the LLM or client. Downstream tools that need the proxy
      receive the path via ``payload["proxy_path"]`` and read it directly
      from the shared filesystem. Passphrases are never persisted.
    * **voms-token-service** — minting is delegated to the service (the only
      component that mounts user homes), and both the proxy and the Globus
      passphrase persist in Vault (``VaultX509Store``, issue #112's
      custodianship model): the passphrase enables hands-free renewal when
      the stored proxy nears expiry, with a bad-passphrase failure on
      renewal unlinking the identity so the portal prompts a re-link.
      Backends fetch the PEM via ``POST /v1/credentials/x509/redeem``
      (``CredentialKind.X509_PROXY_REDEEM``) — no local file exists.

    Passphrase rules (both paths):
    - Never logged, never stored in the in-memory cache; persisted only in
      Vault, only in service mode, as the deliberate custodianship choice.
    - Working copies are zeroed (legacy path) or revealed only at the HTTP
      call boundary (service path — see voms_service.py's module docstring).
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
        backends: list[X509Backend] | None = None,
        targets: frozenset[str] = _DEFAULT_X509_TARGETS,
        voms: str = "atlas",
        valid_hours: str = _DEFAULT_PROXY_VALID_HOURS,
        voms_client: VomsTokenServiceClient | None = None,
        vault_store: VaultX509Store | None = None,
    ) -> None:
        self._settings = settings
        self._cache = cache
        self._targets = targets
        self._voms = voms
        self._valid_hours = valid_hours
        # Service mode requires both halves: the client to mint with and the
        # store to persist in. app.py wires both together (or neither).
        self._voms_client = voms_client
        self._vault_store = vault_store
        # If no backends are provided, default to HomeDirVomsBackend.
        # RCauthBackend is a future slot — add to this list when implemented.
        self.backends: list[X509Backend] = backends or [
            HomeDirVomsBackend(settings=settings)
        ]
        self._log = structlog.get_logger(__name__).bind(provider="X509Provider")

    @property
    def uses_voms_service(self) -> bool:
        """Whether this provider mints via voms-token-service and persists in Vault (True) or via the legacy k8s-Job/local path (False)."""
        return self._voms_client is not None and self._vault_store is not None

    @property
    def voms_client(self) -> VomsTokenServiceClient | None:
        """The voms-token-service client, or None in legacy mode.

        Exposed so ``api/credentials.py``'s preflight route can proxy the
        service's credential-readiness checklist through the same
        authenticated client the mint path uses.
        """
        return self._voms_client

    @property
    def vault_store(self) -> VaultX509Store | None:
        """The Vault-backed link/proxy store, or None in legacy mode.

        Exposed so ``api/credentials.py``'s redeem endpoint can tell which
        mode is active and serve/renew the Vault-stored proxy accordingly.
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

        In voms-token-service mode this covers BOTH custody choices (see
        ``link_status``): a stored passphrase (auto-renew — proxies re-mint
        hands-free) or a still-valid stored proxy with no passphrase
        (until-expiry — the link lasts exactly as long as the proxy). The
        filesystem is never consulted, since minting happens in the
        service's pod, not the broker's.

        In legacy mode: True when both halves of *principal*'s ``~/.globus``
        certificate pair exist and are readable by the broker's uid/gid.

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

        The single source ``is_linked`` and ``/v1/identities`` both read:
        in voms-token-service mode one Vault read decides linked-with-renewal
        (passphrase stored), linked-until-expiry (valid proxy, no
        passphrase), or unlinked — an expired proxy with no passphrase reads
        as UNLINKED, which is the bounded consequence remember=false users
        consented to. Legacy mode reports the filesystem fact with no
        custody mode or expiry.
        """
        if self.uses_voms_service:
            assert self._vault_store is not None  # uses_voms_service checked
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
        return X509LinkStatus(
            linked=await self._legacy_is_linked(principal),
            mode=None,
            proxy_not_after=None,
        )

    async def _legacy_is_linked(self, principal: Principal) -> bool:
        """The legacy-mode linkage check: both halves of ``~/.globus`` readable.

        Mirrors the path construction ``HomeDirVomsBackend`` uses to locate
        the user's home directory, but — unlike ``HomeDirVomsBackend.available()``,
        which only needs the public cert to decide whether it can attempt a
        mint — requires BOTH ``usercert.pem`` and ``userkey.pem``, since
        minting cannot proceed with only the public half.
        """
        if principal.unixname is None:
            return False
        globus_dir = Path(self._settings.home_root) / principal.unixname / ".globus"
        cert_path = globus_dir / "usercert.pem"
        key_path = globus_dir / "userkey.pem"

        def _both_readable() -> bool:
            try:
                return all(
                    p.exists() and os.access(p, os.R_OK) for p in (cert_path, key_path)
                )
            except OSError:
                return False

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _both_readable)

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,
        remember: bool = True,
    ) -> IssuedCredential:
        """Return an x509 proxy reference credential.

        If a valid proxy is already cached, returns immediately without
        touching any backend -- POSIX identity isn't needed just to serve an
        already-minted credential, so this check comes before the guard
        below. If there is no cached proxy and *principal* has no POSIX
        identity at all, raises ``PosixIdentityRequiredError`` naming
        *target*: minting can never succeed for such a principal, and saying
        so immediately is clearer than asking for a passphrase first only to
        fail after it's given. Otherwise, if no passphrase was provided,
        raises ``NeedsUnlock`` so the caller can guide the user to POST their
        passphrase to ``/v1/x509/proxy``.

        ``remember`` is the custody consent captured alongside an explicit
        *passphrase* (service mode only — legacy mode never persists a
        passphrase, so it has nothing to remember): False mints and stores
        the proxy but NOT the passphrase, making the link last exactly the
        proxy's validity window (see ``link_status``). Meaningless without a
        passphrase, and True (the hands-free-renewal default) preserves the
        pre-existing behavior.
        """
        cached = await self._cache.get(
            principal.subject, target, min_remaining=min_remaining_seconds
        )
        # In service mode an EXPLICIT passphrase is a linking act (the user
        # may have just changed their Globus password): it must reach the
        # service and update the stored passphrase, never short-circuit on a
        # still-valid cached credential. Legacy mode keeps its historical
        # cache-first behavior — nothing is persisted there, so there is no
        # stored passphrase a short-circuit could leave stale.
        if cached is not None and not (
            self.uses_voms_service and passphrase is not None
        ):
            self._log.debug(
                "x509.issue.cache_hit", subject=principal.subject, target=target
            )
            return cached

        if self.uses_voms_service:
            return await self._issue_via_service(
                principal, target, min_remaining_seconds, passphrase, remember
            )

        if principal.uid is None or principal.gid is None or principal.unixname is None:
            raise PosixIdentityRequiredError(target, settings=self._settings)

        if passphrase is None:
            raise NeedsUnlock(
                target=target,
                reason="no_cached_proxy",
                unlock_endpoint="/v1/x509/proxy",
            )

        async def _do_mint() -> IssuedCredential:
            meta = await self._mint(principal, passphrase)
            cred = self._build_credential(principal, target, meta)
            await self._cache.put(
                principal.subject, target, cred, proxy_meta=meta, uid=principal.uid
            )
            return cred

        # Single-flighted: concurrent misses for this (subject, target) await
        # one k8s Job / subprocess mint instead of each independently
        # starting their own real-resource mint (issue #94).
        return await self._cache.get_or_mint(
            principal.subject, target, min_remaining_seconds, _do_mint
        )

    async def revoke(self, principal: Principal, target: str) -> None:
        """Clear the cache entry; cache.revoke secure-deletes the proxy file.

        In voms-token-service mode the Vault-stored proxy is cleared too, so
        the redeem endpoint stops serving it — but the LINK (passphrase)
        stays: burning a proxy must not unlink the identity, the next
        issue() simply renews hands-free. Unlinking is a separate,
        deliberate act (a bad-passphrase renewal, or a portal unlink).
        """
        # Grab the path before revoke() pops the entry, for the audit log only.
        meta = self._cache.get_proxy_meta(principal.subject, target)
        await self._cache.revoke(principal.subject, target)
        if self.uses_voms_service:
            assert self._vault_store is not None  # uses_voms_service checked
            await self._vault_store.clear_proxy(principal.subject)
        if meta is not None:
            self._log.info(
                "x509.revoked",
                subject=principal.subject,
                target=target,
                proxy_path=meta.proxy_path,
            )

    # ------------------------------------------------------------------
    # voms-token-service mode (issue #112 follow-up)
    # ------------------------------------------------------------------

    async def _issue_via_service(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int,
        passphrase: SecretBytes | None,
        remember: bool = True,
    ) -> IssuedCredential:
        """Serve the Vault-stored proxy, or mint via voms-token-service.

        Three paths, in order:

        1. A stored proxy with enough validity left is served directly.
           POSIX identity isn't needed just to serve an already-minted
           credential — same rule as the legacy path's cache hit. (Skipped
           when a passphrase was explicitly given: that is a linking act,
           see ``issue()``.)
        2. A passphrase was given (the portal unlock/link flow): mint via
           the service, then persist BOTH the passphrase (the link enabling
           hands-free renewal) and the proxy in Vault.
        3. No passphrase: renew hands-free with the stored link, or raise
           ``NeedsUnlock`` when there is none.
        """
        assert self._vault_store is not None  # uses_voms_service checked by caller
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
                # passphrase (same ordering as the legacy path).
                if (
                    principal.uid is None
                    or principal.gid is None
                    or principal.unixname is None
                ):
                    raise PosixIdentityRequiredError(target, settings=self._settings)
                raise NeedsUnlock(
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
        if principal.uid is None or principal.gid is None or principal.unixname is None:
            raise PosixIdentityRequiredError(target, settings=self._settings)
        return await self._link_and_mint(principal, target, passphrase, remember)

    async def _serve_stored_proxy(
        self, principal: Principal, target: str, min_remaining_seconds: int
    ) -> IssuedCredential | None:
        """Return a credential for the Vault-stored proxy if one with at least *min_remaining_seconds* of validity exists, else None."""
        assert self._vault_store is not None  # uses_voms_service checked by caller
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
        target: str,
        passphrase: SecretBytes,
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
        assert self._voms_client is not None  # uses_voms_service checked by caller
        assert self._vault_store is not None
        # _issue_via_service already rejected a POSIX-less principal; these
        # narrow the types for mypy, mirroring HomeDirVomsBackend.mint().
        assert principal.uid is not None
        assert principal.gid is not None
        assert principal.unixname is not None

        self._cache.check_unlock_rate_limit(principal.uid)
        # The service speaks JSON, so the passphrase crosses as str;
        # SecretStr keeps it out of repr/logs (see voms_service.py).
        passphrase_str = SecretStr(passphrase.get_secret_value().decode())
        try:
            minted = await self._voms_client.mint(
                subject=principal.subject,
                unixname=principal.unixname,
                uid=principal.uid,
                gid=principal.gid,
                passphrase=passphrase_str,
            )
        except VomsServiceBadPassphraseError:
            self._cache.record_failed_unlock(principal.uid)
            raise

        await self._vault_store.store_link(
            principal.subject,
            passphrase=passphrase_str if remember else None,
            unixname=principal.unixname,
            uid=principal.uid,
            gid=principal.gid,
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

    async def renew_from_stored_link(
        self, subject: str, target: str
    ) -> StoredX509Credential:
        """Mint a fresh proxy with *subject*'s Vault-stored passphrase and persist it — the hands-free renewal step.

        Public (also called by the redeem endpoint's renewal path, which
        holds only a broker-token subject, not a live ``Principal``).

        Raises:
            NeedsUnlock: no link is stored, or the stored passphrase was
                rejected — in which case the identity is UNLINKED first (the
                user changed their Globus password; the stored passphrase is
                dead weight) so the portal prompts a re-link. A stored-
                passphrase failure is not a user brute-force attempt, so it
                does not count against the unlock rate limiter.
            VomsServiceMintError: the service failed for an infra reason —
                the link is kept and nothing is unlinked.

        """
        assert self._voms_client is not None  # uses_voms_service checked by caller
        assert self._vault_store is not None
        link = await self._vault_store.get_link(subject)
        if link is None:
            raise NeedsUnlock(
                target=target, reason="not_linked", unlock_endpoint="/v1/x509/proxy"
            )
        # get_link() guarantees the link half is complete; narrow for mypy.
        assert link.passphrase is not None
        assert link.unixname is not None
        assert link.uid is not None
        assert link.gid is not None
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
            raise NeedsUnlock(
                target=target,
                reason="stored_passphrase_rejected",
                unlock_endpoint="/v1/x509/proxy",
            ) from exc
        return await self._store_minted_proxy(subject, minted)

    async def _store_minted_proxy(
        self, subject: str, minted: MintedProxy
    ) -> StoredX509Credential:
        """Persist *minted* in Vault and return it as a stored record."""
        assert self._vault_store is not None  # uses_voms_service checked by caller
        await self._vault_store.store_proxy(
            subject,
            pem=minted.pem,
            dn=minted.dn,
            voms_attributes=minted.voms_attributes,
            not_after=minted.not_after,
        )
        # Same choke point role as _store_proxy_and_parse on the legacy
        # path: every successful service mint counts exactly once.
        metrics.x509_proxy_mints_total.inc()
        self._log.info(
            "x509.proxy_minted",
            subject=subject,
            dn=minted.dn,
            not_after=minted.not_after,
            source="voms_token_service",
        )
        return StoredX509Credential(
            proxy_pem=SecretStr(minted.pem),
            dn=minted.dn,
            voms_attributes=list(minted.voms_attributes),
            not_after=minted.not_after,
        )

    async def _cache_stored_record(
        self, principal: Principal, target: str, record: StoredX509Credential
    ) -> IssuedCredential:
        """Build the redeem-kind credential for *record* and cache it in memory.

        ``uid`` is passed to ``cache.put`` only on link/renewal mints via
        the caller's principal — but a successful put after ANY correct-
        passphrase mint legitimately resets the failed-unlock counter, and
        serving an already-stored proxy involves no passphrase at all, so
        passing the principal's uid unconditionally is harmless: the
        counter only ever holds entries for genuine failures.
        """
        assert record.not_after is not None  # only called with a proxy present
        meta = ProxyMeta(
            dn=record.dn or "",
            voms_attributes=list(record.voms_attributes),
            not_after=record.not_after,
            proxy_path=None,
        )
        cred = self._build_credential(
            principal,
            target,
            meta,
            kind=CredentialKind.X509_PROXY_REDEEM,
            source="voms_token_service",
        )
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

    async def _mint(self, principal: Principal, passphrase: SecretBytes) -> ProxyMeta:
        """Iterate through backends until one is available and mints a proxy."""
        for backend in self.backends:
            if await backend.available(principal):
                self._log.info(
                    "x509.mint.backend_selected",
                    uid=principal.uid,
                    backend=type(backend).__name__,
                )
                return await backend.mint(
                    principal=principal,
                    passphrase=passphrase,
                    valid=self._valid_hours,
                    voms=self._voms,
                    cache=self._cache,
                )
        raise RuntimeError(
            f"No x509 backend is available for principal uid={principal.uid}. "
            "Check that ~/.globus/usercert.pem exists."
        )

    def _build_credential(
        self,
        principal: Principal,
        target: str,
        meta: ProxyMeta,
        kind: CredentialKind = CredentialKind.X509_PROXY_REF,
        source: str | None = None,
    ) -> IssuedCredential:
        proxy_handle = f"px_{principal.uid}_{uuid.uuid4().hex[:8]}"
        audit_id = uuid.uuid4().hex
        if kind == CredentialKind.X509_PROXY_REDEEM:
            # No local file exists — the backend fetches the PEM from Vault
            # via POST /v1/credentials/x509/redeem.
            payload: dict = {"proxy_handle": proxy_handle, "delivery": "redeem"}
        else:
            payload = {
                "proxy_handle": proxy_handle,
                "proxy_path": meta.proxy_path,
                "delivery": "direct",
            }
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=kind,
            expires_at=meta.not_after,
            payload=payload,
            audit_id=audit_id,
            source=(
                source if source is not None else self._resolve_backend_name(principal)
            ),
            execution_model=self.execution_model,
        )

    def _resolve_backend_name(self, principal: Principal) -> str:  # noqa: ARG002
        """Return the name of the first available backend for logging/audit."""
        # Synchronous best-effort — used only for the source field on IssuedCredential.
        # The actual availability check happens during mint(); this is metadata only.
        return type(self.backends[0]).__name__ if self.backends else "unknown"
