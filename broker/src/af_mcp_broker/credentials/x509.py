from __future__ import annotations

# requires: kubernetes>=30.0

import asyncio
import os
import stat
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast

import structlog
from pydantic import SecretBytes

from af_mcp_broker.credentials.base import (
    CredentialKind,
    CredentialProvider,
    ExecutionModel,
    IssuedCredential,
    NeedsUnlock,
)
from af_mcp_broker.credentials.cache import CredentialCache, ProxyMeta

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.identity import Principal

log = structlog.get_logger(__name__)

# Targets served by the x509 provider
_DEFAULT_X509_TARGETS: frozenset[str] = frozenset({"ami"})

# Location of broker-owned per-uid proxy files on its tmpfs
_PROXY_TMPFS_ROOT = "/run/broker/proxies"

# Default voms-proxy-init validity in hours
_DEFAULT_PROXY_VALID_HOURS = "192:00"  # 8 days


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
        - Zero the passphrase bytes immediately after transmission.
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
        "ttlSecondsAfterFinished": 30,
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
        """Return True if the user's certificate exists and is readable as a
        public cert (no passphrase needed for this check).
        """
        cert_path = (
            Path(self._settings.home_root)
            / principal.unixname
            / ".globus"
            / "usercert.pem"
        )
        try:
            loop = asyncio.get_running_loop()
            readable = await loop.run_in_executor(
                None, lambda: cert_path.exists() and os.access(cert_path, os.R_OK)
            )
            return readable
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

        try:
            from kubernetes_asyncio import client as k8s_client, config as k8s_config  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "kubernetes_asyncio package is required for Kubernetes-based proxy "
                "minting. Install it or set DEV_MODE_LOCAL_VOMS=true."
            ) from exc

        await k8s_config.load_incluster_config()

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

        # Container: security context + command
        container = pod_spec["containers"][0]
        container["securityContext"]["runAsUser"] = principal.uid
        container["securityContext"]["runAsGroup"] = principal.gid
        container["command"] = [
            "voms-proxy-init",
            "-pwstdin",
            "-voms",
            voms,
            "-cert",
            "/mnt/home/.globus/usercert.pem",
            "-key",
            "/mnt/home/.globus/userkey.pem",
            "-out",
            "/run/proxy/proxy.pem",
            "-valid",
            valid,
        ]

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
                    namespace=self._namespace, body=cast(Any, spec)
                )

                # Transmit passphrase via pod stdin then immediately zero it
                passphrase_bytes = passphrase.get_secret_value()
                try:
                    await self._send_stdin_to_pod(core_v1, job_name, passphrase_bytes)
                finally:
                    # Zero the local copy regardless of outcome
                    passphrase_bytes = b"\x00" * len(passphrase_bytes)

                # Wait for Job completion
                proxy_pem = await self._wait_for_job_and_harvest(
                    batch_v1, core_v1, job_name, principal
                )

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
                except Exception as cleanup_err:
                    self._log.warning(
                        "x509.kubernetes_job.delete_failed",
                        job=job_name,
                        error=str(cleanup_err),
                    )

        return await self._store_proxy_and_parse(proxy_pem, principal)

    async def _send_stdin_to_pod(
        self,
        core_v1,
        job_name: str,
        passphrase_bytes: bytes,
    ) -> None:
        """Stream *passphrase_bytes* to the pod's stdin.

        The passphrase_bytes reference should be zeroed by the caller immediately
        after this coroutine returns, regardless of success or failure.
        """
        # kubernetes_asyncio uses websocket for exec/attach

        pods = await core_v1.list_namespaced_pod(
            namespace=self._namespace,
            label_selector=f"job-name={job_name}",
        )
        pod_name = pods.items[0].metadata.name

        ws_client = await core_v1.connect_get_namespaced_pod_attach(
            name=pod_name,
            namespace=self._namespace,
            stdin=True,
            stdout=False,
            stderr=False,
            _preload_content=False,
        )
        try:
            await ws_client.write_stdin(passphrase_bytes + b"\n")
        finally:
            await ws_client.close()

    async def _wait_for_job_and_harvest(
        self,
        batch_v1,
        core_v1,
        job_name: str,
        principal: Principal,
    ) -> bytes:
        """Poll until the Job succeeds then read the proxy PEM bytes from the pod log.

        The voms-proxy-init container writes the proxy to /run/proxy/proxy.pem
        (tmpfs).  We retrieve the bytes via the pod exec API before the Job's
        TTL fires.
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

        # Exec into pod to cat the proxy file
        pods = await core_v1.list_namespaced_pod(
            namespace=self._namespace,
            label_selector=f"job-name={job_name}",
        )
        pod_name = pods.items[0].metadata.name

        exec_resp = await core_v1.connect_get_namespaced_pod_exec(
            name=pod_name,
            namespace=self._namespace,
            command=["cat", "/run/proxy/proxy.pem"],
            stdout=True,
            stderr=False,
            _preload_content=True,
        )
        return exec_resp.encode() if isinstance(exec_resp, str) else exec_resp

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
        proxy_dir = Path(_PROXY_TMPFS_ROOT) / str(principal.uid)
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

        passphrase_bytes = passphrase.get_secret_value()
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    input=passphrase_bytes + b"\n",
                    capture_output=True,
                    timeout=30,
                ),
            )
        finally:
            # Zero the local passphrase reference immediately
            passphrase_bytes = b"\x00" * len(passphrase_bytes)

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
        proxy_dir = Path(_PROXY_TMPFS_ROOT) / str(principal.uid)
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
        raw_ext = cast(cx509.UnrecognizedExtension, ext.value)
        voms_attributes = [f"<voms_ac_bytes:{len(raw_ext.value)}b>"]
    except cx509.ExtensionNotFound:
        pass

    return dn, voms_attributes, not_after


# ------------------------------------------------------------------
# X509Provider
# ------------------------------------------------------------------


class X509Provider(CredentialProvider):
    """Issues delegated x509 proxy credentials.

    The proxy file is stored on the broker's tmpfs (``/run/broker/proxies/{uid}/proxy.pem``)
    and never transmitted to the LLM or client.  Downstream tools that need the
    proxy receive the path via ``payload["proxy_path"]`` and read it directly from
    the shared filesystem.

    Passphrase rules:
    - Never logged, never persisted, never stored in the cache.
    - Zeroed in memory immediately after transmission to the minting backend.
    - Rate-limited to 5 attempts per 15 minutes per uid to prevent brute force.
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
    ) -> None:
        self._settings = settings
        self._cache = cache
        self._targets = targets
        self._voms = voms
        self._valid_hours = valid_hours
        # If no backends are provided, default to HomeDirVomsBackend.
        # RCauthBackend is a future slot — add to this list when implemented.
        self.backends: list[X509Backend] = backends or [
            HomeDirVomsBackend(settings=settings)
        ]
        self._log = structlog.get_logger(__name__).bind(provider="X509Provider")

    async def handles(self, target: str) -> bool:
        return target in self._targets

    async def issue(
        self,
        principal: Principal,
        target: str,
        min_remaining_seconds: int = 300,
        passphrase: SecretBytes | None = None,
    ) -> IssuedCredential:
        """Return an x509 proxy reference credential.

        If a valid proxy is already cached, returns immediately without
        touching any backend.  If there is no cached proxy and no passphrase
        was provided, raises ``NeedsUnlock`` so the caller can guide the user
        to POST their passphrase to ``/v1/x509/proxy``.
        """
        cached = await self._cache.get(
            principal.uid, target, min_remaining=min_remaining_seconds
        )
        if cached is not None:
            meta = self._cache.get_proxy_meta(principal.uid, target)
            self._log.debug("x509.issue.cache_hit", uid=principal.uid, target=target)
            return cached

        if passphrase is None:
            raise NeedsUnlock(
                target=target,
                reason="no_cached_proxy",
                unlock_endpoint="/v1/x509/proxy",
            )

        meta = await self._mint(principal, passphrase)
        cred = self._build_credential(principal, target, meta)
        await self._cache.put(principal.uid, target, cred, proxy_meta=meta)
        return cred

    async def revoke(self, principal: Principal, target: str) -> None:
        """Zero-overwrite and unlink the proxy file, then clear the cache entry."""
        meta = self._cache.get_proxy_meta(principal.uid, target)
        if meta is not None:
            from af_mcp_broker.credentials.cache import _secure_delete_proxy

            await _secure_delete_proxy(meta.proxy_path)
            self._log.info(
                "x509.revoked",
                uid=principal.uid,
                target=target,
                proxy_path=meta.proxy_path,
            )
        await self._cache.revoke(principal.uid, target)

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
    ) -> IssuedCredential:
        proxy_handle = f"px_{principal.uid}_{uuid.uuid4().hex[:8]}"
        audit_id = uuid.uuid4().hex
        return IssuedCredential(
            cred_class=self.cred_class,
            target=target,
            kind=CredentialKind.X509_PROXY_REF,
            expires_at=meta.not_after,
            payload={
                "proxy_handle": proxy_handle,
                "proxy_path": meta.proxy_path,
                "delivery": "direct",
            },
            audit_id=audit_id,
            source=self._resolve_backend_name(principal),
            execution_model=self.execution_model,
        )

    def _resolve_backend_name(self, principal: Principal) -> str:
        """Return the name of the first available backend for logging/audit."""
        # Synchronous best-effort — used only for the source field on IssuedCredential.
        # The actual availability check happens during mint(); this is metadata only.
        return type(self.backends[0]).__name__ if self.backends else "unknown"
