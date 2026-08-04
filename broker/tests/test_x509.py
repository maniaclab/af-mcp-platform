"""Unit tests for the testable parts of the x509 proxy provider.

Exercising the Kubernetes attach/harvest flow against a real cluster is out
of scope here; most of these tests cover the pure helpers and the
passphrase-zeroing contract, but a full mint round trip can still be driven
by injecting a fake ``kubernetes_asyncio`` module (see
``_install_fake_k8s_full``) -- used by the issue()-single-flighting tests
below.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import SecretBytes, SecretStr

from af_mcp_broker.credentials.cache import CredentialCache
from af_mcp_broker.credentials.x509 import (
    _PROXY_B64_BEGIN,
    _PROXY_B64_END,
    HomeDirVomsBackend,
    ProxyHarvestError,
    X509Provider,
    _extract_proxy_from_log,
    _parse_proxy_pem,
    _zero_bytearray,
)
from af_mcp_broker.identity import Principal

# ---------------------------------------------------------------------------
# _extract_proxy_from_log
# ---------------------------------------------------------------------------


def _wrap_log(
    proxy_bytes: bytes, *, noise_before: str = "", noise_after: str = ""
) -> str:
    payload = base64.b64encode(proxy_bytes).decode()
    return (
        f"{noise_before}{_PROXY_B64_BEGIN}\n{payload}\n{_PROXY_B64_END}\n{noise_after}"
    )


def test_extract_proxy_with_surrounding_noise():
    proxy = (
        b"-----BEGIN CERTIFICATE-----\nfake proxy bytes\n-----END CERTIFICATE-----\n"
    )
    log = _wrap_log(
        proxy,
        noise_before="voms-proxy-init: contacting voms server...\nCreating proxy .. Done\n",
        noise_after="pod terminated\n",
    )
    assert _extract_proxy_from_log(log) == proxy


def test_extract_proxy_handles_wrapped_base64():
    # `base64` wraps output at 76 cols; validate=False must skip the newlines.
    proxy = bytes(range(256)) * 4
    wrapped = base64.encodebytes(proxy).decode()  # multi-line, like the `base64` tool
    assert "\n" in wrapped.strip()
    log = f"noise\n{_PROXY_B64_BEGIN}\n{wrapped}{_PROXY_B64_END}\n"
    assert _extract_proxy_from_log(log) == proxy


def test_extract_proxy_missing_begin_sentinel():
    log = f"just some logs\n{_PROXY_B64_END}\n"
    with pytest.raises(ValueError, match="begin sentinel"):
        _extract_proxy_from_log(log)


def test_extract_proxy_missing_end_sentinel():
    log = f"{_PROXY_B64_BEGIN}\nZm9v\nno end here\n"
    with pytest.raises(ValueError, match="end sentinel"):
        _extract_proxy_from_log(log)


def test_extract_proxy_empty_payload():
    log = f"{_PROXY_B64_BEGIN}\n{_PROXY_B64_END}\n"
    with pytest.raises(ValueError, match="empty"):
        _extract_proxy_from_log(log)


# ---------------------------------------------------------------------------
# _parse_proxy_pem
# ---------------------------------------------------------------------------


def _make_self_signed_pem(common_name: str, not_after: datetime.datetime) -> bytes:
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = cx509.Name(
        [
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "ATLAS"),
            cx509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    not_before = datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)
    cert = (
        cx509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


def test_parse_proxy_pem_extracts_dn_and_expiry():
    not_after = datetime.datetime(2030, 6, 15, 12, 0, 0, tzinfo=datetime.UTC)
    pem = _make_self_signed_pem("Jane Doe", not_after)

    dn, voms_attributes, parsed_not_after = _parse_proxy_pem(pem)

    assert "CN=Jane Doe" in dn
    assert "O=ATLAS" in dn
    assert parsed_not_after == pytest.approx(not_after.timestamp())
    # Self-signed cert has no VOMS AC extension.
    assert voms_attributes == []


# ---------------------------------------------------------------------------
# Proxy mint counter (issue #84 -- the Grafana dashboard already queries
# af_mcp_x509_proxy_mints_total{username}, but no broker code incremented it)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_proxy_and_parse_increments_mint_counter(tmp_path):
    from prometheus_client import REGISTRY

    not_after = datetime.datetime(2030, 6, 15, 12, 0, 0, tzinfo=datetime.UTC)
    proxy_pem = _make_self_signed_pem("Jane Doe", not_after)
    backend = HomeDirVomsBackend(
        settings=SimpleNamespace(proxy_dir=str(tmp_path / "proxies"))
    )
    principal = _principal("auser")
    before = (
        REGISTRY.get_sample_value(
            "af_mcp_x509_proxy_mints_total", {"username": "auser"}
        )
        or 0.0
    )

    await backend._store_proxy_and_parse(proxy_pem, principal)

    after = REGISTRY.get_sample_value(
        "af_mcp_x509_proxy_mints_total", {"username": "auser"}
    )
    assert after == before + 1


# ---------------------------------------------------------------------------
# Passphrase bytearray zeroing
# ---------------------------------------------------------------------------


def test_zero_bytearray():
    buf = bytearray(b"secret!!")
    _zero_bytearray(buf)
    assert buf == bytearray(len(b"secret!!"))
    assert all(b == 0 for b in buf)


def _install_fake_k8s(monkeypatch, captured: dict) -> None:
    """Inject a minimal fake kubernetes_asyncio into sys.modules."""

    class FakeWsClient:
        async def write_stdin(self, data):
            captured["stdin"] = bytes(data)

        async def close(self):
            captured["closed"] = True

    class FakeCoreV1Api:
        def __init__(self, api_client):
            pass

        async def connect_get_namespaced_pod_attach(self, **kwargs):
            captured["attach_kwargs"] = kwargs
            return FakeWsClient()

    class FakeWsApiClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    k8s = types.ModuleType("kubernetes_asyncio")
    client_mod = types.ModuleType("kubernetes_asyncio.client")
    stream_mod = types.ModuleType("kubernetes_asyncio.stream")
    client_mod.CoreV1Api = FakeCoreV1Api
    stream_mod.WsApiClient = FakeWsApiClient
    k8s.client = client_mod
    k8s.stream = stream_mod

    monkeypatch.setitem(sys.modules, "kubernetes_asyncio", k8s)
    monkeypatch.setitem(sys.modules, "kubernetes_asyncio.client", client_mod)
    monkeypatch.setitem(sys.modules, "kubernetes_asyncio.stream", stream_mod)


def _install_fake_k8s_full(
    monkeypatch,
    proxy_pem: bytes,
    job_names: list[str],
    *,
    job_create_delay: float = 0.0,
) -> None:
    """Inject a fake ``kubernetes_asyncio`` sufficient to drive a full
    ``HomeDirVomsBackend._mint_kubernetes()`` round trip: the Job "creates"
    immediately (recording its name into *job_names*, after an optional
    *job_create_delay* to force concurrent callers to overlap), a pod is
    immediately ``Running`` for stdin attach, the Job immediately
    "succeeds", and the harvested pod log yields *proxy_pem*.
    """

    class FakeWsClient:
        async def write_stdin(self, data):
            pass

        async def close(self):
            pass

    class FakePod:
        def __init__(self, phase: str, name: str):
            self.status = SimpleNamespace(phase=phase)
            self.metadata = SimpleNamespace(name=name)

    class FakeCoreV1Api:
        def __init__(self, api_client):
            pass

        async def list_namespaced_pod(self, namespace, label_selector):
            return SimpleNamespace(items=[FakePod("Running", "fake-mint-pod")])

        async def connect_get_namespaced_pod_attach(self, **kwargs):
            return FakeWsClient()

        async def read_namespaced_pod_log(self, name, namespace, container):
            payload = base64.b64encode(proxy_pem).decode()
            return f"{_PROXY_B64_BEGIN}\n{payload}\n{_PROXY_B64_END}\n"

    class FakeBatchV1Api:
        def __init__(self, api_client):
            pass

        async def create_namespaced_job(self, namespace, body):
            if job_create_delay:
                await asyncio.sleep(job_create_delay)
            job_names.append(body["metadata"]["name"])

        async def read_namespaced_job(self, name, namespace):
            return SimpleNamespace(status=SimpleNamespace(succeeded=True, failed=None))

        async def delete_namespaced_job(self, name, namespace, body):
            pass

    class FakeApiClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class FakeWsApiClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    k8s = types.ModuleType("kubernetes_asyncio")
    client_mod = types.ModuleType("kubernetes_asyncio.client")
    stream_mod = types.ModuleType("kubernetes_asyncio.stream")
    config_mod = types.ModuleType("kubernetes_asyncio.config")

    client_mod.CoreV1Api = FakeCoreV1Api
    client_mod.BatchV1Api = FakeBatchV1Api
    client_mod.ApiClient = FakeApiClient
    client_mod.V1DeleteOptions = SimpleNamespace
    stream_mod.WsApiClient = FakeWsApiClient
    config_mod.load_incluster_config = lambda: None
    k8s.client = client_mod
    k8s.stream = stream_mod
    k8s.config = config_mod

    monkeypatch.setitem(sys.modules, "kubernetes_asyncio", k8s)
    monkeypatch.setitem(sys.modules, "kubernetes_asyncio.client", client_mod)
    monkeypatch.setitem(sys.modules, "kubernetes_asyncio.stream", stream_mod)
    monkeypatch.setitem(sys.modules, "kubernetes_asyncio.config", config_mod)


@pytest.mark.asyncio
async def test_send_stdin_zeros_passphrase_buffer(monkeypatch):
    captured: dict = {}
    _install_fake_k8s(monkeypatch, captured)

    backend = HomeDirVomsBackend(settings=SimpleNamespace(home_root="/data/homes"))

    async def fake_wait_running(core_v1, job_name):
        return "voms-mint-pod-abc1234"

    monkeypatch.setattr(backend, "_wait_for_running_pod", fake_wait_running)

    passphrase_buf = bytearray(b"hunter2-passphrase")
    original_len = len(passphrase_buf)

    await backend._send_stdin_to_pod(
        core_v1=object(), job_name="voms-mint-job", passphrase_buf=passphrase_buf
    )

    # The transport received the passphrase with a trailing newline...
    assert captured["stdin"] == b"hunter2-passphrase\n"
    # ...but the caller's buffer is now all zeros.
    assert passphrase_buf == bytearray(original_len)
    assert all(b == 0 for b in passphrase_buf)
    assert captured["closed"] is True
    assert captured["attach_kwargs"]["container"] == "voms-proxy-init"


@pytest.mark.asyncio
async def test_send_stdin_zeros_buffer_even_when_transport_fails(monkeypatch):
    captured: dict = {}
    _install_fake_k8s(monkeypatch, captured)

    backend = HomeDirVomsBackend(settings=SimpleNamespace(home_root="/data/homes"))

    async def fake_wait_running(core_v1, job_name):
        raise TimeoutError("pod never reached Running")

    monkeypatch.setattr(backend, "_wait_for_running_pod", fake_wait_running)

    passphrase_buf = bytearray(b"another-secret")
    original_len = len(passphrase_buf)

    with pytest.raises(TimeoutError):
        await backend._send_stdin_to_pod(
            core_v1=object(), job_name="voms-mint-job", passphrase_buf=passphrase_buf
        )

    assert passphrase_buf == bytearray(original_len)


# ---------------------------------------------------------------------------
# X509Provider.is_linked
# ---------------------------------------------------------------------------


def _principal(unixname: str, *, uid: int = 50123) -> Principal:
    return Principal(
        subject="user-123",
        email="user@example.org",
        uid=uid,
        gid=5000,
        unixname=unixname,
        groups=["af-atlas-users"],
        raw_token=SecretStr("fake-token"),
    )


@pytest.mark.asyncio
async def test_is_linked_true_when_both_files_present(tmp_path):
    globus_dir = tmp_path / "auser" / ".globus"
    globus_dir.mkdir(parents=True)
    (globus_dir / "usercert.pem").write_text("cert")
    (globus_dir / "userkey.pem").write_text("key")

    provider = X509Provider(
        settings=SimpleNamespace(home_root=str(tmp_path)), cache=CredentialCache()
    )

    assert await provider.is_linked(_principal("auser")) is True


@pytest.mark.asyncio
async def test_is_linked_false_when_key_missing(tmp_path):
    globus_dir = tmp_path / "auser" / ".globus"
    globus_dir.mkdir(parents=True)
    (globus_dir / "usercert.pem").write_text("cert")
    # userkey.pem intentionally absent.

    provider = X509Provider(
        settings=SimpleNamespace(home_root=str(tmp_path)), cache=CredentialCache()
    )

    assert await provider.is_linked(_principal("auser")) is False


@pytest.mark.asyncio
async def test_is_linked_false_when_cert_missing(tmp_path):
    globus_dir = tmp_path / "auser" / ".globus"
    globus_dir.mkdir(parents=True)
    (globus_dir / "userkey.pem").write_text("key")
    # usercert.pem intentionally absent.

    provider = X509Provider(
        settings=SimpleNamespace(home_root=str(tmp_path)), cache=CredentialCache()
    )

    assert await provider.is_linked(_principal("auser")) is False


@pytest.mark.asyncio
async def test_is_linked_false_when_neither_present(tmp_path):
    provider = X509Provider(
        settings=SimpleNamespace(home_root=str(tmp_path)), cache=CredentialCache()
    )

    assert await provider.is_linked(_principal("nosuchuser")) is False


# ---------------------------------------------------------------------------
# _mint_kubernetes: Job-failed vs. harvest-failed must not be miscounted
# ---------------------------------------------------------------------------


def _install_fake_k8s_for_mint(
    monkeypatch,
    captured: dict,
    *,
    job_succeeded: bool,
    job_failed: bool,
    pod_log: str,
) -> None:
    """Inject a fake kubernetes_asyncio sufficient to drive _mint_kubernetes
    end-to-end: Job creation, stdin attach, Job status polling, pod log
    harvest, and Job deletion.
    """

    fake_job = SimpleNamespace(
        status=SimpleNamespace(succeeded=job_succeeded, failed=job_failed)
    )
    fake_pod = SimpleNamespace(
        status=SimpleNamespace(phase="Running"),
        metadata=SimpleNamespace(name="voms-mint-pod-abc123"),
    )
    fake_pod_list = SimpleNamespace(items=[fake_pod])

    class FakeWsClient:
        async def write_stdin(self, data):
            captured["stdin"] = bytes(data)

        async def close(self):
            captured["closed"] = True

    class FakeCoreV1Api:
        def __init__(self, api_client):
            pass

        async def connect_get_namespaced_pod_attach(self, **kwargs):
            captured["attach_kwargs"] = kwargs
            return FakeWsClient()

        async def list_namespaced_pod(self, **kwargs):
            return fake_pod_list

        async def read_namespaced_pod_log(self, **kwargs):
            return pod_log

    class FakeBatchV1Api:
        def __init__(self, api_client):
            pass

        async def create_namespaced_job(self, **kwargs):
            captured["created_job"] = kwargs

        async def read_namespaced_job(self, **kwargs):
            return fake_job

        async def delete_namespaced_job(self, **kwargs):
            captured["deleted_job"] = kwargs

    class FakeApiClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class FakeWsApiClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class FakeV1DeleteOptions:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    def fake_load_incluster_config():
        captured["loaded_incluster_config"] = True

    k8s = types.ModuleType("kubernetes_asyncio")
    client_mod = types.ModuleType("kubernetes_asyncio.client")
    stream_mod = types.ModuleType("kubernetes_asyncio.stream")
    config_mod = types.ModuleType("kubernetes_asyncio.config")
    client_mod.CoreV1Api = FakeCoreV1Api
    client_mod.BatchV1Api = FakeBatchV1Api
    client_mod.ApiClient = FakeApiClient
    client_mod.V1DeleteOptions = FakeV1DeleteOptions
    stream_mod.WsApiClient = FakeWsApiClient
    config_mod.load_incluster_config = fake_load_incluster_config
    k8s.client = client_mod
    k8s.stream = stream_mod
    k8s.config = config_mod

    monkeypatch.setitem(sys.modules, "kubernetes_asyncio", k8s)
    monkeypatch.setitem(sys.modules, "kubernetes_asyncio.client", client_mod)
    monkeypatch.setitem(sys.modules, "kubernetes_asyncio.stream", stream_mod)
    monkeypatch.setitem(sys.modules, "kubernetes_asyncio.config", config_mod)


@pytest.mark.asyncio
async def test_mint_kubernetes_job_failed_records_failed_unlock(monkeypatch):
    """A Job that FAILED is a genuine bad-passphrase signal — it must still
    burn the user's unlock-attempt budget.
    """
    captured: dict = {}
    _install_fake_k8s_for_mint(
        monkeypatch, captured, job_succeeded=False, job_failed=True, pod_log=""
    )

    backend = HomeDirVomsBackend(settings=SimpleNamespace(home_root="/data/homes"))
    cache = CredentialCache()
    monkeypatch.setattr(cache, "record_failed_unlock", MagicMock())
    principal = _principal("auser")

    with pytest.raises(ValueError, match="failed"):
        await backend._mint_kubernetes(
            principal, SecretBytes(b"hunter2"), valid="12:00", voms="atlas", cache=cache
        )

    cache.record_failed_unlock.assert_called_once_with(principal.uid)


@pytest.mark.asyncio
async def test_mint_kubernetes_harvest_failure_does_not_record_failed_unlock(
    monkeypatch,
):
    """A Job that SUCCEEDED but whose pod log is missing the sentinel payload
    is an infra failure (truncated log, kubelet limits, transient read
    issue) — it must NOT be miscounted as a bad-passphrase attempt.
    """
    captured: dict = {}
    pod_log = f"voms-proxy-init: contacting voms server...\n{_PROXY_B64_BEGIN}\ntruncated, no end sentinel\n"
    _install_fake_k8s_for_mint(
        monkeypatch, captured, job_succeeded=True, job_failed=False, pod_log=pod_log
    )

    backend = HomeDirVomsBackend(settings=SimpleNamespace(home_root="/data/homes"))
    cache = CredentialCache()
    monkeypatch.setattr(cache, "record_failed_unlock", MagicMock())
    principal = _principal("auser")

    with pytest.raises(ProxyHarvestError, match="end sentinel"):
        await backend._mint_kubernetes(
            principal, SecretBytes(b"hunter2"), valid="12:00", voms="atlas", cache=cache
        )

    cache.record_failed_unlock.assert_not_called()


# ---------------------------------------------------------------------------
# X509Provider.issue() single-flighting (issue #94)
# ---------------------------------------------------------------------------


def _globus_dir_for(tmp_path, unixname: str) -> None:
    globus_dir = tmp_path / unixname / ".globus"
    globus_dir.mkdir(parents=True)
    (globus_dir / "usercert.pem").write_text("cert")
    (globus_dir / "userkey.pem").write_text("key")


@pytest.mark.asyncio
async def test_issue_single_flights_concurrent_mints(monkeypatch, tmp_path):
    """N concurrent issue() calls for the same (uid, target) with a correct
    passphrase must create exactly one k8s Job (issue #94) -- a real
    resource, unlike the OIDC provider's network fetch."""
    _globus_dir_for(tmp_path, "auser")
    not_after = datetime.datetime(2030, 6, 15, 12, 0, 0, tzinfo=datetime.UTC)
    proxy_pem = _make_self_signed_pem("Jane Doe", not_after)

    job_names: list[str] = []
    _install_fake_k8s_full(monkeypatch, proxy_pem, job_names, job_create_delay=0.01)

    settings = SimpleNamespace(
        home_root=str(tmp_path), proxy_dir=str(tmp_path / "proxies")
    )
    cache = CredentialCache()
    provider = X509Provider(
        settings=settings,
        cache=cache,
        backends=[HomeDirVomsBackend(settings=settings)],
    )
    principal = _principal("auser")
    passphrase = SecretBytes(b"hunter2")

    results = await asyncio.gather(
        *[provider.issue(principal, "ami", passphrase=passphrase) for _ in range(5)]
    )

    assert len(job_names) == 1
    assert all(r.payload["proxy_handle"] for r in results)


@pytest.mark.asyncio
async def test_issue_different_uids_do_not_serialize(monkeypatch, tmp_path):
    """Concurrent mints for different uids must not block on each other's
    single-flight lock."""
    _globus_dir_for(tmp_path, "auser")
    _globus_dir_for(tmp_path, "buser")
    not_after = datetime.datetime(2030, 6, 15, 12, 0, 0, tzinfo=datetime.UTC)
    proxy_pem = _make_self_signed_pem("Jane Doe", not_after)

    entered: list[str] = []
    both_entered = asyncio.Event()

    class _BlockingBatchV1Api:
        def __init__(self, api_client):
            pass

        async def create_namespaced_job(self, namespace, body):
            entered.append(body["metadata"]["name"])
            if len(entered) == 2:
                both_entered.set()
            # Deadlocks (and the test times out) if the two uids were
            # serialized behind a single shared lock instead of per-key ones.
            await asyncio.wait_for(both_entered.wait(), timeout=2.0)

        async def read_namespaced_job(self, name, namespace):
            return SimpleNamespace(status=SimpleNamespace(succeeded=True, failed=None))

        async def delete_namespaced_job(self, name, namespace, body):
            pass

    job_names: list[str] = []
    _install_fake_k8s_full(monkeypatch, proxy_pem, job_names)
    import kubernetes_asyncio.client as fake_client_mod

    monkeypatch.setattr(fake_client_mod, "BatchV1Api", _BlockingBatchV1Api)

    settings = SimpleNamespace(
        home_root=str(tmp_path), proxy_dir=str(tmp_path / "proxies")
    )
    cache = CredentialCache()
    provider = X509Provider(
        settings=settings,
        cache=cache,
        backends=[HomeDirVomsBackend(settings=settings)],
    )
    passphrase = SecretBytes(b"hunter2")

    results = await asyncio.wait_for(
        asyncio.gather(
            provider.issue(
                _principal("auser", uid=60_001), "ami", passphrase=passphrase
            ),
            provider.issue(
                _principal("buser", uid=60_002), "ami", passphrase=passphrase
            ),
        ),
        timeout=2.0,
    )

    assert len(entered) == 2
    assert len(results) == 2
