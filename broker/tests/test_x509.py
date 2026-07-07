"""Unit tests for the testable parts of the x509 proxy provider.

The Kubernetes attach/harvest flow cannot be exercised without a real cluster;
these tests cover the pure helpers and the passphrase-zeroing contract.
"""

from __future__ import annotations

import base64
import datetime
import sys
import types
from types import SimpleNamespace

import pytest

from af_mcp_broker.credentials.x509 import (
    _PROXY_B64_BEGIN,
    _PROXY_B64_END,
    HomeDirVomsBackend,
    _extract_proxy_from_log,
    _parse_proxy_pem,
    _zero_bytearray,
)


# ---------------------------------------------------------------------------
# _extract_proxy_from_log
# ---------------------------------------------------------------------------


def _wrap_log(proxy_bytes: bytes, *, noise_before: str = "", noise_after: str = "") -> str:
    payload = base64.b64encode(proxy_bytes).decode()
    return (
        f"{noise_before}"
        f"{_PROXY_B64_BEGIN}\n{payload}\n{_PROXY_B64_END}\n"
        f"{noise_after}"
    )


def test_extract_proxy_with_surrounding_noise():
    proxy = b"-----BEGIN CERTIFICATE-----\nfake proxy bytes\n-----END CERTIFICATE-----\n"
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
    not_before = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
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
    not_after = datetime.datetime(2030, 6, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
    pem = _make_self_signed_pem("Jane Doe", not_after)

    dn, voms_attributes, parsed_not_after = _parse_proxy_pem(pem)

    assert "CN=Jane Doe" in dn
    assert "O=ATLAS" in dn
    assert parsed_not_after == pytest.approx(not_after.timestamp())
    # Self-signed cert has no VOMS AC extension.
    assert voms_attributes == []


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
