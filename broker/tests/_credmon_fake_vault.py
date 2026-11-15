"""Prefix-agnostic in-memory fake of the Vault KV-v2 HTTP API subset VaultKV uses (GET, CAS POST, LIST, metadata DELETE), shared by the credmon tests.

Unlike test_krb5_vault.py's ``_FakeVault`` (pinned to one store's prefix),
this one stores every path under the KV mount, so a single instance can
back several stores, the credmon subject lister and the sync lease.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx2

from af_mcp_broker.vault_kv import VaultKV

if TYPE_CHECKING:
    from pathlib import Path

ADDR = "https://vault.invalid"
AUTH_MOUNT = "kubernetes"
KV_MOUNT = "secret"


class FakeVault:
    def __init__(self) -> None:
        # Full KV path (below the mount) -> {"data": ..., "version": ...}.
        self.entries: dict[str, dict[str, Any]] = {}

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        path = request.url.path.removeprefix("/v1/")
        if path == f"auth/{AUTH_MOUNT}/login":
            return httpx2.Response(
                200,
                json={"auth": {"client_token": "t", "lease_duration": 3600}},
                request=request,
            )
        for verb in ("data", "metadata"):
            prefix = f"{KV_MOUNT}/{verb}/"
            if path.startswith(prefix):
                return self._kv(request, verb, path[len(prefix) :])
        return httpx2.Response(404, json={"errors": ["unknown path"]}, request=request)

    def _kv(self, request: httpx2.Request, verb: str, key: str) -> httpx2.Response:
        if request.method == "LIST" and verb == "metadata":
            base = key.rstrip("/") + "/"
            children = sorted(
                {
                    k[len(base) :].split("/", 1)[0]
                    + ("/" if "/" in k[len(base) :] else "")
                    for k in self.entries
                    if k.startswith(base)
                }
            )
            if not children:
                return httpx2.Response(404, json={"errors": []}, request=request)
            return httpx2.Response(
                200, json={"data": {"keys": children}}, request=request
            )
        if request.method == "GET" and verb == "data":
            entry = self.entries.get(key)
            if entry is None:
                return httpx2.Response(404, json={"errors": []}, request=request)
            return httpx2.Response(
                200,
                json={
                    "data": {
                        "data": entry["data"],
                        "metadata": {"version": entry["version"]},
                    }
                },
                request=request,
            )
        if request.method == "POST" and verb == "data":
            body = json.loads(request.content.decode())
            current = self.entries.get(key, {}).get("version", 0)
            if body["options"]["cas"] != current:
                return httpx2.Response(
                    400,
                    json={"errors": ["check-and-set parameter did not match"]},
                    request=request,
                )
            self.entries[key] = {"data": body["data"], "version": current + 1}
            return httpx2.Response(
                200, json={"data": {"version": current + 1}}, request=request
            )
        if request.method == "DELETE" and verb == "metadata":
            self.entries.pop(key, None)
            return httpx2.Response(204, request=request)
        return httpx2.Response(404, json={"errors": ["unhandled"]}, request=request)


def make_vault_kv(fake: FakeVault, tmp_path: Path) -> VaultKV:
    sa_token = tmp_path / "sa-token"
    sa_token.write_text("fake-sa-jwt\n")
    return VaultKV(
        addr=ADDR,
        auth_mount=AUTH_MOUNT,
        auth_role="af-mcp-broker",
        kv_mount=KV_MOUNT,
        sa_token_path=str(sa_token),
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(fake.handle)),
    )
