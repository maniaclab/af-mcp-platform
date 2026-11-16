"""In-memory fake of the Vault KV-v2 HTTP API subset ``VaultKV`` uses (K8s auth login, GET, CAS POST, LIST, metadata DELETE), shared by every test that backs a store with Vault.

The fake is served through ``httpx2.MockTransport`` (``FakeVault.handle``).
``make_vault_kv`` wires a ``VaultKV`` to one.
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
AUTH_ROLE = "af-mcp-broker"
KV_MOUNT = "secret"

_CAS_MISMATCH = "check-and-set parameter did not match the current version"


class FakeVault:
    """Behaves as Vault does for a path that was never written *or* whose metadata was destroyed: GET 404s, LIST 404s, and a CAS write with ``cas=0`` succeeds (current version 0).

    The broker only destroys via the metadata endpoint (never a bare
    soft-delete on ``data``), so one absent-key state covers both cases.

    ``entries`` maps the KV path to ``{"data": dict, "version": int}``. The
    path is taken below the KV mount, and below ``key_prefix`` when one is
    given (a store pinned to one prefix then sees ``<subject>/<kind>``-style
    keys); requests outside ``key_prefix`` 404 as an unknown path.

    Failure injection:

    - ``kv_status``: every KV request answers this status instead of running
      the normal logic (error-mapping tests).
    - ``cas_conflicts``: the next N data writes are rejected with a CAS
      mismatch, as a concurrent writer would; ``write_attempts`` counts every
      data write, rejected or not.
    - ``login_lease_duration``: lease of the minted client token; every login
      body lands in ``login_calls``.
    """

    def __init__(
        self,
        *,
        key_prefix: str = "",
        login_lease_duration: int = 3600,
        kv_status: int | None = None,
        cas_conflicts: int = 0,
    ) -> None:
        self.entries: dict[str, dict[str, Any]] = {}
        self.login_calls: list[dict[str, Any]] = []
        self.write_attempts = 0
        self.login_lease_duration = login_lease_duration
        self.kv_status = kv_status
        self.cas_conflicts = cas_conflicts
        self._key_prefix = f"{key_prefix.strip('/')}/" if key_prefix else ""

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        path = request.url.path.removeprefix("/v1/")

        if path == f"auth/{AUTH_MOUNT}/login" and request.method == "POST":
            self.login_calls.append(json.loads(request.content.decode()))
            return httpx2.Response(
                200,
                json={
                    "auth": {
                        "client_token": "vault-test-token",
                        "lease_duration": self.login_lease_duration,
                        "renewable": True,
                    }
                },
                request=request,
            )

        for verb in ("data", "metadata"):
            mount_prefix = f"{KV_MOUNT}/{verb}/{self._key_prefix}"
            if path.startswith(mount_prefix):
                if self.kv_status is not None:
                    return httpx2.Response(
                        self.kv_status,
                        json={"errors": ["internal error"]},
                        request=request,
                    )
                return self._kv(request, verb, path[len(mount_prefix) :])
        return httpx2.Response(404, json={"errors": ["unknown path"]}, request=request)

    def _kv(self, request: httpx2.Request, verb: str, key: str) -> httpx2.Response:
        if request.method == "LIST" and verb == "metadata":
            # Immediate children; a child that has children of its own gets a
            # trailing "/", as in Vault.
            base = key.rstrip("/") + "/" if key else ""
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
            self.write_attempts += 1
            body = json.loads(request.content.decode())
            current = self.entries.get(key, {}).get("version", 0)
            if self.cas_conflicts > 0:
                self.cas_conflicts -= 1
                return httpx2.Response(
                    400, json={"errors": [_CAS_MISMATCH]}, request=request
                )
            if body["options"]["cas"] != current:
                return httpx2.Response(
                    400, json={"errors": [_CAS_MISMATCH]}, request=request
                )
            self.entries[key] = {"data": body["data"], "version": current + 1}
            return httpx2.Response(
                200, json={"data": {"version": current + 1}}, request=request
            )
        if request.method == "DELETE" and verb == "metadata":
            self.entries.pop(key, None)
            return httpx2.Response(204, request=request)
        return httpx2.Response(404, json={"errors": ["unhandled"]}, request=request)


def make_vault_kv(fake: FakeVault, sa_token_path: Path) -> VaultKV:
    """Build a ``VaultKV`` talking to *fake*; *sa_token_path* is the written service-account token file (the ``sa_token_path`` fixture)."""
    return VaultKV(
        addr=ADDR,
        auth_mount=AUTH_MOUNT,
        auth_role=AUTH_ROLE,
        kv_mount=KV_MOUNT,
        sa_token_path=str(sa_token_path),
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(fake.handle)),
    )
