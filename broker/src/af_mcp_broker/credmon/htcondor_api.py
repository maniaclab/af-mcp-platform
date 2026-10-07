"""``CredentialStoreClient`` backed by golang-htcondor's htcondor-api REST server.

Contract (webapi/httpserver/handlers_credd.go): ``POST {api_url}/api/v1/
creds/service/{service}`` with JSON ``{"cred_type", "credential",
"service", "user", "refresh"}``. htcondor-api forwards it to credd's
STORE_CRED; storing for a ``user`` other than the caller requires the
caller's identity to be listed in credd's ``CRED_SUPER_USERS``.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import httpx
import structlog

from af_mcp_broker.credmon.storer import CredentialStoreClient, CredentialStoreError
from af_mcp_broker.http import get_http_client

if TYPE_CHECKING:
    from pydantic import SecretStr

# Upper bound on how much of an htcondor-api error body is relayed into
# CredentialStoreError -- enough for credd's reason, never a full dump.
_MAX_ERROR_DETAIL_CHARS = 300


class HTCondorApiCredentialStore(CredentialStoreClient):
    """Stores OAuth service credentials in credd through htcondor-api, authenticated with a static bearer token."""

    def __init__(
        self,
        *,
        api_url: str,
        token: SecretStr,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = api_url.rstrip("/")
        self._token = token
        self._http_client = http_client
        self._log = structlog.get_logger(__name__).bind(
            component="HTCondorApiCredentialStore"
        )

    def _http(self) -> httpx.AsyncClient:
        return self._http_client if self._http_client is not None else get_http_client()

    async def store_service_credential(
        self, *, user: str, service: str, credential: dict[str, str]
    ) -> None:
        # Base64 explicitly: the handler base64-decodes when it can and
        # falls back to the raw string otherwise, so sending raw JSON would
        # depend on it never happening to parse as base64.
        encoded = base64.b64encode(json.dumps(credential).encode()).decode()
        try:
            resp = await self._http().post(
                f"{self._base_url}/api/v1/creds/service/{service}",
                headers={"Authorization": f"Bearer {self._token.get_secret_value()}"},
                json={
                    "cred_type": "oauth",
                    "credential": encoded,
                    "service": service,
                    "user": user,
                    # refresh=true -> credd writes <service>.top, the file
                    # the credmon scans; false would write .use directly.
                    "refresh": True,
                },
                timeout=30.0,
            )
        except httpx.HTTPError as exc:
            self._log.warning(
                "htcondor_api.store.unreachable",
                service=service,
                user=user,
                error=str(exc),
            )
            raise CredentialStoreError("htcondor-api could not be reached.") from exc

        if resp.status_code not in (httpx.codes.OK, httpx.codes.CREATED):
            # htcondor-api's error body carries credd's reason (e.g. the
            # caller is not a CRED_SUPER_USER); it never echoes the stored
            # credential, so a truncated copy is safe and actionable.
            detail = resp.text[:_MAX_ERROR_DETAIL_CHARS]
            self._log.warning(
                "htcondor_api.store.failed",
                service=service,
                user=user,
                upstream_status=resp.status_code,
            )
            raise CredentialStoreError(
                f"htcondor-api store failed (status {resp.status_code}): {detail}"
            )
