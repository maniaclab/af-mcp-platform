"""Constants shared by the tests of ``test_x509_redeem``."""

from __future__ import annotations

# ami is an x509 backend (auth_type: x509): that single flag drives portal
# minting (X509Provider registration), aggregator identity-JWT injection, and
# this endpoint's audience gate. An explicit identity_providers entry
# covering it is required too (conftest's app_client_factory default
# supplies one; the broker refuses to start otherwise).
_BACKENDS_YAML = (
    "services:\n"
    "  - name: ami\n"
    "    prefix: ami\n"
    "    url: http://ami-mcp.invalid/mcp\n"
    "    auth_type: x509\n"
    "    required_permission: read_data\n"
)
