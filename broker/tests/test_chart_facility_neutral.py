"""The Helm chart names no facility: comments, examples and test values included.

The chart is deployed by many facilities, each with its own Keycloak realm,
address ranges and virtual organisation; one facility's hostnames, networks
or experiment names in the chart would read as defaults. Facility values
belong in the deploying facility's own repository. Placeholders use
``example.org``, ``examplevo`` and the documentation address ranges.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

_CHART = Path(__file__).resolve().parents[2] / "charts" / "af-mcp-platform"

# Lower-case; matched against lower-cased file content.
_FACILITY_MARKERS = ("uchicago", "mwt2", "atlas")

# Every address or CIDR in the chart must sit inside one of these: the
# private, special-use and documentation ranges (RFC 1918, 3927, 4193, 4291,
# 5737, 3849). A facility's real network is never one of them, so this
# catches one leaking into the chart without the test naming any facility.
_ALLOWED_V4 = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)
_ALLOWED_V6 = tuple(
    ipaddress.IPv6Network(cidr)
    for cidr in ("::1/128", "fc00::/7", "fe80::/10", "2001:db8::/32")
)
# The whole address space is allowed only as itself (the internet rule),
# never as a parent that would admit every address.
_ALLOWED_EXACT = frozenset(
    {ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")}
)

# Candidate address literals, optionally with a prefix length. Version
# strings like 1.2.3 never match the four-octet form, and the IPv6 form
# needs at least two colon-separated groups next to a `::` or a full
# eight-group address, so YAML keys like `a:b` do not match.
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?(?![\w.])")
_IPV6 = re.compile(
    r"(?<![\w:])([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(/\d{1,3})?(?![\w:])"
)


def _chart_files() -> list[Path]:
    return sorted(path for path in _CHART.rglob("*") if path.is_file())


def _addresses(line: str) -> list[str]:
    found = []
    for pattern in (_IPV4, _IPV6):
        for match in pattern.finditer(line):
            text = match.group(1) + (match.group(2) or "")
            try:
                ipaddress.ip_network(text, strict=False)
            except ValueError:
                continue
            found.append(text)
    return found


def _is_allowed(text: str) -> bool:
    network = ipaddress.ip_network(text, strict=False)
    if network in _ALLOWED_EXACT:
        return True
    if isinstance(network, ipaddress.IPv4Network):
        return any(network.subnet_of(allowed) for allowed in _ALLOWED_V4)
    return any(network.subnet_of(allowed) for allowed in _ALLOWED_V6)


def test_chart_files_are_found() -> None:
    assert _chart_files()


@pytest.mark.parametrize(
    ("text", "allowed"),
    [
        ("10.0.0.0/8", True),
        ("169.254.169.254/32", True),
        ("192.0.2.0/24", True),
        ("2001:db8::/32", True),
        ("fc00::/7", True),
        ("0.0.0.0/0", True),
        ("::/0", True),
        ("198.18.0.0/15", False),
        ("8.8.8.8", False),
        ("2606:4700::/32", False),
    ],
)
def test_address_allowlist(text: str, allowed: bool) -> None:
    assert _is_allowed(text) is allowed


def test_address_scan_finds_literals() -> None:
    assert _addresses("cidr: 192.0.2.0/24 and 2001:db8::/32") == [
        "192.0.2.0/24",
        "2001:db8::/32",
    ]
    assert _addresses("version: 1.2.3 image: repo:0.10.0 key: a:b") == []


def test_chart_has_no_facility_address() -> None:
    offenders = [
        f"{path.relative_to(_CHART)}:{number}: {text}"
        for path in _chart_files()
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        for text in _addresses(line)
        if not _is_allowed(text)
    ]

    assert offenders == []


@pytest.mark.parametrize("marker", _FACILITY_MARKERS)
def test_chart_has_no_facility_marker(marker: str) -> None:
    offenders = [
        f"{path.relative_to(_CHART)}:{number}"
        for path in _chart_files()
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        if marker in line.lower()
    ]

    assert offenders == []
