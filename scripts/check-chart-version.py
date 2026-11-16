#!/usr/bin/env python3
"""Fail unless the chart's ``version`` equals a release tag without its ``v``.

The chart is pushed to the OCI registry under the version in ``Chart.yaml``,
while the release is identified by the git tag (``tbump.toml`` bumps both
together). A mismatch would publish the chart under a version that names a
different release.

Usage:
    python3 scripts/check-chart-version.py v1.2.3 charts/af-mcp-platform/Chart.yaml
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Anchored at line start so `appVersion:` does not match. Chart.yaml is read as
# text, not YAML, so the script runs on a bare CI runner without PyYAML.
_VERSION_LINE = re.compile(r"^version:\s*[\"']?([^\s\"']+)[\"']?\s*$", re.MULTILINE)


def chart_version(chart_yaml: Path) -> str:
    """Return the ``version`` field of a ``Chart.yaml``."""
    match = _VERSION_LINE.search(chart_yaml.read_text())
    if match is None:
        msg = f"no version field in {chart_yaml}"
        raise ValueError(msg)
    return match.group(1)


def main(argv: list[str]) -> int:
    """Return 0 when ``argv[0]`` is ``v`` plus the chart's version, else 1."""
    tag, chart_yaml = argv
    try:
        version = chart_version(Path(chart_yaml))
    except ValueError as exc:
        print(exc, file=sys.stderr)  # noqa: T201
        return 1
    if tag != f"v{version}":
        print(  # noqa: T201
            f"tag {tag} does not match Chart.yaml version {version} "
            f"(expected tag v{version})",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
