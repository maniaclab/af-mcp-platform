"""The public repository names neither the private deployment repository nor one facility.

The deployment's GitOps repository is private; a pointer to it is unusable
to public readers and discloses its existence. Documentation and comments
say "the deployment's GitOps repository" instead.

Configuration guidance, examples, defaults and tests use ``example.org`` and
neutral names rather than one facility's. The reference deployment's name
may appear only where it states provenance; each such phrase is listed in
``_FACILITY_NAME_ALLOWED``. Both names are assembled from fragments so this
file does not itself contain them.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PRIVATE_REPO_NAME = re.compile("flux" + "[_-]" + "apps", re.IGNORECASE)
_FACILITY_NAME = re.compile("u" + "chicago", re.IGNORECASE)

# file -> exact phrases (matched case-insensitively) in which the facility
# name may stay. Everything else naming it fails.
_FACILITY_NAME_ALLOWED: dict[str, tuple[str, ...]] = {
    # Provenance: the reference deployment.
    "README.md": (
        "[UChicago ATLAS Analysis Facility](https://af.uchicago.edu/)",
        "The UChicago ATLAS AF reference deployment runs:",
    ),
    "docs/index.md": ("[UChicago ATLAS Analysis Facility](https://af.uchicago.edu/)",),
    "docs/ecosystem.md": ("make up the UChicago ATLAS Analysis",),
    "CLAUDE.md": (
        "The reference deployment is UChicago's ATLAS Analysis Facility (`mcp.af.uchicago.edu`",
    ),
    "PRODUCT.md": (
        "The reference deployment is UChicago's ATLAS Analysis Facility (AF)",
        "`mcp-portal.af.uchicago.edu`",
        "`mcp.af.uchicago.edu`",
    ),
    ".claude-plugin/marketplace.json": ('"name": "UChicago ATLAS Analysis Facility"',),
    "portal/src/pages/index.astro": (
        "Already running at UChicago",
        "The UChicago ATLAS Analysis Facility uses MCP Platform today",
    ),
    # Guards that name the facility so it cannot leak into the chart.
    "broker/tests/unit/test_chart_facility_neutral.py": ('"uchicago"',),
    "broker/tests/integration/test_chart_values_schema.py": ('"uchicago"',),
}


def _tracked_files() -> list[Path]:
    listing = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=_REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    paths = (_REPO_ROOT / name for name in listing.split("\0") if name)
    # A tracked symlink to a directory has no content of its own to scan.
    return [path for path in paths if path.is_file()]


def _text(path: Path) -> str:
    # Binary files are matched on their raw bytes too: a name in an image's
    # metadata is as public as one in prose.
    return path.read_bytes().decode("utf-8", errors="replace")


_TRACKED = _tracked_files()


@pytest.mark.parametrize(
    "path", _TRACKED, ids=lambda path: str(path.relative_to(_REPO_ROOT))
)
def test_tracked_file_does_not_name_the_private_repository(path: Path) -> None:
    assert not _PRIVATE_REPO_NAME.search(_text(path))


# This file holds the allowlist itself, so it is the one file not scanned.
@pytest.mark.parametrize(
    "path",
    [path for path in _TRACKED if path != Path(__file__).resolve()],
    ids=lambda path: str(path.relative_to(_REPO_ROOT)),
)
def test_tracked_file_names_the_facility_only_in_allowed_phrases(path: Path) -> None:
    text = _text(path).lower()
    for phrase in _FACILITY_NAME_ALLOWED.get(str(path.relative_to(_REPO_ROOT)), ()):
        text = text.replace(phrase.lower(), "")
    assert not _FACILITY_NAME.search(text)


@pytest.mark.parametrize("name", sorted(_FACILITY_NAME_ALLOWED))
def test_allowed_facility_phrases_are_still_present(name: str) -> None:
    text = (_REPO_ROOT / name).read_text().lower()
    for phrase in _FACILITY_NAME_ALLOWED[name]:
        assert phrase.lower() in text, f"stale allowlist entry in {name}: {phrase}"
