"""The public repository never names the private deployment repository.

The deployment's GitOps repository is private; a pointer to it is unusable
to public readers and discloses its existence. Documentation and comments
say "the deployment's GitOps repository" instead. The name is assembled
from fragments so this file does not itself contain it.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PRIVATE_REPO_NAME = re.compile("flux" + "[_-]" + "apps", re.IGNORECASE)


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


@pytest.mark.parametrize(
    "path",
    _tracked_files(),
    ids=lambda path: str(path.relative_to(_REPO_ROOT)),
)
def test_tracked_file_does_not_name_the_private_repository(path: Path) -> None:
    # Binary files are matched on their raw bytes too: a name in an image's
    # metadata is as public as one in prose.
    assert not _PRIVATE_REPO_NAME.search(
        path.read_bytes().decode("utf-8", errors="replace")
    )
