#!/usr/bin/env python3
"""Write the af-mcp-builder skill's copy of docs/mcp-design.md.

docs/mcp-design.md is the canonical text. An installed skill is a bare
directory that cannot reach docs/, so the skill carries a generated copy with
the links to sibling docs rewritten as absolute GitHub URLs.

Usage:
    python3 scripts/sync-skill-guide.py           # write the copy
    python3 scripts/sync-skill-guide.py --check   # exit 1 if the copy differs
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "mcp-design.md"
TARGET = ROOT / "skills" / "af-mcp-builder" / "references" / "mcp-design.md"
DOCS_URL = "https://github.com/maniaclab/af-mcp-platform/blob/main/docs/"
HEADER = (
    "<!-- Generated from docs/mcp-design.md by scripts/sync-skill-guide.py. "
    "Do not edit; edit the source and rerun the script. -->\n\n"
)

# A markdown link target that is a bare sibling page: name.md or name.md#anchor.
SIBLING_LINK = re.compile(r"\]\(([A-Za-z0-9_-]+\.md)(#[^)]*)?\)")


def render() -> str:
    """Return the text the skill's copy must contain."""
    body = SOURCE.read_text()
    return HEADER + SIBLING_LINK.sub(
        lambda m: f"]({DOCS_URL}{m.group(1)}{m.group(2) or ''})", body
    )


def main() -> int:
    """Write or check the copy."""
    expected = render()
    if "--check" in sys.argv[1:]:
        if not TARGET.exists() or TARGET.read_text() != expected:
            print(
                f"{TARGET.relative_to(ROOT)} is out of date with "
                f"{SOURCE.relative_to(ROOT)}; run: python3 scripts/sync-skill-guide.py",
                file=sys.stderr,
            )
            return 1
        return 0
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(expected)
    return 0


if __name__ == "__main__":
    sys.exit(main())
