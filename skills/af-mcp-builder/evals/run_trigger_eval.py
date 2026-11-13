#!/usr/bin/env python3
"""Trigger-eval harness that tests the real skill (not a command shim).

For each (description, query, run) it creates a fresh sandbox project whose
.claude/skills/af-mcp-builder/SKILL.md carries the candidate description, runs
`claude -p` with stream-json, and records whether the Skill tool was invoked
with the skill's name within the first MAX_TOOLS tool calls.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SKILL_SRC = Path(__file__).resolve().parents[1]
FIXTURES = SKILL_SRC / "evals" / "fixtures"
NAME = "af-mcp-builder"


def make_sandbox(description: str, root: Path) -> Path:
    sb = Path(tempfile.mkdtemp(dir=root))
    dst = sb / ".claude" / "skills" / NAME
    dst.mkdir(parents=True)
    text = (SKILL_SRC / "SKILL.md").read_text()
    # replace the single-line description in frontmatter
    text = re.sub(
        r"^description:.*$",
        "description: " + json.dumps(description),
        text,
        count=1,
        flags=re.MULTILINE,
    )
    (dst / "SKILL.md").write_text(text)
    # a small repo-like context so path-referencing queries are plausible
    shutil.copy(FIXTURES / "noncompliant-python" / "server.py", sb / "server.py")
    return sb


def run_one(args):
    description, query, root, model, timeout, max_tools = args
    sb = make_sandbox(description, root)
    cmd = [
        "claude",
        "-p",
        query,
        "--output-format",
        "stream-json",
        "--verbose",
        "--model",
        model,
        "--setting-sources",
        "project",
        "--strict-mcp-config",
        "--disallowedTools",
        "Bash",
        "Write",
        "Edit",
        "WebFetch",
        "WebSearch",
    ]
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    p = subprocess.Popen(
        cmd,
        cwd=sb,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    info = {"visible": None, "tools": [], "triggered": False, "timeout": False}
    start = time.time()
    try:
        for line in p.stdout:
            if time.time() - start > timeout:
                info["timeout"] = True
                break
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("type") == "system" and ev.get("subtype") == "init":
                skills = ev.get("skills", [])
                info["visible"] = any(NAME in s for s in skills)
                info["n_skills"] = len(skills)
            if ev.get("type") == "assistant":
                for c in ev["message"].get("content", []):
                    if c.get("type") == "tool_use":
                        info["tools"].append(c["name"])
                        if c["name"] == "Skill" and NAME in json.dumps(
                            c.get("input", {})
                        ):
                            info["triggered"] = True
                if info["triggered"] or len(info["tools"]) >= max_tools:
                    break
            if ev.get("type") == "result":
                break
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()
        shutil.rmtree(sb, ignore_errors=True)
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--queries", required=True)
    ap.add_argument("--description", required=True, help="text or @file")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--model", default="claude-sonnet-5-5")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--max-tools", type=int, default=3)
    ap.add_argument("--split", choices=["train", "test", "all"], default="all")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    desc = a.description
    if desc.startswith("@"):
        desc = Path(desc[1:]).read_text().strip()
    qs = json.loads(Path(a.queries).read_text())
    if a.split != "all":
        qs = [q for q in qs if q["split"] == a.split]
    root = Path(tempfile.mkdtemp(prefix="trig-"))
    jobs = [
        (desc, q["query"], root, a.model, a.timeout, a.max_tools)
        for q in qs
        for _ in range(a.runs)
    ]
    with ThreadPoolExecutor(a.workers) as ex:
        res = list(ex.map(run_one, jobs))
    out = []
    for i, q in enumerate(qs):
        rs = res[i * a.runs : (i + 1) * a.runs]
        out.append(
            {
                **q,
                "triggers": sum(r["triggered"] for r in rs),
                "runs": a.runs,
                "visible": [r["visible"] for r in rs],
                "timeouts": sum(r["timeout"] for r in rs),
                "first_tools": [r["tools"][:3] for r in rs],
            }
        )
    Path(a.out).write_text(json.dumps({"description": desc, "results": out}, indent=1))
    shutil.rmtree(root, ignore_errors=True)
    for r in out:
        sys.stderr.write(
            f"{r['triggers']}/{r['runs']} want={r['should_trigger']} "
            f"vis={r['visible']} {r['query'][:70]}\n"
        )


if __name__ == "__main__":
    main()
