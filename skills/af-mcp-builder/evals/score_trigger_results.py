#!/usr/bin/env python3
"""Score the output of run_trigger_eval.py: recall, precision and F1 per split.

Each result file holds ``{"description": ..., "results": [...]}`` where every
result has ``id``, ``split`` ("train" or "test"), ``should_trigger``,
``triggers`` (runs in which the skill fired) and ``runs``. Counts are pooled
over runs, not over queries: a query that fires in 2 of 3 runs contributes 2
true positives and 1 false negative when it should trigger, and 2 false
positives (and 1 true negative) when it should not.

Several files can be pooled with ``--pool`` (same queries, repeated runs).

    python score_trigger_results.py trigger_results/original.json
    python score_trigger_results.py --pool trigger_results/final_run1.json trigger_results/final_run2.json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

Z_95 = 1.96


@dataclass(frozen=True)
class SplitScore:
    """Pooled confusion counts for one split and the metrics derived from them."""

    n_pos: int  # queries that should trigger
    n_neg: int  # queries that should not
    tp: int
    fn: int
    fp: int
    tn: int

    @property
    def recall(self) -> float:
        """Fraction of should-trigger runs that fired; 0.0 when there are none."""
        positives = self.tp + self.fn
        return self.tp / positives if positives else 0.0

    @property
    def precision(self) -> float | None:
        """Fraction of fired runs that should have fired; None when nothing fired."""
        fired = self.tp + self.fp
        return self.tp / fired if fired else None

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall; 0.0 when either is 0 or undefined."""
        precision = self.precision
        if precision is None or precision + self.recall == 0:
            return 0.0
        return 2 * precision * self.recall / (precision + self.recall)

    @property
    def recall_ci(self) -> tuple[float, float]:
        """Wilson 95% interval on recall, over pooled should-trigger runs."""
        return wilson_interval(self.tp, self.tp + self.fn)


def wilson_interval(successes: int, n: int) -> tuple[float, float]:
    """Wilson score interval; it stays inside [0, 1] for p near 0 or 1."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + Z_95**2 / n
    centre = (p + Z_95**2 / (2 * n)) / denom
    half = Z_95 * math.sqrt(p * (1 - p) / n + Z_95**2 / (4 * n**2)) / denom
    # Clamp: at p = 0 or 1 rounding leaves the bound a few ulp outside [0, 1].
    return (max(0.0, centre - half), min(1.0, centre + half))


def pool_results(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sum ``triggers`` and ``runs`` per query id across result files."""
    pooled: dict[str, dict[str, Any]] = {}
    for data in files:
        for r in data["results"]:
            entry = pooled.get(r["id"])
            if entry is None:
                pooled[r["id"]] = {
                    "id": r["id"],
                    "split": r["split"],
                    "should_trigger": r["should_trigger"],
                    "triggers": r["triggers"],
                    "runs": r["runs"],
                }
                continue
            if (entry["split"], entry["should_trigger"]) != (
                r["split"],
                r["should_trigger"],
            ):
                msg = f"query {r['id']} differs between result files"
                raise ValueError(msg)
            entry["triggers"] += r["triggers"]
            entry["runs"] += r["runs"]
    return list(pooled.values())


def score_split(results: list[dict[str, Any]], split: str) -> SplitScore:
    """Pool the confusion counts of the results in one split."""
    tp = fn = fp = tn = n_pos = n_neg = 0
    for r in results:
        if r["split"] != split:
            continue
        if not 0 <= r["triggers"] <= r["runs"]:
            msg = f"query {r['id']}: triggers {r['triggers']} not in [0, {r['runs']}]"
            raise ValueError(msg)
        if r["should_trigger"]:
            n_pos += 1
            tp += r["triggers"]
            fn += r["runs"] - r["triggers"]
        else:
            n_neg += 1
            fp += r["triggers"]
            tn += r["runs"] - r["triggers"]
    return SplitScore(n_pos=n_pos, n_neg=n_neg, tp=tp, fn=fn, fp=fp, tn=tn)


def score(results: list[dict[str, Any]]) -> dict[str, SplitScore]:
    """Score the train and test splits; a split with no queries is all zeros."""
    return {split: score_split(results, split) for split in ("train", "test")}


def format_scores(label: str, scores: dict[str, SplitScore]) -> str:
    """One line per split."""
    lines = [label]
    for split, s in scores.items():
        precision = "n/a" if s.precision is None else f"{s.precision:.2f}"
        low, high = s.recall_ci
        lines.append(
            f"  {split}: queries +{s.n_pos}/-{s.n_neg} "
            f"recall={s.recall:.2f} [95% CI {low:.2f}-{high:.2f}] "
            f"precision={precision} f1={s.f1:.2f} "
            f"TP={s.tp}/{s.tp + s.fn} FP={s.fp}/{s.fp + s.tn}"
        )
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument(
        "--pool",
        action="store_true",
        help="treat the files as repeated runs of one description and sum them",
    )
    args = ap.parse_args()
    loaded = [json.loads(f.read_text()) for f in args.files]
    if args.pool:
        label = ", ".join(f.name for f in args.files)
        sys.stdout.write(format_scores(label, score(pool_results(loaded))) + "\n")
        return
    for f, data in zip(args.files, loaded, strict=True):
        sys.stdout.write(format_scores(f.name, score(data["results"])) + "\n")


if __name__ == "__main__":
    main()
