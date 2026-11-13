"""Unit tests for evals/score_trigger_results.py: the metric math and split handling."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from types import ModuleType

SKILL_DIR = Path(__file__).resolve().parent.parent
SCRIPT = SKILL_DIR / "evals" / "score_trigger_results.py"
RESULTS_DIR = SKILL_DIR / "evals" / "trigger_results"
QUERIES = SKILL_DIR / "evals" / "trigger_queries.json"


@pytest.fixture(scope="module")
def scorer() -> ModuleType:
    """Import evals/score_trigger_results.py, which is not on the package path."""
    spec = importlib.util.spec_from_file_location("score_trigger_results", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through sys.modules at class creation.
    sys.modules["score_trigger_results"] = module
    spec.loader.exec_module(module)
    return module


def result(
    qid: str, split: str, should: bool, triggers: int, runs: int = 3
) -> dict[str, Any]:
    return {
        "id": qid,
        "split": split,
        "should_trigger": should,
        "triggers": triggers,
        "runs": runs,
    }


class TestMetricMath:
    def test_counts_are_pooled_over_runs(self, scorer: ModuleType) -> None:
        # 2 positives (3/3 and 1/3 fired), 1 negative (1/3 fired).
        rs = [
            result("p1", "test", True, 3),
            result("p2", "test", True, 1),
            result("n1", "test", False, 1),
        ]
        s = scorer.score(rs)["test"]
        assert (s.tp, s.fn, s.fp, s.tn) == (4, 2, 1, 2)
        assert (s.n_pos, s.n_neg) == (2, 1)
        assert s.recall == pytest.approx(4 / 6)
        assert s.precision == pytest.approx(4 / 5)
        expected_f1 = 2 * (4 / 5) * (4 / 6) / ((4 / 5) + (4 / 6))
        assert s.f1 == pytest.approx(expected_f1)

    def test_perfect(self, scorer: ModuleType) -> None:
        rs = [result("p1", "train", True, 3), result("n1", "train", False, 0)]
        s = scorer.score(rs)["train"]
        assert (s.recall, s.precision, s.f1) == (1.0, 1.0, 1.0)

    def test_nothing_fires_has_undefined_precision_and_zero_f1(
        self, scorer: ModuleType
    ) -> None:
        rs = [result("p1", "train", True, 0), result("n1", "train", False, 0)]
        s = scorer.score(rs)["train"]
        assert s.recall == 0.0
        assert s.precision is None
        assert s.f1 == 0.0

    def test_only_false_positives(self, scorer: ModuleType) -> None:
        rs = [result("p1", "train", True, 0), result("n1", "train", False, 3)]
        s = scorer.score(rs)["train"]
        assert s.precision == 0.0
        assert s.f1 == 0.0

    def test_empty_split_is_all_zeros(self, scorer: ModuleType) -> None:
        s = scorer.score([])["train"]
        assert (s.tp, s.fn, s.fp, s.tn, s.n_pos, s.n_neg) == (0, 0, 0, 0, 0, 0)
        assert s.recall == 0.0
        assert s.precision is None

    def test_triggers_above_runs_is_rejected(self, scorer: ModuleType) -> None:
        with pytest.raises(ValueError, match="not in"):
            scorer.score([result("p1", "train", True, 4)])


class TestSplitHandling:
    def test_splits_are_scored_independently(self, scorer: ModuleType) -> None:
        rs = [
            result("p1", "train", True, 0),
            result("p2", "test", True, 3),
            result("n1", "train", False, 3),
            result("n2", "test", False, 0),
        ]
        scores = scorer.score(rs)
        assert scores["train"].recall == 0.0
        assert scores["train"].precision == 0.0
        assert scores["test"].recall == 1.0
        assert scores["test"].precision == 1.0

    def test_unknown_split_is_ignored(self, scorer: ModuleType) -> None:
        scores = scorer.score([result("p1", "dev", True, 3)])
        assert scores["train"].n_pos == 0
        assert scores["test"].n_pos == 0


class TestPooling:
    def test_pool_sums_runs_per_query(self, scorer: ModuleType) -> None:
        a = {"results": [result("p1", "test", True, 2), result("n1", "test", False, 0)]}
        b = {"results": [result("p1", "test", True, 3), result("n1", "test", False, 1)]}
        pooled = {r["id"]: r for r in scorer.pool_results([a, b])}
        assert (pooled["p1"]["triggers"], pooled["p1"]["runs"]) == (5, 6)
        assert (pooled["n1"]["triggers"], pooled["n1"]["runs"]) == (1, 6)

    def test_pool_rejects_a_query_that_changed_label(self, scorer: ModuleType) -> None:
        a = {"results": [result("p1", "test", True, 2)]}
        b = {"results": [result("p1", "test", False, 2)]}
        with pytest.raises(ValueError, match="differs"):
            scorer.pool_results([a, b])


class TestWilsonInterval:
    @pytest.mark.parametrize(
        ("successes", "n"), [(0, 10), (10, 10), (5, 10), (24, 24), (1, 40)]
    )
    def test_inside_unit_interval_and_brackets_estimate(
        self, scorer: ModuleType, successes: int, n: int
    ) -> None:
        low, high = scorer.wilson_interval(successes, n)
        assert 0.0 <= low <= successes / n <= high <= 1.0

    def test_known_value(self, scorer: ModuleType) -> None:
        # 24/24 successes: lower bound is n / (n + z^2).
        low, high = scorer.wilson_interval(24, 24)
        assert low == pytest.approx(24 / (24 + 1.96**2), abs=1e-3)
        assert high == pytest.approx(1.0)

    def test_no_runs_is_uninformative(self, scorer: ModuleType) -> None:
        assert scorer.wilson_interval(0, 0) == (0.0, 1.0)


class TestCommittedResults:
    """The committed raw results and query set agree with each other."""

    def test_every_result_file_matches_the_query_set(self, scorer: ModuleType) -> None:
        queries = {q["id"]: q for q in json.loads(QUERIES.read_text())}
        files = sorted(RESULTS_DIR.glob("*.json"))
        assert files
        for f in files:
            if f.name.startswith("original_stock"):
                continue  # scored from the stock harness, which lacks first_tools
            for r in json.loads(f.read_text())["results"]:
                q = queries[r["id"]]
                assert (r["split"], r["should_trigger"]) == (
                    q["split"],
                    q["should_trigger"],
                )

    def test_query_set_size_and_split(self) -> None:
        queries = json.loads(QUERIES.read_text())
        assert len(queries) >= 21
        assert {q["split"] for q in queries} == {"train", "test"}
        assert sum(q["should_trigger"] for q in queries) >= 12

    def test_cli_pools_two_runs(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--pool",
                str(RESULTS_DIR / "final_run1.json"),
                str(RESULTS_DIR / "final_run2.json"),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert proc.returncode == 0
        assert "TP=75/78" in proc.stdout
        assert "TP=48/48" in proc.stdout
