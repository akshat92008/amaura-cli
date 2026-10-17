"""Benchmark runner evaluating Amaura verification against expected verdicts and release gates."""

from pathlib import Path
from typing import Optional

from amaura.benchmarks.metrics import BenchmarkMetrics
from amaura.config import AmauraConfig
from amaura.models.run import OverallVerdict
from amaura.orchestration.runner import verify_project


class BenchmarkCase:
    def __init__(
        self,
        name: str,
        path: Path,
        task_file: Path,
        expected_verdict: OverallVerdict,
        is_critical_defect: bool = False,
        category: str = "known_bad",  # "known_good", "known_bad", "holdout", "adversarial"
    ):
        self.name = name
        self.path = path
        self.task_file = task_file
        self.expected_verdict = expected_verdict
        self.is_critical_defect = is_critical_defect
        self.category = category


class BenchmarkRunner:
    """Executes verification against standard defect fixtures to measure defect recall and prevent regressions."""

    def __init__(self, config: Optional[AmauraConfig] = None):
        self.config = config or AmauraConfig()

    def run_suite(self, cases: list[BenchmarkCase]) -> BenchmarkMetrics:
        metrics = BenchmarkMetrics()
        metrics.total_cases = len(cases)

        for case in cases:
            rec = verify_project(project_dir=case.path, task_file=case.task_file, config=self.config)

            if case.category == "known_good":
                metrics.known_good_cases += 1
                if rec.overall_verdict == case.expected_verdict:
                    metrics.true_negatives += 1
                else:
                    metrics.false_positives += 1

            elif case.category in ("known_bad", "holdout", "adversarial"):
                metrics.known_bad_cases += 1
                if case.is_critical_defect:
                    metrics.critical_defects_total += 1

                # Strict comparison against expected_verdict
                if rec.overall_verdict == case.expected_verdict:
                    metrics.true_positives += 1
                    if case.is_critical_defect:
                        metrics.critical_defects_detected += 1
                else:
                    metrics.false_negatives += 1

        return metrics.compute()
