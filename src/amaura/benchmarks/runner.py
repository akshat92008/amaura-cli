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

    def run_suite(self, cases: list[BenchmarkCase], min_cases: int = 1) -> BenchmarkMetrics:
        metrics = BenchmarkMetrics()
        metrics.total_cases = len(cases)
        reproducible_count = 0
        total_supported_claims = 0
        valid_supported_claims = 0

        for case in cases:
            rec = verify_project(project_dir=case.path, task_file=case.task_file, config=self.config)

            # Measure reproducibility: re-run case to verify deterministic result invariance (Rule 11)
            rec_repro = verify_project(project_dir=case.path, task_file=case.task_file, config=self.config)
            if rec.overall_verdict == rec_repro.overall_verdict:
                reproducible_count += 1

            # Measure claim-support precision across evaluated claims
            for clm in rec.claims:
                if clm.status.value == "supported":
                    total_supported_claims += 1
                    if case.expected_verdict == OverallVerdict.PASSED or rec.overall_verdict != OverallVerdict.PASSED:
                        valid_supported_claims += 1

            if case.expected_verdict == OverallVerdict.PASSED:
                metrics.known_good_cases += 1
                if rec.overall_verdict == case.expected_verdict:
                    metrics.true_negatives += 1
                else:
                    metrics.false_positives += 1

            else:
                metrics.known_bad_cases += 1
                if case.category == "holdout":
                    metrics.holdout_cases += 1
                elif case.category == "adversarial":
                    metrics.adversarial_cases += 1

                if case.is_critical_defect:
                    metrics.critical_defects_total += 1

                # Strict comparison against expected_verdict
                if rec.overall_verdict == case.expected_verdict:
                    metrics.true_positives += 1
                    if case.is_critical_defect:
                        metrics.critical_defects_detected += 1
                    if case.category == "adversarial":
                        metrics.adversarial_detected += 1
                else:
                    metrics.false_negatives += 1

        if cases:
            metrics.reproducibility_rate = reproducible_count / len(cases)
        if total_supported_claims > 0:
            metrics.claim_support_precision = valid_supported_claims / total_supported_claims
        else:
            metrics.claim_support_precision = 1.0

        return metrics.compute(min_cases=min_cases)
