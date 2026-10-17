"""Benchmark metrics calculation for verification reliability."""

from pydantic import BaseModel


class BenchmarkMetrics(BaseModel):
    total_cases: int = 0
    known_good_cases: int = 0
    known_bad_cases: int = 0
    holdout_cases: int = 0

    true_positives: int = 0   # Defects correctly flagged as FAILED/INCONCLUSIVE
    false_positives: int = 0  # Known-good cases incorrectly flagged as FAILED
    false_negatives: int = 0  # Defects that slipped through as PASSED
    true_negatives: int = 0   # Known-good correctly marked PASSED

    critical_defects_total: int = 0
    critical_defects_detected: int = 0

    defect_recall: float = 0.0
    critical_defect_recall: float = 0.0
    false_positive_rate: float = 0.0
    inconclusive_rate: float = 0.0
    passed_release_gate: bool = False

    def compute(self) -> "BenchmarkMetrics":
        if self.known_bad_cases > 0:
            self.defect_recall = self.true_positives / self.known_bad_cases
        if self.critical_defects_total > 0:
            self.critical_defect_recall = self.critical_defects_detected / self.critical_defects_total
        if self.known_good_cases > 0:
            self.false_positive_rate = self.false_positives / self.known_good_cases

        # Release gate criteria: 100% critical defect recall and 0% false positive rate on standard fixtures
        self.passed_release_gate = (
            self.critical_defect_recall >= 1.0 and self.false_positive_rate == 0.0
        )
        return self
