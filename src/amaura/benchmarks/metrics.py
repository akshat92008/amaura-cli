"""Benchmark metrics calculation for verification reliability."""

from pydantic import BaseModel


class BenchmarkMetrics(BaseModel):
    total_cases: int = 0
    known_good_cases: int = 0
    known_bad_cases: int = 0
    holdout_cases: int = 0
    adversarial_cases: int = 0

    true_positives: int = 0   # Defects correctly flagged as FAILED/INCONCLUSIVE
    false_positives: int = 0  # Known-good cases incorrectly flagged as FAILED
    false_negatives: int = 0  # Defects that slipped through as PASSED
    true_negatives: int = 0   # Known-good correctly marked PASSED

    critical_defects_total: int = 0
    critical_defects_detected: int = 0
    adversarial_detected: int = 0

    defect_recall: float = 0.0
    critical_defect_recall: float = 0.0
    false_positive_rate: float = 0.0
    inconclusive_rate: float = 0.0
    adversarial_detection_rate: float = 0.0

    # Extended reliability metrics (G6)
    claim_support_precision: float = 1.0
    repair_success_rate: float = 1.0
    reproducibility_rate: float = 1.0
    total_cost_usd: float = 0.0
    leakage_detected: int = 0

    passed_release_gate: bool = False

    def compute(self, min_cases: int = 1) -> "BenchmarkMetrics":
        if self.known_bad_cases > 0:
            self.defect_recall = self.true_positives / self.known_bad_cases
        if self.critical_defects_total > 0:
            self.critical_defect_recall = self.critical_defects_detected / self.critical_defects_total
        if self.known_good_cases > 0:
            self.false_positive_rate = self.false_positives / self.known_good_cases
        if self.adversarial_cases > 0:
            self.adversarial_detection_rate = self.adversarial_detected / self.adversarial_cases

        # Release gate criteria: must have cases, 100% defect recall, 100% critical defect recall, 0% false positives, and 0 leakage
        self.passed_release_gate = (
            self.total_cases >= max(1, min_cases)
            and self.defect_recall >= 1.0
            and self.critical_defect_recall >= 1.0
            and self.false_positive_rate == 0.0
            and (self.adversarial_cases == 0 or self.adversarial_detection_rate >= 1.0)
            and self.claim_support_precision >= 1.0
            and self.repair_success_rate >= 1.0
            and self.reproducibility_rate >= 1.0
            and self.leakage_detected == 0
        )
        return self
