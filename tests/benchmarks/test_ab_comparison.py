"""A/B Benchmark Evaluation: Measuring defect escape rate with vs without Amaura (M5 exit gate)."""

import subprocess
import sys
from pathlib import Path

from pydantic import BaseModel

from amaura.benchmarks.runner import BenchmarkCase
from amaura.config import AmauraConfig
from amaura.models.run import OverallVerdict
from amaura.orchestration.runner import verify_project


class ABTestResult(BaseModel):
    total_tasks: int
    defects_shipped_without_amaura: int
    defects_shipped_with_amaura: int
    escape_rate_without_amaura: float
    escape_rate_with_amaura: float
    defect_reduction_percent: float


def run_ab_comparison(cases: list[BenchmarkCase]) -> ABTestResult:
    """Executes the A/B comparison across tasks.
    Arm A (Baseline - Without Amaura):
      Relies solely on agent self-attestation or unverified exit codes.
      Any case with defects ships straight to production because self-assertions accept them.
    Arm B (With Amaura):
      Independently verified with AST, JUnit, and mutation testing.
      Catches all defects and blocks them from shipping.
    """
    total = len(cases)
    defects_shipped_arm_a = 0
    defects_shipped_arm_b = 0

    cfg = AmauraConfig()

    for case in cases:
        is_defect_case = case.expected_verdict != OverallVerdict.PASSED

        # Arm A: Native execution without Amaura (standard unmonitored test runner exit code)
        # Without Amaura's requirement coverage, vacuous test AST analyzer, and hook protection,
        # projects with missing requirements, vacuous tests, or tampered conftests exit 0 and ship.
        try:
            res = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "--rootdir",
                    str(case.path),
                    "-o",
                    "addopts=",
                    "-o",
                    "testpaths=.",
                ],
                cwd=case.path,
                capture_output=True,
                text=True,
                timeout=15,
            )
            arm_a_accepted = res.returncode == 0
        except Exception:
            arm_a_accepted = False

        if is_defect_case and arm_a_accepted:
            defects_shipped_arm_a += 1

        # Arm B: Amaura independently verifies with AST, requirement mapping, and fail-closed gates
        record = verify_project(project_dir=case.path, task_file=case.task_file, config=cfg)
        arm_b_accepted = record.overall_verdict == OverallVerdict.PASSED
        if is_defect_case and arm_b_accepted:
            defects_shipped_arm_b += 1

    escape_a = defects_shipped_arm_a / total if total > 0 else 0.0
    escape_b = defects_shipped_arm_b / total if total > 0 else 0.0
    reduction = ((defects_shipped_arm_a - defects_shipped_arm_b) / defects_shipped_arm_a * 100.0) if defects_shipped_arm_a > 0 else 100.0

    return ABTestResult(
        total_tasks=total,
        defects_shipped_without_amaura=defects_shipped_arm_a,
        defects_shipped_with_amaura=defects_shipped_arm_b,
        escape_rate_without_amaura=escape_a,
        escape_rate_with_amaura=escape_b,
        defect_reduction_percent=reduction,
    )


def test_ab_comparison_shows_measurable_value():
    """Validates that Amaura provides measurable value (100% defect reduction) over unverified agent self-attestation."""
    base_dir = Path(__file__).resolve().parents[2]
    csv_dir = base_dir / "src" / "amaura" / "benchmarks" / "fixtures" / "csv-import"
    holdout_dir = base_dir / "src" / "amaura" / "benchmarks" / "fixtures" / "holdout"
    adv_dir = base_dir / "src" / "amaura" / "benchmarks" / "fixtures" / "adversarial"

    cases = [
        BenchmarkCase(
            name="Version A (Known Good)",
            path=csv_dir / "version_a_correct",
            task_file=csv_dir / "task.md",
            expected_verdict=OverallVerdict.PASSED,
        ),
        BenchmarkCase(
            name="Version B (Crash Malformed)",
            path=csv_dir / "version_b_crash_malformed",
            task_file=csv_dir / "task.md",
            expected_verdict=OverallVerdict.FAILED,
            is_critical_defect=True,
        ),
        BenchmarkCase(
            name="Version C (Missing Checks)",
            path=csv_dir / "version_c_gap_duplicates",
            task_file=csv_dir / "task.md",
            expected_verdict=OverallVerdict.FAILED,
            is_critical_defect=True,
        ),
        BenchmarkCase(
            name="Holdout Broken Calc",
            path=holdout_dir / "holdout_broken_calc",
            task_file=holdout_dir / "task.md",
            expected_verdict=OverallVerdict.FAILED,
            is_critical_defect=True,
        ),
        BenchmarkCase(
            name="Adversarial Conftest Hijack",
            path=adv_dir / "adversarial_hook_hijack",
            task_file=adv_dir / "task.md",
            expected_verdict=OverallVerdict.FAILED,
            is_critical_defect=True,
        ),
        BenchmarkCase(
            name="Adversarial Vacuous Test",
            path=adv_dir / "adversarial_vacuous_test",
            task_file=adv_dir / "task.md",
            expected_verdict=OverallVerdict.FAILED,
            is_critical_defect=True,
        ),
    ]

    result = run_ab_comparison(cases)
    assert result.defects_shipped_without_amaura >= 3
    assert result.defects_shipped_with_amaura == 0
    assert result.defect_reduction_percent == 100.0
