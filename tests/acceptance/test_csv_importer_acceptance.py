"""Acceptance tests for the three CSV Importer reference versions."""

from pathlib import Path

from amaura.models.run import OverallVerdict
from amaura.orchestration.runner import verify_project


def test_version_a_correct_satisfies_all_requirements():
    base_dir = Path(__file__).resolve().parents[2]
    project_dir = base_dir / "examples" / "csv-import" / "version_a_correct"
    task_file = base_dir / "examples" / "csv-import" / "task.md"

    record = verify_project(project_dir=project_dir, task_file=task_file)
    assert record.overall_verdict == OverallVerdict.PASSED
    assert len(record.findings) == 0
    assert all(c.status.value == "supported" for c in record.claims)


def test_version_b_catches_malformed_csv_crash():
    base_dir = Path(__file__).resolve().parents[2]
    project_dir = base_dir / "examples" / "csv-import" / "version_b_crash_malformed"
    task_file = base_dir / "examples" / "csv-import" / "task.md"

    record = verify_project(project_dir=project_dir, task_file=task_file)
    assert record.overall_verdict == OverallVerdict.FAILED
    assert any(f.severity.value in ("critical", "high") for f in record.findings)
    # Check that the malformed acceptance test failed
    chk_malformed = next(c for c in record.checks if "REQ-003" in c.name)
    exec_item = next(e for e in record.executions if e.check_id == chk_malformed.check_id)
    assert exec_item.status.value == "failed"


def test_version_c_detects_untested_duplicate_requirement_gap():
    base_dir = Path(__file__).resolve().parents[2]
    project_dir = base_dir / "examples" / "csv-import" / "version_c_gap_duplicates"
    task_file = base_dir / "examples" / "csv-import" / "task.md"

    record = verify_project(project_dir=project_dir, task_file=task_file)
    # Version C must not silently pass
    assert record.overall_verdict in (OverallVerdict.FAILED, OverallVerdict.INCONCLUSIVE)
    # A test gap or verification gap finding must be reported
    assert any(
        f.finding_type.value in ("test_gap", "verification_gap")
        for f in record.findings
    )
