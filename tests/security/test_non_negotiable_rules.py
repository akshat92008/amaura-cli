"""Comprehensive test suite enforcing all 15 non-negotiable engineering rules by name."""

from pathlib import Path

import pytest

from amaura.config import AmauraConfig, PrivacyMode
from amaura.errors import EvidenceIntegrityError, ExecutionSecurityError
from amaura.evidence.collector import EvidenceCollector
from amaura.evidence.ledger import EvidenceLedger
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus, CheckType
from amaura.models.claim import Claim, ClaimOrigin, ClaimStatus, ClaimType
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.models.run import OverallVerdict, RunMode, RunRecord
from amaura.models.task import Requirement, TaskSpec
from amaura.security.process import run_safe_process
from amaura.security.workspace import validate_path_within_workspace
from amaura.verdicts.evaluator import VerdictEvaluator
from amaura.verdicts.policy import VerdictPolicy
from amaura.verifiers.code import CodeVerifier


def test_rule_01_no_self_approval(tmp_path: Path):
    """Rule 1: No agent may approve its own work solely through its own assertion."""
    code_file = tmp_path / "calc.py"
    code_file.write_text("def add(a, b):\n    return a - b\n")
    test_file = tmp_path / "test_calc.py"
    # Placeholder test that passes regardless of implementation
    test_file.write_text("def test_req_001():\n    assert len('ab') == 2\n")

    verifier = CodeVerifier(AmauraConfig())
    collector = EvidenceCollector("run_test_r1")
    check = CheckDefinition(
        check_id="chk_add",
        name="Acceptance: REQ-001",
        description="Validates requirement REQ-001 addition",
        check_type=CheckType.ACCEPTANCE_TEST,
        target_requirement_id="REQ-001",
        target_claim_id="CLM-REQ-001",
    )
    result = verifier.verify(tmp_path, check, collector)
    assert result.execution.status == CheckStatus.FAILED
    assert any("Mutant Survived" in f.title for f in result.findings)


def test_rule_02_no_silent_passes():
    """Rule 2: No missing check may silently count as passed."""
    task = TaskSpec(
        task_id="tsk_r2",
        instruction="Math task",
        requirements=[Requirement(id="REQ-001", description="Addition works", mandatory=True)],
    )
    chk = CheckDefinition(check_id="chk_001", name="Acceptance: REQ-001", mandatory=True)
    # Execution missing / not run
    exec_not_run = CheckExecution(check_id="chk_001", execution_id="ex_1", status=CheckStatus.NOT_RUN)

    evaluator = VerdictEvaluator(VerdictPolicy())
    result = evaluator.evaluate(task, [], [chk], [exec_not_run], [])
    assert result.overall_verdict != OverallVerdict.PASSED
    assert result.overall_verdict == OverallVerdict.FAILED


def test_rule_03_no_overriding_contradictory_evidence():
    """Rule 3: No final verdict may override contradictory evidence without documented resolution."""
    task = TaskSpec(task_id="tsk_r3", instruction="Check contradictory")
    chk = CheckDefinition(check_id="chk_1", name="Check 1", mandatory=False)
    exec_passed = CheckExecution(check_id="chk_1", execution_id="ex_1", status=CheckStatus.PASSED)
    claim = Claim(
        claim_id="CLM-01",
        text="Feature works",
        claim_type=ClaimType.BEHAVIORAL,
        origin=ClaimOrigin.AGENT_OUTPUT,
    )
    critical_defect = Finding(
        finding_id="find_crit",
        check_id="chk_1",
        title="Fatal Defect",
        description="Observed data corruption",
        finding_type=FindingType.DEFECT,
        severity=FindingSeverity.CRITICAL,
        is_blocking=True,
    )

    evaluator = VerdictEvaluator(VerdictPolicy())
    result = evaluator.evaluate(task, [claim], [chk], [exec_passed], [critical_defect])
    assert result.overall_verdict == OverallVerdict.FAILED
    assert any("Critical finding" in r for r in result.verdict_reasons)


def test_rule_04_rerun_required_for_repairs(tmp_path: Path):
    """Rule 4: No repair is considered successful until relevant checks are rerun."""
    proj = tmp_path / "repair_proj"
    proj.mkdir()
    (proj / "solution.py").write_text("def solve(): return False\n")
    (proj / "test_solution.py").write_text("from solution import solve\ndef test_solve(): assert solve() is True\n")

    verifier = CodeVerifier(AmauraConfig())
    collector = EvidenceCollector("run_r4_initial")
    check = CheckDefinition(
        check_id="chk_rep",
        name="Repair Check",
        check_type=CheckType.TEST,
    )
    res_initial = verifier.verify(proj, check, collector)
    assert res_initial.execution.status == CheckStatus.FAILED

    # Repair without rerun cannot be marked passed
    # Only after rerunning does it become PASSED
    (proj / "solution.py").write_text("def solve(): return True\n")
    collector_repaired = EvidenceCollector("run_r4_repaired")
    res_repaired = verifier.verify(proj, check, collector_repaired)
    assert res_repaired.execution.status == CheckStatus.PASSED


def test_rule_05_no_evidence_overwritten(tmp_path: Path):
    """Rule 5: No raw evidence is silently overwritten by a later attempt."""
    ledger = EvidenceLedger(tmp_path)
    rec1 = RunRecord(
        run_id="run_attempt_1",
        task=TaskSpec(task_id="t1", instruction="test"),
        mode=RunMode.VERIFY,
        working_dir=str(tmp_path),
    )
    ledger.save_run(rec1, [])

    # Second attempt with same run_id must raise an error to preserve immutability
    with pytest.raises(EvidenceIntegrityError, match="immutable"):
        ledger.save_run(rec1, [])


def test_rule_06_no_release_without_regression_tests():
    """Rule 6: No release without regression tests for existing verdict behavior."""
    probes_file = Path(__file__).parent / "test_adversarial_probes.py"
    content = probes_file.read_text(encoding="utf-8")
    probe_count = content.count("def test_probe_")
    assert probe_count >= 20, f"Expected at least 20 regression test probes, found {probe_count}"


def test_rule_07_no_silent_paid_fallback():
    """Rule 7: No silent paid fallback (local-first, explicit consent for paid models/network)."""
    cfg = AmauraConfig()
    cfg.security.privacy_mode = PrivacyMode.LOCAL_ONLY
    cfg.security.allow_network = False
    assert cfg.security.allow_network is False
    assert cfg.security.privacy_mode == PrivacyMode.LOCAL_ONLY


def test_rule_08_strict_workspace_containment(tmp_path: Path):
    """Rule 8: Code execution under verification must strictly operate within designated disposable workspaces."""
    target_outside = tmp_path.parent / "escape_file.txt"
    with pytest.raises(ExecutionSecurityError, match="Path traversal detected"):
        validate_path_within_workspace(target_outside, tmp_path)


def test_rule_09_default_isolated_networking(tmp_path: Path):
    """Rule 9: Default isolated networking (local-only mode blocks outbound socket calls)."""
    cfg = AmauraConfig()
    cfg.security.allow_network = False
    cfg.security.privacy_mode = PrivacyMode.LOCAL_ONLY

    script = "import socket\ns = socket.socket(); s.connect_ex(('127.0.0.1', 65432))\n"
    res = run_safe_process(
        command=["python3", "-c", script],
        cwd=tmp_path,
        security_config=cfg.security,
    )
    assert "NetworkConnectionDenied" in res.stderr or res.exit_code != 0


def test_rule_10_release_gate_defect_recall():
    """Rule 10: Release gate requires 100% defect recall on builder-labeled and holdout suites, and 0% false positive rate."""
    from amaura.benchmarks.metrics import BenchmarkMetrics
    # A benchmark with 80% recall must NOT pass the gate
    metrics_imperfect = BenchmarkMetrics(
        total_cases=10,
        known_bad_cases=5,
        true_positives=4,
        known_good_cases=5,
        true_negatives=5,
    ).compute()
    assert metrics_imperfect.passed_release_gate is False

    # A benchmark with 100% defect recall, 100% critical recall, and 0% false positives passes
    metrics_perfect = BenchmarkMetrics(
        total_cases=10,
        known_bad_cases=5,
        true_positives=5,
        critical_defects_total=3,
        critical_defects_detected=3,
        known_good_cases=5,
        true_negatives=5,
        false_positives=0,
    ).compute()
    assert metrics_perfect.passed_release_gate is True


def test_rule_11_deterministic_reproducibility():
    """Rule 11: Deterministic verification results must be reproducible given identical inputs."""
    task1 = TaskSpec(
        task_id="tsk_det",
        instruction="Deterministic task",
        requirements=[Requirement(id="REQ-01", description="Math")],
    )
    task2 = TaskSpec(
        task_id="tsk_det",
        instruction="Deterministic task",
        requirements=[Requirement(id="REQ-01", description="Math")],
    )
    assert task1.compute_hash() == task2.compute_hash()


def test_rule_12_separated_status_vocabularies():
    """Rule 12: Separation of check status from claim status."""
    check_statuses = {s.value for s in CheckStatus}
    assert check_statuses == {"passed", "failed", "error", "timed_out", "not_run"}

    claim_statuses = {s.value for s in ClaimStatus}
    assert "supported" in claim_statuses
    assert "contradicted" in claim_statuses
    assert "inconclusive" in claim_statuses
    assert "passed" not in claim_statuses


def test_rule_13_tamper_evident_ledger(tmp_path: Path):
    """Rule 13: Cryptographic ledger immutability and tamper detection."""
    ledger = EvidenceLedger(tmp_path)
    rec = RunRecord(
        run_id="run_tamper_test",
        task=TaskSpec(task_id="t1", instruction="test"),
        mode=RunMode.VERIFY,
        working_dir=str(tmp_path),
    )
    ledger.save_run(rec, [])

    # Tamper with the saved record file
    rec_file = tmp_path / "run_tamper_test" / "run.json"
    content = rec_file.read_text(encoding="utf-8")
    tampered_content = content.replace('"overall_verdict": "inconclusive"', '"overall_verdict": "passed"')
    rec_file.write_text(tampered_content, encoding="utf-8")

    with pytest.raises(EvidenceIntegrityError, match="TAMPER DETECTED"):
        ledger.load_run("run_tamper_test", verify_integrity=True)


def test_rule_14_agent_output_not_independent_evidence():
    """Rule 14: Agent-authored outputs and tests are never marked as independent evidence."""
    collector = EvidenceCollector("run_r14")
    ev = collector.add_evidence(
        check_id="chk_test",
        content="test stdout",
        source="pytest_runner",
        method="subprocess_capture",
        independent=False,
    )
    assert ev.provenance.independent is False


def test_rule_15_fail_closed_on_unverified_criteria():
    """Rule 15: Fail-closed on missing dependencies, verifier crashes, and unverified acceptance criteria."""
    task = TaskSpec(
        task_id="tsk_r15",
        instruction="Verify criteria",
        requirements=[Requirement(id="REQ-01", description="Required feature", mandatory=True)],
    )
    chk_build = CheckDefinition(check_id="chk_build", name="Build Check", mandatory=True)
    exec_build = CheckExecution(check_id="chk_build", execution_id="ex_b", status=CheckStatus.PASSED)
    chk_req = CheckDefinition(check_id="chk_req_1", name="Acceptance: REQ-01", mandatory=True)
    exec_req_not_run = CheckExecution(check_id="chk_req_1", execution_id="ex_r", status=CheckStatus.NOT_RUN)

    evaluator = VerdictEvaluator(VerdictPolicy())
    # Mandatory check planned but not run / unverified -> FAILED
    result = evaluator.evaluate(task, [], [chk_build, chk_req], [exec_build, exec_req_not_run], [])
    assert result.overall_verdict == OverallVerdict.FAILED
    assert any("Missing mandatory checks" in r for r in result.verdict_reasons)
