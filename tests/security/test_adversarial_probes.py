"""Adversarial regression test suite validating defenses against evasions, leaks, and bypasses."""

import json
import os
from pathlib import Path

import pytest

from amaura.agents.registry import AgentRegistry
from amaura.config import AmauraConfig, VerificationPolicyConfig
from amaura.errors import AdapterError, EvidenceIntegrityError, VerificationError
from amaura.evidence.collector import EvidenceCollector
from amaura.evidence.ledger import EvidenceLedger
from amaura.models.check import CheckDefinition, CheckType
from amaura.models.claim import Claim, ClaimStatus, ClaimType
from amaura.models.run import OverallVerdict
from amaura.models.task import Requirement, TaskSpec
from amaura.orchestration.runner import verify_project
from amaura.security.process import run_safe_process
from amaura.verdicts.evaluator import VerdictEvaluator
from amaura.verdicts.policy import VerdictPolicy
from amaura.verifiers.code import CodeVerifier
from amaura.verifiers.registry import VerifierRegistry


def test_probe_conftest_exit_code_hijack(tmp_path: Path):
    """An untrusted repo hooks pytest_sessionfinish in conftest.py to force exitstatus=0.
    The verifier must parse JUnit XML directly and detect the failed test.
    """
    code_file = tmp_path / "calculator.py"
    code_file.write_text("def add(a, b):\n    return a + b + 99\n")

    test_file = tmp_path / "test_calculator.py"
    test_file.write_text(
        "from calculator import add\n\n"
        "def test_addition():\n"
        "    assert add(1, 2) == 3\n"
    )

    conftest_file = tmp_path / "conftest.py"
    conftest_file.write_text(
        "def pytest_sessionfinish(session, exitstatus):\n"
        "    # Hostile hijack attempting to turn failure into success\n"
        "    session.exitstatus = 0\n"
    )

    task_file = tmp_path / "task.md"
    task_file.write_text(
        "# Task: Calculator\n\n"
        "## Requirements\n"
        "- REQ-001: Addition works for positive integers\n"
    )

    record = verify_project(project_dir=tmp_path, task_file=task_file)
    assert record.overall_verdict == OverallVerdict.FAILED
    assert any(f.severity.value in ("critical", "high") for f in record.findings)


def test_probe_all_tests_skipped_gaming(tmp_path: Path):
    """An adversary marks all tests with @pytest.mark.skip to achieve exit code 0.
    The verifier must identify 100% skipped suite / test gaps and fail closed.
    """
    code_file = tmp_path / "service.py"
    code_file.write_text("def serve():\n    return True\n")

    test_file = tmp_path / "test_service.py"
    test_file.write_text(
        "import pytest\n\n"
        "@pytest.mark.skip(reason='bypass')\n"
        "def test_serve():\n"
        "    assert True\n"
    )

    task_file = tmp_path / "task.md"
    task_file.write_text(
        "# Task: Service\n\n"
        "## Requirements\n"
        "- REQ-001: Serve requests reliably\n"
    )

    record = verify_project(project_dir=tmp_path, task_file=task_file)
    assert record.overall_verdict in (OverallVerdict.FAILED, OverallVerdict.INCONCLUSIVE)
    assert any(f.finding_type.value in ("test_gap", "defect") for f in record.findings)


def test_probe_vacuous_assertions_detected(tmp_path: Path):
    """AST analyzer must detect tests that only use trivial assertions like assert True or 1 == 1."""
    test_file = tmp_path / "test_vacuous.py"
    test_file.write_text(
        "def test_trivial():\n"
        "    assert True\n"
        "    assert 1 == 1\n"
        "    assert 'apple' == 'apple'\n"
    )

    verifier = CodeVerifier()
    check = CheckDefinition(
        check_id="chk_quality",
        check_type=CheckType.TEST_QUALITY,
        verifier_name="code",
        name="Test Quality",
        description="Verify test quality via AST",
    )
    collector = EvidenceCollector("run_test")
    res = verifier._verify_test_quality(tmp_path, check, collector)

    assert res.execution.status.value == "failed"
    assert any("Vacuous Test Assertions Detected" in f.title for f in res.findings)


def test_probe_pytest_raises_accepted_as_valid_assertion(tmp_path: Path):
    """A test that tests exceptions via pytest.raises or self.assertRaises must NOT be flagged as vacuous."""
    test_file = tmp_path / "test_exception.py"
    test_file.write_text(
        "import pytest\n\n"
        "def test_division_by_zero():\n"
        "    with pytest.raises(ZeroDivisionError):\n"
        "        _ = 1 / 0\n"
    )

    verifier = CodeVerifier()
    check = CheckDefinition(
        check_id="chk_quality_raises",
        check_type=CheckType.TEST_QUALITY,
        verifier_name="code",
        name="Test Quality Raises",
        description="Verify pytest.raises handling",
    )
    collector = EvidenceCollector("run_test")
    res = verifier._verify_test_quality(tmp_path, check, collector)

    assert res.execution.status.value == "passed"
    assert len([f for f in res.findings if "Vacuous" in f.title]) == 0


def test_probe_keyword_gaming_subtraction_defeated(tmp_path: Path):
    """A project with tests named test_validate_inputs must not satisfy a subtraction requirement."""
    calc_file = tmp_path / "calc.py"
    calc_file.write_text("def add(a, b):\n    return a + b\n")

    test_file = tmp_path / "test_calc.py"
    test_file.write_text(
        "def test_validate_inputs():\n"
        "    assert 1 + 1 == 2\n"
    )

    task_file = tmp_path / "task.md"
    task_file.write_text(
        "# Task: Arithmetic\n\n"
        "## Requirements\n"
        "- REQ-001: Subtraction works for integers\n"
    )

    record = verify_project(project_dir=tmp_path, task_file=task_file)
    assert record.overall_verdict in (OverallVerdict.FAILED, OverallVerdict.INCONCLUSIVE)
    assert record.claims[0].status != ClaimStatus.SUPPORTED
    assert any("Untested Acceptance Requirement" in f.title for f in record.findings)


def test_probe_tampered_run_ledger_fails_integrity(tmp_path: Path):
    """If run.json or raw evidence files are tampered with, ledger.load_run must raise EvidenceIntegrityError."""
    runs_dir = tmp_path / "runs"
    ledger = EvidenceLedger(runs_dir)

    record = verify_project(
        project_dir=Path("examples/csv-import/version_a_correct"),
        task_file=Path("examples/csv-import/task.md"),
        config=AmauraConfig(runs_dir=str(runs_dir)),
    )
    run_id = record.run_id

    # 1. Clean load succeeds
    loaded = ledger.load_run(run_id)
    assert loaded.run_id == run_id

    # 2. Tampering with run.json fails hash verification
    run_json = runs_dir / run_id / "run.json"
    data = json.loads(run_json.read_text(encoding="utf-8"))
    data["overall_verdict"] = "failed"
    run_json.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(EvidenceIntegrityError):
        ledger.load_run(run_id)


def test_probe_tampered_evidence_file_fails_integrity(tmp_path: Path):
    """If a raw evidence file is tampered with, ledger.load_run must detect hash mismatch."""
    runs_dir = tmp_path / "runs"
    ledger = EvidenceLedger(runs_dir)

    record = verify_project(
        project_dir=Path("examples/csv-import/version_a_correct"),
        task_file=Path("examples/csv-import/task.md"),
        config=AmauraConfig(runs_dir=str(runs_dir)),
    )
    run_id = record.run_id

    # Tamper with an evidence file in evidence/
    evidence_dir = runs_dir / run_id / "evidence"
    evidence_files = list(evidence_dir.glob("*.txt"))
    assert len(evidence_files) > 0

    target = evidence_files[0]
    target.write_text("TAMPERED EVIDENCE CONTENT", encoding="utf-8")

    with pytest.raises(EvidenceIntegrityError):
        ledger.load_run(run_id)


def test_probe_environment_scrubbing_allowlist():
    """Secrets in parent environment must be scrubbed and not accessible to child process."""
    os.environ["DATABASE_URL"] = "postgres://admin:supersecretpassword@localhost:5432/db"
    os.environ["HF_TOKEN"] = "hf_0123456789abcdef0123456789abcdef"
    os.environ["SUPABASE_KEY"] = "sbp_secretkey1234567890abcdef"
    os.environ["RAZORPAY_KEY"] = "rzp_test_secret12345678"
    os.environ["CUSTOM_SECRET_KEY"] = "super_confidential_token"

    res = run_safe_process(
        command=[
            "python3",
            "-c",
            "import os; print('|'.join(str(os.environ.get(k)) for k in ['DATABASE_URL', 'HF_TOKEN', 'SUPABASE_KEY', 'RAZORPAY_KEY', 'CUSTOM_SECRET_KEY']))",
        ],
        cwd=Path.cwd(),
    )
    assert res.exit_code == 0
    assert res.stdout.strip() == "None|None|None|None|None"


def test_probe_evaluator_zero_checks_fail_closed():
    """An evaluation with zero checks must never return PASSED."""
    policy = VerdictPolicy(VerificationPolicyConfig())
    evaluator = VerdictEvaluator(policy)
    req = Requirement(id="REQ-01", description="Valid parsing", mandatory=True)
    task = TaskSpec(task_id="t1", instruction="Parse", requirements=[req]).freeze()
    claim = Claim(
        claim_id="clm_1",
        text="Everything works",
        claim_type=ClaimType.BEHAVIORAL,
        target_requirement_id="REQ-01",
    )
    result = evaluator.evaluate(
        task=task,
        claims=[claim],
        checks=[],
        executions=[],
        findings=[],
    )
    assert result.overall_verdict in (OverallVerdict.FAILED, OverallVerdict.INCONCLUSIVE)
    assert result.overall_verdict != OverallVerdict.PASSED


def test_probe_registry_unknown_entities_raise_errors():
    """Registries must fail-closed on unknown adapters or verifiers rather than fallback."""
    agent_reg = AgentRegistry()
    with pytest.raises(AdapterError):
        agent_reg.get("nonexistent_unknown_agent")

    verifier_reg = VerifierRegistry(config=AmauraConfig())
    with pytest.raises(VerificationError):
        verifier_reg.get("nonexistent_unknown_verifier")


def test_probe_task_spec_freeze_and_verify_hash():
    """TaskSpec tamper detection must detect mutations to requirements or criteria."""
    task = TaskSpec(
        task_id="t1",
        title="Test Task",
        instruction="Do something",
        requirements=[Requirement(id="REQ-1", description="Valid parsing")],
        acceptance_criteria=["Must pass tests"],
    )
    task.freeze()
    assert task.verify_hash() is True

    # Tamper with criteria
    task.acceptance_criteria.append("Tampered criteria")
    assert task.verify_hash() is False
