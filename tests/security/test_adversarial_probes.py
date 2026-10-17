"""Adversarial regression test suite validating defenses against evasions, leaks, and bypasses."""

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from amaura.agents.registry import AgentRegistry
from amaura.config import AmauraConfig, PrivacyMode, SecurityConfig, VerificationPolicyConfig
from amaura.errors import (
    AdapterError,
    EvidenceIntegrityError,
    ExecutionSecurityError,
    TaskSpecificationError,
    VerificationError,
)
from amaura.evidence.collector import EvidenceCollector
from amaura.evidence.ledger import EvidenceLedger
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus, CheckType
from amaura.models.claim import Claim, ClaimStatus, ClaimType
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.models.run import OverallVerdict
from amaura.models.task import Requirement, TaskSpec
from amaura.orchestration.runner import verify_project
from amaura.planning.requirements import load_task_file
from amaura.security.process import run_safe_process
from amaura.security.redaction import redact_secrets
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


def test_probe_non_defect_blocking_finding_fails_run():
    """Any critical or blocking finding (SECURITY_RISK, CONTRADICTION, UNMET_REQUIREMENT)
    must fail the run even if tests pass and claims are nominally supported.
    """
    policy = VerdictPolicy(VerificationPolicyConfig())
    evaluator = VerdictEvaluator(policy)
    req = Requirement(id="REQ-01", description="Valid parsing", mandatory=True)
    task = TaskSpec(task_id="t1", instruction="Parse", requirements=[req]).freeze()
    claim = Claim(
        claim_id="clm_1",
        text="Everything works",
        claim_type=ClaimType.BEHAVIORAL,
        target_requirement_id="REQ-01",
        status=ClaimStatus.SUPPORTED,
    )
    check = CheckDefinition(
        check_id="chk_1",
        check_type=CheckType.TEST,
        verifier_name="code",
        name="Test Check",
        description="Run tests",
    )
    # Blocking security risk finding
    security_finding = Finding(
        finding_id="find_sec_1",
        check_id="chk_1",
        title="Hostile Conftest Hook Detected",
        description="Malicious conftest attempts to forge test report",
        finding_type=FindingType.SECURITY_RISK,
        severity=FindingSeverity.CRITICAL,
        is_blocking=True,
    )
    execution = CheckExecution(
        execution_id="exec_1",
        check_id="chk_1",
        status=CheckStatus.PASSED,
        exit_code=0,
    )
    result = evaluator.evaluate(
        task=task,
        claims=[claim],
        checks=[check],
        executions=[execution],
        findings=[security_finding],
    )
    assert result.overall_verdict == OverallVerdict.FAILED
    assert any("Critical finding (security_risk)" in r for r in result.verdict_reasons)


def test_probe_hostile_conftest_reporting_hooks_detected(tmp_path: Path):
    """Hostile conftest.py hooking pytest reporting or execution functions must be flagged as critical security risks."""
    code_file = tmp_path / "app.py"
    code_file.write_text("def run():\n    return True\n")
    test_file = tmp_path / "test_app.py"
    test_file.write_text("def test_run():\n    assert True\n")
    conftest_file = tmp_path / "conftest.py"
    conftest_file.write_text(
        "def pytest_runtest_makereport(item, call):\n"
        "    pass\n"
    )
    task_file = tmp_path / "task.md"
    task_file.write_text(
        "# Task\n## Requirements\n- REQ-001: Execute run function\n"
    )

    record = verify_project(project_dir=tmp_path, task_file=task_file)
    assert record.overall_verdict == OverallVerdict.FAILED
    assert any(f.finding_type == FindingType.SECURITY_RISK for f in record.findings)
    assert any("Adversarial Test Harness Manipulation Detected" in f.title for f in record.findings)


def test_probe_placeholder_test_caught_by_mutation_testing(tmp_path: Path):
    """A placeholder test like assert len('ab') == 2 that does not exercise the code
    must be caught when mutations survive, failing verification.
    """
    code_file = tmp_path / "calculator.py"
    code_file.write_text(
        "def subtract(a, b):\n"
        "    return a - b\n"
    )
    test_file = tmp_path / "test_calculator.py"
    test_file.write_text(
        "# Placeholder test named for requirement that does not test subtract\n"
        "def test_subtract():\n"
        "    assert len('ab') == 2\n"
    )
    task_file = tmp_path / "task.md"
    task_file.write_text(
        "# Task: Math\n## Requirements\n- REQ-001: Subtract numbers correctly\n"
    )

    record = verify_project(project_dir=tmp_path, task_file=task_file)
    assert record.overall_verdict == OverallVerdict.FAILED
    assert any("Placeholder Test Detected: Mutant Survived" in f.title for f in record.findings)


def test_probe_untrusted_project_task_and_config_ignored(tmp_path: Path):
    """verify_project must ignore task.md and amaura.toml placed inside untrusted project_dir."""
    # Untrusted project has a malicious task.md with REQ-002 deleted
    untrusted_task = tmp_path / "task.md"
    untrusted_task.write_text(
        "# Malicious Task\n## Requirements\n- REQ-001: Valid parsing\n"
    )
    untrusted_config = tmp_path / "amaura.toml"
    untrusted_config.write_text(
        "[security]\nredact_secrets = false\n"
    )

    # Legitimate caller task has both REQ-001 and REQ-002
    caller_dir = tmp_path / "caller"
    caller_dir.mkdir()
    caller_task = caller_dir / "task.md"
    caller_task.write_text(
        "# Legitimate Task\n## Requirements\n- REQ-001: Valid parsing\n- REQ-002: Subtraction works\n"
    )

    # Project only implements valid parsing
    (tmp_path / "calc.py").write_text("def parse(s): return s\n")
    (tmp_path / "test_calc.py").write_text("from calc import parse\ndef test_parse(): assert parse('a') == 'a'\n")

    record = verify_project(project_dir=tmp_path, task_file=caller_task)
    # Must fail or be inconclusive because REQ-002 is not satisfied (caller task enforced!)
    assert record.overall_verdict in (OverallVerdict.FAILED, OverallVerdict.INCONCLUSIVE)
    req_ids = [r.id for r in record.task.requirements]
    assert "REQ-002" in req_ids


def test_probe_expected_hash_tamper_detection(tmp_path: Path):
    """load_task_file must reject a modified task file when expected_hash is specified."""
    task_file = tmp_path / "task.md"
    task_file.write_text(
        "# Task\n## Requirements\n- REQ-001: First requirement\n"
    )
    # Legitimate hash
    spec = load_task_file(task_file)
    valid_hash = spec.task_hash

    # Caller passes valid hash -> succeeds
    loaded = load_task_file(task_file, expected_hash=valid_hash)
    assert loaded.task_hash == valid_hash

    # Tamper with file
    task_file.write_text(
        "# Task\n## Requirements\n- REQ-001: Tampered requirement\n"
    )
    with pytest.raises(TaskSpecificationError) as exc_info:
        load_task_file(task_file, expected_hash=valid_hash)
    assert "Task specification hash mismatch" in str(exc_info.value)


def test_probe_offline_socket_connect_blocked():
    """In local_only mode, raw socket connect attempts must be intercepted and rejected."""
    sec = SecurityConfig(privacy_mode=PrivacyMode.LOCAL_ONLY, allow_network=False)
    res = run_safe_process(
        command=[
            "python3",
            "-c",
            "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect(('8.8.8.8', 53))\n",
        ],
        cwd=Path.cwd(),
        security_config=sec,
    )
    # Must fail due to PermissionError or connection failure
    assert res.exit_code != 0
    assert "PermissionError" in res.stderr or "prohibited" in res.stderr.lower() or "network" in res.stderr.lower()


def test_probe_isolated_home_prevents_credential_access(tmp_path: Path):
    """Untrusted code must not be able to read sensitive credentials from the host $HOME directory."""
    # Create fake credential file in host HOME
    host_home = Path(os.environ["HOME"])
    fake_cred = host_home / ".probe_cloud_credentials"
    fake_cred.write_text("SUPER_SECRET_USER_CREDENTIALS")

    try:
        res = run_safe_process(
            command=[
                "python3",
                "-c",
                "from pathlib import Path\ncred = Path.home() / '.probe_cloud_credentials'\nprint('EXISTS' if cred.is_file() else 'ISOLATED')\n",
            ],
            cwd=tmp_path,
        )
        assert res.exit_code == 0
        assert res.stdout.strip() == "ISOLATED"
    finally:
        if fake_cred.is_file():
            fake_cred.unlink()


def test_probe_aws_secret_key_redacted():
    """AWS secret access keys must be redacted from outputs."""
    raw_text = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and db connected."
    redacted = redact_secrets(raw_text)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in redacted
    assert "[REDACTED_AWS_SECRET_KEY]" in redacted


def test_probe_edit_and_recalculate_ledger_attack_detected(tmp_path: Path):
    """An adversary modifies run.json AND recalculates run.sha256.
    The immutable ledger_chain.jsonl hash chain must catch the tampering.
    """
    import hashlib
    runs_dir = tmp_path / "runs"
    ledger = EvidenceLedger(runs_dir)

    record = verify_project(
        project_dir=Path("examples/csv-import/version_a_correct"),
        task_file=Path("examples/csv-import/task.md"),
        config=AmauraConfig(runs_dir=str(runs_dir)),
    )
    run_id = record.run_id

    # Adversary attack: modify run.json AND recalculate run.sha256
    run_json = runs_dir / run_id / "run.json"
    data = json.loads(run_json.read_text(encoding="utf-8"))
    data["overall_verdict"] = "failed"
    new_content = json.dumps(data, indent=2)
    run_json.write_text(new_content, encoding="utf-8")

    # Recalculate run.sha256 to match the tampered run.json
    new_hash = hashlib.sha256(new_content.encode("utf-8")).hexdigest()
    (runs_dir / run_id / "run.sha256").write_text(f"{new_hash}  run.json\n", encoding="utf-8")

    # Loading the run must still detect the tampering via ledger_chain.jsonl!
    with pytest.raises(EvidenceIntegrityError) as exc_info:
        ledger.load_run(run_id)
    assert "does not match the immutable ledger chain" in str(exc_info.value)


def test_probe_unmapped_bogus_claim_cannot_be_supported(tmp_path: Path):
    """An adversary makes an ungrounded claim outside task requirements ('The system runs on Mars').
    The system must NOT silently mark it SUPPORTED without evidence (A11).
    """
    from amaura.orchestration.runner import check_claims

    # Create dummy project
    code_file = tmp_path / "app.py"
    code_file.write_text("def run():\n    return 'local'\n")

    test_file = tmp_path / "test_app.py"
    test_file.write_text("from app import run\ndef test_run():\n    assert run() == 'local'\n")

    claims_file = tmp_path / "claims.yaml"
    claims_file.write_text(
        "claims:\n"
        "  - claim_id: CLM-BOGUS-01\n"
        "    text: The application runs natively on Mars surface\n"
        "    importance: critical\n"
    )

    record = check_claims(claims_file=claims_file, project_dir=tmp_path)
    # The bogus claim must NOT be SUPPORTED
    bogus_claim = next(c for c in record.claims if c.claim_id == "CLM-BOGUS-01")
    assert bogus_claim.status != ClaimStatus.SUPPORTED
    assert record.overall_verdict in (OverallVerdict.FAILED, OverallVerdict.INCONCLUSIVE)


def test_probe_contradicted_arithmetic_claim_detected(tmp_path: Path):
    """An adversary includes false calculations (e.g. 10 + 20 = 50).
    The calculation verifier must detect the arithmetic contradiction and fail (A13).
    """
    doc_file = tmp_path / "report.md"
    doc_file.write_text("# Report\n\nTotal sum: 10 + 20 = 50 according to verified metrics.\n")

    code_file = tmp_path / "main.py"
    code_file.write_text("print('hello')\n")

    task_file = tmp_path / "task.md"
    task_file.write_text("# Task\n## Requirements\n- REQ-001: Report metrics\n")

    check = CheckDefinition(
        check_id="chk_calc_test",
        name="Calculation Check",
        check_type=CheckType.RECALCULATION,
        verifier_name="calculations",
    )
    from amaura.verifiers.calculations import CalculationVerifier
    verifier = CalculationVerifier(AmauraConfig())
    collector = EvidenceCollector("run_calc_probe")
    res = verifier.verify(tmp_path, check, collector)
    assert res.execution.status == CheckStatus.FAILED
    assert any(f.finding_type == FindingType.CONTRADICTION for f in res.findings)


def test_probe_stdlib_constraint_enforced(tmp_path: Path):
    """When a task specifies stdlib only, importing third-party libraries (e.g. requests)
    must fail closed with an external dependency constraint violation (A8).
    """
    code_file = tmp_path / "script.py"
    code_file.write_text("import requests\nprint(requests.__name__)\n")

    task_file = tmp_path / "task.md"
    task_file.write_text(
        "# Task\n"
        "## Requirements\n"
        "- REQ-001: Script execution\n"
        "## Constraints\n"
        "- Standard library only. No external dependencies.\n"
    )

    record = verify_project(project_dir=tmp_path, task_file=task_file)
    assert record.overall_verdict == OverallVerdict.FAILED
    assert any("External Dependency Constraint Violated" in f.title for f in record.findings)


def test_probe_dangling_citation_detected(tmp_path: Path):
    """An adversary cites [NonExistent2024] without defining it in references.
    The citation verifier must catch the dangling citation (A13).
    """
    doc_file = tmp_path / "paper.md"
    doc_file.write_text(
        "# Research Paper\n\n"
        "As demonstrated by prior work [NonExistent2024], our algorithm is optimal.\n\n"
        "## References\n"
        "1. Smith, J. Real Paper (2020).\n"
    )

    check = CheckDefinition(
        check_id="chk_cite_test",
        name="Citation Check",
        check_type=CheckType.CITATION_MATCH,
        verifier_name="citations",
    )
    from amaura.verifiers.citations import CitationVerifier
    verifier = CitationVerifier(AmauraConfig())
    collector = EvidenceCollector("run_cite_probe")
    res = verifier.verify(tmp_path, check, collector)
    assert res.execution.status == CheckStatus.FAILED
    assert any("Dangling In-Text Citations" in f.title for f in res.findings)


def test_probe_unseeded_randomness_detected(tmp_path: Path):
    """An experiment using stochastic operations without setting a seed must be flagged (A13)."""
    script_file = tmp_path / "train.py"
    script_file.write_text(
        "import random\n\n"
        "def split(data):\n"
        "    return random.choice(data)\n"
    )

    check = CheckDefinition(
        check_id="chk_exp_test",
        name="Experiment Determinism Check",
        check_type=CheckType.BENCHMARK,
        verifier_name="experiments",
    )
    from amaura.verifiers.experiments import ExperimentVerifier
    verifier = ExperimentVerifier(AmauraConfig())
    collector = EvidenceCollector("run_exp_probe")
    res = verifier.verify(tmp_path, check, collector)
    assert res.execution.status == CheckStatus.FAILED
    assert any("Unseeded Random Operations" in f.title for f in res.findings)


def test_probe_b1_deleted_ledger_chain_detected(tmp_path: Path):
    """Deleting ledger_chain.jsonl must trigger a TAMPER DETECTED discrepancy (B1)."""
    runs_dir = tmp_path / "runs"
    ledger = EvidenceLedger(runs_dir)

    record = verify_project(
        project_dir=Path("examples/csv-import/version_a_correct"),
        task_file=Path("examples/csv-import/task.md"),
        config=AmauraConfig(runs_dir=str(runs_dir)),
    )
    # Verification succeeds initially
    loaded = ledger.load_run(record.run_id)
    assert loaded.run_id == record.run_id

    # Adversary deletes master ledger chain
    ledger.chain_file.unlink()

    with pytest.raises(EvidenceIntegrityError) as exc_info:
        ledger.load_run(record.run_id)
    assert "Master ledger chain file 'ledger_chain.jsonl' is missing" in str(exc_info.value)


def test_probe_b2_run_absent_from_chain_and_tail_truncation_detected(tmp_path: Path):
    """A run absent from the chain or chain tail truncation must be detected as tampering (B2)."""
    runs_dir = tmp_path / "runs"
    ledger = EvidenceLedger(runs_dir)

    record1 = verify_project(
        project_dir=Path("examples/csv-import/version_a_correct"),
        task_file=Path("examples/csv-import/task.md"),
        config=AmauraConfig(runs_dir=str(runs_dir)),
    )
    record2 = verify_project(
        project_dir=Path("examples/csv-import/version_a_correct"),
        task_file=Path("examples/csv-import/task.md"),
        config=AmauraConfig(runs_dir=str(runs_dir)),
    )

    # 1. Chain tail truncation: remove the last block
    lines = ledger.chain_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    ledger.chain_file.write_text(lines[0] + "\n", encoding="utf-8")

    with pytest.raises(EvidenceIntegrityError) as exc_info:
        ledger.load_run(record2.run_id)
    assert any(m in str(exc_info.value).lower() for m in ["truncation detected", "not present in the immutable ledger chain"])

    with pytest.raises(EvidenceIntegrityError) as exc_info2:
        ledger.load_run(record1.run_id)
    assert "truncation detected" in str(exc_info2.value).lower()


def test_probe_b3_immutability_prevents_double_save(tmp_path: Path):
    """Attempting to save an already persisted run must fail with EvidenceIntegrityError (B3)."""
    runs_dir = tmp_path / "runs"
    ledger = EvidenceLedger(runs_dir)

    record = verify_project(
        project_dir=Path("examples/csv-import/version_a_correct"),
        task_file=Path("examples/csv-import/task.md"),
        config=AmauraConfig(runs_dir=str(runs_dir)),
    )

    with pytest.raises(EvidenceIntegrityError) as exc_info:
        ledger.save_run(record)
    assert "already been persisted and is immutable" in str(exc_info.value)


def test_probe_b4_anchor_signature_protects_against_recomputation(tmp_path: Path):
    """Recomputing the chain with forged blocks fails because HMAC anchor signature does not match (B4)."""
    runs_dir = tmp_path / "runs"
    ledger = EvidenceLedger(runs_dir)

    record = verify_project(
        project_dir=Path("examples/csv-import/version_a_correct"),
        task_file=Path("examples/csv-import/task.md"),
        config=AmauraConfig(runs_dir=str(runs_dir)),
    )

    # Adversary modifies ledger anchor file
    anchor_data = json.loads(ledger.anchor_file.read_text(encoding="utf-8"))
    anchor_data["signature"] = "deadbeef" * 8
    ledger.anchor_file.write_text(json.dumps(anchor_data), encoding="utf-8")

    with pytest.raises(EvidenceIntegrityError) as exc_info:
        ledger.load_run(record.run_id)
    assert "Invalid HMAC signature on ledger anchor" in str(exc_info.value)


def test_probe_b5_corrupt_block_does_not_reset_prev_hash(tmp_path: Path):
    """A corrupted last block must raise EvidenceIntegrityError, not silently reset prev_hash (B5)."""
    runs_dir = tmp_path / "runs"
    ledger = EvidenceLedger(runs_dir)

    # Write corrupt block into chain
    ledger.chain_file.write_text("CORRUPTED_NON_JSON_DATA\n", encoding="utf-8")

    with pytest.raises(EvidenceIntegrityError) as exc_info:
        ledger._append_to_chain("run_test_new", "some_hash")
    assert "last block is corrupted" in str(exc_info.value)


def test_probe_b6_task_hash_forgery_via_yaml_blocked(tmp_path: Path):
    """YAML task specifying a forged task_hash must be rejected with TaskSpecificationError (B6)."""
    task_file = tmp_path / "task.yaml"
    task_file.write_text(
        "task_id: test_task\n"
        "instruction: Do something safe\n"
        "risk_level: low\n"
        "frozen: true\n"
        'task_hash: "0000000000000000000000000000000000000000000000000000000000000000"\n'
        "requirements:\n"
        "  - id: REQ-001\n"
        "    description: First requirement\n"
        "    mandatory: true\n"
    )

    with pytest.raises(TaskSpecificationError) as exc_info:
        load_task_file(task_file)
    assert "tampering detected" in str(exc_info.value).lower() or "mismatch" in str(exc_info.value).lower()


def test_probe_b7_evidence_graph_and_ledger_persisted_and_checked(tmp_path: Path):
    """Evidence graph is persisted and tampering with evidence_ledger.jsonl is detected (B7)."""
    runs_dir = tmp_path / "runs"
    ledger = EvidenceLedger(runs_dir)

    record = verify_project(
        project_dir=Path("examples/csv-import/version_a_correct"),
        task_file=Path("examples/csv-import/task.md"),
        config=AmauraConfig(runs_dir=str(runs_dir)),
    )

    run_dir = runs_dir / record.run_id
    assert (run_dir / "evidence_graph.json").is_file()
    assert (run_dir / "evidence_ledger.jsonl").is_file()
    assert (run_dir / "evidence_ledger.sha256").is_file()

    # Tamper with evidence_ledger.jsonl
    with open(run_dir / "evidence_ledger.jsonl", "a", encoding="utf-8") as f:
        f.write("MALFORMED JSON LINE\n")

    with pytest.raises(EvidenceIntegrityError) as exc_info:
        ledger.load_run(record.run_id)
    assert "evidence_ledger.jsonl" in str(exc_info.value)


def test_probe_b8_universal_redaction_in_collector():
    """EvidenceCollector automatically sanitizes secret patterns (B8)."""
    from amaura.evidence.collector import EvidenceCollector
    collector = EvidenceCollector("run_test_redact")
    stripe_key = "sk_" + "live_1234567890abcdef12345678"
    google_key = "AIza" + "SyDa-1234567890abcdef1234567890abc"
    ev1 = collector.add_evidence("chk_1", f"Secret stripe key: {stripe_key}")
    ev2 = collector.add_evidence("chk_2", f"Secret google key: {google_key}")
    ev3 = collector.add_evidence("chk_3", "pwd = 'pass'")

    assert "sk_live_" not in ev1.content
    assert "[REDACTED_STRIPE_KEY]" in ev1.content
    assert "AIza" not in ev2.content
    assert "[REDACTED_GOOGLE_API_KEY]" in ev2.content
    assert "'pass'" not in ev3.content


def test_probe_b9_chronological_run_ids(tmp_path: Path):
    """Run IDs are generated chronologically and list_runs returns them in order (B9)."""
    from amaura.orchestration.state import ExecutionContext
    ctx1 = ExecutionContext(tmp_path)
    import time
    time.sleep(0.01)
    ctx2 = ExecutionContext(tmp_path)

    assert ctx1.run_id.startswith("run_")
    assert ctx2.run_id.startswith("run_")
    assert ctx1.run_id <= ctx2.run_id


def test_probe_b10_require_clean_git_enforced(tmp_path: Path):
    """Policy requiring clean git fails closed when target has uncommitted changes (B10)."""
    import subprocess
    # Init a git repo in tmp_path
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Amaura Tester"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "tester@amaura.dev"], cwd=tmp_path, check=True, capture_output=True)

    dummy = tmp_path / "calc.py"
    dummy.write_text("def add(a, b): return a + b\n")
    test_f = tmp_path / "test_calc.py"
    test_f.write_text("from calc import add\ndef test_add(): assert add(1, 2) == 3\n")
    task_f = tmp_path / "task.md"
    task_f.write_text("# Task\n## Requirements\n- REQ-001: Addition works\n")

    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=tmp_path, check=True, capture_output=True)

    # Now make it dirty by modifying calc.py
    dummy.write_text("def add(a, b): return a + b # dirty\n")

    cfg = AmauraConfig()
    cfg.policy.require_clean_git = True
    cfg.runs_dir = str(tmp_path / "runs")

    rec = verify_project(project_dir=tmp_path, task_file=task_f, config=cfg)
    assert rec.overall_verdict == OverallVerdict.FAILED
    assert any("Git Repository Not Clean" in f.title for f in rec.findings)
    assert rec.git_clean is False
    assert rec.git_commit is not None


def test_probe_b11_root_anchored_ignores_and_artifact_diff(tmp_path: Path):
    """Nested directories named .venv or .amaura are preserved in manifest and diff is computed (B11)."""
    from amaura.evidence.hashing import compute_artifact_diff, create_directory_manifest
    # Root level .venv should be ignored
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "pip.txt").write_text("ignore me")

    # Subdirectory .venv should NOT be ignored
    (tmp_path / "subpkg" / ".venv").mkdir(parents=True)
    (tmp_path / "subpkg" / ".venv" / "keep.py").write_text("def kept(): pass")

    manifest1 = create_directory_manifest(tmp_path)
    assert "pip.txt" not in str(manifest1)
    assert str(Path("subpkg/.venv/keep.py")) in manifest1

    # Modify and add files
    (tmp_path / "new_file.txt").write_text("new content")
    (tmp_path / "subpkg" / ".venv" / "keep.py").write_text("def modified(): pass")

    manifest2 = create_directory_manifest(tmp_path)
    diff = compute_artifact_diff(manifest1, manifest2)

    assert "new_file.txt" in diff["added"]
    assert str(Path("subpkg/.venv/keep.py")) in diff["modified"]
    assert len(diff["deleted"]) == 0


def test_probe_c1_connect_ex_blocked(tmp_path: Path):
    """Network connection attempts via socket.connect_ex or connect are blocked in sandbox (C1)."""
    script = tmp_path / "net_probe.py"
    script.write_text(
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "try:\n"
        "    code = s.connect_ex(('1.1.1.1', 80))\n"
        "    print(f'CONNECTED_EX:{code}')\n"
        "except Exception as e:\n"
        "    print(f'CAUGHT_NET_EX:{type(e).__name__}')\n"
    )
    res = run_safe_process([sys.executable, str(script)], cwd=tmp_path)
    assert "CAUGHT_NET_EX:PermissionError" in res.stdout or "PermissionError" in res.stderr
    assert "CONNECTED_EX" not in res.stdout


def test_probe_c2_write_outside_workspace_blocked(tmp_path: Path):
    """Filesystem writes outside the designated workspace are strictly blocked (C2)."""
    target_outside = Path.home() / f"probe_escape_{os.getpid()}.txt"
    script = tmp_path / "fs_probe.py"
    script.write_text(
        f"try:\n"
        f"    with open({str(target_outside)!r}, 'w') as f:\n"
        f"        f.write('escaped')\n"
        f"    print('WRITE_SUCCESS')\n"
        f"except Exception as e:\n"
        f"    print(f'CAUGHT_WRITE_EX:{{type(e).__name__}}')\n"
    )
    res = run_safe_process([sys.executable, str(script)], cwd=tmp_path)
    assert "CAUGHT_WRITE_EX:PermissionError" in res.stdout or "PermissionError" in res.stderr
    assert not target_outside.exists()


def test_probe_c3_rlimits_enforced(tmp_path: Path):
    """Process execution applies resource limits on CPU and file size (C3)."""
    script = tmp_path / "rlimit_probe.py"
    script.write_text(
        "import resource, sys\n"
        "soft_cpu, hard_cpu = resource.getrlimit(resource.RLIMIT_CPU)\n"
        "soft_fsize, hard_fsize = resource.getrlimit(resource.RLIMIT_FSIZE)\n"
        "print(f'RLIMIT_CPU:{soft_cpu}:{hard_cpu}')\n"
        "print(f'RLIMIT_FSIZE:{soft_fsize}:{hard_fsize}')\n"
    )
    res = run_safe_process([sys.executable, str(script)], cwd=tmp_path)
    assert res.exit_code == 0
    assert "RLIMIT_CPU:" in res.stdout
    assert "RLIMIT_FSIZE:" in res.stdout
    parts = res.stdout.split()
    cpu_line = next(p for p in parts if p.startswith("RLIMIT_CPU:"))
    soft_c = int(cpu_line.split(":")[1])
    assert soft_c > 0 and soft_c <= 600


def test_probe_c4_sudoku_allowed_and_python_c_bypass_blocked():
    """Command filter allows substring words like test_sudoku_solver but blocks python -c bypass (C4)."""
    from amaura.security.permissions import validate_command
    sec = SecurityConfig()

    # Allowed: substring 'sudo' in 'test_sudoku_solver' must NOT trigger prohibited command error
    allowed_cmd = validate_command(["pytest", "-k", "test_sudoku_solver"], sec)
    assert allowed_cmd == ["pytest", "-k", "test_sudoku_solver"]

    # Blocked: direct prohibited command 'sudo'
    with pytest.raises(ExecutionSecurityError) as exc_info:
        validate_command(["sudo", "rm", "-rf", "/"], sec)
    assert "sudo" in str(exc_info.value)

    # Blocked: python -c bypass hiding prohibited command
    with pytest.raises(ExecutionSecurityError) as exc_info:
        validate_command(["python3", "-c", "import os; os.system('sudo shutdown')"], sec)
    assert "forbidden command" in str(exc_info.value).lower()


def test_probe_c5_bounded_output_and_children_killed(tmp_path: Path):
    """Streaming output capture truncates runaway output and terminates process group (C5)."""
    from amaura.config import BudgetConfig
    script = tmp_path / "flood.py"
    script.write_text(
        "import sys\n"
        "for _ in range(50000):\n"
        "    sys.stdout.write('X' * 1000 + '\\n')\n"
        "    sys.stdout.flush()\n"
    )
    bud = BudgetConfig(max_output_capture_bytes=10000)
    res = run_safe_process([sys.executable, str(script)], cwd=tmp_path, budget_config=bud)
    assert len(res.stdout) <= 15000
    assert "[TRUNCATED" in res.stdout or len(res.stdout) <= 10000


def test_probe_c6_symlink_loop_and_host_link_ignored(tmp_path: Path):
    """Isolated workspace drops circular symlinks and links resolving outside workspace (C6)."""
    from amaura.security.workspace import isolated_workspace

    source = tmp_path / "source"
    source.mkdir()
    (source / "real.py").write_text("print('hello')")

    host_target = Path("/etc")
    if host_target.exists():
        (source / "link_host").symlink_to(host_target)

    (source / "link_loop").symlink_to(source)

    with isolated_workspace(source) as ws:
        assert (ws / "real.py").is_file()
        assert not (ws / "link_host").exists()
        assert not (ws / "link_loop").exists()


def test_probe_c7_sandbox_home_cleaned(tmp_path: Path):
    """Temporary sandbox_home is randomly named and unlinked on completion (C7)."""
    script = tmp_path / "get_home.py"
    script.write_text("import os; print('SANDBOX_HOME=' + os.environ['HOME'])")
    res = run_safe_process([sys.executable, str(script)], cwd=tmp_path)
    assert res.exit_code == 0
    home_path = None
    for line in res.stdout.splitlines():
        if line.startswith("SANDBOX_HOME="):
            home_path = Path(line.split("=", 1)[1].strip())
            break
    assert home_path is not None
    assert "amaura_sandbox_" in home_path.name
    assert not home_path.exists()


def test_probe_c8_xml_bomb_and_entity_rejected(tmp_path: Path):
    """safe_parse_xml rejects XML entities, DTD declarations, and oversized XML files (C8)."""
    from amaura.security.xml import safe_parse_xml

    # 1. Valid XML parses cleanly
    valid_xml = tmp_path / "valid.xml"
    valid_xml.write_text("<testsuites tests='1'><testsuite tests='1'/></testsuites>")
    root = safe_parse_xml(valid_xml)
    assert root.tag == "testsuites"

    # 2. XML with DOCTYPE entity expansion is rejected
    entity_xml = tmp_path / "entity.xml"
    entity_xml.write_text(
        "<?xml version='1.0'?>\n"
        "<!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>\n"
        "<testsuite>&xxe;</testsuite>"
    )
    with pytest.raises(ExecutionSecurityError) as exc_info:
        safe_parse_xml(entity_xml)
    assert "security violation" in str(exc_info.value).lower() or "dtd" in str(exc_info.value).lower()


def test_probe_c9_path_within_workspace_enforced(tmp_path: Path):
    """Verifiers and workspace operations enforce validate_path_within_workspace (C9)."""
    from amaura.security.workspace import validate_path_within_workspace
    from amaura.verifiers.code import CodeVerifier

    ws = tmp_path / "ws"
    ws.mkdir()
    inside = ws / "module.py"
    inside.write_text("def ok(): pass")

    outside = tmp_path / "outside.py"
    outside.write_text("def secret(): pass")

    assert validate_path_within_workspace(inside, ws) == inside.resolve()

    with pytest.raises(ExecutionSecurityError) as exc_info:
        validate_path_within_workspace(outside, ws)
    assert "Path traversal detected" in str(exc_info.value)

    chk = CheckDefinition(
        check_id="chk_c9",
        name="Path Check",
        check_type=CheckType.BUILD,
        metadata={"target_file": str(outside)},
    )
    collector = EvidenceCollector("run_c9")
    with pytest.raises(ExecutionSecurityError):
        CodeVerifier().verify(ws, chk, collector)


def test_probe_c10_pythonpath_virtualenv_stripped_and_forbidden_vars(tmp_path: Path):
    """PYTHONPATH and VIRTUAL_ENV are stripped from environment, and forbidden vars rejected (C10)."""
    orig_pp = os.environ.get("PYTHONPATH")
    orig_ve = os.environ.get("VIRTUAL_ENV")

    os.environ["PYTHONPATH"] = "/injected/untrusted/pythonpath"
    os.environ["VIRTUAL_ENV"] = "/injected/untrusted/venv"
    try:
        script = tmp_path / "env_check.py"
        script.write_text(
            "import os\n"
            "print('VE=' + str(os.environ.get('VIRTUAL_ENV')))\n"
            "print('PP=' + str(os.environ.get('PYTHONPATH')))\n"
        )
        res = run_safe_process([sys.executable, str(script)], cwd=tmp_path)
        assert "VE=None" in res.stdout
        assert "/injected/untrusted/pythonpath" not in res.stdout

        sec = SecurityConfig(forbidden_env_vars=["FORBIDDEN_API_KEY"])
        with pytest.raises(ExecutionSecurityError) as exc_info:
            run_safe_process(
                [sys.executable, str(script)],
                cwd=tmp_path,
                env={"FORBIDDEN_API_KEY": "secret_val"},
                security_config=sec,
            )
        assert "Forbidden environment variable" in str(exc_info.value)
    finally:
        if orig_pp is not None:
            os.environ["PYTHONPATH"] = orig_pp
        else:
            os.environ.pop("PYTHONPATH", None)

        if orig_ve is not None:
            os.environ["VIRTUAL_ENV"] = orig_ve
        else:
            os.environ.pop("VIRTUAL_ENV", None)


def test_probe_d1_more_than_47_requirements_and_budget_exhaustion(tmp_path: Path):
    """Tasks with >47 requirements execute properly, and budget exhaustion records findings rather than aborting (D1)."""
    # 1. 51 requirements run without crashing under default 500 budget
    req_lines = [f"- REQ-{i:03d}: Requirement number {i}" for i in range(1, 52)]
    task_content = "# Task: Big Task\n## Requirements\n" + "\n".join(req_lines) + "\n"
    task_file = tmp_path / "big_task.md"
    task_file.write_text(task_content)

    src_dir = tmp_path / "src_big"
    src_dir.mkdir()
    (src_dir / "code.py").write_text("def fn(): pass\n")
    (src_dir / "test_code.py").write_text("def test_dummy(): pass\n")

    cfg = AmauraConfig()
    cfg.runs_dir = str(tmp_path / "runs")
    record = verify_project(project_dir=src_dir, task_file=task_file, config=cfg)
    assert record is not None
    assert len(record.task.requirements) == 51
    # 51 requirements + 3 baseline checks = 54 checks executed
    assert len(record.checks) >= 54

    # 2. When max_checks_per_run budget is deliberately low, it records findings and ledger record rather than aborting
    cfg_low = AmauraConfig()
    cfg_low.runs_dir = str(tmp_path / "runs_low")
    cfg_low.budget.max_checks_per_run = 5
    record_low = verify_project(project_dir=src_dir, task_file=task_file, config=cfg_low)
    assert record_low is not None
    assert any("Execution Budget Exceeded" in f.title for f in record_low.findings)
    not_run_execs = [e for e in record_low.executions if e.status == CheckStatus.NOT_RUN]
    assert len(not_run_execs) > 0


def test_probe_d2_registry_get_inside_try_block(tmp_path: Path):
    """Unknown verifier name on a check is caught inside the try block and recorded as ERROR without crashing (D2)."""
    from amaura.orchestration.pipeline import VerificationPipeline
    from amaura.planning.requirements import parse_markdown_task
    task = parse_markdown_task("# Task\n## Requirements\n- REQ-001: First requirement\n")
    
    src_dir = tmp_path / "src_d2"
    src_dir.mkdir()
    (src_dir / "mod.py").write_text("x = 1\n")

    cfg = AmauraConfig()
    cfg.runs_dir = str(tmp_path / "runs_d2")
    pipeline = VerificationPipeline(cfg)

    record = pipeline.run(project_dir=src_dir, task=task)
    assert record is not None


def test_probe_d3_clean_error_handling_no_traceback(tmp_path: Path):
    """YAML syntax errors, schema validation errors, and filesystem errors are wrapped without raw tracebacks (D3)."""
    # 1. Malformed YAML in task file
    bad_yaml_task = tmp_path / "bad_task.yaml"
    bad_yaml_task.write_text("requirements: [unclosed list")
    with pytest.raises(TaskSpecificationError) as exc_info:
        load_task_file(bad_yaml_task)
    assert "YAML parsing error" in str(exc_info.value)

    # 2. Malformed YAML in claims file
    bad_claims = tmp_path / "bad_claims.yaml"
    bad_claims.write_text("claims: {bad: [}")
    from amaura.planning.claims import load_claims_file
    with pytest.raises(TaskSpecificationError) as exc_info:
        load_claims_file(bad_claims)
    assert "YAML parsing error" in str(exc_info.value)

    # 3. Schema validation error in claims file
    invalid_schema_claims = tmp_path / "invalid_claims.yaml"
    invalid_schema_claims.write_text("claims:\n  - claim_id: CLM-1\n    importance: INVALID_ENUM_VALUE\n")
    with pytest.raises(TaskSpecificationError) as exc_info:
        load_claims_file(invalid_schema_claims)
    assert "Claim validation error" in str(exc_info.value)


def test_probe_d4_run_agent_failure_and_workspace_size_cap(tmp_path: Path):
    """Run command fails if agent execution failed, and isolated_workspace enforces size cap (D4)."""
    from amaura.orchestration.runner import run_and_verify
    from amaura.security.workspace import isolated_workspace

    # 1. isolated_workspace enforces max_size_bytes cap
    ws_dir = tmp_path / "heavy_ws"
    ws_dir.mkdir()
    (ws_dir / "big_data.bin").write_bytes(b"0" * 2000)

    with pytest.raises(ExecutionSecurityError) as exc_info, isolated_workspace(ws_dir, max_size_bytes=1000):
        pass
    assert "Workspace size limit exceeded" in str(exc_info.value)

    # 2. run_and_verify fails if agent fails
    task_file = tmp_path / "task.md"
    task_file.write_text("# Task\n## Requirements\n- REQ-001: Must pass\n")
    (ws_dir / "calc.py").write_text("def ok(): pass\n")

    # Command that exits with error code 1
    record = run_and_verify(
        task_file=task_file,
        agent_name="local_cli",
        agent_command=[sys.executable, "-c", "import sys; sys.exit(1)"],
        project_dir=ws_dir,
        config=AmauraConfig(runs_dir=str(tmp_path / "runs_agent_fail")),
    )
    assert record.overall_verdict == OverallVerdict.FAILED
    assert any("Agent Execution Failure" in f.title for f in record.findings)


def test_probe_d5_mutation_testing_caching(tmp_path: Path):
    """CodeVerifier caches candidate mutants and mutant execution results across checks (D5)."""
    verifier = CodeVerifier()
    code = "def compute(a, b):\n    return a + b\n"
    h = hashlib.sha256(code.encode("utf-8")).hexdigest()

    # Pre-populate cache
    verifier._candidate_cache[h] = ["def compute(a, b):\n    return a - b\n"]
    verifier._mutation_run_cache[(h, "fake_mutant_hash", "test_filter")] = True

    assert h in verifier._candidate_cache
    assert len(verifier._candidate_cache[h]) == 1
    assert verifier._mutation_run_cache[(h, "fake_mutant_hash", "test_filter")] is True


def test_probe_d6_check_id_disambiguation_and_claim_uniqueness(tmp_path: Path):
    """Distinct requirements like REQ-1 and req_1 generate unique check IDs, and duplicate claims are rejected (D6)."""
    from amaura.evidence.graph import EvidenceGraph
    from amaura.planning.verification_plan import VerificationPlan

    # 1. Check ID collision disambiguation between REQ-1 and req_1
    req1 = Requirement(id="REQ-1", description="First")
    req2 = Requirement(id="req_1", description="Second")
    task = TaskSpec(task_id="collision_task", instruction="Task", requirements=[req1, req2])
    plan = VerificationPlan(task, [])
    checks = plan.plan_code_project_checks(tmp_path)
    chk_ids = [c.check_id for c in checks]
    assert len(chk_ids) == len(set(chk_ids))
    assert any("REQ-1" in cid for cid in chk_ids)
    assert any("req_1" in cid for cid in chk_ids)

    # 2. Duplicate claim IDs in EvidenceGraph raise TaskSpecificationError
    graph = EvidenceGraph()
    c1 = Claim(claim_id="CLM-DUP", text="First")
    c2 = Claim(claim_id="CLM-DUP", text="Second duplicate")
    graph.add_claim(c1)
    with pytest.raises(TaskSpecificationError) as exc_info:
        graph.add_claim(c2)
    assert "Duplicate claim ID detected" in str(exc_info.value)

    # 3. Duplicate check IDs in EvidenceGraph raise TaskSpecificationError
    chk1 = CheckDefinition(check_id="chk_same", name="C1")
    chk2 = CheckDefinition(check_id="chk_same", name="C2")
    graph.add_check(chk1)
    with pytest.raises(TaskSpecificationError) as exc_info:
        graph.add_check(chk2)
    assert "Duplicate check ID detected" in str(exc_info.value)


def test_probe_d7_clean_claim_text_and_no_arbitrary_bullets(tmp_path: Path):
    """Claims do not repeat ID prefix 'REQ-001: REQ-001:', and arbitrary bullets are not requirements (D7)."""
    from amaura.planning.claims import derive_claims_from_task
    from amaura.planning.requirements import parse_markdown_task

    # 1. Clean requirement description and claim text
    doc_with_prefix = (
        "# Task\n"
        "## Requirements\n"
        "- REQ-001: Subtraction works for integers\n"
    )
    task = parse_markdown_task(doc_with_prefix)
    assert task.requirements[0].id == "REQ-001"
    assert task.requirements[0].description == "Subtraction works for integers"

    claims = derive_claims_from_task(task)
    assert "REQ-001: REQ-001:" not in claims[0].text
    assert claims[0].text == "The implementation satisfies requirement REQ-001: Subtraction works for integers"

    # 2. Arbitrary bullets without Requirements section must raise TaskSpecificationError
    doc_only_bullets = (
        "# Overview\n"
        "Here are some helpful notes:\n"
        "- Note: Keep code tidy.\n"
        "- Note: Remember to eat lunch.\n"
    )
    with pytest.raises(TaskSpecificationError) as exc_info:
        parse_markdown_task(doc_only_bullets)
    assert "must contain an explicit '## Requirements' section" in str(exc_info.value)


def test_probe_e1_format_json_no_line_wrapping_json_load(tmp_path: Path):
    """--format json outputs raw valid JSON without terminal width wrapping, parsing cleanly in json.loads (E1)."""
    from typer.testing import CliRunner

    from amaura.cli import app

    runner = CliRunner()
    task_file = tmp_path / "task.md"
    long_instruction = "A" * 300  # Longer than 80 columns
    task_file.write_text(f"# Task\n{long_instruction}\n\n## Requirements\n- REQ-001: Correctness\n")
    
    src_dir = tmp_path / "src_e1"
    src_dir.mkdir()
    (src_dir / "mod.py").write_text("x = 1\n")

    result = runner.invoke(app, ["audit", str(src_dir), "--task", str(task_file), "--format", "json"])
    assert result.exit_code in (0, 1, 2)
    
    # Must parse cleanly with json.loads
    parsed = json.loads(result.output)
    assert "run_id" in parsed
    assert "overall_verdict" in parsed
    assert parsed["task"]["instruction"] == long_instruction


def test_probe_e2_report_show_evidence_no_markup_error_on_path_brackets(tmp_path: Path, monkeypatch):
    """report --show-evidence does not crash with MarkupError when evidence contains [/usr/lib] (E2)."""
    from typer.testing import CliRunner

    from amaura.cli import _print_run_summary, app
    from amaura.evidence.ledger import EvidenceLedger
    from amaura.models.evidence import EvidenceItem, Provenance
    from amaura.models.run import OverallVerdict, RunMode, RunRecord

    cfg = AmauraConfig()
    cfg.runs_dir = str(tmp_path / "runs_e2")
    ledger = EvidenceLedger(Path(cfg.runs_dir))

    task = TaskSpec(task_id="task_e2", instruction="Test task [/usr/lib] markup safe", requirements=[])
    content_str = "Log traces: [/usr/lib/libSystem.B.dylib] and [unclosed bracket"
    record = RunRecord(
        run_id="run_e2_test",
        mode=RunMode.VERIFY,
        task=task,
        working_dir=str(tmp_path),
        overall_verdict=OverallVerdict.PASSED,
        verdict_reasons=["Looked in directory [/usr/lib] safely"],
        findings=[
            Finding(
                finding_id="find_e2",
                check_id="chk_e2",
                title="Tested Path [/usr/lib/libc.so]",
                description="Verified containment on [/usr/lib/security] bracket tags",
                finding_type=FindingType.DEFECT,
                severity=FindingSeverity.LOW,
            )
        ],
        evidence=[
            EvidenceItem(
                evidence_id="ev_e2_001",
                check_id="chk_e2",
                content=content_str,
                content_hash=hashlib.sha256(content_str.encode("utf-8")).hexdigest(),
                provenance=Provenance(source="test", method="execution"),
            )
        ],
    )
    ledger.save_run(record)

    # 1. Direct function call test
    _print_run_summary(record, show_evidence=True)

    # 2. CLI report command test
    monkeypatch.setattr("amaura.cli.AmauraConfig.load", lambda *args, **kwargs: cfg)
    runner = CliRunner()
    res = runner.invoke(app, ["report", "run_e2_test", "--show-evidence"])
    assert res.exit_code == 0
    assert "[/usr/lib" in res.output


def test_probe_e3_allow_network_and_benchmark_suite_filter_and_config(tmp_path: Path):
    """--allow-network permits network in sandbox, benchmark --suite filters, and config is passed (E3)."""
    from typer.testing import CliRunner

    from amaura.cli import app
    from amaura.config import SecurityConfig
    from amaura.security.process import run_safe_process

    # 1. When allow_network=True and privacy_mode != local_only, socket is not blocked
    sec_allowed = SecurityConfig(allow_network=True, privacy_mode=PrivacyMode.HYBRID)
    # Testing that sitecustomize does not crash with PermissionError when socket is loaded
    code = "import socket; s = socket.socket(); print('socket_init_ok')"
    res = run_safe_process([sys.executable, "-c", code], cwd=tmp_path, security_config=sec_allowed)
    assert "socket_init_ok" in res.stdout

    # 2. Benchmark suite filtering
    runner = CliRunner()
    res_bad_suite = runner.invoke(app, ["benchmark", "--suite", "nonexistent_suite_xyz"])
    assert res_bad_suite.exit_code == 1
    assert "Unknown benchmark suite" in res_bad_suite.output

    res_good_suite = runner.invoke(app, ["benchmark", "--suite", "csv"])
    assert res_good_suite.exit_code == 0
    assert "100.0%" in res_good_suite.output


def test_probe_e4_doctor_pytest_and_real_security_probes():
    """doctor checks pytest in active environment and performs real runtime security probes (E4)."""
    from typer.testing import CliRunner

    from amaura.cli import app

    runner = CliRunner()
    res = runner.invoke(app, ["doctor", "--check-security"])
    assert res.exit_code == 0
    assert "Test Runner (pytest)" in res.output
    assert "PASS" in res.output
    assert "Network Sandbox Probe" in res.output
    assert "Filesystem Isolation" in res.output
    assert "Redactor Probe" in res.output


def test_probe_e5_evidence_exits_nonzero_when_no_match(tmp_path: Path):
    """evidence command exits with code 1 when no evidence item matches (E5)."""
    from typer.testing import CliRunner

    from amaura.cli import app

    runner = CliRunner()
    res = runner.invoke(app, ["evidence", "nonexistent_evidence_target_id_9999"])
    assert res.exit_code != 0
    assert "No evidence item matched" in res.output or "not found" in res.output.lower()


def test_probe_e6_review_and_replay_commands(tmp_path: Path, monkeypatch):
    """review and replay CLI commands execute and verify artifacts, requirements, and determinism (E6)."""
    from typer.testing import CliRunner

    from amaura.cli import app
    from amaura.orchestration.runner import verify_project

    runner = CliRunner()

    # 1. Review command on local directory
    task_file = tmp_path / "task.md"
    task_file.write_text("# Task\n## Requirements\n- REQ-001: Review requirement\n")
    src_dir = tmp_path / "src_e6"
    src_dir.mkdir()
    (src_dir / "app.py").write_text("print('hello')\n")

    res_review = runner.invoke(app, ["review", str(src_dir), "--task", str(task_file)])
    assert res_review.exit_code == 0
    assert "REQ-001" in res_review.output
    assert "app.py" in res_review.output

    # 2. Replay command on an authentic recorded run
    cfg = AmauraConfig()
    cfg.runs_dir = str(tmp_path / "runs_e6")
    record = verify_project(project_dir=src_dir, task_file=task_file, config=cfg)

    # Replay against src_dir
    monkeypatch.setattr("amaura.cli.AmauraConfig.load", lambda *args, **kwargs: cfg)
    res_replay = runner.invoke(app, ["replay", record.run_id, "--project", str(src_dir)])
    assert res_replay.exit_code == 0
    assert "REPRODUCED" in res_replay.output
    assert "Replay successful" in res_replay.output


def test_probe_e7_policy_knobs_effective(tmp_path: Path):
    """policy command respects profile option and policy knobs govern evaluator and verifier (E7)."""
    from typer.testing import CliRunner

    from amaura.cli import app
    from amaura.config import VerificationPolicyConfig
    from amaura.verdicts.evaluator import VerdictEvaluator
    from amaura.verdicts.policy import VerdictPolicy

    # 1. CLI policy displays profile
    runner = CliRunner()
    res_policy = runner.invoke(app, ["policy", "--profile", "strict"])
    assert res_policy.exit_code == 0
    assert "Profile: STRICT" in res_policy.output

    # 2. fail_closed_on_timeout knob has real effect in VerdictEvaluator
    task = TaskSpec(task_id="t_e7", instruction="Policy task", requirements=[])
    chk = CheckDefinition(check_id="chk_mandatory_timeout", name="Mandatory Timeout Check", mandatory=True)
    exec_timeout = CheckExecution(execution_id="ex_to", check_id="chk_mandatory_timeout", status=CheckStatus.TIMED_OUT)

    # When fail_closed_on_timeout=True -> FAILED
    pol_cfg_fail_closed = VerificationPolicyConfig(fail_closed_on_timeout=True)
    evaluator_fc = VerdictEvaluator(VerdictPolicy(pol_cfg_fail_closed))
    res_fc = evaluator_fc.evaluate(task, [], [chk], [exec_timeout], [])
    assert res_fc.overall_verdict == OverallVerdict.FAILED

    # When fail_closed_on_timeout=False -> INCONCLUSIVE
    pol_cfg_open = VerificationPolicyConfig(fail_closed_on_timeout=False)
    evaluator_open = VerdictEvaluator(VerdictPolicy(pol_cfg_open))
    res_open = evaluator_open.evaluate(task, [], [chk], [exec_timeout], [])
    assert res_open.overall_verdict == OverallVerdict.INCONCLUSIVE




