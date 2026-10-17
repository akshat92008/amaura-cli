"""Adversarial regression test suite validating defenses against evasions, leaks, and bypasses."""

import json
import os
from pathlib import Path

import pytest

from amaura.agents.registry import AgentRegistry
from amaura.config import AmauraConfig, PrivacyMode, SecurityConfig, VerificationPolicyConfig
from amaura.errors import AdapterError, EvidenceIntegrityError, TaskSpecificationError, VerificationError
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

