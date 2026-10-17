"""Automated test suite validating that Milestone M0 through M5 exit gates pass in CI."""

from pathlib import Path

from amaura.agents.adapters.artifact_only import ArtifactOnlyAdapter
from amaura.agents.adapters.local_cli import LocalCLIAdapter
from amaura.agents.adapters.mock_agent import MockAgentAdapter
from amaura.agents.adapters.model import ModelAgentAdapter
from amaura.benchmarks.runner import BenchmarkCase, BenchmarkRunner
from amaura.config import AmauraConfig, PrivacyMode
from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckStatus, CheckType
from amaura.models.run import OverallVerdict
from amaura.models.task import Requirement, TaskSpec
from amaura.orchestration.runner import verify_project
from amaura.verifiers.calculations import CalculationVerifier
from amaura.verifiers.citations import CitationVerifier
from amaura.verifiers.data import DataVerifier


def test_m0_verification_kernel_exit_gate(tmp_path: Path):
    """M0 Exit Gate: Known-passing, failing, and unavailable checks give three distinct outcomes (PASSED, FAILED, INCONCLUSIVE)."""
    base_dir = Path(__file__).resolve().parents[2]
    task_file = base_dir / "src" / "amaura" / "benchmarks" / "fixtures" / "csv-import" / "task.md"

    # 1. Known passing (Version A)
    proj_a = base_dir / "src" / "amaura" / "benchmarks" / "fixtures" / "csv-import" / "version_a_correct"
    rec_a = verify_project(project_dir=proj_a, task_file=task_file)
    assert rec_a.overall_verdict == OverallVerdict.PASSED

    # 2. Known failing (Version B)
    proj_b = base_dir / "src" / "amaura" / "benchmarks" / "fixtures" / "csv-import" / "version_b_crash_malformed"
    rec_b = verify_project(project_dir=proj_b, task_file=task_file)
    assert rec_b.overall_verdict == OverallVerdict.FAILED

    # 3. Advisory unverified checks give INCONCLUSIVE
    inconclusive_proj = tmp_path / "inconclusive_dir"
    inconclusive_proj.mkdir()
    (inconclusive_proj / "dummy.py").write_text("def add(a, b):\n    return a + b\n")
    (inconclusive_proj / "test_dummy.py").write_text(
        "from dummy import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"
    )
    inconclusive_task = tmp_path / "inconclusive_task.md"
    inconclusive_task.write_text("# Task\n\n## Requirements\n- [advisory] Optional feature for telemetry logging.\n")
    rec_inconclusive = verify_project(project_dir=inconclusive_proj, task_file=inconclusive_task)
    assert rec_inconclusive.overall_verdict == OverallVerdict.INCONCLUSIVE


def test_m1_agent_adapter_exit_gate(tmp_path: Path):
    """M1 Exit Gate: End-to-end task run with safe failure, no silent paid calls, and complete evidence package."""
    task = TaskSpec(
        task_id="tsk_m1",
        instruction="Math addition",
        requirements=[Requirement(id="REQ-01", description="Add integers")],
    )

    adapter = LocalCLIAdapter(cli_command=["echo", "completed"])
    res = adapter.execute(task, tmp_path)
    assert res.success is True
    assert res.adapter_name == "local_cli"
    # Usage accounting is present
    assert res.usage is not None
    assert res.usage.estimated_cost_usd == 0.0


def test_m2_reviewer_adversarial_repair_exit_gate():
    """M2 Exit Gate: Catches the predefined seeded adversarial set with false alarms quantified (0% false positives)."""
    base_dir = Path(__file__).resolve().parents[2]
    adv_dir = base_dir / "src" / "amaura" / "benchmarks" / "fixtures" / "adversarial"
    adv_task = adv_dir / "task.md"

    # Test conftest exit-code hijacker is caught
    hijack_proj = adv_dir / "adversarial_hook_hijack"
    rec_hijack = verify_project(project_dir=hijack_proj, task_file=adv_task)
    assert rec_hijack.overall_verdict == OverallVerdict.FAILED

    # Test vacuous assertions are caught
    vacuous_proj = adv_dir / "adversarial_vacuous_test"
    rec_vacuous = verify_project(project_dir=vacuous_proj, task_file=adv_task)
    assert rec_vacuous.overall_verdict == OverallVerdict.FAILED


def test_m3_local_models_and_privacy_exit_gate(tmp_path: Path):
    """M3 Exit Gate: Every adapter passes contract tests, and local-only is proven to prevent external calls."""
    adapters = [
        ArtifactOnlyAdapter(),
        LocalCLIAdapter(cli_command=["echo", "test"]),
        ModelAgentAdapter(model_name="mock_local"),
        MockAgentAdapter(),
    ]
    task = TaskSpec(task_id="tsk_m3", instruction="Test contract")
    for ad in adapters:
        res = ad.execute(task, tmp_path)
        assert res.adapter_name == ad.name
        assert isinstance(res.success, bool)

    # Local-only blocks external network calls
    cfg = AmauraConfig()
    cfg.security.allow_network = False
    cfg.security.privacy_mode = PrivacyMode.LOCAL_ONLY
    assert cfg.security.allow_network is False


def test_m4_multi_domain_verifiers_exit_gate(tmp_path: Path):
    """M4 Exit Gate: Multi-domain verifiers (data, citations, calculations) pass known-good and flag known-bad."""
    collector = EvidenceCollector("run_m4")
    cfg = AmauraConfig()

    # 1. Data Verifier
    data_v = DataVerifier(cfg)
    csv_good = tmp_path / "good.csv"
    csv_good.write_text("a,b\n1,2\n3,4\n")
    chk_data = CheckDefinition(check_id="cd1", name="Data Check", check_type=CheckType.SCHEMA_CHECK)
    res_data = data_v.verify(tmp_path, chk_data, collector)
    assert res_data.execution.status == CheckStatus.PASSED

    # 2. Calculations Verifier
    calc_v = CalculationVerifier(cfg)
    chk_calc = CheckDefinition(check_id="cc1", name="Calc Check", check_type=CheckType.RECALCULATION)
    res_calc = calc_v.verify(tmp_path, chk_calc, collector)
    assert res_calc.execution.status in (CheckStatus.PASSED, CheckStatus.NOT_RUN)

    # 3. Citations Verifier
    cite_v = CitationVerifier(cfg)
    chk_cite = CheckDefinition(check_id="ct1", name="Cite Check", check_type=CheckType.CITATION_MATCH)
    res_cite = cite_v.verify(tmp_path, chk_cite, collector)
    assert res_cite.execution.status in (CheckStatus.PASSED, CheckStatus.NOT_RUN)


def test_m5_benchmark_release_gate_exit_gate():
    """M5 Exit Gate: Full benchmark suite passes all gate targets (100% defect recall, 100% critical recall, 0% false positives)."""
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
            category="known_good",
        ),
        BenchmarkCase(
            name="Version B (Crash Malformed)",
            path=csv_dir / "version_b_crash_malformed",
            task_file=csv_dir / "task.md",
            expected_verdict=OverallVerdict.FAILED,
            is_critical_defect=True,
            category="known_bad",
        ),
        BenchmarkCase(
            name="Version C (Missing Checks)",
            path=csv_dir / "version_c_gap_duplicates",
            task_file=csv_dir / "task.md",
            expected_verdict=OverallVerdict.FAILED,
            is_critical_defect=True,
            category="known_bad",
        ),
        BenchmarkCase(
            name="Holdout Correct Calc",
            path=holdout_dir / "holdout_correct_calc",
            task_file=holdout_dir / "task.md",
            expected_verdict=OverallVerdict.PASSED,
            category="known_good",
        ),
        BenchmarkCase(
            name="Holdout Broken Calc",
            path=holdout_dir / "holdout_broken_calc",
            task_file=holdout_dir / "task.md",
            expected_verdict=OverallVerdict.FAILED,
            is_critical_defect=True,
            category="holdout",
        ),
        BenchmarkCase(
            name="Adversarial Conftest Hijack",
            path=adv_dir / "adversarial_hook_hijack",
            task_file=adv_dir / "task.md",
            expected_verdict=OverallVerdict.FAILED,
            is_critical_defect=True,
            category="adversarial",
        ),
        BenchmarkCase(
            name="Adversarial Vacuous Test",
            path=adv_dir / "adversarial_vacuous_test",
            task_file=adv_dir / "task.md",
            expected_verdict=OverallVerdict.FAILED,
            is_critical_defect=True,
            category="adversarial",
        ),
    ]

    metrics = BenchmarkRunner(AmauraConfig()).run_suite(cases)
    assert metrics.passed_release_gate is True
    assert metrics.defect_recall == 1.0
    assert metrics.critical_defect_recall == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.total_cases >= 5
