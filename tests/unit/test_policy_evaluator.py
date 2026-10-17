"""Unit tests for deterministic verdict evaluation and fail-closed rules."""

from amaura.config import VerificationPolicyConfig
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus
from amaura.models.claim import Claim, ClaimStatus
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.models.run import OverallVerdict
from amaura.models.task import Requirement, TaskSpec
from amaura.verdicts.evaluator import VerdictEvaluator
from amaura.verdicts.policy import VerdictPolicy


def test_evaluator_all_passed():
    policy = VerdictPolicy(VerificationPolicyConfig())
    evaluator = VerdictEvaluator(policy)

    req = Requirement(id="REQ-01", description="Valid parsing", mandatory=True)
    task = TaskSpec(task_id="t1", instruction="Parse", requirements=[req]).freeze()

    claim = Claim(claim_id="CLM-REQ-01", text="Satisfies REQ-01", target_requirement_id="REQ-01")
    check = CheckDefinition(check_id="chk_01", name="Acceptance", target_requirement_id="REQ-01", mandatory=True)
    execution = CheckExecution(execution_id="e1", check_id="chk_01", status=CheckStatus.PASSED)

    result = evaluator.evaluate(
        task=task,
        claims=[claim],
        checks=[check],
        executions=[execution],
        findings=[],
    )

    assert result.overall_verdict == OverallVerdict.PASSED
    assert result.updated_claims[0].status == ClaimStatus.SUPPORTED


def test_evaluator_fail_closed_on_mandatory_check():
    policy = VerdictPolicy(VerificationPolicyConfig())
    evaluator = VerdictEvaluator(policy)

    req = Requirement(id="REQ-01", description="Valid parsing", mandatory=True)
    task = TaskSpec(task_id="t1", instruction="Parse", requirements=[req]).freeze()

    claim = Claim(claim_id="CLM-REQ-01", text="Satisfies REQ-01", target_requirement_id="REQ-01")
    check = CheckDefinition(check_id="chk_01", name="Acceptance", target_requirement_id="REQ-01", mandatory=True)
    execution = CheckExecution(execution_id="e1", check_id="chk_01", status=CheckStatus.FAILED)

    result = evaluator.evaluate(
        task=task,
        claims=[claim],
        checks=[check],
        executions=[execution],
        findings=[],
    )

    assert result.overall_verdict == OverallVerdict.FAILED
    assert result.updated_claims[0].status == ClaimStatus.CONTRADICTED


def test_evaluator_cannot_override_critical_defect():
    policy = VerdictPolicy(VerificationPolicyConfig())
    evaluator = VerdictEvaluator(policy)

    req = Requirement(id="REQ-01", description="Valid parsing", mandatory=True)
    task = TaskSpec(task_id="t1", instruction="Parse", requirements=[req]).freeze()

    claim = Claim(claim_id="CLM-REQ-01", text="Satisfies REQ-01", target_requirement_id="REQ-01")
    check1 = CheckDefinition(check_id="chk_cosmetic", name="Cosmetic Lint", mandatory=False)
    check2 = CheckDefinition(check_id="chk_build", name="Build", mandatory=True)

    exec1 = CheckExecution(execution_id="e1", check_id="chk_cosmetic", status=CheckStatus.PASSED)
    exec2 = CheckExecution(execution_id="e2", check_id="chk_build", status=CheckStatus.PASSED)

    # But a critical blocking finding exists
    finding = Finding(
        finding_id="f1",
        check_id="chk_build",
        title="Unhandled Crash",
        description="Crash on malformed input",
        finding_type=FindingType.DEFECT,
        severity=FindingSeverity.CRITICAL,
        is_blocking=True,
    )

    result = evaluator.evaluate(
        task=task,
        claims=[claim],
        checks=[check1, check2],
        executions=[exec1, exec2],
        findings=[finding],
    )

    # Critical defect must fail the run despite cosmetic/build passing checks
    assert result.overall_verdict == OverallVerdict.FAILED
