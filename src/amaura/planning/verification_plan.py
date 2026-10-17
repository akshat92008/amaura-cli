"""Verification planner compiling requirements and claims into executable check suites."""

from pathlib import Path

from amaura.models.check import CheckDefinition, CheckType
from amaura.models.claim import Claim
from amaura.models.task import TaskSpec


class VerificationPlan:
    """Ordered set of verification checks configured for a target project."""

    def __init__(self, task: TaskSpec, claims: list[Claim] | None = None):
        self.task = task
        self.claims = claims or []
        self.checks: list[CheckDefinition] = []

    def plan_code_project_checks(self, project_dir: Path) -> list[CheckDefinition]:
        """Plans standard code verification checks: build/syntax, test execution, test quality/coverage,
        and task-specific acceptance tests.
        """
        checks: list[CheckDefinition] = []

        # 1. Build and Syntax Check
        checks.append(
            CheckDefinition(
                check_id="chk_build_syntax",
                name="Build & Syntax Validation",
                description="Verifies that all project source files parse and compile without syntax errors",
                check_type=CheckType.BUILD,
                verifier_name="code",
                mandatory=True,
                timeout_seconds=30,
            )
        )

        # 2. Existing Test Suite Execution Check
        checks.append(
            CheckDefinition(
                check_id="chk_test_suite",
                name="Project Test Suite Execution",
                description="Executes project unit and integration tests to verify functionality and prevent regressions",
                check_type=CheckType.TEST,
                verifier_name="code",
                mandatory=True,
                timeout_seconds=45,
            )
        )

        # 3. Test Quality and Coverage Gap Analysis
        checks.append(
            CheckDefinition(
                check_id="chk_test_quality",
                name="Test Quality & Requirement Coverage Analysis",
                description="Examines test AST for vacuous assertions (assert True), empty tests, skipped tests, and requirement coverage gaps",
                check_type=CheckType.TEST_QUALITY,
                verifier_name="code",
                mandatory=True,
                timeout_seconds=20,
            )
        )

        # 4. Map each task requirement to an explicit acceptance check
        for req in self.task.requirements:
            check_id = f"chk_req_{req.id.lower().replace('-', '_')}"
            checks.append(
                CheckDefinition(
                    check_id=check_id,
                    name=f"Acceptance: {req.id}",
                    description=f"Validates requirement satisfaction for: {req.description}",
                    check_type=CheckType.ACCEPTANCE_TEST,
                    verifier_name="code",
                    mandatory=req.mandatory,
                    timeout_seconds=30,
                    target_requirement_id=req.id,
                    target_claim_id=f"CLM-{req.id}",
                )
            )

        self.checks = checks
        return checks
