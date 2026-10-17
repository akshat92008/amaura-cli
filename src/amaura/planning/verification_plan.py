"""Verification planner compiling requirements, constraints, and claims into executable check suites."""

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

        # 4. Map each task requirement to an explicit acceptance check (D6: ensure unique check_ids)
        used_check_ids = {c.check_id for c in checks}
        for req in self.task.requirements:
            base_check_id = f"chk_req_{req.id.replace(' ', '_')}"
            check_id = base_check_id
            suffix = 1
            while check_id in used_check_ids:
                check_id = f"{base_check_id}_{suffix}"
                suffix += 1
            used_check_ids.add(check_id)

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

        return checks

    def plan_checks(self, project_dir: Path) -> list[CheckDefinition]:
        """Plans complete multi-verifier check suite across code, constraints, acceptance criteria,
        domain data, documents, calculations, and explicit claims.
        """
        checks: list[CheckDefinition] = []

        # 1. Base code checks
        checks.extend(self.plan_code_project_checks(project_dir))

        # 2. Enforce Task Constraints (A8)
        for idx, constraint in enumerate(self.task.constraints, start=1):
            check_id = f"chk_constraint_{idx:02d}"
            checks.append(
                CheckDefinition(
                    check_id=check_id,
                    name=f"Constraint: {constraint[:50]}",
                    description=f"Enforces task constraint: {constraint}",
                    check_type=CheckType.CONSTRAINT,
                    verifier_name="code",
                    mandatory=True,
                    timeout_seconds=30,
                    metadata={"constraint": constraint},
                )
            )

        # 3. Enforce Task Acceptance Criteria (A8)
        for idx, criterion in enumerate(self.task.acceptance_criteria, start=1):
            check_id = f"chk_criterion_{idx:02d}"
            checks.append(
                CheckDefinition(
                    check_id=check_id,
                    name=f"Acceptance Criterion: {criterion[:50]}",
                    description=f"Validates task acceptance criterion: {criterion}",
                    check_type=CheckType.ACCEPTANCE_TEST,
                    verifier_name="code",
                    mandatory=True,
                    timeout_seconds=30,
                )
            )

        # 4. Plan checks for Unmapped Claims (A11)
        # Any claim not mapped to a task requirement must be independently tested as a proposition
        covered_claim_ids = {c.target_claim_id for c in checks if c.target_claim_id}
        for claim in self.claims:
            if claim.claim_id not in covered_claim_ids:
                chk_id = f"chk_claim_{claim.claim_id.lower().replace('-', '_')}"
                verifier_name = "code"
                check_type = CheckType.ACCEPTANCE_TEST
                claim_lower = claim.text.lower()
                if any(w in claim_lower for w in ("csv", "column", "row", "data", "schema", "table")):
                    verifier_name = "data"
                    check_type = CheckType.SCHEMA_CHECK
                elif any(w in claim_lower for w in ("sum", "total", "average", "percentage", "recalculat", "math", "formula", "arithmetic")):
                    verifier_name = "calculations"
                    check_type = CheckType.RECALCULATION
                elif any(w in claim_lower for w in ("cite", "citation", "reference", "bibliography", "paper", "doi")):
                    verifier_name = "citations"
                    check_type = CheckType.CITATION_MATCH
                elif any(w in claim_lower for w in ("document", "readme", "section", "markdown", "report")):
                    verifier_name = "documents"
                    check_type = CheckType.DOC_CONSTRAINT
                elif any(w in claim_lower for w in ("seed", "reproducib", "experiment", "leakage", "training", "stochastic")):
                    verifier_name = "experiments"
                    check_type = CheckType.BENCHMARK

                checks.append(
                    CheckDefinition(
                        check_id=chk_id,
                        name=f"Proposition: {claim.claim_id}",
                        description=f"Independently validates proposition: {claim.text}",
                        check_type=check_type,
                        verifier_name=verifier_name,
                        mandatory=claim.importance == "critical",
                        timeout_seconds=30,
                        target_claim_id=claim.claim_id,
                    )
                )

        # 5. Multi-Domain Verifier Discovery (A13)
        # If project has CSV files and no schema check planned yet
        has_csv = any(project_dir.rglob("*.csv")) if project_dir.is_dir() else False
        if has_csv and not any(c.verifier_name == "data" for c in checks):
            checks.append(
                CheckDefinition(
                    check_id="chk_data_integrity",
                    name="Data Schema & Integrity Validation",
                    description="Independently verifies CSV and tabular files for schema conformance, parse errors, and duplicate rows",
                    check_type=CheckType.SCHEMA_CHECK,
                    verifier_name="data",
                    mandatory=False,
                    timeout_seconds=30,
                )
            )

        # If project has bib files or citation references and no citation check planned yet
        has_bib = any(project_dir.rglob("*.bib")) if project_dir.is_dir() else False
        if has_bib and not any(c.verifier_name == "citations" for c in checks):
            checks.append(
                CheckDefinition(
                    check_id="chk_citations_integrity",
                    name="Academic Citation Integrity",
                    description="Verifies that all in-text citations resolve to valid bibliography entries without placeholders",
                    check_type=CheckType.CITATION_MATCH,
                    verifier_name="citations",
                    mandatory=False,
                    timeout_seconds=30,
                )
            )

        self.checks = checks
        return checks
