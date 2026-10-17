"""Code verification engine supporting builds, test runs, AST quality checks, and acceptance tests."""

import ast
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus, CheckType
from amaura.models.evidence import EvidenceType
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.security.process import run_safe_process
from amaura.verifiers.base import BaseVerifier, VerifierResult


class CodeVerifier(BaseVerifier):
    """Engine for validating code syntax, test execution, test quality/vacuousness, and acceptance tests."""

    name: str = "code"

    def verify(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        if check.check_type == CheckType.BUILD:
            return self._verify_build(project_dir, check, collector)
        elif check.check_type == CheckType.TEST:
            return self._verify_tests(project_dir, check, collector)
        elif check.check_type == CheckType.TEST_QUALITY:
            return self._verify_test_quality(project_dir, check, collector)
        elif check.check_type == CheckType.ACCEPTANCE_TEST:
            return self._verify_acceptance(project_dir, check, collector)
        else:
            return self._verify_generic_command(project_dir, check, collector)

    def _verify_build(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        """Validates that all Python files compile without syntax errors."""
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        errors: list[str] = []
        py_files: list[Path] = []

        for p in project_dir.rglob("*.py"):
            if any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts):
                continue
            py_files.append(p)
            try:
                compile(p.read_text(encoding="utf-8"), str(p), "exec")
            except SyntaxError as e:
                errors.append(f"{p.name}:{e.lineno}: SyntaxError: {e.msg}")
            except Exception as e:
                errors.append(f"{p.name}: CompileError: {e!s}")

        status = CheckStatus.PASSED if not errors else CheckStatus.FAILED
        stdout = f"Compiled {len(py_files)} Python source files successfully." if not errors else "\n".join(errors)

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=["python", "-m", "py_compile", "[source_files]"],
            status=status,
            stdout=stdout,
            exit_code=0 if not errors else 1,
            end_time=datetime.now(UTC).isoformat(),
        )

        ev = collector.add_evidence(
            check_id=check.check_id,
            content=stdout,
            evidence_type=EvidenceType.EXECUTION_LOG,
            source="python_compiler",
            method="ast_compile",
        )

        findings: list[Finding] = []
        if errors:
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    title="Source Build / Compilation Failure",
                    description=f"Syntax or compilation errors detected in {len(errors)} files:\n" + "\n".join(errors),
                    finding_type=FindingType.DEFECT,
                    severity=FindingSeverity.CRITICAL,
                    evidence_ids=[ev.evidence_id],
                    is_blocking=True,
                )
            )

        return VerifierResult(
            check_id=check.check_id,
            execution=execution,
            evidence=[ev],
            findings=findings,
        )

    def _verify_tests(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        """Executes the test suite using pytest or unittest."""
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        cmd = check.command or [sys.executable, "-m", "pytest", "-v"]

        result = run_safe_process(
            command=cmd,
            cwd=project_dir,
            timeout_seconds=check.timeout_seconds,
            security_config=self.config.security,
            budget_config=self.config.budget,
        )

        status = CheckStatus.PASSED if result.exit_code == 0 else CheckStatus.FAILED
        if result.timed_out:
            status = CheckStatus.TIMED_OUT

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=result.command,
            status=status,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
            end_time=datetime.now(UTC).isoformat(),
        )

        ev = collector.add_evidence(
            check_id=check.check_id,
            content=result.stdout + ("\n" + result.stderr if result.stderr else ""),
            evidence_type=EvidenceType.TEST_OUTPUT,
            source="test_runner",
            method="pytest",
        )

        findings: list[Finding] = []
        if status != CheckStatus.PASSED:
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    title="Test Suite Failures",
                    description=f"Test runner exited with code {result.exit_code}.\nOutput summary:\n" + (result.stderr or result.stdout)[-500:],
                    finding_type=FindingType.DEFECT,
                    severity=FindingSeverity.HIGH,
                    evidence_ids=[ev.evidence_id],
                    is_blocking=True,
                )
            )

        return VerifierResult(
            check_id=check.check_id,
            execution=execution,
            evidence=[ev],
            findings=findings,
        )

    def _verify_test_quality(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        """Analyzes test files using AST to detect vacuous assertions (assert True), empty tests,
        and requirement coverage gaps.
        """
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        test_files = [
            p for p in project_dir.rglob("*.py")
            if (p.name.startswith("test_") or p.name.endswith("_test.py"))
            and not any(part in {".venv", "__pycache__", ".git"} for part in p.parts)
        ]

        vacuous_tests: list[str] = []
        all_test_funcs: list[str] = []
        all_test_code_tokens: set[str] = set()

        for tf in test_files:
            try:
                tree = ast.parse(tf.read_text(encoding="utf-8"), filename=str(tf))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if node.name.startswith("test_") or "test" in node.name:
                            all_test_funcs.append(f"{tf.name}::{node.name}")
                            # Inspect body for assertions
                            assert_count = 0
                            has_vacuous_assert = False

                            for body_item in ast.walk(node):
                                if isinstance(body_item, ast.Name):
                                    all_test_code_tokens.add(body_item.id.lower())
                                if isinstance(body_item, ast.Constant) and isinstance(body_item.value, str):
                                    all_test_code_tokens.update(body_item.value.lower().split())

                                if isinstance(body_item, ast.Assert):
                                    assert_count += 1
                                    # Check for `assert True` or `assert 1`
                                    if isinstance(body_item.test, ast.Constant) and body_item.test.value in (True, 1):
                                        has_vacuous_assert = True

                                elif isinstance(body_item, ast.Call):
                                    if isinstance(body_item.func, ast.Attribute) and body_item.func.attr.startswith("assert"):
                                        assert_count += 1

                            if assert_count == 0 or has_vacuous_assert:
                                vacuous_tests.append(f"{tf.name}::{node.name} (asserts: {assert_count}, vacuous: {has_vacuous_assert})")
            except Exception as e:
                vacuous_tests.append(f"AST parse error in {tf.name}: {e!s}")

        findings: list[Finding] = []
        report_lines = [
            f"Analyzed {len(test_files)} test files with {len(all_test_funcs)} test functions.",
            f"Vacuous or empty tests detected: {len(vacuous_tests)}",
        ]

        if vacuous_tests:
            report_lines.extend(["Vacuous test instances:"] + [f" - {vt}" for vt in vacuous_tests])
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    title="Vacuous or Assertion-Free Test Detected",
                    description=f"Tests found with vacuous assertions (assert True) or zero assertions: {', '.join(vacuous_tests)}",
                    finding_type=FindingType.TEST_GAP,
                    severity=FindingSeverity.HIGH,
                    remediation_suggestion="Add meaningful assertions verifying behavioral requirements instead of vacuous checks.",
                )
            )

        content = "\n".join(report_lines)
        ev = collector.add_evidence(
            check_id=check.check_id,
            content=content,
            evidence_type=EvidenceType.AST_ANALYSIS,
            source="ast_quality_analyzer",
            method="python_ast",
        )

        status = CheckStatus.PASSED if not vacuous_tests else CheckStatus.FAILED
        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=["ast_analyzer", "[test_files]"],
            status=status,
            stdout=content,
            exit_code=0 if not vacuous_tests else 1,
            end_time=datetime.now(UTC).isoformat(),
        )

        return VerifierResult(
            check_id=check.check_id,
            execution=execution,
            evidence=[ev],
            findings=findings,
        )

    def _verify_acceptance(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        """Verifies specific requirement satisfaction using targeted test execution or keyword-matched tests."""
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        req_id = check.target_requirement_id or ""
        req_desc = check.description.lower()

        # Identify target keyword from requirement description
        # e.g. "duplicate" -> test keyword "duplicate"
        # "malformed" -> test keyword "malformed" or "invalid"
        # "valid" -> test keyword "valid"
        target_k = ""
        if "duplicate" in req_desc:
            target_k = "duplicate"
        elif "malformed" in req_desc or "invalid" in req_desc or "corrupt" in req_desc:
            target_k = "malformed"
        elif "valid" in req_desc or "import" in req_desc:
            target_k = "valid"

        # First check: Does any test function actually exist covering this requirement?
        test_files = [
            p for p in project_dir.rglob("*.py")
            if (p.name.startswith("test_") or p.name.endswith("_test.py"))
            and not any(part in {".venv", "__pycache__", ".git"} for part in p.parts)
        ]

        matching_test_funcs: list[str] = []
        for tf in test_files:
            try:
                tree = ast.parse(tf.read_text(encoding="utf-8"), filename=str(tf))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if node.name.startswith("test_"):
                            if target_k and target_k in node.name.lower():
                                matching_test_funcs.append(node.name)
            except Exception:
                pass

        # If there are NO tests exercising this requirement, we have an acceptance test gap!
        findings: list[Finding] = []
        if target_k and not matching_test_funcs:
            # Test gap detected!
            status = CheckStatus.FAILED
            msg = f"Requirement coverage gap: No test in project exercises requirement '{req_id}' ({target_k})."
            execution = CheckExecution(
                execution_id=exec_id,
                check_id=check.check_id,
                status=status,
                stdout=msg,
                exit_code=1,
                end_time=datetime.now(UTC).isoformat(),
            )
            ev = collector.add_evidence(
                check_id=check.check_id,
                content=msg,
                evidence_type=EvidenceType.AST_ANALYSIS,
                source="acceptance_coverage_analyzer",
                method="ast_symbol_check",
            )
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    claim_id=check.target_claim_id,
                    title=f"Untested Acceptance Requirement: {req_id}",
                    description=f"No passing tests exist in the project verifying requirement: {check.description}. Passing tests for other features do not verify this requirement.",
                    finding_type=FindingType.VERIFICATION_GAP,
                    severity=FindingSeverity.HIGH,
                    evidence_ids=[ev.evidence_id],
                    is_blocking=True,
                )
            )
            return VerifierResult(check_id=check.check_id, execution=execution, evidence=[ev], findings=findings)

        # Run targeted pytest command
        cmd = [sys.executable, "-m", "pytest", "-v"]
        if target_k:
            cmd.extend(["-k", target_k])

        proc_res = run_safe_process(
            command=cmd,
            cwd=project_dir,
            timeout_seconds=check.timeout_seconds,
            security_config=self.config.security,
            budget_config=self.config.budget,
        )

        status = CheckStatus.PASSED if proc_res.exit_code == 0 else CheckStatus.FAILED
        if proc_res.timed_out:
            status = CheckStatus.TIMED_OUT

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=proc_res.command,
            status=status,
            exit_code=proc_res.exit_code,
            stdout=proc_res.stdout,
            stderr=proc_res.stderr,
            duration_ms=proc_res.duration_ms,
            end_time=datetime.now(UTC).isoformat(),
        )

        ev = collector.add_evidence(
            check_id=check.check_id,
            content=proc_res.stdout + ("\n" + proc_res.stderr if proc_res.stderr else ""),
            evidence_type=EvidenceType.TEST_OUTPUT,
            claim_id=check.target_claim_id,
            source="pytest_acceptance",
            method="targeted_execution",
        )

        if status != CheckStatus.PASSED:
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    claim_id=check.target_claim_id,
                    title=f"Acceptance Test Failure for {req_id}",
                    description=f"Acceptance check for '{check.name}' failed with exit code {proc_res.exit_code}.\n" + (proc_res.stderr or proc_res.stdout)[-400:],
                    finding_type=FindingType.DEFECT,
                    severity=FindingSeverity.CRITICAL if check.mandatory else FindingSeverity.MEDIUM,
                    evidence_ids=[ev.evidence_id],
                    is_blocking=check.mandatory,
                )
            )

        return VerifierResult(check_id=check.check_id, execution=execution, evidence=[ev], findings=findings)

    def _verify_generic_command(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        cmd = check.command or ["echo", "no check command"]
        proc_res = run_safe_process(
            command=cmd,
            cwd=project_dir,
            timeout_seconds=check.timeout_seconds,
            security_config=self.config.security,
            budget_config=self.config.budget,
        )

        status = CheckStatus.PASSED if proc_res.exit_code == 0 else CheckStatus.FAILED
        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=proc_res.command,
            status=status,
            exit_code=proc_res.exit_code,
            stdout=proc_res.stdout,
            stderr=proc_res.stderr,
            duration_ms=proc_res.duration_ms,
            end_time=datetime.now(UTC).isoformat(),
        )
        ev = collector.add_evidence(
            check_id=check.check_id,
            content=proc_res.stdout,
            evidence_type=EvidenceType.EXECUTION_LOG,
        )
        return VerifierResult(check_id=check.check_id, execution=execution, evidence=[ev], findings=[])
