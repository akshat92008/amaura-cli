"""Code verification engine supporting AST quality checks, independent JUnit parsing, and rigorous acceptance tests."""

import ast
import re
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus, CheckType
from amaura.models.evidence import EvidenceType
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.security.process import run_safe_process
from amaura.verifiers.base import BaseVerifier, VerifierResult


def is_trivial_constant(node: ast.AST) -> bool:
    """Checks if an AST expression is a trivial constant (e.g. True, False, 1, 0, 'string')."""
    return isinstance(node, ast.Constant)


def is_trivial_comparison(node: ast.AST) -> bool:
    """Checks if an AST expression is a trivial comparison (e.g. 1 == 1, 'a' == 'a', True == True)."""
    if isinstance(node, ast.Compare):
        if is_trivial_constant(node.left) and len(node.comparators) == 1 and is_trivial_constant(node.comparators[0]):
            try:
                # If literal values evaluate to equal
                if ast.literal_eval(node.left) == ast.literal_eval(node.comparators[0]):
                    return True
            except Exception:
                pass
    return False


def inspect_test_function_assertions(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[int, int, bool]:
    """Inspects a test function node for assertions, vacuous checks, pytest.raises, and skip decorators.
    Returns (valid_assert_count, vacuous_assert_count, is_skipped).
    """
    valid_asserts = 0
    vacuous_asserts = 0
    is_skipped = False

    # 1. Check decorators for skip markers
    for dec in func_node.decorator_list:
        dec_name = ""
        if isinstance(dec, ast.Name):
            dec_name = dec.id
        elif isinstance(dec, ast.Attribute):
            dec_name = dec.attr
        elif isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Attribute):
                dec_name = dec.func.attr
            elif isinstance(dec.func, ast.Name):
                dec_name = dec.func.id

        if "skip" in dec_name.lower():
            is_skipped = True

    # 2. Walk AST for assertion constructs
    for node in ast.walk(func_node):
        # assert statement
        if isinstance(node, ast.Assert):
            if is_trivial_constant(node.test) or is_trivial_comparison(node.test):
                vacuous_asserts += 1
            else:
                valid_asserts += 1

        # pytest.raises / self.assertRaises inside with blocks
        elif isinstance(node, ast.With):
            for item in node.items:
                ctx_expr = item.context_expr
                if isinstance(ctx_expr, ast.Call):
                    func_str = ""
                    if isinstance(ctx_expr.func, ast.Attribute):
                        func_str = ctx_expr.func.attr
                    elif isinstance(ctx_expr.func, ast.Name):
                        func_str = ctx_expr.func.id

                    if func_str in ("raises", "warns", "assertRaises", "assertWarns"):
                        valid_asserts += 1

        # self.assert* call
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr.startswith("assert") and node.func.attr != "assert_":
                    valid_asserts += 1

    return valid_asserts, vacuous_asserts, is_skipped


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
        """Validates that all Python files compile without syntax errors. Fails if no source files found."""
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

        findings: list[Finding] = []
        if not py_files:
            status = CheckStatus.FAILED
            stdout = "No Python source files found in project."
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    title="Empty Project",
                    description="No Python source files (.py) exist in the project directory to compile.",
                    finding_type=FindingType.DEFECT,
                    severity=FindingSeverity.CRITICAL,
                    is_blocking=True,
                )
            )
        elif errors:
            status = CheckStatus.FAILED
            stdout = "\n".join(errors)
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    title="Source Build / Compilation Failure",
                    description=f"Syntax or compilation errors detected in {len(errors)} files:\n" + stdout,
                    finding_type=FindingType.DEFECT,
                    severity=FindingSeverity.CRITICAL,
                    is_blocking=True,
                )
            )
        else:
            status = CheckStatus.PASSED
            stdout = f"Compiled {len(py_files)} Python source files successfully."

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=["python", "-m", "py_compile", "[source_files]"],
            status=status,
            stdout=stdout,
            exit_code=0 if status == CheckStatus.PASSED else 1,
            end_time=datetime.now(UTC).isoformat(),
        )

        ev = collector.add_evidence(
            check_id=check.check_id,
            content=stdout,
            evidence_type=EvidenceType.EXECUTION_LOG,
            source="python_compiler",
            method="ast_compile",
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
        """Executes test suite and parses JUnit XML independently to defeat conftest exit-code manipulation."""
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        findings: list[Finding] = []

        with tempfile.TemporaryDirectory() as tmp_dir:
            junit_xml = Path(tmp_dir) / "junit_report.xml"

            # Execute pytest writing machine-readable JUnit XML report
            cmd = [
                sys.executable,
                "-m",
                "pytest",
                "-v",
                f"--junitxml={junit_xml}",
                "-o",
                "addopts=",
            ]

            proc_res = run_safe_process(
                command=cmd,
                cwd=project_dir,
                timeout_seconds=check.timeout_seconds,
                security_config=self.config.security,
                budget_config=self.config.budget,
            )

            # Parse JUnit XML directly to obtain objective test counts
            total_tests = 0
            failures = 0
            errors = 0
            skipped = 0
            xml_parsed = False

            if junit_xml.is_file():
                try:
                    tree = ET.parse(junit_xml)
                    root = tree.getroot()
                    # Root can be <testsuites> or <testsuite>
                    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
                    for s in suites:
                        total_tests += int(s.attrib.get("tests", 0))
                        failures += int(s.attrib.get("failures", 0))
                        errors += int(s.attrib.get("errors", 0))
                        skipped += int(s.attrib.get("skipped", 0))
                    xml_parsed = True
                except Exception:
                    pass

            # Evaluate objective test status
            status = CheckStatus.PASSED
            summary_reasons = []

            if proc_res.timed_out:
                status = CheckStatus.TIMED_OUT
                summary_reasons.append("Test runner timed out.")
            elif not xml_parsed and proc_res.exit_code != 0:
                status = CheckStatus.FAILED
                summary_reasons.append(f"Test runner exited with code {proc_res.exit_code}.")
            elif xml_parsed:
                if total_tests == 0:
                    status = CheckStatus.FAILED
                    summary_reasons.append("No tests were discovered or executed.")
                elif failures > 0 or errors > 0:
                    status = CheckStatus.FAILED
                    summary_reasons.append(f"Observed {failures} failure(s) and {errors} error(s) in test suite.")
                elif skipped == total_tests:
                    status = CheckStatus.FAILED
                    summary_reasons.append(f"All {total_tests} test(s) were skipped. Zero active tests ran.")
                elif proc_res.exit_code != 0:
                    status = CheckStatus.FAILED
                    summary_reasons.append(f"Process exited with code {proc_res.exit_code}.")
            elif proc_res.exit_code != 0:
                status = CheckStatus.FAILED
                summary_reasons.append(f"Test runner exited with code {proc_res.exit_code}.")

            stdout = proc_res.stdout
            if summary_reasons:
                stdout += "\n" + "\n".join(summary_reasons)

            execution = CheckExecution(
                execution_id=exec_id,
                check_id=check.check_id,
                command=proc_res.command,
                status=status,
                exit_code=proc_res.exit_code if status == CheckStatus.PASSED else (proc_res.exit_code or 1),
                stdout=stdout,
                stderr=proc_res.stderr,
                duration_ms=proc_res.duration_ms,
                end_time=datetime.now(UTC).isoformat(),
            )

            ev = collector.add_evidence(
                check_id=check.check_id,
                content=stdout + ("\n" + proc_res.stderr if proc_res.stderr else ""),
                evidence_type=EvidenceType.TEST_OUTPUT,
                source="test_runner",
                method="pytest_junit_xml",
            )

            if status != CheckStatus.PASSED:
                findings.append(
                    Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:8]}",
                        check_id=check.check_id,
                        title="Test Suite Execution Failure",
                        description="; ".join(summary_reasons) if summary_reasons else "Test suite failed.",
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
        """Analyzes test files using AST to detect vacuous assertions (assert True, 1==1), empty tests,
        and skipped tests. Properly recognizes pytest.raises and self.assertRaises.
        """
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        test_files = [
            p for p in project_dir.rglob("*.py")
            if (p.name.startswith("test_") or p.name.endswith("_test.py"))
            and not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts)
        ]

        vacuous_tests: list[str] = []
        skipped_tests: list[str] = []
        total_test_functions = 0

        for tf in test_files:
            try:
                tree = ast.parse(tf.read_text(encoding="utf-8"), filename=str(tf))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        # Only inspect actual test functions, not helper functions
                        if node.name.startswith("test_"):
                            total_test_functions += 1
                            valid_count, vacuous_count, is_skip = inspect_test_function_assertions(node)

                            if is_skip:
                                skipped_tests.append(f"{tf.name}::{node.name}")

                            if valid_count == 0 or vacuous_count > 0:
                                vacuous_tests.append(
                                    f"{tf.name}::{node.name} (valid asserts: {valid_count}, vacuous: {vacuous_count})"
                                )
            except Exception as e:
                vacuous_tests.append(f"AST parse error in {tf.name}: {e!s}")

        findings: list[Finding] = []
        report_lines = [
            f"Analyzed {len(test_files)} test file(s) containing {total_test_functions} test function(s).",
            f"Vacuous or assertion-free tests: {len(vacuous_tests)}",
            f"Skipped tests: {len(skipped_tests)}",
        ]

        if vacuous_tests:
            report_lines.extend(["Vacuous test instances:"] + [f" - {vt}" for vt in vacuous_tests])
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    title="Vacuous Test Assertions Detected",
                    description=f"Tests found with zero valid assertions or trivial asserts (e.g. assert True, 1==1): {', '.join(vacuous_tests)}",
                    finding_type=FindingType.TEST_GAP,
                    severity=FindingSeverity.HIGH,
                    is_blocking=True,
                )
            )

        if skipped_tests:
            report_lines.extend(["Skipped tests:"] + [f" - {st}" for st in skipped_tests])
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    title="Skipped Tests Detected",
                    description=f"Tests marked with skip decorators: {', '.join(skipped_tests)}",
                    finding_type=FindingType.TEST_GAP,
                    severity=FindingSeverity.MEDIUM,
                    is_blocking=False,
                )
            )

        status = CheckStatus.PASSED if not vacuous_tests else CheckStatus.FAILED
        content = "\n".join(report_lines)

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=["ast_analyzer", "[test_files]"],
            status=status,
            stdout=content,
            exit_code=0 if status == CheckStatus.PASSED else 1,
            end_time=datetime.now(UTC).isoformat(),
        )

        ev = collector.add_evidence(
            check_id=check.check_id,
            content=content,
            evidence_type=EvidenceType.AST_ANALYSIS,
            source="ast_quality_analyzer",
            method="python_ast",
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
        """Verifies requirement satisfaction by searching for explicitly matching test functions or targets,
        preventing generic fallback substrings like 'valid' from falsely passing.
        """
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        req_id = check.target_requirement_id or ""
        desc_clean = check.description.lower()

        # Remove generic boilerplate prefix "validates requirement satisfaction for: "
        boilerplate_prefix = "validates requirement satisfaction for:"
        if desc_clean.startswith(boilerplate_prefix):
            desc_clean = desc_clean[len(boilerplate_prefix):].strip()

        # Extract specific distinctive domain keywords from requirement description
        # Reject generic stop words: valid, validates, requirement, satisfaction, check, test, ensure
        words = re.findall(r"\b[a-zA-Z]{3,}\b", desc_clean)
        stop_words = {"validates", "requirement", "satisfaction", "ensure", "check", "test", "should", "must", "with", "from", "into"}
        distinctive_keywords = [w for w in words if w not in stop_words]

        test_files = [
            p for p in project_dir.rglob("*.py")
            if (p.name.startswith("test_") or p.name.endswith("_test.py"))
            and not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts)
        ]

        # Look for tests explicitly targeting this requirement by ID or distinctive keywords
        matched_test_funcs: list[str] = []
        req_id_slug = req_id.lower().replace("-", "_")

        for tf in test_files:
            try:
                tree = ast.parse(tf.read_text(encoding="utf-8"), filename=str(tf))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if node.name.startswith("test_"):
                            name_lower = node.name.lower()
                            # 1. Match by exact requirement ID (e.g. test_req_001)
                            if req_id_slug and req_id_slug in name_lower:
                                matched_test_funcs.append(node.name)
                                continue

                            # 2. Match by distinctive keywords from description
                            # Must match a specific domain keyword (e.g. duplicate, malformed, subtract)
                            matched_kw = [kw for kw in distinctive_keywords if kw in name_lower]
                            if matched_kw:
                                matched_test_funcs.append(node.name)
            except Exception:
                pass

        findings: list[Finding] = []

        # If no tests match the requirement, report requirement coverage gap!
        if not matched_test_funcs:
            status = CheckStatus.NOT_RUN
            msg = (
                f"Requirement Coverage Gap: No test in project exercises requirement '{req_id}'. "
                f"Passing tests for other features do NOT establish satisfaction."
            )
            execution = CheckExecution(
                execution_id=exec_id,
                check_id=check.check_id,
                status=status,
                stdout=msg,
                exit_code=0,
                end_time=datetime.now(UTC).isoformat(),
            )
            ev = collector.add_evidence(
                check_id=check.check_id,
                content=msg,
                evidence_type=EvidenceType.AST_ANALYSIS,
                claim_id=check.target_claim_id,
                source="acceptance_coverage_analyzer",
                method="ast_symbol_check",
            )
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    claim_id=check.target_claim_id,
                    title=f"Untested Acceptance Requirement: {req_id}",
                    description=msg,
                    finding_type=FindingType.VERIFICATION_GAP,
                    severity=FindingSeverity.HIGH if check.mandatory else FindingSeverity.MEDIUM,
                    evidence_ids=[ev.evidence_id],
                    is_blocking=check.mandatory,
                )
            )
            return VerifierResult(check_id=check.check_id, execution=execution, evidence=[ev], findings=findings)

        # Execute only the matching tests
        k_filter = " or ".join(matched_test_funcs)
        with tempfile.TemporaryDirectory() as tmp_dir:
            junit_xml = Path(tmp_dir) / "junit_report.xml"
            cmd = [
                sys.executable,
                "-m",
                "pytest",
                "-v",
                f"--junitxml={junit_xml}",
                "-k",
                k_filter,
                "-o",
                "addopts=",
            ]

            proc_res = run_safe_process(
                command=cmd,
                cwd=project_dir,
                timeout_seconds=check.timeout_seconds,
                security_config=self.config.security,
                budget_config=self.config.budget,
            )

            # Parse XML
            failures = 0
            errors = 0
            total_ran = 0
            if junit_xml.is_file():
                try:
                    tree = ET.parse(junit_xml)
                    root = tree.getroot()
                    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
                    for s in suites:
                        total_ran += int(s.attrib.get("tests", 0))
                        failures += int(s.attrib.get("failures", 0))
                        errors += int(s.attrib.get("errors", 0))
                except Exception:
                    pass

            status = CheckStatus.PASSED
            if proc_res.timed_out:
                status = CheckStatus.TIMED_OUT
            elif failures > 0 or errors > 0 or proc_res.exit_code != 0 or total_ran == 0:
                status = CheckStatus.FAILED

            execution = CheckExecution(
                execution_id=exec_id,
                check_id=check.check_id,
                command=proc_res.command,
                status=status,
                exit_code=proc_res.exit_code if status == CheckStatus.PASSED else (proc_res.exit_code or 1),
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
                        title=f"Acceptance Failure for {req_id}",
                        description=f"Acceptance test for '{req_id}' ({k_filter}) failed.",
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
        if not check.command:
            status = CheckStatus.FAILED
            msg = f"Check '{check.check_id}' defines no executable command."
            execution = CheckExecution(
                execution_id=exec_id,
                check_id=check.check_id,
                status=status,
                stdout=msg,
                exit_code=1,
                end_time=datetime.now(UTC).isoformat(),
            )
            ev = collector.add_evidence(check_id=check.check_id, content=msg)
            finding = Finding(
                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                check_id=check.check_id,
                title="Missing Check Command",
                description=msg,
                finding_type=FindingType.VERIFICATION_GAP,
                severity=FindingSeverity.HIGH,
                is_blocking=True,
            )
            return VerifierResult(check_id=check.check_id, execution=execution, evidence=[ev], findings=[finding])

        proc_res = run_safe_process(
            command=check.command,
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
