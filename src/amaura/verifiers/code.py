"""Code verification engine supporting AST quality checks, independent JUnit parsing, and rigorous acceptance tests."""

import ast
import copy
import hashlib
import os
import re
import sys
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus, CheckType
from amaura.models.evidence import EvidenceType
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.security.process import run_safe_process
from amaura.security.workspace import validate_path_within_workspace
from amaura.security.xml import safe_parse_xml
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
    """Inspects a test function node for assertions, vacuous checks, pytest.raises, skips, and assertion delegation.
    Returns (valid_assert_count, vacuous_assert_count, is_skipped).
    """
    valid_asserts = 0
    vacuous_asserts = 0
    is_skipped = False

    # 1. Check decorators for skip / xfail markers
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

        if any(marker in dec_name.lower() for marker in ("skip", "xfail")):
            is_skipped = True

    # 2. Walk AST for assertion constructs, skips/xfails in body, and helper delegation
    for node in ast.walk(func_node):
        # Check for pytest.skip() or pytest.xfail() called inside body
        if isinstance(node, ast.Call):
            call_name = ""
            if isinstance(node.func, ast.Attribute):
                call_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                call_name = node.func.id
            if call_name in ("skip", "xfail"):
                is_skipped = True

        # assert statement
        if isinstance(node, ast.Assert):
            # Check for vacuous asserts: tuple assert (x, "msg"), trivial constant (assert True), or trivial comparison (1==1)
            if (
                (isinstance(node.test, ast.Tuple) and len(node.test.elts) > 0)
                or is_trivial_constant(node.test)
                or is_trivial_comparison(node.test)
            ):
                vacuous_asserts += 1
            # Check 4: assert x == x (comparing identical AST expressions)
            elif isinstance(node.test, ast.Compare) and len(node.test.comparators) == 1:
                left_dump = ast.dump(node.test.left)
                right_dump = ast.dump(node.test.comparators[0])
                if left_dump == right_dump and isinstance(node.test.ops[0], (ast.Eq, ast.Is)):
                    vacuous_asserts += 1
                else:
                    valid_asserts += 1
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

        # Calls to assertion methods or helper functions: self.assert*, assertTrue, assertEqual, check_*, verify_*
        elif isinstance(node, ast.Call):
            call_name = ""
            if isinstance(node.func, ast.Attribute):
                call_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                call_name = node.func.id

            # unittest style assertions: self.assertTrue(True), self.assertEqual(x, x), etc.
            if call_name.startswith("assert") and call_name != "assert_":
                # Check for assertTrue(True) / assertFalse(False) or assertEqual(x, x)
                is_vacuous_unit = (
                    (call_name in ("assertTrue", "assertFalse") and len(node.args) >= 1 and is_trivial_constant(node.args[0]))
                    or (call_name in ("assertEqual", "assertIs") and len(node.args) >= 2 and ast.dump(node.args[0]) == ast.dump(node.args[1]))
                )
                if is_vacuous_unit:
                    vacuous_asserts += 1
                else:
                    valid_asserts += 1
            # Helper function delegation (e.g. check_result(...), verify_output(...), assert_valid(...))
            elif any(prefix in call_name.lower() for prefix in ("check_", "verify_", "validate_", "ensure_")):
                valid_asserts += 1

    return valid_asserts, vacuous_asserts, is_skipped


def detect_adversarial_conftest_hooks(project_dir: Path) -> list[str]:
    """Inspects any conftest.py or test configuration files to detect hostile reporting,
    exit status manipulation, forced process exit, or report forging.
    Avoids false-positives on benign inspection of report.outcome.
    """
    violations: list[str] = []

    # 1. Check for untrusted sitecustomize.py in project dir
    sitecustom = project_dir / "sitecustomize.py"
    if sitecustom.is_file():
        violations.append(f"{sitecustom.name} detected in project root (potential interpreter hijack)")

    # 2. Check for hostile pytest.ini or configuration options attempting to disable hooks or load external plugins
    for ini_name in ["pytest.ini", "tox.ini", "setup.cfg"]:
        ini_file = project_dir / ini_name
        if ini_file.is_file():
            try:
                ini_content = ini_file.read_text(encoding="utf-8", errors="ignore")
                if "-p " in ini_content or "plugins" in ini_content.lower():
                    violations.append(f"{ini_name} specifies custom plugins or options")
            except Exception:
                pass

    for cf in project_dir.rglob("conftest.py"):
        if any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in cf.parts):
            continue
        try:
            cf_tree = ast.parse(cf.read_text(encoding="utf-8"), filename=str(cf))
            for node in ast.walk(cf_tree):
                # Check for pytest_plugins declaration
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == "pytest_plugins":
                            violations.append(f"{cf.name} defines 'pytest_plugins' (unauthorized plugin loading)")

                # Check for os._exit or sys.exit in conftest
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute) and node.func.attr in ("_exit", "exit"):
                        violations.append(f"{cf.name} calls '{node.func.attr}' to hijack process termination")
                    elif isinstance(node.func, ast.Name) and node.func.id in ("exit", "quit"):
                        violations.append(f"{cf.name} calls '{node.func.id}' to hijack process termination")
                    # Check for getattr(os, "_exit")
                    elif isinstance(node.func, ast.Name) and node.func.id == "getattr":
                        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and node.args[1].value in ("_exit", "exit"):
                            violations.append(f"{cf.name} calls '{node.args[1].value}' via getattr")

                # Check for direct write/store assignment to outcome or exitstatus (NOT benign reads)
                elif isinstance(node, ast.Attribute) and node.attr in ("exitstatus", "outcome"):
                    if isinstance(node.ctx, ast.Store):
                        violations.append(f"{cf.name} overwrites attribute '{node.attr}'")

                # Check for hooks that forge reports or outcomes
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name in ("pytest_runtest_makereport", "pytest_runtest_logreport", "pytest_report_teststatus", "pytest_pyfunc_call"):
                        violations.append(f"{cf.name} defines hostile reporting hook '{node.name}'")
                    elif node.name == "pytest_sessionfinish":
                        # If sessionfinish modifies outcome/exitstatus or calls exit
                        for subnode in ast.walk(node):
                            if isinstance(subnode, ast.Attribute) and subnode.attr in ("exitstatus", "outcome") and isinstance(subnode.ctx, ast.Store):
                                violations.append(f"{cf.name}::{node.name} modifies '{subnode.attr}'")
                                break
                            elif isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Attribute) and subnode.func.attr in ("_exit", "exit"):
                                violations.append(f"{cf.name}::{node.name} calls '{subnode.func.attr}'")
                                break
                            elif isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Name) and subnode.func.id == "getattr":
                                if len(subnode.args) >= 2 and isinstance(subnode.args[1], ast.Constant) and subnode.args[1].value in ("_exit", "exit"):
                                    violations.append(f"{cf.name}::{node.name} calls '{subnode.args[1].value}' via getattr")
                                    break
                    elif node.name in ("pytest_configure", "pytest_unconfigure"):
                        for subnode in ast.walk(node):
                            if isinstance(subnode, ast.Call):
                                func = subnode.func
                                if isinstance(func, ast.Attribute) and func.attr in ("_exit", "exit"):
                                    violations.append(f"{cf.name}::{node.name} calls '{func.attr}'")
                                    break
                                elif isinstance(func, ast.Name) and func.id == "getattr":
                                    if len(subnode.args) >= 2 and isinstance(subnode.args[1], ast.Constant) and subnode.args[1].value in ("_exit", "exit"):
                                        violations.append(f"{cf.name}::{node.name} calls '{subnode.args[1].value}' via getattr")
                                        break
                                elif isinstance(func, ast.Name) and func.id == "open":
                                    if len(subnode.args) >= 2 and isinstance(subnode.args[1], ast.Constant) and "w" in str(subnode.args[1].value):
                                        violations.append(f"{cf.name}::{node.name} writes to file (potential report tampering)")
                                        break
                                elif isinstance(func, ast.Attribute) and func.attr in ("write_text", "write_bytes"):
                                    violations.append(f"{cf.name}::{node.name} writes to file (potential report tampering)")
                                    break
        except Exception:
            pass
    return violations


def find_imported_source_modules(test_files: list[Path], project_dir: Path) -> list[Path]:
    """Finds project source files directly imported by the given test files."""
    imported_files: set[Path] = set()
    for tf in test_files:
        try:
            tree = ast.parse(tf.read_text(encoding="utf-8"), filename=str(tf))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_mod = alias.name.split(".")[0]
                        for cand in [
                            tf.parent / f"{top_mod}.py",
                            project_dir / f"{top_mod}.py",
                            project_dir / "src" / f"{top_mod}.py",
                            project_dir / top_mod / "__init__.py",
                            project_dir / "src" / top_mod / "__init__.py",
                        ]:
                            if cand.is_file():
                                imported_files.add(cand.resolve())
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top_mod = node.module.split(".")[0]
                        for cand in [
                            tf.parent / f"{top_mod}.py",
                            project_dir / f"{top_mod}.py",
                            project_dir / "src" / f"{top_mod}.py",
                            project_dir / top_mod / "__init__.py",
                            project_dir / "src" / top_mod / "__init__.py",
                        ]:
                            if cand.is_file():
                                imported_files.add(cand.resolve())
        except Exception:
            pass
    return sorted(imported_files)


def generate_candidate_mutants(source: str, max_mutants: int = 5) -> list[str]:
    """Generates candidate mutant source strings using targeted fault injection:
    1. Invert/replace Return statements (return None)
    2. Replace function bodies with a fault (raise RuntimeError)
    3. Invert Comparison operators (== <-> !=, in <-> not in, < <-> >=, etc.)
    4. Invert Boolean constants (True <-> False)
    """
    try:
        base_tree = ast.parse(source)
    except Exception:
        return []

    mutants: list[str] = []

    # 1. Mutate Return statements to return None
    for node in ast.walk(base_tree):
        if len(mutants) >= max_mutants:
            break
        if isinstance(node, ast.Return) and node.value is not None:
            if isinstance(node.value, ast.Constant) and node.value.value is None:
                continue
            new_tree = copy.deepcopy(base_tree)
            for sub in ast.walk(new_tree):
                if isinstance(sub, ast.Return) and getattr(sub, "lineno", None) == getattr(node, "lineno", None):
                    sub.value = ast.Constant(value=None)
                    try:
                        mutants.append(ast.unparse(new_tree))
                    except Exception:
                        pass
                    break

    # 2. Mutate function bodies to raise RuntimeError
    for node in ast.walk(base_tree):
        if len(mutants) >= max_mutants:
            break
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            new_tree = copy.deepcopy(base_tree)
            for sub in ast.walk(new_tree):
                if isinstance(sub, type(node)) and sub.name == node.name and getattr(sub, "lineno", None) == getattr(node, "lineno", None):
                    err_node = ast.Raise(
                        exc=ast.Call(
                            func=ast.Name(id="RuntimeError", ctx=ast.Load()),
                            args=[ast.Constant(value="Amaura mutation fault injection")],
                            keywords=[],
                        )
                    )
                    sub.body = [err_node]
                    try:
                        mutants.append(ast.unparse(new_tree))
                    except Exception:
                        pass
                    break

    # 3. Mutate comparisons
    comp_map = {
        ast.Eq: ast.NotEq,
        ast.NotEq: ast.Eq,
        ast.In: ast.NotIn,
        ast.NotIn: ast.In,
        ast.Lt: ast.GtE,
        ast.Gt: ast.LtE,
        ast.LtE: ast.Gt,
        ast.GtE: ast.Lt,
        ast.Is: ast.IsNot,
        ast.IsNot: ast.Is,
    }
    for node in ast.walk(base_tree):
        if len(mutants) >= max_mutants:
            break
        if isinstance(node, ast.Compare) and len(node.ops) > 0:
            op_type = type(node.ops[0])
            if op_type in comp_map:
                new_tree = copy.deepcopy(base_tree)
                for sub in ast.walk(new_tree):
                    if isinstance(sub, ast.Compare) and getattr(sub, "lineno", None) == getattr(node, "lineno", None):
                        sub.ops[0] = comp_map[op_type]()
                        try:
                            mutants.append(ast.unparse(new_tree))
                        except Exception:
                            pass
                        break

    # 4. Mutate boolean constants
    for node in ast.walk(base_tree):
        if len(mutants) >= max_mutants:
            break
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            new_tree = copy.deepcopy(base_tree)
            for sub in ast.walk(new_tree):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, bool) and getattr(sub, "lineno", None) == getattr(node, "lineno", None):
                    sub.value = not sub.value
                    try:
                        mutants.append(ast.unparse(new_tree))
                    except Exception:
                        pass
                    break

    return mutants


def parse_pytest_terminal_output(stdout: str) -> dict:
    """Parses pytest's standard terminal output to cross-check against XML reports."""
    summary: dict = {
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "has_failures_section": False,
        "failed_test_names": [],
    }
    if not stdout:
        return summary

    if "= FAILURES =" in stdout or "= ERRORS =" in stdout:
        summary["has_failures_section"] = True

    for line in stdout.splitlines():
        line_clean = line.strip()
        if line_clean.startswith(("FAILED ", "ERROR ")):
            test_target = line_clean.split()[1] if len(line_clean.split()) > 1 else line_clean
            summary["failed_test_names"].append(test_target)

    # Match summary line: e.g. '= 1 failed, 2 passed in 0.12s =' or '= 2 passed in 0.05s ='
    summary_match = re.search(r"=+\s*(.+?)\s+in\s+[\d\.]+s\s*=+", stdout)
    if summary_match:
        text = summary_match.group(1)
        for part in text.split(","):
            part = part.strip()
            p_m = re.match(r"^(\d+)\s+([a-z]+)", part)
            if p_m:
                count = int(p_m.group(1))
                category = p_m.group(2)
                if category.startswith("fail"):
                    summary["failed"] = count
                elif category.startswith("pass"):
                    summary["passed"] = count
                elif category.startswith("error"):
                    summary["errors"] = count
                elif category.startswith("skip"):
                    summary["skipped"] = count

    if summary["failed_test_names"] and summary["failed"] == 0:
        summary["failed"] = len(summary["failed_test_names"])

    return summary


class CodeVerifier(BaseVerifier):
    """Engine for validating code syntax, test execution, test quality/vacuousness, and acceptance tests."""

    name: str = "code"

    def __init__(self, config=None):
        super().__init__(config)
        self._candidate_cache: dict[str, list[str]] = {}
        self._mutation_run_cache: dict[tuple[str, str, str], bool] = {}

    def verify(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        if check.metadata.get("target_file"):
            validate_path_within_workspace(Path(check.metadata["target_file"]), project_dir)

        if check.check_type == CheckType.BUILD:
            return self._verify_build(project_dir, check, collector)
        elif check.check_type == CheckType.TEST:
            return self._verify_tests(project_dir, check, collector)
        elif check.check_type == CheckType.TEST_QUALITY:
            return self._verify_test_quality(project_dir, check, collector)
        elif check.check_type == CheckType.ACCEPTANCE_TEST:
            return self._verify_acceptance(project_dir, check, collector)
        elif check.check_type in (CheckType.LINT, CheckType.CONSTRAINT) or check.metadata.get("constraint"):
            return self._verify_constraints(project_dir, check, collector)
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
            validate_path_within_workspace(p, project_dir)
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
            stdout = "No Python source files (.py) discovered in project directory."
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    title="Missing Source Files",
                    description="No Python source files (.py) exist in the project directory to build or compile.",
                    finding_type=FindingType.DEFECT,
                    severity=FindingSeverity.HIGH,
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

    def _find_python_executable(self, project_dir: Path) -> str:
        """Finds the appropriate Python executable for testing the target project.
        Prefers target's virtual environment if present, falling back to sys.executable (H1).
        """
        for venv_name in (".venv", "venv", "env"):
            venv_py = project_dir / venv_name / "bin" / "python"
            if venv_py.is_file() and os.access(venv_py, os.X_OK):
                return str(venv_py)
            venv_py_win = project_dir / venv_name / "Scripts" / "python.exe"
            if venv_py_win.is_file():
                return str(venv_py_win)
        return sys.executable

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

            # Execute pytest writing machine-readable JUnit XML report (-B prevents bytecode caching)
            cmd = [
                self._find_python_executable(project_dir),
                "-B",
                "-m",
                "pytest",
                "-v",
                f"--junitxml={junit_xml}",
                "-o",
                "addopts=",
                "--override-ini=addopts=",
            ]

            conftest_violations = detect_adversarial_conftest_hooks(project_dir)
            if conftest_violations:
                findings.append(
                    Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:8]}",
                        check_id=check.check_id,
                        title="Adversarial Test Harness Manipulation Detected",
                        description=f"Hostile test hook(s) detected in conftest.py: {', '.join(conftest_violations)}. Test harness cannot be trusted.",
                        finding_type=FindingType.SECURITY_RISK,
                        severity=FindingSeverity.CRITICAL,
                        is_blocking=True,
                    )
                )

            proc_res = run_safe_process(
                command=cmd,
                cwd=project_dir,
                timeout_seconds=check.timeout_seconds,
                security_config=self.config.security,
                budget_config=self.config.budget,
                env={
                    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )

            # Parse JUnit XML directly to obtain objective test counts
            total_tests = 0
            failures = 0
            errors = 0
            skipped = 0
            xml_parsed = False

            if junit_xml.is_file():
                try:
                    root = safe_parse_xml(junit_xml)
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

            # Cross-check terminal stdout against XML report (A1: catches atexit, unconfigure, and output forgeries)
            term_summary = parse_pytest_terminal_output(proc_res.stdout)
            has_terminal_failures = (
                term_summary["failed"] > 0
                or term_summary["errors"] > 0
                or term_summary["has_failures_section"]
                or bool(term_summary["failed_test_names"])
            )

            # Evaluate objective test status
            status = CheckStatus.PASSED
            summary_reasons = []

            if conftest_violations:
                status = CheckStatus.FAILED
                summary_reasons.append(f"Adversarial test harness manipulation detected: {', '.join(conftest_violations)}")
            elif proc_res.timed_out:
                status = CheckStatus.TIMED_OUT
                summary_reasons.append("Test runner timed out.")
            elif proc_res.exit_code != 0:
                status = CheckStatus.FAILED
                summary_reasons.append(f"Process exited with non-zero code {proc_res.exit_code}.")
            elif has_terminal_failures:
                status = CheckStatus.FAILED
                fail_details = []
                if term_summary["failed"] > 0:
                    fail_details.append(f"{term_summary['failed']} failure(s)")
                if term_summary["errors"] > 0:
                    fail_details.append(f"{term_summary['errors']} error(s)")
                if not fail_details:
                    fail_details.append("failures detected in terminal output")
                summary_reasons.append(
                    f"Test failures detected in terminal output: {', '.join(fail_details)} "
                    f"(cross-check against XML report failures={failures}, errors={errors})."
                )
                if failures == 0 and errors == 0:
                    findings.append(
                        Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:8]}",
                            check_id=check.check_id,
                            title="Adversarial Report Discrepancy",
                            description="Terminal output recorded test failures, but JUnit XML report indicated success. Possible atexit or hook report spoofing.",
                            finding_type=FindingType.SECURITY_RISK,
                            severity=FindingSeverity.CRITICAL,
                            is_blocking=True,
                        )
                    )
            elif not xml_parsed:
                status = CheckStatus.FAILED
                summary_reasons.append(
                    f"Test runner report was missing or unparsable (exit code: {proc_res.exit_code}). "
                    "Unverified test runs cannot be treated as passed."
                )
            elif total_tests == 0:
                status = CheckStatus.FAILED
                summary_reasons.append("No tests were discovered or executed.")
            elif failures > 0 or errors > 0:
                status = CheckStatus.FAILED
                summary_reasons.append(f"Observed {failures} failure(s) and {errors} error(s) in test suite.")
            elif skipped == total_tests:
                status = CheckStatus.FAILED
                summary_reasons.append(f"All {total_tests} test(s) were skipped. Zero active tests ran.")

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
                independent=False,
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
                ast_tree = ast.parse(tf.read_text(encoding="utf-8"), filename=str(tf))
                for node in ast.walk(ast_tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        # Only inspect actual test functions, not helper functions
                        if node.name.startswith("test_"):
                            total_test_functions += 1
                            valid_count, _vacuous_count, is_skip = inspect_test_function_assertions(node)

                            if is_skip:
                                skipped_tests.append(f"{tf.name}::{node.name}")

                            if valid_count == 0:
                                vacuous_tests.append(
                                    f"{tf.name}::{node.name} (zero valid assertions or checks)"
                                )
            except Exception as e:
                vacuous_tests.append(f"AST parse error in {tf.name}: {e!s}")

        findings: list[Finding] = []
        report_lines = [
            f"Analyzed {len(test_files)} test file(s) containing {total_test_functions} test function(s).",
            f"Vacuous or assertion-free tests: {len(vacuous_tests)}",
            f"Skipped tests: {len(skipped_tests)}",
        ]

        allow_vacuous = getattr(getattr(self.config, "policy", None), "allow_vacuous_tests", False)
        if vacuous_tests:
            report_lines.extend(["Vacuous test instances:"] + [f" - {vt}" for vt in vacuous_tests])
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    title="Vacuous Test Assertions Detected",
                    description=f"Tests found with zero valid assertions or trivial asserts (e.g. assert True, 1==1): {', '.join(vacuous_tests)}",
                    finding_type=FindingType.TEST_GAP,
                    severity=FindingSeverity.LOW if allow_vacuous else FindingSeverity.HIGH,
                    is_blocking=not allow_vacuous,
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

        status = CheckStatus.PASSED if (not vacuous_tests or allow_vacuous) else CheckStatus.FAILED
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
        req_id_slug = req_id.lower().replace("-", "_") if req_id else ""
        req_id_clean = req_id.lower().replace("-", "").replace("_", "") if req_id else ""

        # Explicit acceptance tests declared in check metadata (A2: explicit mapping, no keyword guessing)
        raw_acc = check.metadata.get("acceptance_tests", [])
        if isinstance(raw_acc, str):
            raw_acc = [t.strip() for t in raw_acc.split(",") if t.strip()]
        explicit_acceptance_tests = [
            t.lower().strip() for t in raw_acc if t.strip()
        ]

        test_files = [
            p for p in project_dir.rglob("*.py")
            if (p.name.startswith("test_") or p.name.endswith("_test.py"))
            and not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts)
        ]

        # Look for tests explicitly targeting this requirement by ID, decorator, or explicit acceptance mapping
        matched_test_funcs: list[str] = []
        matched_test_files: list[Path] = []

        for tf in test_files:
            try:
                ast_tree = ast.parse(tf.read_text(encoding="utf-8"), filename=str(tf))
                for node in ast.walk(ast_tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if node.name.startswith("test_"):
                            name_lower = node.name.lower()
                            doc = ast.get_docstring(node) or ""

                            # 1. Match by explicit acceptance test name declared in task spec
                            if name_lower in explicit_acceptance_tests or node.name in explicit_acceptance_tests:
                                matched_test_funcs.append(node.name)
                                matched_test_files.append(tf)
                                continue

                            # 2. Match by requirement decorator (e.g. @pytest.mark.requirement("REQ-001"))
                            has_req_mark = False
                            for dec in node.decorator_list:
                                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in ("requirement", "req"):
                                    if len(dec.args) > 0 and isinstance(dec.args[0], ast.Constant) and str(dec.args[0].value).lower() == req_id.lower():
                                        has_req_mark = True
                            if has_req_mark:
                                matched_test_funcs.append(node.name)
                                matched_test_files.append(tf)
                                continue

                            # 3. Match by exact requirement ID in test function name (e.g. test_req_001, test_req1)
                            if req_id_slug and (
                                f"_{req_id_slug}" in name_lower
                                or f"{req_id_slug}_" in name_lower
                                or name_lower == f"test_{req_id_slug}"
                                or (req_id_clean and f"_{req_id_clean}" in name_lower)
                            ):
                                matched_test_funcs.append(node.name)
                                matched_test_files.append(tf)
                                continue

                            # 4. Match by requirement ID in docstring with word boundaries (e.g. "REQ-001")
                            if req_id and re.search(r"\b" + re.escape(req_id) + r"\b", doc, re.IGNORECASE):
                                matched_test_funcs.append(node.name)
                                matched_test_files.append(tf)
                                continue
            except Exception:
                pass

        findings: list[Finding] = []

        # Check for adversarial conftest hooks attempting to hijack outcomes
        conftest_violations = detect_adversarial_conftest_hooks(project_dir)
        if conftest_violations:
            status = CheckStatus.FAILED
            msg = f"Hostile test hook(s) detected in conftest.py: {', '.join(conftest_violations)}. Test harness cannot be trusted."
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
                claim_id=check.target_claim_id,
                source="conftest_security_scanner",
                method="ast_inspection",
            )
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    claim_id=check.target_claim_id,
                    title="Adversarial Test Harness Manipulation Detected",
                    description=msg,
                    finding_type=FindingType.SECURITY_RISK,
                    severity=FindingSeverity.CRITICAL,
                    evidence_ids=[ev.evidence_id],
                    is_blocking=True,
                )
            )
            return VerifierResult(check_id=check.check_id, execution=execution, evidence=[ev], findings=findings)

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
                self._find_python_executable(project_dir),
                "-B",
                "-m",
                "pytest",
                "-v",
                f"--junitxml={junit_xml}",
                "-k",
                k_filter,
                "-o",
                "addopts=",
                "--override-ini=addopts=",
            ]

            proc_res = run_safe_process(
                command=cmd,
                cwd=project_dir,
                timeout_seconds=check.timeout_seconds,
                security_config=self.config.security,
                budget_config=self.config.budget,
                env={
                    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )

            # Parse XML
            failures = 0
            errors = 0
            total_ran = 0
            if junit_xml.is_file():
                try:
                    root = safe_parse_xml(junit_xml)
                    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
                    for s in suites:
                        total_ran += int(s.attrib.get("tests", 0))
                        failures += int(s.attrib.get("failures", 0))
                        errors += int(s.attrib.get("errors", 0))
                except Exception:
                    pass

            term_summary = parse_pytest_terminal_output(proc_res.stdout)
            has_terminal_failures = (
                term_summary["failed"] > 0
                or term_summary["errors"] > 0
                or term_summary["has_failures_section"]
                or bool(term_summary["failed_test_names"])
            )

            status = CheckStatus.PASSED
            if proc_res.timed_out:
                status = CheckStatus.TIMED_OUT
            elif proc_res.exit_code != 0 or failures > 0 or errors > 0 or total_ran == 0 or has_terminal_failures:
                status = CheckStatus.FAILED

            # Mutation Testing: If test passed, verify that injecting defects into source code causes test failure.
            # This completely defeats placeholder tests (e.g. assert len("ab") == 2) and conftest outcome forgers.
            if status == CheckStatus.PASSED:
                py_src_files = [
                    p for p in project_dir.rglob("*.py")
                    if not (p.name.startswith("test_") or p.name.endswith("_test.py") or p.name == "conftest.py")
                    and not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts)
                ]
                # Target source files imported by the matching test suite
                imported_src_files = find_imported_source_modules(matched_test_files, project_dir)
                target_src_files = imported_src_files if imported_src_files else py_src_files

                mutant_tested = False
                mutant_killed = False

                for src_p in target_src_files:
                    if mutant_killed:
                        break
                    original_code = src_p.read_text(encoding="utf-8")
                    src_hash = hashlib.sha256(original_code.encode("utf-8")).hexdigest()
                    if src_hash in self._candidate_cache:
                        candidates = self._candidate_cache[src_hash]
                    else:
                        candidates = generate_candidate_mutants(original_code, max_mutants=5)
                        self._candidate_cache[src_hash] = candidates

                    for mutated_code in candidates:
                        mutant_tested = True
                        mutant_hash = hashlib.sha256(mutated_code.encode("utf-8")).hexdigest()
                        cache_key = (src_hash, mutant_hash, k_filter)

                        if cache_key in self._mutation_run_cache:
                            m_failed = self._mutation_run_cache[cache_key]
                        else:
                            try:
                                # CRUCIAL (A4): Unlink stale XML before each mutant run to prevent stale report reuse
                                junit_xml.unlink(missing_ok=True)
                                src_p.write_text(mutated_code, encoding="utf-8")
                                for pyc in project_dir.rglob("*.pyc"):
                                    try:
                                        pyc.unlink(missing_ok=True)
                                    except Exception:
                                        pass
                                m_res = run_safe_process(
                                    command=cmd,
                                    cwd=project_dir,
                                    timeout_seconds=check.timeout_seconds,
                                    security_config=self.config.security,
                                    budget_config=self.config.budget,
                                    env={
                                        "PYTHONDONTWRITEBYTECODE": "1",
                                        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                                        "PYTHONNOUSERSITE": "1",
                                    },
                                )
                                m_failed = m_res.exit_code != 0 or m_res.timed_out
                                m_term = parse_pytest_terminal_output(m_res.stdout)
                                if m_term["failed"] > 0 or m_term["errors"] > 0 or m_term["has_failures_section"]:
                                    m_failed = True

                                if junit_xml.is_file():
                                    try:
                                        m_root = safe_parse_xml(junit_xml)
                                        m_suites = [m_root] if m_root.tag == "testsuite" else list(m_root.findall("testsuite"))
                                        for s in m_suites:
                                            if int(s.attrib.get("failures", 0)) > 0 or int(s.attrib.get("errors", 0)) > 0:
                                                m_failed = True
                                    except Exception:
                                        pass

                                if "FAILED " in m_res.stdout or "ERROR " in m_res.stdout:
                                    m_failed = True
                            finally:
                                src_p.write_text(original_code, encoding="utf-8")
                                for pyc in project_dir.rglob("*.pyc"):
                                    try:
                                        pyc.unlink(missing_ok=True)
                                    except Exception:
                                        pass

                            self._mutation_run_cache[cache_key] = m_failed

                        if m_failed:
                            mutant_killed = True
                            break

                if mutant_tested and not mutant_killed:
                    status = CheckStatus.FAILED
                    findings.append(
                        Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:8]}",
                            check_id=check.check_id,
                            claim_id=check.target_claim_id,
                            title=f"Placeholder Test Detected: Mutant Survived ({req_id})",
                            description=(
                                f"Acceptance test for '{req_id}' ({k_filter}) passed even after mutating source code. "
                                f"The test assertions do not depend on the implementation logic or the harness is forged."
                            ),
                            finding_type=FindingType.TEST_GAP,
                            severity=FindingSeverity.CRITICAL,
                            is_blocking=True,
                        )
                    )

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

            # A12: Agent-authored test execution output is NEVER independent evidence
            ev = collector.add_evidence(
                check_id=check.check_id,
                content=proc_res.stdout + ("\n" + proc_res.stderr if proc_res.stderr else ""),
                evidence_type=EvidenceType.TEST_OUTPUT,
                claim_id=check.target_claim_id,
                source="pytest_acceptance",
                method="targeted_execution",
                independent=False,
            )

            if status != CheckStatus.PASSED and not findings:
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

    def _verify_constraints(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        """Validates task constraints:
        1. Stdlib-only constraint (scanning against sys.stdlib_module_names and local modules).
        2. Sensitive data / secret leakage constraint.
        3. No-network / offline execution constraint.
        """
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        constraint_text = check.metadata.get("constraint") or check.description
        c_lower = constraint_text.lower()
        findings: list[Finding] = []
        report_lines: list[str] = [f"Verifying constraint: {constraint_text}"]
        passed = True

        py_src_files = [
            p for p in project_dir.rglob("*.py")
            if not (p.name.startswith("test_") or p.name.endswith("_test.py") or p.name == "conftest.py")
            and not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts)
        ]

        # 1. Stdlib-only check
        if any(term in c_lower for term in ("stdlib", "standard library", "no external dependencies", "standard lib", "only standard library")):
            stdlib_names: set[str] | frozenset[str] = getattr(sys, "stdlib_module_names", set())
            unauthorized_imports: list[tuple[str, str]] = []
            for src_p in py_src_files:
                try:
                    tree = ast.parse(src_p.read_text(encoding="utf-8"), filename=str(src_p))
                    for node in ast.walk(tree):
                        mod_names: list[str] = []
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                mod_names.append(alias.name.split(".")[0])
                        elif isinstance(node, ast.ImportFrom):
                            if node.level == 0 and node.module:
                                mod_names.append(node.module.split(".")[0])

                        for mod in mod_names:
                            if mod in stdlib_names:
                                continue
                            is_local = (
                                (project_dir / f"{mod}.py").is_file()
                                or (project_dir / "src" / f"{mod}.py").is_file()
                                or (project_dir / mod).is_dir()
                                or (project_dir / "src" / mod).is_dir()
                                or (src_p.parent / f"{mod}.py").is_file()
                            )
                            if not is_local:
                                unauthorized_imports.append((src_p.name, mod))
                except Exception:
                    pass

            if unauthorized_imports:
                passed = False
                details = ", ".join(f"{f} imports '{m}'" for f, m in unauthorized_imports)
                msg = f"Unauthorized external dependencies detected: {details}. Task requires Python standard library only."
                report_lines.append(f"FAIL: {msg}")
                findings.append(
                    Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:8]}",
                        check_id=check.check_id,
                        claim_id=check.target_claim_id,
                        title="External Dependency Constraint Violated",
                        description=msg,
                        finding_type=FindingType.DEFECT,
                        severity=FindingSeverity.HIGH,
                        is_blocking=True,
                    )
                )
            else:
                report_lines.append(f"PASS: All {len(py_src_files)} source files strictly use standard library modules.")

        # 2. Sensitive data / secrets check
        if any(term in c_lower for term in ("sensitive", "secret", "password", "token", "credential", "leak", "log")):
            secret_patterns = [
                (re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|bearer|access[_-]?token)\s*=\s*['\"][A-Za-z0-9_\-+=/]{6,}['\"]"), "hardcoded credential assignment"),
                (re.compile(r"(?i)postgres(?:ql)?://[A-Za-z0-9_\-]+:[^@\s]+@"), "database connection URI with credentials"),
                (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI API key"),
                (re.compile(r"hf_[A-Za-z0-9]{20,}"), "HuggingFace token"),
            ]
            leaks_found: list[str] = []
            for p in project_dir.rglob("*"):
                if p.is_file() and not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts):
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                        for pat, pat_desc in secret_patterns:
                            if pat.search(content):
                                leaks_found.append(f"{p.name} contains {pat_desc}")
                    except Exception:
                        pass

            if leaks_found:
                passed = False
                msg = f"Sensitive data exposure detected: {'; '.join(leaks_found[:5])}"
                report_lines.append(f"FAIL: {msg}")
                findings.append(
                    Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:8]}",
                        check_id=check.check_id,
                        claim_id=check.target_claim_id,
                        title="Sensitive Data Leakage Detected",
                        description=msg,
                        finding_type=FindingType.SECURITY_RISK,
                        severity=FindingSeverity.CRITICAL,
                        is_blocking=True,
                    )
                )
            else:
                report_lines.append("PASS: No sensitive credentials, secrets, or passwords found in project files.")

        # 3. Local execution / no network check
        if any(term in c_lower for term in ("network", "offline", "local")):
            network_mods = {"requests", "urllib.request", "httpx", "aiohttp", "socket"}
            for src_p in py_src_files:
                try:
                    tree = ast.parse(src_p.read_text(encoding="utf-8"), filename=str(src_p))
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                if alias.name in network_mods:
                                    passed = False
                                    findings.append(
                                        Finding(
                                            finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                            check_id=check.check_id,
                                            title="Network Access Constraint Violated",
                                            description=f"{src_p.name} imports network library '{alias.name}'. Task requires local-only execution.",
                                            finding_type=FindingType.DEFECT,
                                            severity=FindingSeverity.HIGH,
                                            is_blocking=True,
                                        )
                                    )
                except Exception:
                    pass

        status = CheckStatus.PASSED if passed else CheckStatus.FAILED
        content = "\n".join(report_lines)

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=["constraint_inspector", f"[{check.check_id}]"],
            status=status,
            stdout=content,
            exit_code=0 if passed else 1,
            end_time=datetime.now(UTC).isoformat(),
        )

        ev = collector.add_evidence(
            check_id=check.check_id,
            content=content,
            evidence_type=EvidenceType.AST_ANALYSIS,
            claim_id=check.target_claim_id,
            source="constraint_verifier",
            method="static_ast_and_content_scan",
            independent=True,
        )

        return VerifierResult(
            check_id=check.check_id,
            execution=execution,
            evidence=[ev],
            findings=findings,
        )

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
