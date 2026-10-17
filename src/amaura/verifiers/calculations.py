"""Calculation and mathematical recomputation verification engine."""

import ast
import csv
import operator
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus
from amaura.models.evidence import EvidenceType
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.verifiers.base import BaseVerifier, VerifierResult

# Safe mathematical evaluation operators
_SAFE_OPERATORS: dict[type[ast.AST], Any] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def safe_eval_arithmetic(expr_str: str) -> float | None:
    """Safely evaluates basic arithmetic expressions using AST without eval()."""
    try:
        parsed = ast.parse(expr_str.strip(), mode="eval")

        def _eval_node(node: ast.AST) -> float:
            if isinstance(node, ast.Expression):
                return _eval_node(node.body)
            elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return float(node.value)
            elif isinstance(node, ast.BinOp):
                left = _eval_node(node.left)
                right = _eval_node(node.right)
                op = _SAFE_OPERATORS.get(type(node.op))
                if op is None:
                    raise ValueError(f"Unsupported operator: {type(node.op)}")
                if type(node.op) in (ast.Div, ast.FloorDiv, ast.Mod) and right == 0:
                    raise ZeroDivisionError("Division by zero")
                return float(op(left, right))
            elif isinstance(node, ast.UnaryOp):
                operand = _eval_node(node.operand)
                op = _SAFE_OPERATORS.get(type(node.op))
                if op is None:
                    raise ValueError(f"Unsupported unary operator: {type(node.op)}")
                return float(op(operand))
            else:
                raise TypeError(f"Unsupported node type: {type(node)}")

        return _eval_node(parsed)
    except Exception:
        return None


class CalculationVerifier(BaseVerifier):
    """Engine for independently recalculating mathematical claims, tabular totals, and metrics."""

    name: str = "calculations"

    def verify(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        findings: list[Finding] = []
        report_lines: list[str] = ["CalculationVerifier: Independent mathematical and tabular recomputation."]
        passed = True

        # 1. Check explicit expression from metadata if configured
        expr = check.metadata.get("expression")
        expected_val_str = check.metadata.get("expected")
        if expr and expected_val_str:
            computed = safe_eval_arithmetic(expr)
            try:
                expected = float(expected_val_str)
                if computed is None or abs(computed - expected) > 1e-4:
                    passed = False
                    msg = f"Arithmetic check failed: expression '{expr}' evaluated to {computed}, expected {expected}."
                    report_lines.append(f"FAIL: {msg}")
                    findings.append(
                        Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:8]}",
                            check_id=check.check_id,
                            claim_id=check.target_claim_id,
                            title="Mathematical Recomputation Mismatch",
                            description=msg,
                            finding_type=FindingType.DEFECT,
                            severity=FindingSeverity.HIGH,
                            is_blocking=True,
                        )
                    )
                else:
                    report_lines.append(f"PASS: Expression '{expr}' verified ({computed} == {expected}).")
            except ValueError:
                pass

        # 2. Recompute tabular totals and column sums in CSV files
        csv_files = [
            p for p in project_dir.rglob("*.csv")
            if not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts)
        ]
        for cf in csv_files:
            try:
                with open(cf, "r", encoding="utf-8", errors="replace") as f:
                    rows = list(csv.reader(f))
                if len(rows) < 3:
                    continue

                header = rows[0]
                data_rows = rows[1:-1]
                last_row = rows[-1]

                # Check if last row is a summary / total row
                if any(kw in str(last_row[0]).lower() for kw in ("total", "sum", "subtotal")):
                    for col_idx in range(1, min(len(header), len(last_row))):
                        try:
                            claimed_total = float(last_row[col_idx].replace(",", "").replace("$", ""))
                            column_values = []
                            for r in data_rows:
                                if col_idx < len(r) and r[col_idx].strip():
                                    val_str = r[col_idx].replace(",", "").replace("$", "")
                                    column_values.append(float(val_str))

                            actual_sum = sum(column_values)
                            if column_values and abs(actual_sum - claimed_total) > 0.01:
                                passed = False
                                col_name = header[col_idx] if col_idx < len(header) else f"Column {col_idx}"
                                msg = (
                                    f"Tabular total discrepancy in {cf.name} for '{col_name}': "
                                    f"claimed total is {claimed_total}, but independent sum of {len(column_values)} rows is {actual_sum:.2f}."
                                )
                                report_lines.append(f"FAIL: {msg}")
                                findings.append(
                                    Finding(
                                        finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                        check_id=check.check_id,
                                        claim_id=check.target_claim_id,
                                        title=f"Tabular Total Calculation Error in {cf.name}",
                                        description=msg,
                                        finding_type=FindingType.DEFECT,
                                        severity=FindingSeverity.HIGH,
                                        is_blocking=True,
                                    )
                                )
                        except (ValueError, IndexError):
                            continue
            except Exception:
                pass

        # 3. Scan markdown and text files for arithmetic equations and percentages
        doc_files = [
            p for p in project_dir.rglob("*")
            if p.is_file() and p.suffix.lower() in (".md", ".txt", ".rst")
            and not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts)
        ]
        # Regex for equations: A + B = C, A - B = C, A * B = C
        eq_pattern = re.compile(r"\b(\d+(?:\.\d+)?)\s*([\+\-\*])\s*(\d+(?:\.\d+)?)\s*=\s*(\d+(?:\.\d+)?)\b")
        # Regex for percentage claims: X% of Y is/equals Z
        pct_pattern = re.compile(r"\b(\d+(?:\.\d+)?)\s*%\s*(?:of)\s*(\d+(?:\.\d+)?)\s*(?:is|=|equals)\s*(\d+(?:\.\d+)?)\b", re.IGNORECASE)

        for df in doc_files:
            try:
                text = df.read_text(encoding="utf-8", errors="ignore")
                for a_s, op_s, b_s, c_s in eq_pattern.findall(text):
                    a, b, claimed = float(a_s), float(b_s), float(c_s)
                    actual = a + b if op_s == "+" else (a - b if op_s == "-" else a * b)
                    if abs(actual - claimed) > 1e-4:
                        passed = False
                        msg = f"Arithmetic contradiction in {df.name}: '{a_s} {op_s} {b_s} = {c_s}' is incorrect (computed: {actual})."
                        report_lines.append(f"FAIL: {msg}")
                        findings.append(
                            Finding(
                                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                check_id=check.check_id,
                                claim_id=check.target_claim_id,
                                title=f"Arithmetic Contradiction in {df.name}",
                                description=msg,
                                finding_type=FindingType.CONTRADICTION,
                                severity=FindingSeverity.HIGH,
                                is_blocking=True,
                            )
                        )

                for pct_s, total_s, claimed_s in pct_pattern.findall(text):
                    pct, total, claimed = float(pct_s), float(total_s), float(claimed_s)
                    actual = (pct / 100.0) * total
                    if abs(actual - claimed) > 0.05 * max(abs(actual), 1.0):
                        passed = False
                        msg = f"Percentage calculation error in {df.name}: '{pct_s}% of {total_s}' claimed as {claimed_s}, but computed value is {actual:.2f}."
                        report_lines.append(f"FAIL: {msg}")
                        findings.append(
                            Finding(
                                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                check_id=check.check_id,
                                claim_id=check.target_claim_id,
                                title=f"Percentage Calculation Error in {df.name}",
                                description=msg,
                                finding_type=FindingType.DEFECT,
                                severity=FindingSeverity.HIGH,
                                is_blocking=True,
                            )
                        )
            except Exception:
                pass

        status = CheckStatus.PASSED if passed else CheckStatus.FAILED
        if passed and len(report_lines) == 1:
            report_lines.append("No arithmetic inconsistencies or calculation defects observed.")

        content = "\n".join(report_lines)
        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=["calculation_evaluator", f"[{check.check_id}]"],
            status=status,
            stdout=content,
            exit_code=0 if passed else 1,
            end_time=datetime.now(UTC).isoformat(),
        )

        ev = collector.add_evidence(
            check_id=check.check_id,
            content=content,
            evidence_type=EvidenceType.EXECUTION_LOG,
            claim_id=check.target_claim_id,
            source="calculation_recomputor",
            method="independent_ast_and_data_arithmetic",
            independent=True,
        )

        return VerifierResult(
            check_id=check.check_id,
            execution=execution,
            evidence=[ev],
            findings=findings,
        )
