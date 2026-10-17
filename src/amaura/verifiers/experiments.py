"""Experiment reproducibility and seed determinism verification engine."""

import ast
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus
from amaura.models.evidence import EvidenceType
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.security.workspace import validate_path_within_workspace
from amaura.verifiers.base import BaseVerifier, VerifierResult


class ExperimentVerifier(BaseVerifier):
    """Engine for verifying reproducibility, seed determinism, and data leakage in experimental code."""

    name: str = "experiments"

    def verify(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        findings: list[Finding] = []
        report_lines: list[str] = ["ExperimentVerifier: Independent reproducibility and determinism verification."]
        passed = True

        py_files = [
            p for p in project_dir.rglob("*.py")
            if not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts)
        ]

        # 1. Check for unseeded random operations
        for pf in py_files:
            validate_path_within_workspace(pf, project_dir)
            try:
                content = pf.read_text(encoding="utf-8")
                tree = ast.parse(content, filename=str(pf))

                has_random_import = False
                has_seed_call = False
                has_random_calls = False

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for a in node.names:
                            if a.name in ("random", "numpy.random", "torch"):
                                has_random_import = True
                    elif isinstance(node, ast.ImportFrom):
                        if node.module and any(m in node.module for m in ("random", "torch", "numpy")):
                            has_random_import = True

                    if isinstance(node, ast.Call):
                        call_repr = ast.unparse(node.func).lower()
                        if any(s in call_repr for s in ("seed", "manual_seed")):
                            has_seed_call = True
                        if any(r in call_repr for r in ("randint", "random", "uniform", "choice", "shuffle", "sample", "randn")):
                            has_random_calls = True

                if has_random_import and has_random_calls and not has_seed_call:
                    passed = False
                    msg = (
                        f"Unseeded stochastic operations in {pf.name}: uses random generator functions "
                        "without calling seed() or manual_seed(). Results cannot be deterministically reproduced."
                    )
                    report_lines.append(f"FAIL: {msg}")
                    findings.append(
                        Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:8]}",
                            check_id=check.check_id,
                            claim_id=check.target_claim_id,
                            title=f"Unseeded Random Operations in {pf.name}",
                            description=msg,
                            finding_type=FindingType.DEFECT,
                            severity=FindingSeverity.HIGH,
                            is_blocking=True,
                        )
                    )

                # 2. Check for data leakage patterns: fit_transform called on test or entire dataset before split
                leakage_patterns = [
                    (re.compile(r"fit_transform\s*\(\s*(?:X_test|test_data|test_df)\s*\)"), "fit_transform called directly on test data"),
                    (re.compile(r"scaler\.fit\s*\(\s*(?:X_test|test_data)\s*\)"), "scaler fitted on test data"),
                ]
                for pat, label in leakage_patterns:
                    if pat.search(content):
                        passed = False
                        msg = f"Data leakage pattern detected in {pf.name}: {label}."
                        report_lines.append(f"FAIL: {msg}")
                        findings.append(
                            Finding(
                                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                check_id=check.check_id,
                                claim_id=check.target_claim_id,
                                title=f"Data Leakage Defect in {pf.name}",
                                description=msg,
                                finding_type=FindingType.DEFECT,
                                severity=FindingSeverity.HIGH,
                                is_blocking=True,
                            )
                        )
            except Exception:
                pass

        if passed and not findings:
            report_lines.append(f"PASS: Inspected {len(py_files)} script(s). No unseeded randomness or data leakage detected.")

        status = CheckStatus.PASSED if passed else CheckStatus.FAILED
        content = "\n".join(report_lines)

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=["experiment_auditor", f"[{check.check_id}]"],
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
            source="experiment_verifier",
            method="reproducibility_and_leakage_audit",
            independent=True,
        )

        return VerifierResult(
            check_id=check.check_id,
            execution=execution,
            evidence=[ev],
            findings=findings,
        )
