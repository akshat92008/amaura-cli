"""Data and schema verification engine."""

import csv
import uuid
from datetime import UTC, datetime
from pathlib import Path

from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus
from amaura.models.evidence import EvidenceType
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.security.workspace import validate_path_within_workspace
from amaura.verifiers.base import BaseVerifier, VerifierResult


class DataVerifier(BaseVerifier):
    """Engine for independently validating CSV, tabular data schemas, duplicates, and row integrity."""

    name: str = "data"

    def verify(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        csv_files = list(project_dir.rglob("*.csv"))

        findings: list[Finding] = []
        report_lines = [f"DataVerifier: Inspecting {len(csv_files)} CSV data files."]
        all_passed = True

        for cf in csv_files:
            validate_path_within_workspace(cf, project_dir)
            try:
                with open(cf, "r", encoding="utf-8", errors="replace") as f:
                    reader = csv.reader(f)
                    header = next(reader, None)
                    if not header:
                        report_lines.append(f"{cf.name}: Warning - Empty CSV file.")
                        continue

                    expected_cols = len(header)
                    seen_rows = set()
                    duplicate_count = 0
                    malformed_rows = []

                    for line_no, row in enumerate(reader, start=2):
                        if len(row) != expected_cols:
                            malformed_rows.append(f"Line {line_no}: expected {expected_cols} cols, found {len(row)}")
                        row_tuple = tuple(row)
                        if row_tuple in seen_rows:
                            duplicate_count += 1
                        else:
                            seen_rows.add(row_tuple)

                    if malformed_rows:
                        all_passed = False
                        msg = f"{cf.name} contains {len(malformed_rows)} malformed rows: " + "; ".join(malformed_rows[:5])
                        report_lines.append(f"ERROR: {msg}")
                        findings.append(
                            Finding(
                                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                check_id=check.check_id,
                                title=f"Malformed Data Rows in {cf.name}",
                                description=msg,
                                finding_type=FindingType.DEFECT,
                                severity=FindingSeverity.HIGH,
                            )
                        )

                    if duplicate_count > 0:
                        report_lines.append(f"{cf.name}: detected {duplicate_count} duplicate rows.")

            except Exception as e:
                all_passed = False
                err_msg = f"Failed to parse CSV {cf.name}: {e!s}"
                report_lines.append(f"ERROR: {err_msg}")
                findings.append(
                    Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:8]}",
                        check_id=check.check_id,
                        title=f"Data Ingestion Error in {cf.name}",
                        description=err_msg,
                        finding_type=FindingType.DEFECT,
                        severity=FindingSeverity.HIGH,
                    )
                )

        status = CheckStatus.PASSED if all_passed else CheckStatus.FAILED
        content = "\n".join(report_lines)
        ev = collector.add_evidence(
            check_id=check.check_id,
            content=content,
            evidence_type=EvidenceType.EXECUTION_LOG,
            source="data_verifier",
            method="csv_schema_inspection",
        )

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            status=status,
            stdout=content,
            exit_code=0 if all_passed else 1,
            end_time=datetime.now(UTC).isoformat(),
        )

        return VerifierResult(
            check_id=check.check_id,
            execution=execution,
            evidence=[ev],
            findings=findings,
        )
