"""Document and deliverable verification engine."""

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus
from amaura.models.evidence import EvidenceType
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.verifiers.base import BaseVerifier, VerifierResult


class DocumentVerifier(BaseVerifier):
    """Engine for verifying document deliverables, section completeness,
    required headers, and absence of placeholder text.
    """

    name: str = "documents"

    def verify(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        findings: list[Finding] = []
        report_lines: list[str] = ["DocumentVerifier: Independent document structure and deliverable completeness verification."]
        passed = True

        # 1. Verify required target file if specified
        target_rel = check.metadata.get("target_file")
        if target_rel:
            target_file = project_dir / target_rel
            if not target_file.is_file() or target_file.stat().st_size == 0:
                passed = False
                msg = f"Required deliverable file '{target_rel}' is missing or empty."
                report_lines.append(f"FAIL: {msg}")
                findings.append(
                    Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:8]}",
                        check_id=check.check_id,
                        claim_id=check.target_claim_id,
                        title=f"Missing Deliverable: {target_rel}",
                        description=msg,
                        finding_type=FindingType.DEFECT,
                        severity=FindingSeverity.HIGH,
                        is_blocking=True,
                    )
                )

        # 2. Inspect all markdown and deliverable documentation in project
        doc_files = [
            p for p in project_dir.rglob("*")
            if p.is_file() and p.suffix.lower() in (".md", ".rst", ".txt")
            and not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts)
        ]

        # Check required sections if configured
        req_sections_str = check.metadata.get("required_sections")
        required_sections = [s.strip().lower() for s in req_sections_str.split(",")] if req_sections_str else []

        for df in doc_files:
            try:
                content = df.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                # Extract markdown headings (# Title, ## Section)
                headings: list[str] = []
                for line in lines:
                    m = re.match(r"^#{1,6}\s+(.+)$", line)
                    if m:
                        headings.append(m.group(1).strip())

                # Check required sections
                if required_sections:
                    found_headings_lower = [h.lower() for h in headings]
                    for req_sec in required_sections:
                        if not any(req_sec in h for h in found_headings_lower):
                            passed = False
                            msg = f"Document '{df.name}' is missing required section: '{req_sec}'."
                            report_lines.append(f"FAIL: {msg}")
                            findings.append(
                                Finding(
                                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                    check_id=check.check_id,
                                    claim_id=check.target_claim_id,
                                    title=f"Missing Required Section in {df.name}",
                                    description=msg,
                                    finding_type=FindingType.DEFECT,
                                    severity=FindingSeverity.HIGH,
                                    is_blocking=True,
                                )
                            )

                # Check for empty sections (heading followed immediately by another heading)
                for i in range(len(lines) - 1):
                    line = lines[i].strip()
                    next_line = lines[i + 1].strip()
                    if line.startswith("#") and next_line.startswith("#"):
                        # Empty heading with zero body text
                        findings.append(
                            Finding(
                                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                check_id=check.check_id,
                                claim_id=check.target_claim_id,
                                title=f"Empty Section in {df.name}",
                                description=f"Section '{line}' contains no body content before '{next_line}'.",
                                finding_type=FindingType.TEST_GAP,
                                severity=FindingSeverity.MEDIUM,
                                is_blocking=False,
                            )
                        )

                # Check for placeholder text (TODO, TBD, FIXME, Lorem ipsum)
                placeholder_patterns = [
                    (r"\bTODO\b", "TODO placeholder"),
                    (r"\bTBD\b", "TBD placeholder"),
                    (r"\bFIXME\b", "FIXME placeholder"),
                    (r"(?i)lorem ipsum", "Lorem Ipsum filler text"),
                    (r"\[insert\s+[^\]]+\]", "Bracketed insert prompt"),
                ]
                for pat, label in placeholder_patterns:
                    matches = re.findall(pat, content)
                    if matches:
                        msg = f"Found {len(matches)} instance(s) of {label} in {df.name}."
                        report_lines.append(f"WARN: {msg}")
                        findings.append(
                            Finding(
                                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                check_id=check.check_id,
                                claim_id=check.target_claim_id,
                                title=f"Placeholder Text in {df.name}",
                                description=msg,
                                finding_type=FindingType.TEST_GAP,
                                severity=FindingSeverity.MEDIUM,
                                is_blocking=False,
                            )
                        )
            except Exception:
                pass

        if passed and not [f for f in findings if f.is_blocking]:
            report_lines.append(f"PASS: Inspected {len(doc_files)} document(s). Structure and required sections verified.")

        status = CheckStatus.PASSED if passed else CheckStatus.FAILED
        content = "\n".join(report_lines)

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=["document_inspector", f"[{check.check_id}]"],
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
            source="document_verifier",
            method="markdown_structure_and_completeness_scan",
            independent=True,
        )

        return VerifierResult(
            check_id=check.check_id,
            execution=execution,
            evidence=[ev],
            findings=findings,
        )
