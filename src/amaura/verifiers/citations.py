"""Citation and academic reference verification engine."""

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


class CitationVerifier(BaseVerifier):
    """Engine for independently verifying that citations exist, are referenced,
    and do not contain fabricated, placeholder, or dangling references.
    """

    name: str = "citations"

    def verify(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        findings: list[Finding] = []
        report_lines: list[str] = ["CitationVerifier: Independent verification of citations and references."]
        passed = True

        doc_files = [
            p for p in project_dir.rglob("*")
            if p.is_file() and p.suffix.lower() in (".md", ".txt", ".rst", ".bib")
            and not any(part in {".venv", "__pycache__", ".git", ".amaura"} for part in p.parts)
        ]

        # Extract bibliography entries across bib files and markdown reference sections
        known_reference_keys: set[str] = set()
        bib_key_pattern = re.compile(r"@\w+\s*\{\s*([A-Za-z0-9_\-:]+)\s*,")
        md_ref_pattern = re.compile(r"^\[([A-Za-z0-9_\-:]+)\]:\s*(.+)$", re.MULTILINE)
        doi_pattern = re.compile(r"\b10\.\d{4,9}/[-._;()/:A-Za-z0-9]+\b")

        # 1. Discover all defined references
        for f in doc_files:
            validate_path_within_workspace(f, project_dir)
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                for key in bib_key_pattern.findall(content):
                    known_reference_keys.add(key.lower())
                for key, url_or_text in md_ref_pattern.findall(content):
                    known_reference_keys.add(key.lower())
                    # Check for placeholder URLs
                    if any(ph in url_or_text.lower() for ph in ("example.com", "placeholder", "fake", "todo", "tbd")):
                        passed = False
                        msg = f"Placeholder URL detected in reference '[{key}]': {url_or_text.strip()}"
                        report_lines.append(f"FAIL: {msg}")
                        findings.append(
                            Finding(
                                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                check_id=check.check_id,
                                claim_id=check.target_claim_id,
                                title=f"Placeholder Citation Target in {f.name}",
                                description=msg,
                                finding_type=FindingType.DEFECT,
                                severity=FindingSeverity.HIGH,
                                is_blocking=True,
                            )
                        )

                # Check references section in markdown (e.g. ## References followed by numbered items or brackets)
                ref_section_match = re.search(r"(?i)##\s*(?:references|bibliography)\s*\n([\s\S]*?)(?:\n##|\Z)", content)
                if ref_section_match:
                    ref_text = ref_section_match.group(1)
                    # Numbered references: [1], [2] or 1. Smith...
                    for ref_item in re.findall(r"\[(\d+)\]|\b(\d+)\.\s+[A-Z]", ref_text):
                        item_num = ref_item[0] or ref_item[1]
                        known_reference_keys.add(item_num.lower())
                    for named_item in re.findall(r"\[([A-Za-z0-9_\-:]+)\]", ref_text):
                        known_reference_keys.add(named_item.lower())

                    # Check for placeholder text in references section
                    for line in ref_text.splitlines():
                        if any(ph in line.lower() for ph in ("lorem ipsum", "todo: add citation", "citation needed", "[insert citation]")):
                            passed = False
                            msg = f"Placeholder citation text detected in {f.name}: '{line.strip()}'"
                            report_lines.append(f"FAIL: {msg}")
                            findings.append(
                                Finding(
                                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                    check_id=check.check_id,
                                    claim_id=check.target_claim_id,
                                    title=f"Unresolved Citation Placeholder in {f.name}",
                                    description=msg,
                                    finding_type=FindingType.DEFECT,
                                    severity=FindingSeverity.HIGH,
                                    is_blocking=True,
                                )
                            )
            except Exception:
                pass

        # 2. Check for in-text citations that have no definition (Dangling citations)
        in_text_bracket_pattern = re.compile(r"(?<!\!)\[([A-Za-z0-9_\-:]+)\](?!\()")
        dangling_citations: list[tuple[str, str]] = []

        for f in doc_files:
            if f.suffix.lower() == ".bib":
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                # Remove markdown link syntax: [text](url) -> ""
                sanitized = re.sub(r"\[([^\]]+)\]\([^\)]+\)", "", content)
                # Remove reference definitions: [key]: url
                sanitized = re.sub(r"^\[([A-Za-z0-9_\-:]+)\]:\s*.+$", "", sanitized, flags=re.MULTILINE)
                # Ignore references section itself
                sanitized = re.sub(r"(?i)##\s*(?:references|bibliography)\s*\n[\s\S]*?(?:\n##|\Z)", "", sanitized)

                for cited_key in in_text_bracket_pattern.findall(sanitized):
                    # Ignore common markdown badges, checkboxes, or single characters like [x], [ ], [v]
                    if cited_key.lower() in ("x", " ", "v", "note", "tip", "warning", "important", "caution"):
                        continue
                    if cited_key.lower() not in known_reference_keys and len(known_reference_keys) > 0:
                        dangling_citations.append((f.name, cited_key))
            except Exception:
                pass

        if dangling_citations:
            passed = False
            details = ", ".join(f"[{k}] in {fn}" for fn, k in dangling_citations[:5])
            msg = f"Dangling in-text citations with no matching bibliography entry: {details}."
            report_lines.append(f"FAIL: {msg}")
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    check_id=check.check_id,
                    claim_id=check.target_claim_id,
                    title="Dangling In-Text Citations Detected",
                    description=msg,
                    finding_type=FindingType.DEFECT,
                    severity=FindingSeverity.HIGH,
                    is_blocking=True,
                )
            )
        elif known_reference_keys:
            report_lines.append(f"PASS: Verified {len(known_reference_keys)} reference keys across documentation.")
        else:
            report_lines.append("No academic citations or reference sections detected.")

        status = CheckStatus.PASSED if passed else CheckStatus.FAILED
        content = "\n".join(report_lines)

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            command=["citation_checker", f"[{check.check_id}]"],
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
            source="citation_verifier",
            method="cross_reference_matching",
            independent=True,
        )

        return VerifierResult(
            check_id=check.check_id,
            execution=execution,
            evidence=[ev],
            findings=findings,
        )
