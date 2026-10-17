"""Document verification engine (M4 roadmap milestone)."""

import uuid
from datetime import UTC, datetime
from pathlib import Path

from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus
from amaura.models.evidence import EvidenceType
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.verifiers.base import BaseVerifier, VerifierResult


class DocumentVerifier(BaseVerifier):
    """Engine for verifying deliverable existence and section completeness (M4)."""

    name: str = "documents"

    def verify(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        content = "Document verifier is planned for Milestone M4 and is not active in v0.1 kernel."

        ev = collector.add_evidence(
            check_id=check.check_id,
            content=content,
            evidence_type=EvidenceType.EXECUTION_LOG,
            source="document_verifier",
            method="unimplemented_milestone_stub",
        )

        execution = CheckExecution(
            execution_id=exec_id,
            check_id=check.check_id,
            status=CheckStatus.NOT_RUN,
            stdout=content,
            exit_code=0,
            end_time=datetime.now(UTC).isoformat(),
        )

        finding = Finding(
            finding_id=f"find_{uuid.uuid4().hex[:8]}",
            check_id=check.check_id,
            title="Document Verifier Not Active",
            description=content,
            finding_type=FindingType.VERIFICATION_GAP,
            severity=FindingSeverity.INFO,
        )

        return VerifierResult(
            check_id=check.check_id,
            execution=execution,
            evidence=[ev],
            findings=[finding],
        )
