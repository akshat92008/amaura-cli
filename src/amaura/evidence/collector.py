"""Evidence collection service."""

import uuid

from amaura.evidence.hashing import hash_string
from amaura.evidence.provenance import build_provenance
from amaura.models.evidence import EvidenceItem, EvidenceType
from amaura.security.redaction import redact_secrets


class EvidenceCollector:
    """Collects and stores verifiable evidence items during a run."""

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.items: list[EvidenceItem] = []
        self._item_map: dict[str, EvidenceItem] = {}

    def add_evidence(
        self,
        check_id: str,
        content: str,
        evidence_type: EvidenceType = EvidenceType.EXECUTION_LOG,
        claim_id: str | None = None,
        source: str = "execution_runner",
        method: str = "subprocess_capture",
        independent: bool = False,
        limitations: list[str] | None = None,
    ) -> EvidenceItem:
        """Creates and indexes a new EvidenceItem with automated secret scrubbing."""
        evidence_id = f"ev_{uuid.uuid4().hex[:10]}"
        provenance = build_provenance(source=source, method=method, independent=independent)

        sanitized_content = redact_secrets(content)
        item = EvidenceItem(
            evidence_id=evidence_id,
            check_id=check_id,
            claim_id=claim_id,
            evidence_type=evidence_type,
            content=sanitized_content,
            content_hash=hash_string(sanitized_content),
            provenance=provenance,
            limitations=limitations or [],
        )

        self.items.append(item)
        self._item_map[evidence_id] = item
        return item

    def get_evidence(self, evidence_id: str) -> EvidenceItem | None:
        return self._item_map.get(evidence_id)

    def get_for_check(self, check_id: str) -> list[EvidenceItem]:
        return [item for item in self.items if item.check_id == check_id]

    def get_for_claim(self, claim_id: str) -> list[EvidenceItem]:
        return [item for item in self.items if item.claim_id == claim_id]
