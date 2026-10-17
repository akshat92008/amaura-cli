"""Evidence models with provenance and cryptographic integrity."""

import hashlib
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    TEST_OUTPUT = "test_output"
    EXECUTION_LOG = "execution_log"
    SOURCE_PASSAGE = "source_passage"
    RECALCULATED_VALUE = "recalculated_value"
    FILE_DIFF = "file_diff"
    ARTIFACT_HASH = "artifact_hash"
    AST_ANALYSIS = "ast_analysis"
    BENCHMARK_RECORD = "benchmark_record"


class Provenance(BaseModel):
    source: str
    method: str
    tool_version: str = "amaura-0.1.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    environment: dict[str, str] = Field(default_factory=dict)
    independent: bool = True


class EvidenceItem(BaseModel):
    evidence_id: str
    check_id: str
    claim_id: str | None = None
    evidence_type: EvidenceType = EvidenceType.EXECUTION_LOG
    content: str
    content_hash: str = ""
    provenance: Provenance
    limitations: list[str] = Field(default_factory=list)

    def model_post_init(self, __context) -> None:
        if not self.content_hash and self.content is not None:
            self.content_hash = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
