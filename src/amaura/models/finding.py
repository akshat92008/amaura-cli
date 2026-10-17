"""Finding models representing structured conclusions from verification."""

from enum import Enum

from pydantic import BaseModel, Field


class FindingType(str, Enum):
    DEFECT = "defect"
    UNMET_REQUIREMENT = "unmet_requirement"
    CONTRADICTION = "contradiction"
    TEST_GAP = "test_gap"
    SECURITY_RISK = "security_risk"
    VERIFICATION_GAP = "verification_gap"
    SUPPORTED_ASSERTION = "supported_assertion"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    finding_id: str
    check_id: str
    claim_id: str | None = None
    title: str
    description: str
    finding_type: FindingType = FindingType.DEFECT
    severity: FindingSeverity = FindingSeverity.MEDIUM
    evidence_ids: list[str] = Field(default_factory=list)
    remediation_suggestion: str | None = None
    is_blocking: bool = False
