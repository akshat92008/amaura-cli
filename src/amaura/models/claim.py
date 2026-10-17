"""Claim models and typed verification statuses."""

from enum import Enum

from pydantic import BaseModel, Field


class ClaimType(str, Enum):
    FACTUAL = "factual"
    BEHAVIORAL = "behavioral"
    NUMERICAL = "numerical"
    PROCEDURAL = "procedural"
    CAUSAL = "causal"
    EVALUATIVE = "evaluative"


class ClaimOrigin(str, Enum):
    USER_REQUIREMENT = "user_requirement"
    AGENT_OUTPUT = "agent_output"
    EXTERNAL_SOURCE = "external_source"
    SYSTEM_INFERENCE = "system_inference"


class ClaimStatus(str, Enum):
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    INCONCLUSIVE = "inconclusive"
    NOT_CHECKED = "not_checked"
    NOT_APPLICABLE = "not_applicable"


class Claim(BaseModel):
    claim_id: str
    text: str
    claim_type: ClaimType = ClaimType.BEHAVIORAL
    origin: ClaimOrigin = ClaimOrigin.USER_REQUIREMENT
    importance: str = "high"  # low, medium, high, critical
    required_evidence: str = ""
    status: ClaimStatus = ClaimStatus.NOT_CHECKED
    target_requirement_id: str | None = None
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
