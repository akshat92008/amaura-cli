"""Task specification and requirement models."""

import hashlib
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Requirement(BaseModel):
    id: str
    description: str
    mandatory: bool = True
    risk_level: RiskLevel = RiskLevel.MEDIUM
    domain: str = "code"
    acceptance_criteria: list[str] = Field(default_factory=list)


class TaskSpec(BaseModel):
    task_id: str
    instruction: str
    requirements: list[Requirement] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    acceptance_criteria: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    task_hash: str = ""
    frozen: bool = False

    def compute_hash(self) -> str:
        """Computes deterministic, canonical SHA-256 hash of the complete task specification."""
        import json
        payload = {
            "task_id": self.task_id,
            "instruction": self.instruction,
            "risk_level": self.risk_level.value,
            "requirements": [
                {
                    "id": req.id,
                    "description": req.description,
                    "mandatory": req.mandatory,
                    "risk_level": req.risk_level.value,
                    "domain": req.domain,
                    "acceptance_criteria": sorted(req.acceptance_criteria),
                }
                for req in sorted(self.requirements, key=lambda r: r.id)
            ],
            "constraints": sorted(self.constraints),
            "assumptions": sorted(self.assumptions),
            "acceptance_criteria": sorted(self.acceptance_criteria),
        }
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def freeze(self) -> "TaskSpec":
        """Freezes the task specification to prevent silent redefinition of requirements."""
        self.task_hash = self.compute_hash()
        self.frozen = True
        return self

    def verify_hash(self, expected_hash: str | None = None) -> bool:
        """Verifies that the task content matches an expected hash or has not been altered since freezing."""
        computed = self.compute_hash()
        if expected_hash:
            return computed == expected_hash
        if not self.task_hash:
            return False
        return computed == self.task_hash
