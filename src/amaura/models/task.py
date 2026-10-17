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
    risk_level: RiskLevel = RiskLevel.MEDIUM
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    task_hash: str = ""
    frozen: bool = False

    def compute_hash(self) -> str:
        """Computes deterministic SHA-256 hash of the frozen task specification."""
        content = f"{self.task_id}:{self.instruction}:{len(self.requirements)}"
        for req in sorted(self.requirements, key=lambda r: r.id):
            content += f":{req.id}:{req.description}:{req.mandatory}"
        for c in sorted(self.constraints):
            content += f":{c}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def freeze(self) -> "TaskSpec":
        """Freezes the task specification to prevent silent redefinition of requirements."""
        self.task_hash = self.compute_hash()
        self.frozen = True
        return self
