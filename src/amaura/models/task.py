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
        """Computes deterministic SHA-256 hash of the complete task specification."""
        content = f"{self.task_id}:{self.instruction}:{self.risk_level.value}:{len(self.requirements)}"
        for req in sorted(self.requirements, key=lambda r: r.id):
            crit_str = ",".join(sorted(req.acceptance_criteria))
            content += f":{req.id}:{req.description}:{req.mandatory}:{req.risk_level.value}:{req.domain}:{crit_str}"
        for c in sorted(self.constraints):
            content += f":constraint:{c}"
        for a in sorted(self.assumptions):
            content += f":assumption:{a}"
        for ac in sorted(self.acceptance_criteria):
            content += f":acceptance:{ac}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def freeze(self) -> "TaskSpec":
        """Freezes the task specification to prevent silent redefinition of requirements."""
        self.task_hash = self.compute_hash()
        self.frozen = True
        return self

    def verify_hash(self) -> bool:
        """Verifies that the task content has not been tampered with or altered since freezing."""
        if not self.task_hash:
            return False
        return self.compute_hash() == self.task_hash
