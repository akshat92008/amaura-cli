"""Base verifier interface and result types."""

from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel, Field

from amaura.config import AmauraConfig
from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckExecution
from amaura.models.evidence import EvidenceItem
from amaura.models.finding import Finding


class VerifierResult(BaseModel):
    check_id: str
    execution: CheckExecution
    evidence: list[EvidenceItem] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class BaseVerifier(ABC):
    """Abstract base class for all domain-specific verification engines."""

    name: str = "base"

    def __init__(self, config: AmauraConfig | None = None):
        self.config = config or AmauraConfig()

    @abstractmethod
    def verify(
        self,
        project_dir: Path,
        check: CheckDefinition,
        collector: EvidenceCollector,
    ) -> VerifierResult:
        """Executes verification check against target project and returns structured result."""
