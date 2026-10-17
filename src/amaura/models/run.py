"""RunRecord model aggregating complete execution and verification state."""

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from amaura.models.check import CheckDefinition, CheckExecution
from amaura.models.claim import Claim
from amaura.models.evidence import EvidenceItem
from amaura.models.finding import Finding
from amaura.models.task import TaskSpec


class OverallVerdict(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    SUPPORTED_WITH_LIMITATIONS = "supported_with_limitations"


class RunMode(str, Enum):
    VERIFY = "verify"
    AUDIT = "audit"
    RUN = "run"
    CLAIM_CHECK = "claim_check"


class RunRecord(BaseModel):
    run_id: str
    mode: RunMode = RunMode.VERIFY
    task: TaskSpec
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    working_dir: str
    git_commit: str | None = None
    git_clean: bool | None = None
    claims: list[Claim] = Field(default_factory=list)
    checks: list[CheckDefinition] = Field(default_factory=list)
    executions: list[CheckExecution] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    overall_verdict: OverallVerdict = OverallVerdict.INCONCLUSIVE
    verdict_reasons: list[str] = Field(default_factory=list)
    policy_applied: str = "standard"
    limitations: list[str] = Field(default_factory=list)
    unverified_areas: list[str] = Field(default_factory=list)
    artifacts_manifest: dict[str, str] = Field(default_factory=dict)
