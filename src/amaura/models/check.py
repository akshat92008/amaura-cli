"""Check definition and execution record models."""

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    TIMED_OUT = "timed_out"
    NOT_RUN = "not_run"


class CheckType(str, Enum):
    BUILD = "build"
    TEST = "test"
    LINT = "lint"
    ACCEPTANCE_TEST = "acceptance_test"
    TEST_QUALITY = "test_quality"
    ADVERSARIAL = "adversarial"
    RECALCULATION = "recalculation"
    SCHEMA_CHECK = "schema_check"
    CITATION_MATCH = "citation_match"
    DOC_CONSTRAINT = "doc_constraint"
    BENCHMARK = "benchmark"


class CheckDefinition(BaseModel):
    check_id: str
    name: str
    description: str = ""
    check_type: CheckType = CheckType.ACCEPTANCE_TEST
    verifier_name: str = "code"
    command: list[str] | None = None
    mandatory: bool = True
    timeout_seconds: int = 30
    target_requirement_id: str | None = None
    target_claim_id: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class CheckExecution(BaseModel):
    execution_id: str
    check_id: str
    command: list[str] = Field(default_factory=list)
    start_time: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    end_time: str = ""
    duration_ms: int = 0
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    status: CheckStatus = CheckStatus.NOT_RUN
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    error_message: str | None = None
    executed_by_tool: str = "amaura"
