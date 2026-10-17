"""Base agent adapter contract and interface."""

from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel, Field

from amaura.models.task import TaskSpec


class AgentCapability(str):
    CODE_EDIT = "code_edit"
    RESEARCH = "research"
    DATA_ANALYSIS = "data_analysis"
    AUDIT_ONLY = "audit_only"
    INTERACTIVE = "interactive"


class AgentRunResult(BaseModel):
    adapter_name: str
    success: bool
    modified_files: list[str] = Field(default_factory=list)
    output: str = ""
    error_message: str | None = None
    execution_time_ms: int = 0
    metadata: dict[str, str] = Field(default_factory=dict)


class BaseAgentAdapter(ABC):
    """Abstract base class for all pluggable agent adapters."""

    name: str = "base"
    version: str = "0.1.0"
    capabilities: list[str] = []
    execution_mode: str = "unspecified"
    limitations: list[str] = []

    @abstractmethod
    def execute(self, task: TaskSpec, workspace_dir: Path) -> AgentRunResult:
        """Executes an agent workflow against the target workspace directory."""
