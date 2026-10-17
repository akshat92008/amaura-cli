"""Mock agent adapter for deterministic testing and benchmark validation."""

from collections.abc import Callable
from pathlib import Path

from amaura.agents.base import AgentCapability, AgentRunResult, BaseAgentAdapter
from amaura.models.task import TaskSpec


class MockAgentAdapter(BaseAgentAdapter):
    """Adapter for testing that can inject predefined code changes or simulate failure states."""

    name: str = "mock_agent"
    version: str = "0.1.0"
    capabilities = [AgentCapability.CODE_EDIT, AgentCapability.AUDIT_ONLY]
    execution_mode = "in_process_mock"
    limitations = ["Only for testing and regression suites."]

    def __init__(self, action: Callable[[Path], None] | None = None):
        self.action = action

    def execute(self, task: TaskSpec, workspace_dir: Path) -> AgentRunResult:
        if self.action:
            self.action(workspace_dir)
        return AgentRunResult(
            adapter_name=self.name,
            success=True,
            output="Mock agent execution completed.",
        )
