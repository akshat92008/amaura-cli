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
        pre_snapshot = {
            str(p.relative_to(workspace_dir)): p.read_bytes()
            for p in workspace_dir.rglob("*")
            if p.is_file()
        }
        if self.action:
            self.action(workspace_dir)
        post_snapshot = {
            str(p.relative_to(workspace_dir)): p.read_bytes()
            for p in workspace_dir.rglob("*")
            if p.is_file()
        }
        modified = sorted(
            [rel for rel, b in post_snapshot.items() if rel not in pre_snapshot or pre_snapshot[rel] != b]
            + [rel for rel in pre_snapshot if rel not in post_snapshot]
        )
        return AgentRunResult(
            adapter_name=self.name,
            success=True,
            modified_files=modified,
            output="Mock agent execution completed.",
        )
