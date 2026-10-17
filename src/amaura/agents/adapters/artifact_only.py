"""Artifact-only agent adapter for auditing completed work."""

from pathlib import Path

from amaura.agents.base import AgentCapability, AgentRunResult, BaseAgentAdapter
from amaura.models.task import TaskSpec


class ArtifactOnlyAdapter(BaseAgentAdapter):
    """Adapter for auditing existing artifacts without executing an external agent."""

    name: str = "artifact_only"
    version: str = "0.1.0"
    capabilities = [AgentCapability.AUDIT_ONLY]
    execution_mode = "passive_inspection"
    limitations = ["Does not generate or modify source code."]

    def execute(self, task: TaskSpec, workspace_dir: Path) -> AgentRunResult:
        files = [str(p.relative_to(workspace_dir)) for p in workspace_dir.rglob("*") if p.is_file()]
        return AgentRunResult(
            adapter_name=self.name,
            success=True,
            modified_files=files,
            output=f"Audited {len(files)} existing workspace files passively.",
        )
