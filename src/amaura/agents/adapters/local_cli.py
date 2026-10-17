"""Local CLI agent adapter for running external AI coding agents in an isolated workspace."""

import time
from pathlib import Path

from amaura.agents.base import AgentCapability, AgentRunResult, BaseAgentAdapter
from amaura.models.task import TaskSpec
from amaura.security.process import run_safe_process


class LocalCLIAdapter(BaseAgentAdapter):
    """Adapter executing an external installed agent binary (e.g., local CLI tool) in an isolated workspace."""

    name: str = "local_cli"
    version: str = "0.1.0"
    capabilities = [AgentCapability.CODE_EDIT]
    execution_mode = "subcommand_isolated"
    limitations = ["Depends on host installation and tool CLI interface."]

    def __init__(self, cli_command: list[str] | None = None):
        self.cli_command = cli_command or ["echo", "Agent finished task."]

    def execute(self, task: TaskSpec, workspace_dir: Path) -> AgentRunResult:
        start_t = time.perf_counter()
        proc_res = run_safe_process(
            command=self.cli_command,
            cwd=workspace_dir,
            timeout_seconds=60,
        )
        duration_ms = int((time.perf_counter() - start_t) * 1000)

        return AgentRunResult(
            adapter_name=self.name,
            success=proc_res.exit_code == 0,
            output=proc_res.stdout,
            error_message=proc_res.stderr if proc_res.exit_code != 0 else None,
            execution_time_ms=duration_ms,
        )
