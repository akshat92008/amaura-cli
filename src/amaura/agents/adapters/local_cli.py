"""Local CLI agent adapter for running external AI coding agents in an isolated workspace."""

import hashlib
import time
from pathlib import Path

from amaura.agents.base import AgentCapability, AgentRunResult, BaseAgentAdapter
from amaura.errors import AdapterError
from amaura.models.task import TaskSpec
from amaura.security.process import run_agent_process


def format_task_markdown(task: TaskSpec) -> str:
    """Formats a TaskSpec into clear markdown instructions for coding agents."""
    lines = [f"# Task: {task.task_id}", "", task.instruction, ""]
    if task.requirements:
        lines.append("## Requirements")
        for req in task.requirements:
            crit = f" (Acceptance: {', '.join(req.acceptance_criteria)})" if req.acceptance_criteria else ""
            lines.append(f"- {req.id}: {req.description}{crit}")
        lines.append("")
    if task.constraints:
        lines.append("## Constraints")
        for c in task.constraints:
            lines.append(f"- {c}")
        lines.append("")
    if task.assumptions:
        lines.append("## Assumptions")
        for a in task.assumptions:
            lines.append(f"- {a}")
        lines.append("")
    if task.acceptance_criteria:
        lines.append("## Acceptance Criteria")
        for ac in task.acceptance_criteria:
            lines.append(f"- {ac}")
        lines.append("")
    return "\n".join(lines)


def _snapshot_workspace(workspace_dir: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for p in workspace_dir.rglob("*"):
        if p.is_file():
            try:
                rel = str(p.relative_to(workspace_dir))
                snapshot[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                pass
    return snapshot


class LocalCLIAdapter(BaseAgentAdapter):
    """Adapter executing an external installed agent binary (e.g., local CLI tool) in an isolated workspace."""

    name: str = "local_cli"
    version: str = "0.1.0"
    capabilities = [AgentCapability.CODE_EDIT]
    execution_mode = "subcommand_isolated"
    limitations = ["Depends on host installation and tool CLI interface."]

    def __init__(self, cli_command: list[str] | None = None):
        self.cli_command = cli_command

    def execute(self, task: TaskSpec, workspace_dir: Path) -> AgentRunResult:
        if not self.cli_command:
            raise AdapterError(
                "LocalCLIAdapter requires an explicit agent CLI command. Specify --agent-cmd or configure cli_command."
            )

        # F1: Write task instructions into workspace for file-reading agents
        task_md = workspace_dir / "task.md"
        task_content = format_task_markdown(task)
        task_md.write_text(task_content, encoding="utf-8")

        # F3: Snapshot workspace after writing task.md to track agent modifications accurately
        pre_snapshot = _snapshot_workspace(workspace_dir)

        # F1: Substitute placeholders in cli_command
        formatted_cmd: list[str] = []
        for token in self.cli_command:
            sub = (
                token.replace("{task_file}", str(task_md.resolve()))
                .replace("{prompt}", task_content)
                .replace("{task}", task.instruction)
                .replace("{task_id}", task.task_id)
                .replace("{workspace}", str(workspace_dir.resolve()))
            )
            formatted_cmd.append(sub)

        env = {
            "AMAURA_TASK_FILE": str(task_md.resolve()),
            "AMAURA_TASK_ID": task.task_id,
            "AMAURA_TASK_PROMPT": task_content,
            "AMAURA_TASK_INSTRUCTION": task.instruction,
        }

        # F2: Execute via run_agent_process (preserving API keys, real HOME, and allowing network)
        start_t = time.perf_counter()
        proc_res = run_agent_process(
            command=formatted_cmd,
            cwd=workspace_dir,
            env=env,
            timeout_seconds=60,
        )
        duration_ms = int((time.perf_counter() - start_t) * 1000)

        # F3: Determine exact added, modified, or deleted files
        post_snapshot = _snapshot_workspace(workspace_dir)
        modified_files = sorted(
            [rel for rel, h in post_snapshot.items() if rel not in pre_snapshot or pre_snapshot[rel] != h]
            + [rel for rel in pre_snapshot if rel not in post_snapshot]
        )

        return AgentRunResult(
            adapter_name=self.name,
            success=proc_res.exit_code == 0,
            modified_files=modified_files,
            output=proc_res.stdout,
            error_message=proc_res.stderr if proc_res.exit_code != 0 else None,
            execution_time_ms=duration_ms,
        )
