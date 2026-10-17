"""Execution orchestrator providing high-level commands for runs, audits, and verifications."""

from pathlib import Path

from amaura.agents.registry import AgentRegistry
from amaura.config import AmauraConfig, PolicyProfile
from amaura.models.run import RunMode, RunRecord
from amaura.models.task import TaskSpec
from amaura.orchestration.pipeline import VerificationPipeline
from amaura.planning.claims import load_claims_file
from amaura.planning.requirements import load_task_file, parse_markdown_task
from amaura.security.workspace import isolated_workspace


def find_or_create_default_task(project_dir: Path) -> TaskSpec:
    """Attempts to discover task.md or generates default task specification."""
    for candidate_name in ["task.md", "TASK.md", "requirements.md"]:
        candidate = project_dir / candidate_name
        if candidate.is_file():
            return load_task_file(candidate)

    # Fallback default task
    default_text = f"# Task: Verify {project_dir.name}\n\n## Requirements\n- Ensure code compiles and passes tests."
    return parse_markdown_task(default_text, filename="default_task.md")


def verify_project(
    project_dir: Path,
    task_file: Path | None = None,
    policy_profile: PolicyProfile | None = None,
    config: AmauraConfig | None = None,
) -> RunRecord:
    """Runs standard verification on a project directory."""
    cfg = config or AmauraConfig.load(start_dir=project_dir)
    pipeline = VerificationPipeline(cfg)

    task = load_task_file(task_file) if task_file else find_or_create_default_task(project_dir)
    return pipeline.run(
        project_dir=project_dir,
        task=task,
        mode=RunMode.VERIFY,
        policy_override=policy_profile,
    )


def audit_project(
    project_dir: Path,
    task_file: Path | None = None,
    config: AmauraConfig | None = None,
) -> RunRecord:
    """Audits existing completed work non-destructively without executing modifying agents."""
    cfg = config or AmauraConfig.load(start_dir=project_dir)
    pipeline = VerificationPipeline(cfg)

    task = load_task_file(task_file) if task_file else find_or_create_default_task(project_dir)
    return pipeline.run(
        project_dir=project_dir,
        task=task,
        mode=RunMode.AUDIT,
    )


def check_claims(
    claims_file: Path,
    project_dir: Path | None = None,
    config: AmauraConfig | None = None,
) -> RunRecord:
    """Verifies explicit claims from a claims file against a project."""
    target_dir = (project_dir or Path.cwd()).resolve()
    cfg = config or AmauraConfig.load(start_dir=target_dir)
    pipeline = VerificationPipeline(cfg)

    claims = load_claims_file(claims_file)
    task = find_or_create_default_task(target_dir)

    return pipeline.run(
        project_dir=target_dir,
        task=task,
        claims=claims,
        mode=RunMode.CLAIM_CHECK,
    )


def run_and_verify(
    task_file: Path,
    agent_name: str = "artifact_only",
    project_dir: Path | None = None,
    policy_profile: PolicyProfile | None = None,
    config: AmauraConfig | None = None,
) -> RunRecord:
    """Executes an agent in an isolated workspace, then independently verifies output."""
    base_dir = (project_dir or Path.cwd()).resolve()
    cfg = config or AmauraConfig.load(start_dir=base_dir)
    task = load_task_file(task_file)

    agent_registry = AgentRegistry()
    adapter = agent_registry.get(agent_name)

    # Use isolated workspace for execution
    with isolated_workspace(base_dir) as ws:
        # Run agent
        adapter.execute(task, ws)
        # Verify result in isolated workspace
        pipeline = VerificationPipeline(cfg)
        record = pipeline.run(
            project_dir=ws,
            task=task,
            mode=RunMode.RUN,
            policy_override=policy_profile,
        )

    return record
