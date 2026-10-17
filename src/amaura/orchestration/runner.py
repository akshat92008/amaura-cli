"""Execution orchestrator providing isolated execution, non-destructive audits, and tamper validation."""

from pathlib import Path
from typing import Optional

from amaura.agents.registry import AgentRegistry
from amaura.config import AmauraConfig, PolicyProfile
from amaura.errors import ExecutionSecurityError
from amaura.evidence.hashing import create_directory_manifest, verify_manifest_integrity
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

    default_text = f"# Task: Verify {project_dir.name}\n\n## Requirements\n- Ensure code compiles and passes tests."
    return parse_markdown_task(default_text, filename="default_task.md")


def verify_project(
    project_dir: Path,
    task_file: Optional[Path] = None,
    policy_profile: Optional[PolicyProfile] = None,
    config: Optional[AmauraConfig] = None,
) -> RunRecord:
    """Runs verification on a project directory inside an isolated disposable workspace."""
    cfg = config or AmauraConfig.load(start_dir=project_dir)
    pipeline = VerificationPipeline(cfg)

    task = load_task_file(task_file) if task_file else find_or_create_default_task(project_dir)

    # Always execute checks in an isolated disposable copy to prevent mutating the original
    with isolated_workspace(project_dir) as ws:
        return pipeline.run(
            project_dir=ws,
            task=task,
            mode=RunMode.VERIFY,
            policy_override=policy_profile,
        )


def audit_project(
    project_dir: Path,
    task_file: Optional[Path] = None,
    config: Optional[AmauraConfig] = None,
) -> RunRecord:
    """Audits existing completed work non-destructively in an isolated workspace,
    strictly verifying that the audited directory remains completely untouched.
    """
    cfg = config or AmauraConfig.load(start_dir=project_dir)
    pipeline = VerificationPipeline(cfg)

    task = load_task_file(task_file) if task_file else find_or_create_default_task(project_dir)

    # Snapshot original project directory manifest before audit
    initial_manifest = create_directory_manifest(project_dir)

    with isolated_workspace(project_dir) as ws:
        record = pipeline.run(
            project_dir=ws,
            task=task,
            mode=RunMode.AUDIT,
        )

    # Guarantee non-destructive audit: verify original project directory is unchanged
    is_valid, discrepancies = verify_manifest_integrity(project_dir, initial_manifest)
    if not is_valid:
        raise ExecutionSecurityError(
            "Non-destructive audit violation: Source project was modified during audit!\n" + "\n".join(discrepancies)
        )

    return record


def check_claims(
    claims_file: Path,
    project_dir: Optional[Path] = None,
    config: Optional[AmauraConfig] = None,
) -> RunRecord:
    """Verifies explicit claims from a claims file against a project."""
    target_dir = (project_dir or Path.cwd()).resolve()
    cfg = config or AmauraConfig.load(start_dir=target_dir)
    pipeline = VerificationPipeline(cfg)

    claims = load_claims_file(claims_file)
    task = find_or_create_default_task(target_dir)

    with isolated_workspace(target_dir) as ws:
        return pipeline.run(
            project_dir=ws,
            task=task,
            claims=claims,
            mode=RunMode.CLAIM_CHECK,
        )


def run_and_verify(
    task_file: Path,
    agent_name: str = "artifact_only",
    project_dir: Optional[Path] = None,
    policy_profile: Optional[PolicyProfile] = None,
    config: Optional[AmauraConfig] = None,
) -> RunRecord:
    """Executes an agent in an isolated workspace, then independently verifies output."""
    base_dir = (project_dir or Path.cwd()).resolve()
    cfg = config or AmauraConfig.load(start_dir=base_dir)
    task = load_task_file(task_file)

    agent_registry = AgentRegistry()
    adapter = agent_registry.get(agent_name)  # Will raise AdapterError on unknown name

    with isolated_workspace(base_dir) as ws:
        # Run agent
        agent_res = adapter.execute(task, ws)

        # Verify result in isolated workspace
        pipeline = VerificationPipeline(cfg)
        record = pipeline.run(
            project_dir=ws,
            task=task,
            mode=RunMode.RUN,
            policy_override=policy_profile,
        )

        # Record agent execution metadata into record
        record.limitations.append(f"Agent '{agent_name}' result: success={agent_res.success}")

    return record
