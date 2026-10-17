"""High-level runner APIs orchestrating verification, claim checks, and agent runs."""

import uuid
from pathlib import Path
from typing import Optional

from amaura.agents.adapters.local_cli import LocalCLIAdapter
from amaura.agents.registry import AgentRegistry
from amaura.config import AmauraConfig, PolicyProfile
from amaura.errors import ExecutionSecurityError
from amaura.evidence.hashing import create_directory_manifest, verify_manifest_integrity
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.models.run import OverallVerdict, RunMode, RunRecord
from amaura.models.task import TaskSpec
from amaura.orchestration.pipeline import VerificationPipeline
from amaura.planning.claims import load_claims_file
from amaura.planning.requirements import load_task_file, parse_markdown_task
from amaura.security.workspace import isolated_workspace


def find_or_create_default_task(project_dir: Path, caller_dir: Optional[Path] = None) -> TaskSpec:
    """Discovers task.md from caller_dir or generates an immutable strict default task specification.
    Never blindly trusts task.md discovered inside the untrusted project directory!
    """
    search_dir = caller_dir or Path.cwd()
    for candidate_name in ["task.md", "TASK.md", "requirements.md"]:
        candidate = search_dir / candidate_name
        if candidate.is_file():
            return load_task_file(candidate)

    default_text = f"# Task: Verify {project_dir.name}\n\n## Requirements\n- Ensure all tests pass without failures or unhandled crashes."
    return parse_markdown_task(default_text, filename="default_task.md")


def verify_project(
    project_dir: Path,
    task_file: Optional[Path] = None,
    expected_hash: Optional[str] = None,
    policy_profile: Optional[PolicyProfile] = None,
    config: Optional[AmauraConfig] = None,
) -> RunRecord:
    """Runs verification on a project directory inside an isolated disposable workspace."""
    cfg = config or AmauraConfig.load(start_dir=Path.cwd())
    pipeline = VerificationPipeline(cfg)

    task = (
        load_task_file(task_file, expected_hash=expected_hash)
        if task_file
        else find_or_create_default_task(project_dir, caller_dir=Path.cwd())
    )

    # Always execute checks in an isolated disposable copy to prevent mutating the original
    with isolated_workspace(project_dir) as ws:
        return pipeline.run(
            project_dir=ws,
            task=task,
            source_dir=project_dir,
            mode=RunMode.VERIFY,
            policy_override=policy_profile,
        )


def audit_project(
    project_dir: Path,
    task_file: Optional[Path] = None,
    expected_hash: Optional[str] = None,
    config: Optional[AmauraConfig] = None,
) -> RunRecord:
    """Audits existing completed work non-destructively in an isolated workspace,
    strictly verifying that the audited directory remains completely untouched.
    """
    cfg = config or AmauraConfig.load(start_dir=Path.cwd())
    pipeline = VerificationPipeline(cfg)

    task = (
        load_task_file(task_file, expected_hash=expected_hash)
        if task_file
        else find_or_create_default_task(project_dir, caller_dir=Path.cwd())
    )

    # Snapshot original project directory manifest before audit
    initial_manifest = create_directory_manifest(project_dir)

    with isolated_workspace(project_dir) as ws:
        record = pipeline.run(
            project_dir=ws,
            task=task,
            source_dir=project_dir,
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
    cfg = config or AmauraConfig.load(start_dir=Path.cwd())
    pipeline = VerificationPipeline(cfg)

    claims = load_claims_file(claims_file)
    task = find_or_create_default_task(target_dir, caller_dir=Path.cwd())

    with isolated_workspace(target_dir) as ws:
        return pipeline.run(
            project_dir=ws,
            task=task,
            claims=claims,
            source_dir=target_dir,
            mode=RunMode.CLAIM_CHECK,
        )


def run_and_verify(
    task_file: Path,
    agent_name: str = "artifact_only",
    agent_command: Optional[list[str]] = None,
    expected_hash: Optional[str] = None,
    project_dir: Optional[Path] = None,
    policy_profile: Optional[PolicyProfile] = None,
    config: Optional[AmauraConfig] = None,
) -> RunRecord:
    """Executes an agent in an isolated workspace, then independently verifies output."""
    base_dir = (project_dir or Path.cwd()).resolve()
    cfg = config or AmauraConfig.load(start_dir=Path.cwd())
    task = load_task_file(task_file, expected_hash=expected_hash)

    agent_registry = AgentRegistry()
    adapter = agent_registry.get(agent_name)  # Will raise AdapterError on unknown name
    if isinstance(adapter, LocalCLIAdapter) and agent_command:
        adapter.cli_command = agent_command

    with isolated_workspace(base_dir, max_size_bytes=cfg.budget.max_workspace_bytes) as ws:
        # Run agent
        agent_res = adapter.execute(task, ws)

        # Verify result in isolated workspace
        pipeline = VerificationPipeline(cfg)
        record = pipeline.run(
            project_dir=ws,
            task=task,
            source_dir=base_dir,
            mode=RunMode.RUN,
            policy_override=policy_profile,
            extra_limitations=[f"Agent '{agent_name}' result: success={agent_res.success}"],
        )

        # F4: Record agent token and cost usage
        if agent_res.usage:
            record.agent_usage = agent_res.usage
            record.limitations.append(
                f"Agent usage: {agent_res.usage.total_tokens} tokens (${agent_res.usage.estimated_cost_usd:.4f})"
            )

        # D4: Do not ignore agent failure
        if not agent_res.success:
            record.findings.append(
                Finding(
                    finding_id=f"find_agent_err_{uuid.uuid4().hex[:8]}",
                    check_id="chk_agent_execution",
                    title="Agent Execution Failure",
                    description=f"Agent '{agent_name}' failed to complete task: {agent_res.error_message or agent_res.output or 'exit code non-zero'}",
                    finding_type=FindingType.DEFECT,
                    severity=FindingSeverity.CRITICAL,
                    is_blocking=True,
                )
            )
            record.overall_verdict = OverallVerdict.FAILED
            record.verdict_reasons.append(f"Agent '{agent_name}' execution failed (success=False).")

    return record
