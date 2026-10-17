"""Amaura CLI — An evidence-first reliability layer for AI agents."""

import platform
import shlex
import shutil
import sys
from pathlib import Path
from typing import Optional

import typer
import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from amaura.agents.registry import AgentRegistry
from amaura.benchmarks.runner import BenchmarkCase, BenchmarkRunner
from amaura.config import AmauraConfig, PolicyProfile, PrivacyMode
from amaura.errors import AmauraError, EvidenceIntegrityError
from amaura.evidence.ledger import EvidenceLedger
from amaura.models.check import CheckStatus
from amaura.models.run import OverallVerdict
from amaura.orchestration.runner import (
    audit_project,
    check_claims,
    run_and_verify,
    verify_project,
)
from amaura.reporting.json_report import generate_json_report
from amaura.reporting.markdown import generate_markdown_report
from amaura.security.redaction import redact_secrets
from amaura.security.workspace import validate_path_within_workspace

app = typer.Typer(
    name="amaura",
    help="Amaura Verify — An evidence-first reliability layer for AI agents.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def init(
    target_dir: Path = typer.Argument(Path("."), help="Directory to initialize Amaura configuration in"),
):
    """Create local configuration and a starter verification policy."""
    resolved = target_dir.resolve()
    resolved.mkdir(parents=True, exist_ok=True)

    config_path = resolved / "amaura.toml"
    if config_path.exists():
        console.print(f"[yellow]Configuration already exists at {config_path}[/yellow]")
        return

    cfg = AmauraConfig()
    cfg.save(config_path)

    # Initialize .amaura directories
    amaura_dir = resolved / ".amaura"
    (amaura_dir / "runs").mkdir(parents=True, exist_ok=True)

    console.print(Panel.fit(
        f"[green]✓ Initialized Amaura verification environment[/green]\n"
        f"• Configuration: [bold]{config_path}[/bold]\n"
        f"• Audit ledger: [bold]{amaura_dir / 'runs'}[/bold]\n"
        f"• Default policy: [bold]{cfg.policy.profile.value}[/bold] (Fail-closed)",
        title="Amaura Init",
    ))


@app.command()
def doctor(
    check_security: bool = typer.Option(False, "--check-security", help="Perform comprehensive security permission check"),
):
    """Check runtime, adapters, permissions, dependencies, and configuration."""
    table = Table(title="Amaura System Diagnostics & Environment", show_header=True)
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Details", style="dim")

    # Python version
    py_ver = sys.version.split()[0]
    table.add_row("Python Runtime", "[green]PASS[/green]", f"{py_ver} on {platform.system()} ({platform.machine()})")

    # Git tool
    git_path = shutil.which("git")
    if git_path:
        table.add_row("Git CLI", "[green]PASS[/green]", git_path)
    else:
        table.add_row("Git CLI", "[yellow]WARN[/yellow]", "git not found on PATH; worktree isolation degraded")

    # Pytest tool
    pytest_path = shutil.which("pytest")
    if pytest_path:
        table.add_row("Test Runner (pytest)", "[green]PASS[/green]", pytest_path)
    else:
        table.add_row("Test Runner (pytest)", "[red]FAIL[/red]", "pytest is required on PATH for code verification")

    # Security configuration
    cfg = AmauraConfig.load()
    sec_status = "[green]SECURE[/green]" if cfg.security.privacy_mode == PrivacyMode.LOCAL_ONLY else "[yellow]NETWORK_ALLOWED[/yellow]"
    table.add_row("Privacy Mode", sec_status, f"{cfg.security.privacy_mode.value} (Zero-cost baseline)")

    # Redaction
    redaction_status = "[green]ENABLED[/green]" if cfg.security.redact_secrets else "[red]DISABLED[/red]"
    table.add_row("Secret Redaction", redaction_status, "Credentials, keys, and tokens scrubbed from evidence")

    # Active Config
    config_file = AmauraConfig.find_config_path()
    cfg_loc = str(config_file) if config_file else "Defaults (in-memory)"
    table.add_row("Active Config", "[green]LOADED[/green]", cfg_loc)

    # Security checks
    if check_security:
        # Test secret redactor
        test_secret = "Bearer sk-1234567890abcdef1234567890"
        redacted = redact_secrets(test_secret)
        redact_pass = "[REDACTED" in redacted
        table.add_row(
            "Security: Redactor Probe",
            "[green]PASS[/green]" if redact_pass else "[red]FAIL[/red]",
            "Verified secret pattern interception",
        )

        # Test path traversal containment
        try:
            validate_path_within_workspace(Path("/etc/passwd"), Path("/tmp"))
            traversal_pass = False
        except Exception:
            traversal_pass = True
        table.add_row(
            "Security: Path Containment",
            "[green]PASS[/green]" if traversal_pass else "[red]FAIL[/red]",
            "Verified out-of-workspace traversal prevention",
        )

    console.print(table)


@app.command()
def agents():
    """List supported agent adapters and their capabilities."""
    registry = AgentRegistry()
    table = Table(title="Supported Agent Adapters", show_header=True)
    table.add_column("Adapter", style="cyan")
    table.add_column("Execution Mode", style="magenta")
    table.add_column("Capabilities")
    table.add_column("Version", style="dim")

    for adapter in registry.list_adapters():
        table.add_row(
            adapter.name,
            adapter.execution_mode,
            ", ".join(adapter.capabilities),
            adapter.version,
        )

    console.print(table)


def _handle_cli_error(cmd_name: str, exc: Exception) -> None:
    """Handles exceptions in CLI commands cleanly without raw tracebacks (D3)."""
    if isinstance(exc, typer.Exit):
        raise exc
    if isinstance(exc, AmauraError):
        console.print(f"[red]{cmd_name} Error:[/red] {exc.message}")
    elif isinstance(exc, (shutil.Error, OSError)):
        console.print(f"[red]{cmd_name} Filesystem Error:[/red] {exc}")
    elif isinstance(exc, ValidationError):
        console.print(f"[red]{cmd_name} Schema Validation Error:[/red] {exc}")
    elif isinstance(exc, yaml.YAMLError):
        console.print(f"[red]{cmd_name} YAML Syntax Error:[/red] {exc}")
    else:
        console.print(f"[red]{cmd_name} Execution Error:[/red] {exc}")
    raise typer.Exit(code=1)


@app.command()
def verify(
    path: Path = typer.Argument(Path("."), help="Path to project directory to verify"),
    task: Optional[Path] = typer.Option(None, "--task", "-t", help="Path to task specification file"),
    expected_hash: Optional[str] = typer.Option(None, "--expected-hash", help="Expected SHA-256 hash of task specification"),
    profile: Optional[PolicyProfile] = typer.Option(None, "--profile", "-p", help="Verification policy profile"),
    no_network: bool = typer.Option(True, "--no-network/--allow-network", help="Enforce local-only isolated execution"),
):
    """Run applicable checks on existing work."""
    cfg = AmauraConfig.load(start_dir=Path.cwd())
    if no_network:
        cfg.security.allow_network = False
        cfg.security.privacy_mode = PrivacyMode.LOCAL_ONLY

    try:
        record = verify_project(
            project_dir=path,
            task_file=task,
            expected_hash=expected_hash,
            policy_profile=profile,
            config=cfg,
        )
        _print_run_summary(record)
        if record.overall_verdict == OverallVerdict.FAILED:
            raise typer.Exit(code=1)
        elif record.overall_verdict == OverallVerdict.INCONCLUSIVE:
            raise typer.Exit(code=2)
    except Exception as exc:
        _handle_cli_error("Verification", exc)


@app.command()
def audit(
    path: Path = typer.Argument(Path("."), help="Path to project to audit"),
    task: Optional[Path] = typer.Option(None, "--task", "-t", help="Path to task specification file"),
    expected_hash: Optional[str] = typer.Option(None, "--expected-hash", help="Expected SHA-256 hash of task specification"),
    format: str = typer.Option("text", "--format", "-f", help="Output format: text, json, or markdown"),
):
    """Audit completed work without assuming it is trustworthy (strictly non-destructive)."""
    cfg = AmauraConfig.load(start_dir=Path.cwd())
    try:
        record = audit_project(project_dir=path, task_file=task, expected_hash=expected_hash, config=cfg)
        if format == "json":
            console.print(generate_json_report(record))
        elif format == "markdown":
            console.print(generate_markdown_report(record))
        else:
            _print_run_summary(record)

        if record.overall_verdict == OverallVerdict.FAILED:
            raise typer.Exit(code=1)
        elif record.overall_verdict == OverallVerdict.INCONCLUSIVE:
            raise typer.Exit(code=2)
    except Exception as exc:
        _handle_cli_error("Audit", exc)


@app.command(name="claim-check")
def claim_check(
    claims_file: Path = typer.Argument(..., help="Path to YAML or JSON claims file"),
    project: Path = typer.Option(Path("."), "--project", "-p", help="Target project to verify claims against"),
):
    """Verify explicit claims against available evidence."""
    try:
        record = check_claims(claims_file=claims_file, project_dir=project)
        _print_run_summary(record)
        if record.overall_verdict == OverallVerdict.FAILED:
            raise typer.Exit(code=1)
        elif record.overall_verdict == OverallVerdict.INCONCLUSIVE:
            raise typer.Exit(code=2)
    except Exception as exc:
        _handle_cli_error("Claim-Check", exc)


@app.command()
def report(
    run_id: str = typer.Argument("latest", help="Run ID or 'latest' to display"),
    show_evidence: bool = typer.Option(False, "--show-evidence", help="Include full raw evidence logs in output"),
    format: str = typer.Option("text", "--format", "-f", help="Format: text, json, or markdown"),
):
    """Display findings and evidence-backed verdict of a verification run."""
    cfg = AmauraConfig.load()
    ledger = EvidenceLedger(Path(cfg.runs_dir))

    try:
        record = ledger.load_run(run_id, verify_integrity=True)
    except EvidenceIntegrityError as exc:
        console.print(Panel(
            f"[bold red]CRITICAL: TAMPER DETECTED IN RUN AUDIT PACKAGE[/bold red]\n{exc.message}",
            title="Evidence Integrity Error",
        ))
        raise typer.Exit(code=1)
    except Exception as exc:
        _handle_cli_error("Report", exc)

    if not record:
        console.print(f"[red]Run '{run_id}' not found in ledger at {ledger.runs_dir}[/red]")
        raise typer.Exit(code=1)

    if format == "json":
        console.print(generate_json_report(record))
    elif format == "markdown":
        console.print(generate_markdown_report(record))
    else:
        _print_run_summary(record, show_evidence=show_evidence)


@app.command()
def evidence(
    id_arg: str = typer.Argument(..., help="Evidence ID, Check ID, or Claim ID to inspect"),
    run_id: str = typer.Option("latest", "--run", "-r", help="Run ID to look up"),
):
    """Inspect the raw evidence associated with a claim or check."""
    cfg = AmauraConfig.load()
    ledger = EvidenceLedger(Path(cfg.runs_dir))

    try:
        record = ledger.load_run(run_id, verify_integrity=True)
    except EvidenceIntegrityError as exc:
        console.print(f"[red]Integrity Error:[/red] {exc.message}")
        raise typer.Exit(code=1)

    if not record:
        console.print(f"[red]Run '{run_id}' not found.[/red]")
        raise typer.Exit(code=1)

    matched = [
        ev for ev in record.evidence
        if ev.evidence_id == id_arg or ev.check_id == id_arg or ev.claim_id == id_arg
    ]

    if not matched:
        console.print(f"[yellow]No evidence item matched '{id_arg}' in run {record.run_id}[/yellow]")
        return

    for ev in matched:
        console.print(Panel(
            ev.content,
            title=f"Evidence {ev.evidence_id} (Check: {ev.check_id})",
            subtitle=f"Hash: {ev.content_hash[:16]}... | Source: {ev.provenance.source}",
        ))


@app.command()
def policy(
    profile: Optional[PolicyProfile] = typer.Option(None, "--profile", "-p", help="View specific policy profile"),
):
    """Display and validate the active verification policy reflecting real configuration."""
    cfg = AmauraConfig.load()
    p_cfg = cfg.policy

    table = Table(title=f"Amaura Active Verification Policy — Profile: {p_cfg.profile.value.upper()}", show_header=True)
    table.add_column("Setting / Directive", style="cyan")
    table.add_column("Value / State", style="bold")
    table.add_column("Description")

    table.add_row(
        "Active Profile",
        p_cfg.profile.value.upper(),
        "Evaluation strictness profile (strict, standard, permissive)",
    )
    table.add_row(
        "Fail-Closed on Timeout",
        "[green]TRUE[/green]" if p_cfg.fail_closed_on_timeout else "[yellow]FALSE[/yellow]",
        "Timed-out mandatory checks fail rather than silently passing",
    )
    table.add_row(
        "Fail-Closed on Missing Check",
        "[green]TRUE[/green]" if p_cfg.fail_closed_on_missing_check else "[yellow]FALSE[/yellow]",
        "Mandatory requirement without executed test cannot evaluate to PASSED",
    )
    table.add_row(
        "Require All Mandatory Tests",
        "[green]TRUE[/green]" if p_cfg.require_all_mandatory_acceptance_tests else "[yellow]FALSE[/yellow]",
        "Every mandatory requirement requires observed evidence",
    )
    table.add_row(
        "Enforce Clean Git",
        "[green]TRUE[/green]" if p_cfg.require_clean_git else "[dim]FALSE[/dim]",
        "Require clean Git working tree before verification",
    )
    table.add_row(
        "Privacy Mode",
        cfg.security.privacy_mode.value.upper(),
        "Local-only execution with zero network transmission",
    )

    console.print(table)


@app.command(name="runs")
def list_runs_cmd():
    """List historical verification runs sorted chronologically."""
    cfg = AmauraConfig.load()
    ledger = EvidenceLedger(Path(cfg.runs_dir))
    run_ids = ledger.list_runs()
    if not run_ids:
        console.print(f"[yellow]No verification runs found in {ledger.runs_dir}[/yellow]")
        return

    table = Table(title="Amaura Historical Verification Runs", show_header=True)
    table.add_column("Run ID", style="cyan")
    table.add_column("Timestamp", style="dim")
    table.add_column("Verdict", style="bold")
    table.add_column("Policy")
    table.add_column("Task ID", style="dim")

    for rid in run_ids:
        try:
            rec = ledger.load_run(rid, verify_integrity=False)
            if rec:
                table.add_row(
                    rec.run_id,
                    rec.timestamp,
                    rec.overall_verdict.value.upper(),
                    rec.policy_applied,
                    rec.task.task_id,
                )
            else:
                table.add_row(rid, "-", "-", "-", "-")
        except Exception:
            table.add_row(rid, "[red]CORRUPT[/red]", "-", "-", "-")

    console.print(table)


@app.command()
def benchmark(
    suite: str = typer.Option("all", "--suite", "-s", help="Benchmark suite to execute"),
):
    """Evaluate Amaura verification against standard defect fixtures and release gates."""
    base_dir = Path(__file__).resolve().parents[2]
    csv_example = base_dir / "examples" / "csv-import"
    task_file = csv_example / "task.md"

    cases: list[BenchmarkCase] = []

    if csv_example.exists():
        # Version A: Known Good
        cases.append(
            BenchmarkCase(
                name="CSV Import (Version A - Correct)",
                path=csv_example / "version_a_correct",
                task_file=task_file,
                expected_verdict=OverallVerdict.PASSED,
                category="known_good",
            )
        )
        # Version B: Known Bad (Crashes on malformed input)
        cases.append(
            BenchmarkCase(
                name="CSV Import (Version B - Crash Malformed)",
                path=csv_example / "version_b_crash_malformed",
                task_file=task_file,
                expected_verdict=OverallVerdict.FAILED,
                is_critical_defect=True,
                category="known_bad",
            )
        )
        # Version C: Test Gap (Duplicate requirement untested)
        cases.append(
            BenchmarkCase(
                name="CSV Import (Version C - Duplicate Test Gap)",
                path=csv_example / "version_c_gap_duplicates",
                task_file=task_file,
                expected_verdict=OverallVerdict.INCONCLUSIVE,
                category="known_bad",
            )
        )

    runner = BenchmarkRunner()
    metrics = runner.run_suite(cases)

    table = Table(title="Amaura Reliability Benchmark & Release Gate Evaluation", show_header=True)
    table.add_column("Evaluation Metric", style="cyan")
    table.add_column("Measured Value", style="bold")
    table.add_column("Gate Target")

    table.add_row("Total Evaluated Cases", str(metrics.total_cases), "-")
    table.add_row("Defect Recall", f"{metrics.defect_recall * 100:.1f}%", "100.0%")
    table.add_row("Critical Defect Recall", f"{metrics.critical_defect_recall * 100:.1f}%", "100.0%")
    table.add_row("False Positive Rate", f"{metrics.false_positive_rate * 100:.1f}%", "0.0%")
    gate_status = "[green]PASSED[/green]" if metrics.passed_release_gate else "[red]FAILED[/red]"
    table.add_row("Release Gate Status", gate_status, "Must Pass")

    console.print(table)
    if not metrics.passed_release_gate:
        raise typer.Exit(code=1)


@app.command()
def run(
    task: Path = typer.Argument(..., help="Path to task markdown file"),
    agent: str = typer.Option("artifact_only", "--agent", "-a", help="Agent adapter to operate"),
    agent_cmd: Optional[str] = typer.Option(None, "--agent-cmd", help="CLI command to execute when using local_cli agent"),
    expected_hash: Optional[str] = typer.Option(None, "--expected-hash", help="Expected SHA-256 hash of task specification"),
    profile: Optional[PolicyProfile] = typer.Option(None, "--profile", "-p", help="Verification policy profile"),
):
    """Execute an agent workflow in an isolated workspace and verify the output."""
    try:
        agent_command = shlex.split(agent_cmd) if agent_cmd else None
        record = run_and_verify(
            task_file=task,
            agent_name=agent,
            agent_command=agent_command,
            expected_hash=expected_hash,
            policy_profile=profile,
        )
        _print_run_summary(record)
        if record.overall_verdict == OverallVerdict.FAILED:
            raise typer.Exit(code=1)
        elif record.overall_verdict == OverallVerdict.INCONCLUSIVE:
            raise typer.Exit(code=2)
    except Exception as exc:
        _handle_cli_error("Run", exc)


def _print_run_summary(record, show_evidence: bool = False):
    """Prints a styled terminal summary of the verification result."""
    verdict_colors = {
        OverallVerdict.PASSED: "bold green",
        OverallVerdict.FAILED: "bold red",
        OverallVerdict.INCONCLUSIVE: "bold yellow",
        OverallVerdict.SUPPORTED_WITH_LIMITATIONS: "bold blue",
    }
    color = verdict_colors.get(record.overall_verdict, "bold white")

    task_desc = record.task.instruction.splitlines()[0] if record.task.instruction else record.task.task_id
    console.print(Panel(
        f"[bold]Task:[/bold] {task_desc}\n"
        f"[bold]Run ID:[/bold] `{record.run_id}` | [bold]Policy:[/bold] {record.policy_applied}\n"
        f"[bold]Final Verdict:[/bold] [{color}]{record.overall_verdict.value.upper()}[/{color}]",
        title=f"Amaura Verify Report — {record.task.task_id}",
    ))

    if record.verdict_reasons:
        console.print("[bold]Verdict Analysis:[/bold]")
        for reason in record.verdict_reasons:
            console.print(f" • {reason}")
        console.print()

    exec_map = {e.check_id: e for e in record.executions}
    chk_table = Table(title="Executed Checks & Verifications", show_header=True)
    chk_table.add_column("Check ID", style="dim")
    chk_table.add_column("Check Name", style="cyan")
    chk_table.add_column("Status", style="bold")
    chk_table.add_column("Duration")

    for c in record.checks:
        e = exec_map.get(c.check_id)
        if e:
            st_color = "green" if e.status == CheckStatus.PASSED else ("yellow" if e.status == CheckStatus.NOT_RUN else "red")
            chk_table.add_row(c.check_id, c.name, f"[{st_color}]{e.status.value.upper()}[/{st_color}]", f"{e.duration_ms}ms")
        else:
            chk_table.add_row(c.check_id, c.name, "[yellow]NOT_RUN[/yellow]", "-")

    console.print(chk_table)

    if record.findings:
        console.print("\n[bold]Findings & Discrepancies:[/bold]")
        for f in record.findings:
            f_color = "red" if f.severity.value in ("critical", "high") else "yellow"
            console.print(f" • [{f_color}]{f.severity.value.upper()}[/{f_color}] [bold]{f.title}[/bold]: {f.description}")

    if show_evidence and record.evidence:
        console.print("\n[bold]Captured Evidence Ledger:[/bold]")
        for ev in record.evidence:
            console.print(Panel(
                ev.content,
                title=f"Evidence `{ev.evidence_id}` — Check `{ev.check_id}`",
                subtitle=f"SHA-256: {ev.content_hash[:16]}... | Method: {ev.provenance.method}",
            ))


def main():
    app()


if __name__ == "__main__":
    main()
