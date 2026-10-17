"""Extended end-to-end integration tests for CLI commands: run, claim-check, timeout, and tool failures (H4)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from amaura.cli import app
from amaura.models.check import CheckDefinition

runner = CliRunner()


def test_e2e_cli_claim_check(tmp_path: Path):
    base_dir = Path(__file__).resolve().parents[2]
    proj = str(base_dir / "examples" / "csv-import" / "version_a_correct")
    claims_file = tmp_path / "claims.yaml"
    claims_file.write_text(
        """
claims:
  - claim_id: CLM-E2E-001
    text: "CSV parsing works correctly"
    claim_type: behavioral
    origin: agent_output
    importance: high
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["claim-check", str(claims_file), "--project", proj])
    # The default checks should run and produce a structured report
    assert "default_task" in result.output or "Run ID" in result.output
    assert result.exit_code in (0, 1, 2)


def test_e2e_cli_claim_check_json_format(tmp_path: Path):
    base_dir = Path(__file__).resolve().parents[2]
    proj = str(base_dir / "examples" / "csv-import" / "version_a_correct")
    claims_file = tmp_path / "claims.yaml"
    claims_file.write_text(
        """
- "Basic tests pass"
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["claim-check", str(claims_file), "--project", proj, "--format", "json"])
    assert result.exit_code in (0, 1, 2)
    data = json.loads(result.output)
    assert "run_id" in data
    assert data["mode"] == "claim_check"


def test_e2e_cli_claim_check_missing_file():
    result = runner.invoke(app, ["claim-check", "nonexistent_claims_file_123.yaml"])
    assert result.exit_code != 0
    assert "Claims file not found" in result.output or "Error" in result.output


def test_e2e_cli_run_artifact_only(tmp_path: Path):
    # In tmp_path, create a minimal project
    proj_dir = tmp_path / "target_proj"
    proj_dir.mkdir()
    (proj_dir / "test_calc.py").write_text("def test_ok(): assert 1 == 1\n", encoding="utf-8")
    task_file = tmp_path / "task.md"
    task_file.write_text("# Task: Math\n\n## Requirements\n- Ensure calculations work.\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["run", str(task_file), "--project", str(proj_dir), "--agent", "artifact_only", "--format", "json"],
    )
    assert result.exit_code in (0, 1, 2)
    data = json.loads(result.output)
    assert data["mode"] == "run"
    assert "run_id" in data


def test_e2e_cli_run_local_cli(tmp_path: Path):
    proj_dir = tmp_path / "cli_proj"
    proj_dir.mkdir()
    (proj_dir / "test_dummy.py").write_text("def test_dummy(): pass\n", encoding="utf-8")
    task_file = tmp_path / "task.md"
    task_file.write_text("# Task: CLI\n\n## Requirements\n- Ensure dummy passes.\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "run",
            str(task_file),
            "--project",
            str(proj_dir),
            "--agent",
            "local_cli",
            "--agent-cmd",
            "python3 -c 'print(\"agent done\")'",
            "--format",
            "json",
        ],
    )
    assert result.exit_code in (0, 1, 2)
    data = json.loads(result.output)
    assert data["mode"] == "run"
    assert "run_id" in data


def test_e2e_cli_timeout_handling(tmp_path: Path, monkeypatch):
    # Patch default timeout on CheckDefinition to 1 second so test executes quickly
    original_init = CheckDefinition.__init__

    def fast_timeout_init(self, *args, **kwargs):
        kwargs.setdefault("timeout_seconds", 1)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(CheckDefinition, "__init__", fast_timeout_init)

    proj_dir = tmp_path / "timeout_proj"
    proj_dir.mkdir()
    (proj_dir / "test_hang.py").write_text(
        "import time\ndef test_hang():\n    time.sleep(5)\n",
        encoding="utf-8",
    )
    task_file = tmp_path / "task.md"
    task_file.write_text(
        "# Task: Timeout Test\n\n## Requirements\n- Must pass test_hang.\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["verify", str(proj_dir), "--task", str(task_file)])
    assert result.exit_code != 0
    assert "FAILED" in result.output or "timed_out" in result.output.lower() or "TIMED_OUT" in result.output


def test_e2e_cli_missing_tool_or_command(tmp_path: Path):
    proj_dir = tmp_path / "missing_tool_proj"
    proj_dir.mkdir()
    task_file = tmp_path / "task.md"
    task_file.write_text("# Task: Missing Tool\n\n## Requirements\n- Test req.\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "run",
            str(task_file),
            "--project",
            str(proj_dir),
            "--agent",
            "local_cli",
            "--agent-cmd",
            "nonexistent_binary_xyz_12345",
        ],
    )
    assert result.exit_code != 0
    assert "Error" in result.output or "failed" in result.output.lower()
