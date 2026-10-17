"""Integration tests for the Amaura CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from amaura.cli import app

runner = CliRunner()


def test_cli_doctor():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Python Runtime" in result.output
    assert "Privacy Mode" in result.output


def test_cli_agents():
    result = runner.invoke(app, ["agents"])
    assert result.exit_code == 0
    assert "artifact_only" in result.output
    assert "local_cli" in result.output
    assert "model" in result.output


def test_cli_policy():
    result = runner.invoke(app, ["policy"])
    assert result.exit_code == 0
    assert "Fail-Closed" in result.output


def test_cli_verify_version_a():
    base_dir = Path(__file__).resolve().parents[2]
    proj = str(base_dir / "examples" / "csv-import" / "version_a_correct")
    task = str(base_dir / "examples" / "csv-import" / "task.md")
    result = runner.invoke(app, ["verify", proj, "--task", task])
    assert result.exit_code == 0
    assert "PASSED" in result.output


def test_cli_verify_version_b():
    base_dir = Path(__file__).resolve().parents[2]
    proj = str(base_dir / "examples" / "csv-import" / "version_b_crash_malformed")
    task = str(base_dir / "examples" / "csv-import" / "task.md")
    result = runner.invoke(app, ["verify", proj, "--task", task])
    assert result.exit_code != 0
    assert "FAILED" in result.output


def test_cli_benchmark():
    result = runner.invoke(app, ["benchmark"])
    assert result.exit_code == 0
    assert "100.0%" in result.output
    assert "PASSED" in result.output


def test_cli_review():
    base_dir = Path(__file__).resolve().parents[2]
    proj = str(base_dir / "examples" / "csv-import" / "version_a_correct")
    task = str(base_dir / "examples" / "csv-import" / "task.md")
    result = runner.invoke(app, ["review", proj, "--task", task])
    assert result.exit_code == 0
    assert "Task Requirements" in result.output
    assert "REQ-001" in result.output


def test_cli_format_json():
    import json
    base_dir = Path(__file__).resolve().parents[2]
    proj = str(base_dir / "examples" / "csv-import" / "version_a_correct")
    task = str(base_dir / "examples" / "csv-import" / "task.md")
    result = runner.invoke(app, ["audit", proj, "--task", task, "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["overall_verdict"] == "passed"
    assert "run_id" in data


def test_cli_benchmark_suite():
    result = runner.invoke(app, ["benchmark", "--suite", "csv"])
    assert result.exit_code == 0
    assert "100.0%" in result.output

    result_bad = runner.invoke(app, ["benchmark", "--suite", "nonexistent"])
    assert result_bad.exit_code == 1
