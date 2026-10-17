"""Security tests for command validation, path containment, and execution controls."""

import tempfile
from pathlib import Path

import pytest

from amaura.errors import ExecutionSecurityError
from amaura.security.permissions import validate_command
from amaura.security.process import run_safe_process
from amaura.security.workspace import validate_path_within_workspace


def test_forbidden_command_detection():
    with pytest.raises(ExecutionSecurityError):
        validate_command(["rm", "-rf", "/"])

    with pytest.raises(ExecutionSecurityError):
        validate_command(["sudo", "apt-get", "install", "malware"])


def test_workspace_path_traversal_detection():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        safe_path = root / "subdir" / "file.txt"
        safe_path.parent.mkdir(parents=True)
        safe_path.write_text("ok")

        # Safe path resolves properly
        assert validate_path_within_workspace(safe_path, root) == safe_path.resolve()

        # Path traversal outside root
        evil_path = root / ".." / ".." / "etc" / "passwd"
        with pytest.raises(ExecutionSecurityError):
            validate_path_within_workspace(evil_path, root)


def test_process_timeout_enforcement():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Run a sleep command with 1s timeout
        res = run_safe_process(
            command=["python3", "-c", "import time; time.sleep(3)"],
            cwd=Path(tmp_dir),
            timeout_seconds=1,
        )
        assert res.timed_out is True
        assert res.exit_code == -1
        assert "timed out" in res.stderr.lower()
