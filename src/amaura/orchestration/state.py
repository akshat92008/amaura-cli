"""Run state and workspace execution context."""

import subprocess
import uuid
from pathlib import Path

from amaura.models.run import RunMode


class ExecutionContext:
    """Holds active run identifiers, paths, and environment state."""

    def __init__(self, target_dir: Path, mode: RunMode = RunMode.VERIFY):
        self.run_id = f"run_{uuid.uuid4().hex[:12]}"
        self.target_dir = target_dir.resolve()
        self.mode = mode

    def get_git_info(self) -> tuple[str | None, bool | None]:
        """Retrieves git commit hash and clean status if target is a git repository."""
        try:
            res_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.target_dir,
                capture_output=True,
                text=True,
                timeout=5,
            )
            commit = res_commit.stdout.strip() if res_commit.returncode == 0 else None

            res_status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.target_dir,
                capture_output=True,
                text=True,
                timeout=5,
            )
            clean = (len(res_status.stdout.strip()) == 0) if res_status.returncode == 0 else None
            return commit, clean
        except Exception:
            return None, None
