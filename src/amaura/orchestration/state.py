"""Run state and workspace execution context."""

import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from amaura.models.run import RunMode


class ExecutionContext:
    """Holds active run identifiers, paths, and environment state."""

    def __init__(
        self,
        target_dir: Path,
        source_dir: Path | None = None,
        mode: RunMode = RunMode.VERIFY,
    ):
        now = datetime.now(UTC)
        self.run_id = f"run_{now.strftime('%Y%m%d_%H%M%S_%f')}_{uuid.uuid4().hex[:6]}"
        self.target_dir = target_dir.resolve()
        self.source_dir = (source_dir or target_dir).resolve()
        self.mode = mode

    def get_git_info(self) -> tuple[str | None, bool | None]:
        """Retrieves git commit hash and clean status if source or target is a git repository."""
        try:
            res_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.source_dir,
                capture_output=True,
                text=True,
                timeout=5,
            )
            commit = res_commit.stdout.strip() if res_commit.returncode == 0 else None

            res_status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.source_dir,
                capture_output=True,
                text=True,
                timeout=5,
            )
            clean = (len(res_status.stdout.strip()) == 0) if res_status.returncode == 0 else None
            return commit, clean
        except Exception:
            return None, None
