"""Workspace containment and isolation primitives."""

import shutil
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from amaura.errors import ExecutionSecurityError


def validate_path_within_workspace(target_path: Path, workspace_root: Path) -> Path:
    """Verifies that target_path resolves strictly within workspace_root, preventing path traversal."""
    resolved_root = workspace_root.resolve()
    resolved_target = target_path.resolve()

    try:
        resolved_target.relative_to(resolved_root)
    except ValueError:
        raise ExecutionSecurityError(
            f"Path traversal detected: '{target_path}' resolves outside workspace '{workspace_root}'"
        )

    return resolved_target


@contextmanager
def isolated_workspace(source_dir: Path, prefix: str = "amaura_ws_") -> Generator[Path, None, None]:
    """Creates a temporary, isolated copy of the workspace for safe execution and verification."""
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        # Copy source contents ignoring .git, .amaura, .venv to keep it clean and fast
        def ignore_patterns(dir_path: str, names: list[str]) -> set[str]:
            ignored = set()
            for name in names:
                if name in {".git", ".amaura", ".venv", "__pycache__", ".pytest_cache"}:
                    ignored.add(name)
            return ignored

        shutil.copytree(source_dir, temp_dir, dirs_exist_ok=True, ignore=ignore_patterns)
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
