"""Workspace containment and isolation primitives."""

import shutil
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from amaura.errors import ExecutionSecurityError


def validate_path_within_workspace(target_path: Path, workspace_root: Path) -> Path:
    """Verifies that target_path resolves strictly within workspace_root, preventing path traversal (C9)."""
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
    """Creates a temporary, isolated copy of the workspace for safe execution and verification.
    
    Protections (C6):
    - Sets symlinks=True to avoid following external or cyclic symlinks during copy.
    - Inspects all symlinks in source_dir: any symlink pointing outside source_dir or creating
      a directory loop is dropped/ignored, preventing host file exposure or recursive crashes.
    - Root-anchors ignore patterns (.git, .venv, .amaura).
    """
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        resolved_source = source_dir.resolve()

        def ignore_patterns(dir_path: str, names: list[str]) -> set[str]:
            ignored = set()
            is_root = Path(dir_path).resolve() == resolved_source
            for name in names:
                # 1. Root-anchored repo / environment exclusions
                if (is_root and name in {".git", ".amaura", ".venv"}) or name in {"__pycache__", ".pytest_cache"}:
                    ignored.add(name)
                    continue

                # 2. Symlink security inspection (C6)
                p = Path(dir_path) / name
                if p.is_symlink():
                    try:
                        target = p.resolve()
                        # If symlink points outside source workspace, drop it to prevent host file leaks
                        target.relative_to(resolved_source)
                        # If symlink points to source root or ancestor directory, drop it to prevent loops
                        if target == resolved_source or target in p.resolve().parents or target in p.parents:
                            ignored.add(name)
                    except (ValueError, RuntimeError, OSError):
                        # Symlink points outside source_dir or creates an infinite loop
                        ignored.add(name)

            return ignored

        # symlinks=True copies symlinks as symlinks rather than traversing target files/trees
        shutil.copytree(source_dir, temp_dir, dirs_exist_ok=True, ignore=ignore_patterns, symlinks=True)
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
