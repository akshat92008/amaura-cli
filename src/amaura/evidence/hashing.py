"""Cryptographic hashing and artifact integrity utilities."""

import hashlib
from pathlib import Path


def hash_string(text: str) -> str:
    """Computes SHA-256 hex digest of a string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    """Computes SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_file(file_path: Path) -> str:
    """Computes SHA-256 hex digest of a file in streaming chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def create_directory_manifest(
    root_dir: Path,
    ignore_patterns: set[str] | None = None,
) -> dict[str, str]:
    """Generates an artifact manifest mapping relative paths to their SHA-256 hashes.
    Directories like .git, .amaura, and .venv are only ignored when root-anchored (B11).
    """
    root_anchored_ignored = {".git", ".amaura", ".venv"}
    anywhere_ignored = ignore_patterns or {"__pycache__", ".pytest_cache", ".DS_Store"}

    manifest: dict[str, str] = {}
    resolved_root = root_dir.resolve()

    if not resolved_root.is_dir():
        return manifest

    for path in sorted(resolved_root.rglob("*")):
        if path.is_file():
            rel_path = path.relative_to(resolved_root)
            # Root-anchor root repository and environment directories
            if rel_path.parts[0] in root_anchored_ignored:
                continue
            # Ignore cache artifacts at any depth
            if any(part in anywhere_ignored for part in rel_path.parts):
                continue
            manifest[str(rel_path)] = hash_file(path)

    return manifest


def compute_artifact_diff(
    initial_manifest: dict[str, str],
    final_manifest: dict[str, str],
) -> dict[str, list[str]]:
    """Computes added, modified, and deleted artifacts between two directory manifests."""
    added = sorted([p for p in final_manifest if p not in initial_manifest])
    deleted = sorted([p for p in initial_manifest if p not in final_manifest])
    modified = sorted([
        p for p in final_manifest
        if p in initial_manifest and final_manifest[p] != initial_manifest[p]
    ])
    return {
        "added": added,
        "modified": modified,
        "deleted": deleted,
    }


def verify_manifest_integrity(
    root_dir: Path,
    expected_manifest: dict[str, str],
) -> tuple[bool, list[str]]:
    """Verifies that current files match expected SHA-256 hashes.
    Returns (is_valid, list of discrepancies).
    """
    discrepancies: list[str] = []
    current_manifest = create_directory_manifest(root_dir)

    # Check for modified or missing files
    for expected_path, expected_hash in expected_manifest.items():
        if expected_path not in current_manifest:
            discrepancies.append(f"Missing artifact: {expected_path}")
        elif current_manifest[expected_path] != expected_hash:
            discrepancies.append(
                f"Tampered/modified artifact: {expected_path} (expected {expected_hash[:8]}, got {current_manifest[expected_path][:8]})"
            )

    # Check for unexpected newly created files
    for current_path in current_manifest:
        if current_path not in expected_manifest:
            discrepancies.append(f"Unexpected unrecorded artifact: {current_path}")

    return len(discrepancies) == 0, discrepancies
