"""Unit tests for cryptographic hashing and artifact integrity."""

import tempfile
from pathlib import Path

from amaura.evidence.hashing import (
    create_directory_manifest,
    hash_string,
    verify_manifest_integrity,
)


def test_hash_string():
    h1 = hash_string("hello")
    h2 = hash_string("hello")
    h3 = hash_string("world")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64


def test_directory_manifest_and_tamper_detection():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        f1 = root / "file1.txt"
        f2 = root / "subdir" / "file2.txt"
        f2.parent.mkdir(parents=True)
        f1.write_text("content1", encoding="utf-8")
        f2.write_text("content2", encoding="utf-8")

        manifest = create_directory_manifest(root)
        assert len(manifest) == 2
        assert "file1.txt" in manifest
        assert str(Path("subdir/file2.txt")) in manifest

        # 1. Verification matches
        is_valid, discrepancies = verify_manifest_integrity(root, manifest)
        assert is_valid is True
        assert len(discrepancies) == 0

        # 2. Tampered file
        f1.write_text("tampered content", encoding="utf-8")
        is_valid, discrepancies = verify_manifest_integrity(root, manifest)
        assert is_valid is False
        assert any("Tampered/modified artifact" in d for d in discrepancies)

        # 3. Missing file
        f2.unlink()
        is_valid, discrepancies = verify_manifest_integrity(root, manifest)
        assert is_valid is False
        assert any("Missing artifact" in d for d in discrepancies)
