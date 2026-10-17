"""Append-only evidence ledger with tamper-evident checksums and path traversal protections."""

import json
import re
from pathlib import Path
from typing import Optional

from amaura.errors import EvidenceIntegrityError, ExecutionSecurityError
from amaura.evidence.hashing import hash_file, hash_string
from amaura.models.run import RunRecord


class EvidenceLedger:
    """Manages immutable persistence of verification run artifacts and append-only evidence ledgers."""

    def __init__(self, runs_dir: Path):
        self.runs_dir = runs_dir.resolve()
        self.runs_dir.mkdir(parents=True, exist_ok=True)

    def validate_run_id(self, run_id: str) -> str:
        """Sanitizes and validates run_id to prevent path traversal outside runs_dir."""
        if not run_id or not re.match(r"^[a-zA-Z0-9_\-]+$", run_id):
            raise ExecutionSecurityError(f"Invalid or unsafe run_id: '{run_id}'")
        target_dir = (self.runs_dir / run_id).resolve()
        try:
            target_dir.relative_to(self.runs_dir)
        except ValueError:
            raise ExecutionSecurityError(f"Path traversal detected in run_id: '{run_id}'")
        return run_id

    def get_run_dir(self, run_id: str) -> Path:
        clean_id = self.validate_run_id(run_id)
        return self.runs_dir / clean_id

    def save_run(self, record: RunRecord, report_markdown: Optional[str] = None) -> Path:
        """Persists the complete RunRecord, raw evidence files, append-only jsonl ledger, and checksums."""
        run_dir = self.get_run_dir(record.run_id)
        run_dir.mkdir(parents=True, exist_ok=True)

        # 1. Save raw evidence artifacts in an evidence/ subdirectory
        evidence_sub_dir = run_dir / "evidence"
        evidence_sub_dir.mkdir(parents=True, exist_ok=True)
        for item in record.evidence:
            ev_file = evidence_sub_dir / f"{item.evidence_id}.txt"
            ev_file.write_text(item.content, encoding="utf-8")

        # 2. Append to jsonl ledger
        ledger_file = run_dir / "evidence_ledger.jsonl"
        with open(ledger_file, "a", encoding="utf-8") as f:
            f.writelines(json.dumps({"type": "claim", "data": claim.model_dump(mode="json")}) + "\n" for claim in record.claims)
            f.writelines(json.dumps({"type": "check", "data": check.model_dump(mode="json")}) + "\n" for check in record.checks)
            f.writelines(json.dumps({"type": "execution", "data": exec_item.model_dump(mode="json")}) + "\n" for exec_item in record.executions)
            f.writelines(json.dumps({"type": "evidence", "data": ev.model_dump(mode="json")}) + "\n" for ev in record.evidence)
            f.writelines(json.dumps({"type": "finding", "data": finding.model_dump(mode="json")}) + "\n" for finding in record.findings)

        # 3. Save comprehensive run.json
        run_json_file = run_dir / "run.json"
        json_content = record.model_dump_json(indent=2)
        run_json_file.write_text(json_content, encoding="utf-8")

        # 4. Generate cryptographic tamper-evident checksum
        checksum_file = run_dir / "run.sha256"
        run_hash = hash_string(json_content)
        checksum_file.write_text(run_hash, encoding="utf-8")

        # 5. Record into immutable ledger hash chain
        self._append_to_chain(record.run_id, run_hash)

        # 6. Save markdown report if provided
        if report_markdown:
            report_file = run_dir / "report.md"
            report_file.write_text(report_markdown, encoding="utf-8")

        # 7. Update latest pointer
        latest_pointer = self.runs_dir / "latest.txt"
        latest_pointer.write_text(record.run_id, encoding="utf-8")

        return run_dir

    @property
    def chain_file(self) -> Path:
        return self.runs_dir / "ledger_chain.jsonl"

    def _append_to_chain(self, run_id: str, run_hash: str) -> None:
        """Appends a new block to the cryptographic hash chain linking all runs."""
        prev_hash = "0" * 64
        index = 0
        if self.chain_file.is_file():
            lines = [line.strip() for line in self.chain_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines:
                try:
                    last_block = json.loads(lines[-1])
                    prev_hash = last_block.get("block_hash", prev_hash)
                    index = last_block.get("index", 0) + 1
                except Exception:
                    pass

        from datetime import UTC, datetime
        timestamp = datetime.now(UTC).isoformat()
        payload = f"{index}:{run_id}:{run_hash}:{prev_hash}:{timestamp}"
        block_hash = hash_string(payload)
        block = {
            "index": index,
            "run_id": run_id,
            "run_hash": run_hash,
            "prev_hash": prev_hash,
            "timestamp": timestamp,
            "block_hash": block_hash,
        }
        with open(self.chain_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(block) + "\n")

    def _verify_chain_for_run(self, run_id: str, actual_hash: str) -> list[str]:
        """Validates the entire hash chain and ensures the run's recorded hash matches."""
        errors: list[str] = []
        if not self.chain_file.is_file():
            return errors

        lines = [line.strip() for line in self.chain_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        expected_prev = "0" * 64
        run_recorded_hash = None

        for i, line in enumerate(lines):
            try:
                block = json.loads(line)
            except Exception as e:
                errors.append(f"TAMPER DETECTED: Corrupted block {i} in ledger chain: {e!s}")
                return errors

            idx = block.get("index", i)
            b_run_id = block.get("run_id", "")
            b_run_hash = block.get("run_hash", "")
            b_prev = block.get("prev_hash", "")
            b_time = block.get("timestamp", "")
            b_hash = block.get("block_hash", "")

            if b_prev != expected_prev:
                errors.append(
                    f"TAMPER DETECTED: Broken hash chain link at block {i} (expected prev {expected_prev[:12]}..., got {b_prev[:12]}...)"
                )

            computed_block_hash = hash_string(f"{idx}:{b_run_id}:{b_run_hash}:{b_prev}:{b_time}")
            if computed_block_hash != b_hash:
                errors.append(f"TAMPER DETECTED: Forged block hash at block {i}")

            expected_prev = b_hash
            if b_run_id == run_id:
                run_recorded_hash = b_run_hash

        if run_recorded_hash is not None and run_recorded_hash != actual_hash:
            errors.append(
                f"TAMPER DETECTED: run.json does not match the immutable ledger chain! "
                f"(Chain recorded {run_recorded_hash[:12]}..., but run file is {actual_hash[:12]}...)"
            )

        return errors

    def verify_run_integrity(self, run_dir: Path) -> tuple[bool, list[str]]:
        """Verifies that run.json, evidence files, and ledger chain match their cryptographic SHA-256 checksums."""
        discrepancies: list[str] = []
        run_json_file = run_dir / "run.json"
        checksum_file = run_dir / "run.sha256"

        if not run_json_file.is_file():
            return False, ["run.json is missing"]

        actual_hash = hash_file(run_json_file)
        if checksum_file.is_file():
            expected_hash = checksum_file.read_text(encoding="utf-8").strip()
            if expected_hash != actual_hash:
                discrepancies.append(
                    f"TAMPER DETECTED: run.json checksum mismatch (expected {expected_hash[:12]}..., got {actual_hash[:12]}...)"
                )

        # Check against master ledger hash chain (catches edit-and-recompute attacks!)
        if self.chain_file.is_file():
            chain_errors = self._verify_chain_for_run(run_dir.name, actual_hash)
            discrepancies.extend(chain_errors)

        # Check evidence artifacts
        try:
            record_data = json.loads(run_json_file.read_text(encoding="utf-8"))
            record = RunRecord.model_validate(record_data)
            evidence_sub_dir = run_dir / "evidence"

            for ev in record.evidence:
                ev_file = evidence_sub_dir / f"{ev.evidence_id}.txt"
                if not ev_file.is_file():
                    discrepancies.append(f"TAMPER DETECTED: Missing raw evidence file for {ev.evidence_id}")
                else:
                    file_hash = hash_file(ev_file)
                    if file_hash != ev.content_hash:
                        discrepancies.append(
                            f"TAMPER DETECTED: Evidence file {ev.evidence_id} was modified (expected {ev.content_hash[:12]}..., got {file_hash[:12]}...)"
                        )
        except Exception as e:
            discrepancies.append(f"Failed to inspect run evidence integrity: {e!s}")

        return len(discrepancies) == 0, discrepancies

    def load_run(self, run_id: str, verify_integrity: bool = True) -> Optional[RunRecord]:
        """Loads a RunRecord by ID (or 'latest') with automatic cryptographic integrity verification."""
        if run_id == "latest":
            latest_txt = self.runs_dir / "latest.txt"
            if latest_txt.is_file():
                run_id = latest_txt.read_text(encoding="utf-8").strip()
            else:
                runs = self.list_runs()
                if not runs:
                    return None
                run_id = runs[-1]

        clean_id = self.validate_run_id(run_id)
        run_dir = self.runs_dir / clean_id
        target_file = run_dir / "run.json"

        if not target_file.is_file():
            return None

        if verify_integrity:
            is_valid, discrepancies = self.verify_run_integrity(run_dir)
            if not is_valid:
                raise EvidenceIntegrityError(
                    f"Run '{run_id}' failed cryptographic integrity verification:\n" + "\n".join(discrepancies)
                )

        data = json.loads(target_file.read_text(encoding="utf-8"))
        return RunRecord.model_validate(data)

    def list_runs(self) -> list[str]:
        """Lists all existing run IDs sorted chronologically."""
        if not self.runs_dir.is_dir():
            return []
        run_dirs = [d.name for d in self.runs_dir.iterdir() if d.is_dir() and (d / "run.json").is_file()]
        return sorted(run_dirs)
