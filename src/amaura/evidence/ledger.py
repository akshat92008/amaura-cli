"""Append-only evidence ledger with tamper-evident checksums and path traversal protections."""

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
from pathlib import Path
from typing import Optional

from amaura.errors import EvidenceIntegrityError, ExecutionSecurityError
from amaura.evidence.hashing import hash_file, hash_string
from amaura.models.run import RunRecord


class EvidenceLedger:
    """Manages immutable persistence of verification run artifacts and append-only evidence ledgers."""

    def __init__(self, runs_dir: Path, anchor_key_path: Optional[Path] = None):
        self.runs_dir = runs_dir.resolve()
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self._custom_anchor_key_path = anchor_key_path

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

    @property
    def chain_file(self) -> Path:
        return self.runs_dir / "ledger_chain.jsonl"

    @property
    def lock_file(self) -> Path:
        return self.runs_dir / "ledger_chain.lock"

    @property
    def anchor_file(self) -> Path:
        return self.runs_dir / "ledger_anchor.json"

    @property
    def anchor_key_file(self) -> Path:
        if self._custom_anchor_key_path:
            return self._custom_anchor_key_path.resolve()
        # Secure location outside workspace/ledger directory (B1, B4)
        home_key_dir = Path.home() / ".amaura"
        try:
            home_key_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(home_key_dir, 0o700)
            except OSError:
                pass
            return home_key_dir / "ledger_anchor.key"
        except (OSError, PermissionError):
            return self.runs_dir / ".anchor_key"

    def _get_or_create_anchor_key(self) -> bytes:
        """Retrieves or initializes the cryptographic HMAC secret key for the ledger anchor."""
        env_key = os.environ.get("AMAURA_LEDGER_KEY") or os.environ.get("AMAURA_ANCHOR_KEY")
        if env_key:
            return env_key.encode("utf-8")

        key_file = self.anchor_key_file
        if key_file.is_file():
            return key_file.read_bytes()
        key = secrets.token_bytes(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(key_file, flags, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
        except (FileExistsError, OSError):
            if key_file.is_file():
                return key_file.read_bytes()
            fallback_file = self.runs_dir / ".anchor_key"
            if fallback_file.is_file():
                return fallback_file.read_bytes()
            try:
                fd = os.open(fallback_file, flags, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(key)
            except Exception:
                pass
            return key
        return key

    def _update_anchor(self, chain_length: int, head_block_hash: str, last_run_id: str) -> None:
        """Updates the cryptographic anchor file with HMAC signature protecting against chain truncation/recalculation."""
        key = self._get_or_create_anchor_key()
        payload = f"{chain_length}:{head_block_hash}:{last_run_id}".encode()
        sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
        anchor_data = {
            "chain_length": chain_length,
            "head_block_hash": head_block_hash,
            "last_run_id": last_run_id,
            "signature": sig,
        }
        self.anchor_file.write_text(json.dumps(anchor_data, indent=2), encoding="utf-8")

    def _verify_anchor(self, chain_length: int, head_block_hash: str, last_run_id: str) -> list[str]:
        """Verifies that the current chain matches the signed ledger anchor (B4 & B2)."""
        errors: list[str] = []
        if not self.anchor_file.is_file():
            errors.append("TAMPER DETECTED: Master ledger anchor file 'ledger_anchor.json' is missing.")
            return errors

        try:
            data = json.loads(self.anchor_file.read_text(encoding="utf-8"))
            anc_len = data["chain_length"]
            anc_head = data["head_block_hash"]
            anc_last = data["last_run_id"]
            anc_sig = data["signature"]
        except Exception as e:
            errors.append(f"TAMPER DETECTED: Corrupted ledger anchor file: {e!s}")
            return errors

        key = self._get_or_create_anchor_key()
        expected_payload = f"{anc_len}:{anc_head}:{anc_last}".encode()
        expected_sig = hmac.new(key, expected_payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, anc_sig):
            errors.append("TAMPER DETECTED: Invalid HMAC signature on ledger anchor! Chain may have been recomputed.")
            return errors

        if chain_length < anc_len:
            errors.append(
                f"TAMPER DETECTED: Ledger chain truncation detected! Anchor recorded {anc_len} blocks, but chain has only {chain_length}."
            )
        elif chain_length != anc_len or head_block_hash != anc_head or last_run_id != anc_last:
            errors.append(
                f"TAMPER DETECTED: Ledger chain head does not match signed anchor! Expected head {anc_head[:12]}..., got {head_block_hash[:12]}..."
            )

        return errors

    def _append_to_chain(self, run_id: str, run_hash: str) -> None:
        """Appends a new block to the cryptographic hash chain linking all runs using file locking (B5)."""
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        with open(self.lock_file, "a+", encoding="utf-8") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_EX)
            try:
                prev_hash = "0" * 64
                index = 0
                if self.chain_file.is_file():
                    raw = self.chain_file.read_text(encoding="utf-8")
                    lines = [line.strip() for line in raw.splitlines() if line.strip()]
                    if lines:
                        try:
                            last_block = json.loads(lines[-1])
                            if "block_hash" not in last_block or "index" not in last_block:
                                raise ValueError("Block missing required block_hash or index fields")
                            prev_hash = last_block["block_hash"]
                            index = last_block["index"] + 1
                        except Exception as e:
                            # B5: Corrupt last block must NOT silently reset prev_hash to genesis!
                            raise EvidenceIntegrityError(
                                f"TAMPER DETECTED: Cannot append to chain because the last block is corrupted: {e!s}"
                            )

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

                # Update signed external anchor (B4)
                self._update_anchor(
                    chain_length=index + 1,
                    head_block_hash=block_hash,
                    last_run_id=run_id,
                )
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)

    def _verify_chain_for_run(self, run_id: str, actual_hash: str) -> list[str]:
        """Validates the entire hash chain and ensures the run's recorded hash matches (B2, B4, B5)."""
        errors: list[str] = []
        if not self.chain_file.is_file():
            errors.append("TAMPER DETECTED: Master ledger chain file 'ledger_chain.jsonl' is missing.")
            return errors

        with open(self.lock_file, "a+", encoding="utf-8") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_SH)
            try:
                raw = self.chain_file.read_text(encoding="utf-8")
                lines = [line.strip() for line in raw.splitlines() if line.strip()]
                if not lines:
                    errors.append("TAMPER DETECTED: Master ledger chain file 'ledger_chain.jsonl' is empty.")
                    return errors

                last_block_hash = ""
                last_run_id = ""
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
                    last_block_hash = b_hash
                    last_run_id = b_run_id
                    if b_run_id == run_id:
                        run_recorded_hash = b_run_hash

                # Verify signed anchor file protecting against chain truncation and recalculation (B4 & B2)
                anchor_errors = self._verify_anchor(
                    chain_length=len(lines),
                    head_block_hash=last_block_hash,
                    last_run_id=last_run_id,
                )
                errors.extend(anchor_errors)

                # B2: A run absent from the chain must fail loudly, not pass silently!
                if run_recorded_hash is None:
                    errors.append(
                        f"TAMPER DETECTED: Run '{run_id}' is not present in the immutable ledger chain!"
                    )
                elif run_recorded_hash != actual_hash:
                    errors.append(
                        f"TAMPER DETECTED: run.json does not match the immutable ledger chain! "
                        f"(Chain recorded {run_recorded_hash[:12]}..., but run file is {actual_hash[:12]}...)"
                    )
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)

        return errors

    def save_run(
        self,
        record: RunRecord,
        report_markdown: Optional[str] = None,
        graph_dict: Optional[dict] = None,
    ) -> Path:
        """Persists the complete RunRecord, raw evidence files, append-only jsonl ledger, graph, and checksums."""
        run_dir = self.get_run_dir(record.run_id)
        run_json_file = run_dir / "run.json"

        # B3: Enforce run immutability — double saves or overwrites violate Rule 5
        if run_json_file.exists():
            raise EvidenceIntegrityError(
                f"Run '{record.run_id}' has already been persisted and is immutable (Rule 5 violation)!"
            )

        run_dir.mkdir(parents=True, exist_ok=True)

        # 1. Save raw evidence artifacts in an evidence/ subdirectory
        evidence_sub_dir = run_dir / "evidence"
        evidence_sub_dir.mkdir(parents=True, exist_ok=True)
        for item in record.evidence:
            ev_file = evidence_sub_dir / f"{item.evidence_id}.txt"
            ev_file.write_text(item.content, encoding="utf-8")

        # 2. Append to jsonl ledger and save its checksum (B7)
        ledger_file = run_dir / "evidence_ledger.jsonl"
        with open(ledger_file, "a", encoding="utf-8") as f:
            f.writelines(json.dumps({"type": "claim", "data": claim.model_dump(mode="json")}) + "\n" for claim in record.claims)
            f.writelines(json.dumps({"type": "check", "data": check.model_dump(mode="json")}) + "\n" for check in record.checks)
            f.writelines(json.dumps({"type": "execution", "data": exec_item.model_dump(mode="json")}) + "\n" for exec_item in record.executions)
            f.writelines(json.dumps({"type": "evidence", "data": ev.model_dump(mode="json")}) + "\n" for ev in record.evidence)
            f.writelines(json.dumps({"type": "finding", "data": finding.model_dump(mode="json")}) + "\n" for finding in record.findings)

        ledger_hash = hash_file(ledger_file)
        (run_dir / "evidence_ledger.sha256").write_text(ledger_hash, encoding="utf-8")

        # 3. Persist evidence graph and checksum if provided (B7)
        if graph_dict is not None:
            graph_file = run_dir / "evidence_graph.json"
            graph_json = json.dumps(graph_dict, indent=2)
            graph_file.write_text(graph_json, encoding="utf-8")
            (run_dir / "evidence_graph.sha256").write_text(hash_string(graph_json), encoding="utf-8")

        # 4. Save comprehensive run.json
        json_content = record.model_dump_json(indent=2)
        run_json_file.write_text(json_content, encoding="utf-8")

        # 5. Generate cryptographic tamper-evident checksum
        checksum_file = run_dir / "run.sha256"
        run_hash = hash_string(json_content)
        checksum_file.write_text(run_hash, encoding="utf-8")

        # 6. Record into immutable ledger hash chain
        self._append_to_chain(record.run_id, run_hash)

        # 7. Save markdown report if provided
        if report_markdown:
            report_file = run_dir / "report.md"
            report_file.write_text(report_markdown, encoding="utf-8")

        # 8. Update latest pointer
        latest_pointer = self.runs_dir / "latest.txt"
        latest_pointer.write_text(record.run_id, encoding="utf-8")

        return run_dir

    def verify_run_integrity(self, run_dir: Path) -> tuple[bool, list[str]]:
        """Verifies that run.json, evidence files, ledger, and hash chain match their cryptographic SHA-256 checksums."""
        discrepancies: list[str] = []
        run_json_file = run_dir / "run.json"
        checksum_file = run_dir / "run.sha256"

        if not run_json_file.is_file():
            return False, ["run.json is missing"]

        actual_hash = hash_file(run_json_file)
        if not checksum_file.is_file():
            discrepancies.append("TAMPER DETECTED: Checksum file run.sha256 is missing")
        else:
            expected_hash = checksum_file.read_text(encoding="utf-8").strip()
            # Handle possible trailing file names in sha256 file
            clean_expected_hash = expected_hash.split()[0] if expected_hash else ""
            if clean_expected_hash != actual_hash:
                discrepancies.append(
                    f"TAMPER DETECTED: run.json checksum mismatch (expected {clean_expected_hash[:12]}..., got {actual_hash[:12]}...)"
                )

        # B1: Deleting ledger_chain.jsonl must be detected as tampering!
        if not self.chain_file.is_file():
            discrepancies.append("TAMPER DETECTED: Master ledger chain file 'ledger_chain.jsonl' is missing.")
        else:
            chain_errors = self._verify_chain_for_run(run_dir.name, actual_hash)
            discrepancies.extend(chain_errors)

        # B7: Integrity check evidence_ledger.jsonl
        ledger_file = run_dir / "evidence_ledger.jsonl"
        ledger_checksum = run_dir / "evidence_ledger.sha256"
        if not ledger_file.is_file():
            discrepancies.append("TAMPER DETECTED: evidence_ledger.jsonl is missing in run directory")
        else:
            if ledger_checksum.is_file():
                expected_ledg = ledger_checksum.read_text(encoding="utf-8").strip().split()[0]
                actual_ledg = hash_file(ledger_file)
                if expected_ledg != actual_ledg:
                    discrepancies.append(
                        f"TAMPER DETECTED: evidence_ledger.jsonl checksum mismatch (expected {expected_ledg[:12]}..., got {actual_ledg[:12]}...)"
                    )
            try:
                with open(ledger_file, "r", encoding="utf-8") as f:
                    for line_idx, line in enumerate(f):
                        if line.strip():
                            json.loads(line)
            except Exception as e:
                discrepancies.append(f"TAMPER DETECTED: Corrupted entry in evidence_ledger.jsonl: {e!s}")

        # B7: Integrity check evidence_graph.json if present
        graph_file = run_dir / "evidence_graph.json"
        graph_checksum = run_dir / "evidence_graph.sha256"
        if graph_file.is_file():
            if graph_checksum.is_file():
                expected_gr = graph_checksum.read_text(encoding="utf-8").strip().split()[0]
                actual_gr = hash_file(graph_file)
                if expected_gr != actual_gr:
                    discrepancies.append(
                        f"TAMPER DETECTED: evidence_graph.json checksum mismatch (expected {expected_gr[:12]}..., got {actual_gr[:12]}...)"
                    )
            try:
                json.loads(graph_file.read_text(encoding="utf-8"))
            except Exception as e:
                discrepancies.append(f"TAMPER DETECTED: Corrupted evidence_graph.json: {e!s}")

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
        """Lists all existing run IDs sorted chronologically (B9)."""
        if not self.runs_dir.is_dir():
            return []
        runs = []
        for d in self.runs_dir.iterdir():
            if d.is_dir() and (d / "run.json").is_file():
                runs.append(d.name)

        def sort_key(name: str):
            r_json = self.runs_dir / name / "run.json"
            try:
                data = json.loads(r_json.read_text(encoding="utf-8"))
                return (data.get("timestamp", ""), name)
            except Exception:
                mtime = r_json.stat().st_mtime if r_json.is_file() else 0.0
                return (str(mtime), name)

        return sorted(runs, key=sort_key)
