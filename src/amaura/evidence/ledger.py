"""Append-only evidence ledger and run persistence."""

import json
from pathlib import Path

from amaura.models.run import RunRecord


class EvidenceLedger:
    """Manages immutable persistence of verification run artifacts and append-only evidence ledgers."""

    def __init__(self, runs_dir: Path):
        self.runs_dir = runs_dir.resolve()
        self.runs_dir.mkdir(parents=True, exist_ok=True)

    def get_run_dir(self, run_id: str) -> Path:
        return self.runs_dir / run_id

    def save_run(self, record: RunRecord, report_markdown: str | None = None) -> Path:
        """Persists the complete RunRecord, raw evidence files, append-only jsonl ledger, and markdown report."""
        run_dir = self.get_run_dir(record.run_id)
        run_dir.mkdir(parents=True, exist_ok=True)

        # 1. Save raw evidence artifacts in an evidence/ subdirectory
        evidence_sub_dir = run_dir / "evidence"
        evidence_sub_dir.mkdir(parents=True, exist_ok=True)
        for item in record.evidence:
            ev_file = evidence_sub_dir / f"{item.evidence_id}.txt"
            ev_file.write_text(item.content, encoding="utf-8")

        # 2. Save append-only jsonl ledger of events and entries
        ledger_file = run_dir / "evidence_ledger.jsonl"
        with open(ledger_file, "w", encoding="utf-8") as f:
            f.writelines(json.dumps({"type": "claim", "data": claim.model_dump(mode="json")}) + "\n" for claim in record.claims)
            f.writelines(json.dumps({"type": "check", "data": check.model_dump(mode="json")}) + "\n" for check in record.checks)
            f.writelines(json.dumps({"type": "execution", "data": exec_item.model_dump(mode="json")}) + "\n" for exec_item in record.executions)
            f.writelines(json.dumps({"type": "evidence", "data": ev.model_dump(mode="json")}) + "\n" for ev in record.evidence)
            f.writelines(json.dumps({"type": "finding", "data": finding.model_dump(mode="json")}) + "\n" for finding in record.findings)

        # 3. Save comprehensive run.json
        run_json_file = run_dir / "run.json"
        run_json_file.write_text(record.model_dump_json(indent=2), encoding="utf-8")

        # 4. Save markdown report if provided
        if report_markdown:
            report_file = run_dir / "report.md"
            report_file.write_text(report_markdown, encoding="utf-8")

        # 5. Update latest symlink or pointer
        latest_pointer = self.runs_dir / "latest"
        try:
            if latest_pointer.is_symlink() or latest_pointer.exists():
                latest_pointer.unlink()
            latest_pointer.symlink_to(run_dir.name)
        except (OSError, NotImplementedError):
            # Fallback if symlinks unsupported
            latest_pointer = self.runs_dir / "latest.txt"
            latest_pointer.write_text(record.run_id, encoding="utf-8")

        return run_dir

    def load_run(self, run_id: str) -> RunRecord | None:
        """Loads a RunRecord by ID (or 'latest')."""
        if run_id == "latest":
            latest_link = self.runs_dir / "latest"
            if latest_link.is_symlink():
                run_id = latest_link.readlink().name
            else:
                latest_txt = self.runs_dir / "latest.txt"
                if latest_txt.is_file():
                    run_id = latest_txt.read_text(encoding="utf-8").strip()
                else:
                    runs = self.list_runs()
                    if not runs:
                        return None
                    run_id = runs[-1]

        target_file = self.get_run_dir(run_id) / "run.json"
        if not target_file.is_file():
            return None

        data = json.loads(target_file.read_text(encoding="utf-8"))
        return RunRecord.model_validate(data)

    def list_runs(self) -> list[str]:
        """Lists all existing run IDs sorted chronologically."""
        if not self.runs_dir.is_dir():
            return []
        run_dirs = [d.name for d in self.runs_dir.iterdir() if d.is_dir() and (d / "run.json").is_file()]
        return sorted(run_dirs)
