"""Version B: Flawed CSV Importer that crashes on malformed inputs."""

import csv
import io
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImportResult:
    success: bool
    records: list[dict[str, Any]] = field(default_factory=list)
    duplicates: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def import_csv(content: str, key_field: str = "id") -> ImportResult:
    """Parses CSV text, but suffers from an unhandled IndexError crash when encountering malformed rows."""
    stream = io.StringIO(content.strip())
    reader = csv.reader(stream)
    header = next(reader)

    records: list[dict[str, Any]] = []
    seen = set()

    for row in reader:
        # FLAW: Direct index access assuming all rows have exactly 3 columns
        # When a malformed row like '2,Bob' is passed, row[2] raises uncaught IndexError!
        rec = {
            header[0]: row[0],
            header[1]: row[1],
            header[2]: row[2],  # Crashes on malformed rows!
        }
        val_id = row[0]
        if val_id not in seen:
            seen.add(val_id)
            records.append(rec)

    return ImportResult(success=True, records=records)
