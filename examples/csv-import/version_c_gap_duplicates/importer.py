"""Version C: CSV Importer with verification gap (duplicate detection is untested)."""

import csv
import io
from typing import Any

from pydantic import BaseModel, Field


class ImportResult(BaseModel):
    success: bool
    records: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def import_csv(content: str) -> ImportResult:
    """Parses CSV text and handles malformed rows, but duplicate detection was overlooked or left untested."""
    if not content or not content.strip():
        return ImportResult(success=False, errors=["Empty CSV"])

    stream = io.StringIO(content.strip())
    reader = csv.reader(stream)
    header = next(reader, None)
    if not header:
        return ImportResult(success=False, errors=["Missing header"])

    records = []
    errors = []
    expected_cols = len(header)

    for line_no, row in enumerate(reader, start=2):
        if len(row) != expected_cols:
            errors.append(f"Line {line_no}: Column count mismatch")
            continue
        records.append(dict(zip(header, row)))

    return ImportResult(success=len(errors) == 0, records=records, errors=errors)
