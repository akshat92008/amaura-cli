"""Version A: Correct CSV Importer with duplicate detection and safe malformed input rejection (stdlib only)."""

import csv
import io
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImportErrorDetail:
    line_number: int
    reason: str


@dataclass
class ImportResult:
    success: bool
    records: list[dict[str, Any]] = field(default_factory=list)
    duplicates: list[dict[str, Any]] = field(default_factory=list)
    errors: list[ImportErrorDetail] = field(default_factory=list)


def import_csv(content: str, key_field: str = "id") -> ImportResult:
    """Parses CSV text safely, detecting duplicate keys and reporting line-numbered errors without crashing."""
    if not content or not content.strip():
        return ImportResult(
            success=False,
            errors=[ImportErrorDetail(line_number=1, reason="CSV input is empty")],
        )

    errors: list[ImportErrorDetail] = []
    records: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    seen_keys = set()

    try:
        stream = io.StringIO(content.strip())
        reader = csv.reader(stream)
        header = next(reader, None)

        if not header:
            return ImportResult(
                success=False,
                errors=[ImportErrorDetail(line_number=1, reason="Missing CSV header")],
            )

        expected_cols = len(header)
        key_index = -1
        if key_field in header:
            key_index = header.index(key_field)

        for line_no, row in enumerate(reader, start=2):
            # Check for column length mismatch
            if len(row) != expected_cols:
                errors.append(
                    ImportErrorDetail(
                        line_number=line_no,
                        reason=f"Column mismatch: expected {expected_cols} columns, found {len(row)}",
                    )
                )
                continue

            record_dict = dict(zip(header, row))

            # Duplicate detection
            unique_key = row[key_index] if key_index != -1 else tuple(row)
            if unique_key in seen_keys:
                duplicates.append(record_dict)
            else:
                seen_keys.add(unique_key)
                records.append(record_dict)

    except csv.Error as e:
        errors.append(ImportErrorDetail(line_number=1, reason=f"Malformed CSV syntax: {e!s}"))
    except Exception as e:
        errors.append(ImportErrorDetail(line_number=1, reason=f"Parsing error: {e!s}"))

    return ImportResult(
        success=len(errors) == 0,
        records=records,
        duplicates=duplicates,
        errors=errors,
    )
