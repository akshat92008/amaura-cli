"""Machine-readable JSON audit package generator."""

from amaura.models.run import RunRecord


def generate_json_report(record: RunRecord, indent: int = 2) -> str:
    """Serializes the complete RunRecord into machine-readable JSON."""
    return record.model_dump_json(indent=indent)
