"""Unit tests for claim intake and synthesis (H4 coverage boost)."""

from pathlib import Path

import pytest

from amaura.errors import TaskSpecificationError
from amaura.models.task import Requirement, TaskSpec
from amaura.planning.claims import derive_claims_from_task, load_claims_file


def test_derive_claims_from_task_deduplication():
    reqs = [
        Requirement(id="REQ-001", description="First req", mandatory=True),
        Requirement(id="REQ-001", description="Duplicate ID req", mandatory=False),
    ]
    task = TaskSpec(task_id="tsk_test", instruction="Test goal", requirements=reqs)
    claims = derive_claims_from_task(task)
    assert len(claims) == 2
    assert claims[0].claim_id == "CLM-REQ-001"
    assert claims[1].claim_id == "CLM-REQ-001_1"
    assert claims[0].importance == "critical"
    assert claims[1].importance == "medium"


def test_load_claims_file_not_found(tmp_path: Path):
    with pytest.raises(TaskSpecificationError, match="Claims file not found"):
        load_claims_file(tmp_path / "nonexistent.yaml")


def test_load_claims_file_invalid_yaml(tmp_path: Path):
    f = tmp_path / "bad.yaml"
    f.write_text("invalid: yaml: : :", encoding="utf-8")
    with pytest.raises(TaskSpecificationError, match="YAML parsing error"):
        load_claims_file(f)


def test_load_claims_file_invalid_type(tmp_path: Path):
    f = tmp_path / "scalar.yaml"
    f.write_text("12345\n", encoding="utf-8")
    with pytest.raises(TaskSpecificationError, match="Claims document must be a list"):
        load_claims_file(f)


def test_load_claims_file_list_of_strings(tmp_path: Path):
    f = tmp_path / "strings.yaml"
    f.write_text("- 'First factual claim'\n- 'Second factual claim'\n", encoding="utf-8")
    claims = load_claims_file(f)
    assert len(claims) == 2
    assert claims[0].claim_id == "CLM-001"
    assert claims[0].text == "First factual claim"
    assert claims[1].claim_id == "CLM-002"


def test_load_claims_file_dict_format(tmp_path: Path):
    f = tmp_path / "dict_format.yaml"
    f.write_text(
        """
claims:
  - claim_id: CLM-101
    text: "Feature X is enabled"
    claim_type: factual
    origin: agent_output
    importance: high
""",
        encoding="utf-8",
    )
    claims = load_claims_file(f)
    assert len(claims) == 1
    assert claims[0].claim_id == "CLM-101"
    assert claims[0].text == "Feature X is enabled"


def test_load_claims_file_duplicate_id_forbidden(tmp_path: Path):
    f = tmp_path / "dupes.yaml"
    f.write_text(
        """
claims:
  - claim_id: CLM-DUPE
    text: "Claim 1"
  - claim_id: CLM-DUPE
    text: "Claim 2"
""",
        encoding="utf-8",
    )
    with pytest.raises(TaskSpecificationError, match="duplicate claim IDs are forbidden"):
        load_claims_file(f)


def test_load_claims_file_validation_error(tmp_path: Path):
    f = tmp_path / "invalid_claim.yaml"
    f.write_text(
        """
claims:
  - claim_id: CLM-BAD
    claim_type: not_a_valid_type
""",
        encoding="utf-8",
    )
    with pytest.raises(TaskSpecificationError, match="Claim validation error"):
        load_claims_file(f)
