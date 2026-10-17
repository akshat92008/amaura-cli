"""Unit tests for Amaura data models."""

from amaura.models.claim import Claim, ClaimOrigin, ClaimStatus, ClaimType
from amaura.models.evidence import EvidenceItem, EvidenceType, Provenance
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.models.run import OverallVerdict, RunMode, RunRecord
from amaura.models.task import Requirement, TaskSpec


def test_task_spec_freeze_and_hash():
    req = Requirement(id="REQ-001", description="Valid parsing", mandatory=True)
    task = TaskSpec(
        task_id="test_task",
        instruction="Do something",
        requirements=[req],
        constraints=["Local only"],
    )
    assert not task.frozen
    task.freeze()
    assert task.frozen
    assert len(task.task_hash) == 64  # SHA-256


def test_claim_model():
    claim = Claim(
        claim_id="CLM-001",
        text="The CSV import works without crash",
        claim_type=ClaimType.BEHAVIORAL,
        origin=ClaimOrigin.USER_REQUIREMENT,
        status=ClaimStatus.NOT_CHECKED,
    )
    assert claim.claim_id == "CLM-001"
    assert claim.status == ClaimStatus.NOT_CHECKED


def test_evidence_item_hashing():
    prov = Provenance(source="test", method="unit")
    item = EvidenceItem(
        evidence_id="ev_01",
        check_id="chk_01",
        evidence_type=EvidenceType.TEST_OUTPUT,
        content="All 3 tests passed",
        provenance=prov,
    )
    assert len(item.content_hash) == 64


def test_finding_model():
    f = Finding(
        finding_id="find_01",
        check_id="chk_01",
        title="Crash on input",
        description="Unhandled exception",
        finding_type=FindingType.DEFECT,
        severity=FindingSeverity.CRITICAL,
        is_blocking=True,
    )
    assert f.is_blocking is True
    assert f.severity == FindingSeverity.CRITICAL


def test_run_record_serialization():
    req = Requirement(id="REQ-01", description="Basic check")
    task = TaskSpec(task_id="t1", instruction="Run test", requirements=[req]).freeze()
    rec = RunRecord(
        run_id="run_123",
        mode=RunMode.VERIFY,
        task=task,
        working_dir="/tmp",
        overall_verdict=OverallVerdict.PASSED,
        verdict_reasons=["All checks passed"],
    )
    json_data = rec.model_dump_json()
    loaded = RunRecord.model_validate_json(json_data)
    assert loaded.run_id == "run_123"
    assert loaded.overall_verdict == OverallVerdict.PASSED
