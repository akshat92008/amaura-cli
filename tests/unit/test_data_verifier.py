"""Unit tests for DataVerifier (H4 coverage boost)."""

from pathlib import Path

from amaura.config import AmauraConfig
from amaura.evidence.collector import EvidenceCollector
from amaura.models.check import CheckDefinition, CheckStatus, CheckType
from amaura.verifiers.data import DataVerifier


def test_data_verifier_no_csv(tmp_path: Path):
    collector = EvidenceCollector(run_id="run_test")
    verifier = DataVerifier(config=AmauraConfig())
    check = CheckDefinition(
        check_id="chk_data_1",
        name="Data Integrity Check",
        check_type=CheckType.SCHEMA_CHECK,
        target_claim_id="clm_1",
        description="Verify CSV files",
    )
    result = verifier.verify(tmp_path, check, collector)
    assert result.execution.status == CheckStatus.PASSED
    assert len(result.findings) == 0
    assert "Inspecting 0 CSV data files" in result.execution.stdout


def test_data_verifier_valid_csv(tmp_path: Path):
    csv_file = tmp_path / "valid.csv"
    csv_file.write_text("id,name,value\n1,alpha,10\n2,beta,20\n", encoding="utf-8")

    collector = EvidenceCollector(run_id="run_test")
    verifier = DataVerifier(config=AmauraConfig())
    check = CheckDefinition(
        check_id="chk_data_2",
        name="Data Integrity Check",
        check_type=CheckType.SCHEMA_CHECK,
        target_claim_id="clm_1",
        description="Verify CSV files",
    )
    result = verifier.verify(tmp_path, check, collector)
    assert result.execution.status == CheckStatus.PASSED
    assert len(result.findings) == 0
    assert result.execution.exit_code == 0


def test_data_verifier_empty_csv(tmp_path: Path):
    csv_file = tmp_path / "empty.csv"
    csv_file.write_text("", encoding="utf-8")

    collector = EvidenceCollector(run_id="run_test")
    verifier = DataVerifier(config=AmauraConfig())
    check = CheckDefinition(
        check_id="chk_data_3",
        name="Data Integrity Check",
        check_type=CheckType.SCHEMA_CHECK,
        target_claim_id="clm_1",
        description="Verify CSV files",
    )
    result = verifier.verify(tmp_path, check, collector)
    assert result.execution.status == CheckStatus.PASSED
    assert "Warning - Empty CSV file" in result.execution.stdout


def test_data_verifier_malformed_rows(tmp_path: Path):
    csv_file = tmp_path / "bad.csv"
    csv_file.write_text("col1,col2,col3\nval1,val2\nval1,val2,val3,val4\n", encoding="utf-8")

    collector = EvidenceCollector(run_id="run_test")
    verifier = DataVerifier(config=AmauraConfig())
    check = CheckDefinition(
        check_id="chk_data_4",
        name="Data Integrity Check",
        check_type=CheckType.SCHEMA_CHECK,
        target_claim_id="clm_1",
        description="Verify CSV files",
    )
    result = verifier.verify(tmp_path, check, collector)
    assert result.execution.status == CheckStatus.FAILED
    assert len(result.findings) == 1
    assert "bad.csv contains 2 malformed rows" in result.findings[0].description


def test_data_verifier_duplicate_rows(tmp_path: Path):
    csv_file = tmp_path / "dupes.csv"
    csv_file.write_text("col1,col2\na,b\na,b\nc,d\n", encoding="utf-8")

    collector = EvidenceCollector(run_id="run_test")
    verifier = DataVerifier(config=AmauraConfig())
    check = CheckDefinition(
        check_id="chk_data_5",
        name="Data Integrity Check",
        check_type=CheckType.SCHEMA_CHECK,
        target_claim_id="clm_1",
        description="Verify CSV files",
    )
    result = verifier.verify(tmp_path, check, collector)
    assert result.execution.status == CheckStatus.PASSED
    assert "detected 1 duplicate rows" in result.execution.stdout


def test_data_verifier_unreadable_file_exception(tmp_path: Path, monkeypatch):
    csv_file = tmp_path / "unreadable.csv"
    csv_file.write_text("id,val\n1,2\n", encoding="utf-8")

    def mock_open(*args, **kwargs):
        raise OSError("Permission denied")

    monkeypatch.setattr("builtins.open", mock_open)

    collector = EvidenceCollector(run_id="run_test")
    verifier = DataVerifier(config=AmauraConfig())
    check = CheckDefinition(
        check_id="chk_data_6",
        name="Data Integrity Check",
        check_type=CheckType.SCHEMA_CHECK,
        target_claim_id="clm_1",
        description="Verify CSV files",
    )
    result = verifier.verify(tmp_path, check, collector)
    assert result.execution.status == CheckStatus.FAILED
    assert len(result.findings) == 1
    assert "Data Ingestion Error" in result.findings[0].title
