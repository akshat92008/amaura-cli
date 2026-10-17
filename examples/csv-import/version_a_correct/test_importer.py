"""Comprehensive test suite for Version A CSV Importer."""

from importer import import_csv


def test_valid_import():
    content = "id,name,role\n1,Alice,Engineer\n2,Bob,Scientist\n"
    res = import_csv(content)
    assert res.success is True
    assert len(res.records) == 2
    assert res.records[0]["name"] == "Alice"
    assert len(res.errors) == 0


def test_duplicate_detection():
    content = "id,name,role\n1,Alice,Engineer\n1,Alice_Duplicate,Engineer\n2,Bob,Scientist\n"
    res = import_csv(content)
    assert res.success is True
    assert len(res.records) == 2
    assert len(res.duplicates) == 1
    assert res.duplicates[0]["id"] == "1"


def test_malformed_csv_safe_rejection():
    # Uneven columns and broken format
    content = "id,name,role\n1,Alice,Engineer\n2,Bob\n3,Charlie,Designer,ExtraColumn\n"
    res = import_csv(content)
    assert res.success is False
    assert len(res.errors) == 2
    assert res.errors[0].line_number == 3
    assert "expected 3 columns" in res.errors[0].reason
