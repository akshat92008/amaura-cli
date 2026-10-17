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


def test_sensitive_data_not_logged(capsys):
    content = "id,name,password,ssn\n1,Alice,SecretP@ss,123-45-6789\n"
    res = import_csv(content)
    assert res.success is True
    captured = capsys.readouterr()
    assert "SecretP@ss" not in captured.out
    assert "SecretP@ss" not in captured.err
    assert "123-45-6789" not in captured.out
    assert "123-45-6789" not in captured.err
