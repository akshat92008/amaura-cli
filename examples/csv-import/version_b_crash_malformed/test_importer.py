"""Test suite for Version B CSV Importer."""

from importer import import_csv


def test_valid_import():
    content = "id,name,role\n1,Alice,Engineer\n2,Bob,Scientist\n"
    res = import_csv(content)
    assert res.success is True
    assert len(res.records) == 2


def test_duplicate_detection():
    content = "id,name,role\n1,Alice,Engineer\n1,Alice,Engineer\n"
    res = import_csv(content)
    assert res.success is True
    assert len(res.records) == 1


def test_malformed_csv_safe_rejection():
    # Malformed row with only 2 columns triggers unhandled IndexError in Version B!
    content = "id,name,role\n1,Alice,Engineer\n2,Bob\n"
    res = import_csv(content)
    # The requirement is safe rejection without crashing
    assert res.success is False
