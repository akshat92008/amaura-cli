"""Test suite for Version C CSV Importer.
All tests pass, but duplicate detection is completely omitted from verification!
"""

from importer import import_csv


def test_valid_import():
    content = "id,name,role\n1,Alice,Engineer\n2,Bob,Scientist\n"
    res = import_csv(content)
    assert res.success is True
    assert len(res.records) == 2


def test_malformed_csv_safe_rejection():
    content = "id,name,role\n1,Alice,Engineer\n2,Bob\n"
    res = import_csv(content)
    assert res.success is False
    assert len(res.errors) == 1
