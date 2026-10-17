# Task: CSV Import with Duplicate Detection and Malformed Input Rejection

Implement a robust CSV import module that parses tabular data, identifies duplicate records according to a key, and safely rejects malformed inputs with diagnostic error information without crashing.

## Requirements
- REQ-001: Correct valid CSV parsing and import into records. (acceptance: test_valid_import)
- REQ-002: Duplicate detection according to unique key or row identity. (acceptance: test_duplicate_detection)
- REQ-003: Safe rejection of malformed CSV input with line numbers and reasons without unhandled crashes. (acceptance: test_malformed_csv_safe_rejection)
- REQ-004: Sensitive data must not be logged or leaked. (acceptance: test_sensitive_data_not_logged)

## Constraints
- Python 3 standard library (e.g. `csv` module).
- All checks must run locally without network access.
- Any malformed input must return structured errors rather than raising uncaught exceptions.
