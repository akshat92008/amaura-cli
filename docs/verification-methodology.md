# Layered Verification Methodology

Amaura implements seven distinct verification layers:

## Layer 1 — Input and Requirement Integrity
Freezes the original request and acceptance criteria with a cryptographic hash before execution starts. Prevents an agent from quietly redefining success.

## Layer 2 — Artifact Integrity
Generates a SHA-256 manifest of all files in the workspace. Detects unexpected changes, missing files, or out-of-scope edits.

## Layer 3 — Independent Execution
Runs builds and test suites independently without trusting the agent's summary narrative.

## Layer 4 — Test Quality and Adversarial Checks
Analyzes test ASTs for vacuous assertions (`assert True`), empty test bodies, skipped tests, and requirement coverage gaps.

## Layer 5 — Independent Challenge
Evaluates edge cases, failure modes, invalid assumptions, and contradictions between claims and observations.

## Layer 6 — Independent Confirmation
Requires reproducible counterexamples or static confirmation for critical defects.

## Layer 7 — Final Evidence Reconciliation
Maps every requirement and claim to observed execution evidence. Does not allow a missing check to count as passed.
