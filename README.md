# Amaura CLI (Amaura Verify)

> **Never confuse an agent's assertion with evidence that the assertion is true.**

Amaura is an evidence-first reliability layer for AI agents. Its job is not merely to review what an agent produces. Its job is to determine which claims are supported by evidence, which checks actually passed, which failures remain, and what cannot yet be trusted.

---

## Key Features

- **Evidence-First Verification**: Every verdict is backed by an immutable provenance chain:
  `Claim -> Obligation -> Check -> Execution -> Evidence -> Finding -> Verdict`
- **Fail-Closed Verdict Policy**: Critical failures, missing mandatory checks, timeouts, and unverified assumptions cannot silently pass. Cosmetic passes never override critical defects.
- **Test Quality & Adversarial Checks**: Tests the tests themselves. Flags vacuous assertions (`assert True`), skipped tests, and requirement coverage gaps.
- **Pluggable Agent Adapters**: Audits pre-existing code (`artifact_only`), operates local coding agents in isolated workspaces (`local_cli`), or integrates with custom runners.
- **Zero-Cost Local Baseline**: Fully functional offline without requiring external paid API calls or cloud models.
- **Cryptographic Provenance**: Every artifact, task specification, and execution output is fingerprinted with SHA-256.

---

## Installation & Setup

Amaura is built in Python 3 (>= 3.11) with Typer and Pydantic:

```bash
# Clone the repository
git clone https://github.com/amaura-labs/amaura-cli.git
cd amaura-cli

# Install dependencies using uv or pip
uv sync
```

---

## Quickstart & Commands

### 1. Initialize Amaura Environment
```bash
amaura init
```
Generates `amaura.toml` configuration and the `.amaura/runs/` append-only audit directory.

### 2. Verify System Environment
```bash
amaura doctor
```
Checks Python runtime, Git CLI, test runners, privacy settings, and secret redaction.

### 3. Verify Existing Work
```bash
# Verify against a task specification
amaura verify ./examples/csv-import/version_a_correct --task ./examples/csv-import/task.md
```

### 4. Non-Destructive Work Audit
```bash
amaura audit ./project --format markdown
```

### 5. Verify Explicit Claims
```bash
amaura claim-check claims.yaml --project ./project
```

### 6. Inspect Audit Reports & Raw Evidence
```bash
# View the latest run report
amaura report latest

# Include full captured execution logs
amaura report latest --show-evidence

# Inspect a specific check or evidence ID
amaura evidence chk_req_req_001
```

### 7. Run Reliability Benchmarks & Release Gates
```bash
amaura benchmark
```

---

## The Reference Demonstration: CSV Importer

Amaura includes three benchmark versions of a CSV importer fixture (`examples/csv-import/`):

- **Version A (Correct)**: Fully satisfies valid parsing, duplicate detection, and malformed input rejection. **Verdict: PASSED**
- **Version B (Crash on Malformed Input)**: Works on ordinary files but crashes with an unhandled `IndexError` when malformed rows are passed. **Verdict: FAILED** (Catches critical defect).
- **Version C (Verification Gap)**: Tests pass, but tests never test duplicate detection. **Verdict: FAILED / INCONCLUSIVE** (Detects untested mandatory requirement).

---

## Non-Negotiable Engineering Rules

1. No agent may approve its own work solely through its own assertion.
2. No missing check may silently count as passed.
3. No final verdict may override contradictory evidence without a documented resolution.
4. No repair is considered successful until relevant checks are rerun.
5. No raw evidence is silently overwritten by a later attempt.
6. No unsupported claim of scientific validity, security, correctness, or novelty.
7. No hidden paid API fallback.
8. No execution of untrusted commands outside the defined permission policy.
9. No external model call in local-only mode.
10. No release without regression tests for existing verdict behavior.

---

## License

Apache 2.0. Copyright © 2026 Amaura Labs.
