# Amaura CLI — Full Product & Architecture Specification

**Version:** 0.1.0  
**Status:** Implemented & Verified  
**Classification:** Core System Architecture  

---

## 1. Mission & Defining Principles

Amaura is an **evidence-first reliability layer for AI agents**.

In an era where autonomous AI agents generate code, execute workflows, and self-report task success, their self-attestations are fundamentally unverified. A passing exit code or a claim of *"All tests pass and all requirements are met"* cannot be accepted as truth without independent, reproducible evidence.

### Defining Principle
> **Never confuse an agent's assertion with evidence that the assertion is true.**

### Five Core Questions Answered on Every Run
1. **What exactly was claimed?** (Frozen, canonical task requirements and explicit claims).
2. **What evidence would establish or contradict each claim?** (Deterministic verification plan).
3. **What checks were actually executed, and in what environment?** (Isolated disposable workspace with resource limits and network isolation).
4. **What did the evidence establish, fail to establish, or contradict?** (Strict mapping from evidence to findings to claim statuses).
5. **What remains uncertain, and what would be needed to resolve it?** (Fail-closed verdict policy and explicit verification gap reporting).

---

## 2. Ten Immutable Engineering Rules

Amaura enforces ten non-negotiable rules governing all verification pipelines, verdict policies, and audit ledgers:

1. **Rule 1 (No Self-Approval):** No agent may approve its own work solely through its own assertion. Agent-authored tests and self-reported metrics are treated as untrusted hypotheses, not ground truth.
2. **Rule 2 (No Silent Passes):** No missing check or unexecuted verification may silently count as passed.
3. **Rule 3 (Evidence Precedence):** No final verdict may override contradictory evidence without documented, verifiable resolution.
4. **Rule 4 (Rerun Required for Repairs):** No repair or patch is considered successful until all relevant checks are rerun and verified in a fresh environment.
5. **Rule 5 (Evidence Immutability):** No raw evidence is silently overwritten by a later attempt. All verification attempts generate immutable, chronologically ordered records.
6. **Rule 6 (Regression Testing):** No release without regression tests for existing verdict behavior.
7. **Rule 7 (Deterministic Verification):** Verification results must be reproducible given identical source trees, task specifications, and environment parameters.
8. **Rule 8 (Strict Containment):** Code execution under verification must strictly operate within designated disposable workspaces without host contamination.
9. **Rule 9 (Default Isolated Networking):** Outbound network access is prohibited by default during verification unless explicitly authorized by policy.
10. **Rule 10 (Release Gate Integrity):** Release gate requires 100% defect recall on builder-labeled and holdout suites, and 0% false positive rate on known-good implementations before any production release.

---

## 3. Architecture & Core Subsystems

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                   AMAURA CLI                                    │
│  (verify | audit | run | claim-check | benchmark | review | replay | policy)   │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        ┌───────────────────────┐             ┌───────────────────────┐
        │   Task Specification  │             │     Claims Intake     │
        │ (Canonical SHA-256)   │             │ (YAML / Markdown / ID)│
        └───────────┬───────────┘             └───────────┬───────────┘
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
                       ┌───────────────────────────────┐
                       │   Verification Plan Engine    │
                       │ (Deterministic Check Mapping) │
                       └───────────────┬───────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        ┌───────────────────────┐             ┌───────────────────────┐
        │  Isolated Workspace   │             │  Safe Process Runner  │
        │ (Symlink Guard & Cap) │             │ (rlimits, env scrub)  │
        └───────────┬───────────┘             └───────────┬───────────┘
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
                       ┌───────────────────────────────┐
                       │     Independent Verifiers     │
                       │ ┌───────────────────────────┐ │
                       │ │ Code (AST, JUnit, Mutants)│ │
                       │ │ Data (CSV schema & dupes) │ │
                       │ │ Calculations (Sympy/Arith)│ │
                       │ │ Citations & Documents     │ │
                       │ └───────────────────────────┘ │
                       └───────────────┬───────────────┘
                                       ▼
                       ┌───────────────────────────────┐
                       │   Evidence Ledger & Graph     │
                       │ (SHA-256 Hash-Chain & Manifest│
                       └───────────────┬───────────────┘
                                       ▼
                       ┌───────────────────────────────┐
                       │   Deterministic Verdict Engine│
                       │ (Fail-Closed, Support Matrix) │
                       └───────────────┬───────────────┘
                                       ▼
                       ┌───────────────────────────────┐
                       │   Structured Reports & UX     │
                       │ (Terminal, JSON, Markdown)    │
                       └───────────────────────────────┘
```

### 3.1 Task Specifications & Claim Intake
- **TaskSpec**: Canonical task definitions with instructions, acceptance criteria, constraints, and risk levels. Tasks are hashed via deterministic JSON serialization (`task_hash`) and can be `frozen`.
- **Claim**: Fine-grained propositions categorized by origin (`user_requirement`, `agent_output`, `inferred`), type (`factual`, `behavioral`, `performance`, `constraint`), and importance (`critical`, `high`, `medium`, `low`).

### 3.2 Independent Verifiers
Verifiers execute in isolation and output structured evidence and findings:
- **CodeVerifier**: 
  - AST quality inspections (detects vacuous `assert True`, literal comparisons, missing assertions, and skip hooks).
  - Independent JUnit XML parsing (bypasses conftest exit code manipulation and fake assertions).
  - Target venv auto-discovery (`_find_python_executable` prefers target project's `.venv` over host interpreter).
  - AST-guided first-order mutation testing with bytecode bypass (`-B`, `PYTHONDONTWRITEBYTECODE=1`, pycache cleanup) to detect placeholder tests where mutants survive.
- **DataVerifier**: Inspects CSV/tabular data schemas, checks header column alignment, counts duplicate rows, detects malformed entries, and enforces workspace path boundaries.
- **CalculationsVerifier**: Recomputes mathematical formulas and statistical claims independently using deterministic precision.
- **CitationsVerifier & DocumentsVerifier**: Validates text assertions, references, and document constraints.

### 3.3 Sandboxing & Security Confinement
- **Workspace Isolation**: Execution operates strictly in temporary disposable directories (`isolated_workspace`). External and cyclic symlinks are pruned before execution to prevent path traversal and recursive loops. Workspace size is capped at 100MB by default.
- **Process Sandbox**: Subprocesses run with stripped environments (`clean_env` allowlist), restrictive POSIX resource limits (`setrlimit` on CPU, address space, open files, and processes), `shell=False`, and timeout enforcement via process groups (`os.killpg`).
- **Network Isolation**: Outbound network requests in `local_only` mode are intercepted and rejected across all socket operations (`connect`, `connect_ex`).
- **Secret Redaction**: High-entropy API keys (OpenAI, Anthropic, Stripe, AWS, GitHub, Google AIza, JWTs) are scrubbed before persistence.

### 3.4 Tamper-Evident Evidence Ledger
- Each run writes an immutable run record (`run.json`), evidence items (`evidence.jsonl`), and manifest (`manifest.json`).
- All runs are appended to a cryptographic ledger chain (`ledger_chain.jsonl`) protected by SHA-256 block hashing (`block_hash = sha256(prev_hash + run_id + manifest_hash + record_hash)`).
- Cross-process file locking prevents race conditions and detects any file deletion or tampering.

### 3.5 Deterministic Verdict Evaluator
Strict separation between execution status and claim status:
- **Check Statuses**: `PASSED`, `FAILED`, `ERROR`, `TIMED_OUT`, `NOT_RUN`.
- **Claim Statuses**: `VERIFIED`, `CONTRADICTED`, `UNVERIFIED`, `INSUFFICIENT_EVIDENCE`, `NOT_CHECKED`.
- **Overall Verdict**: `PASSED`, `FAILED`, `INCONCLUSIVE`, `SUPPORTED_WITH_LIMITATIONS`.

---

## 4. Benchmark & Release Gate (Rule 10)

The release gate enforces reliability across a battery of test suites:
- **CSV Import Suite**: Version A (Correct), Version B (Crash on malformed), Version C (Unchecked acceptance).
- **Holdout Suite**: Unseen correct implementations and edge cases.
- **Adversarial Suite**: Conftest exit code hijackers, mutant survivors, empty test suites, and path traversal probes.

**Gate Target Requirements:**
- Defect Recall: `100.0%`
- Critical Defect Recall: `100.0%`
- False Positive Rate: `0.0%`
- Adversarial Evasion Detection: `100.0%`
- Gate Status: `PASSED`

---

## 5. Milestone Implementation Status & Roadmap

Amaura maintains strict transparency between verified capabilities and roadmap milestones:

- **M0 (Verification Kernel - Completed)**: Independent check runners, evidence graph, cryptographic SHA-256 ledger chaining, and fail-closed 3-state verdict engine.
- **M1 (Agent Adapters - Foundational)**: Standardized adapter interfaces (`artifact_only`, `local_cli`, `model`), usage tracking, and timeout guards. Autonomous multi-turn agent execution loops remain roadmap.
- **M2 (Adversarial Evasion & Test Hardening - Completed Core)**: Terminal stdout cross-checking against JUnit XML, AST detection of hostile conftest hooks, vacuous test identification, and bytecode-isolated mutation testing. Automated iterative code repair is roadmap.
- **M3 (Local-First Privacy & OS Sandbox - Completed Core)**: OS-level kernel isolation via `sandbox-exec` (Darwin) and `bwrap`/`unshare` (Linux), outbound socket blocking in local mode, workspace boundary containment, and externalized ledger anchor keys (`~/.amaura/ledger_anchor.key`).
- **M4 (Multi-Domain Verifiers - Foundational)**: Syntactic verification across code AST, CSV data schemas, and mathematical calculations. Deep NLP-based citation verification and automated ontology lookups remain roadmap.
- **M5 (Reliability Benchmark Release Gate - Completed)**: Full automated test harness validating 100% defect recall, 100% critical recall, 0% false positives, and 100% reproducibility across known-good, known-bad, holdout, and adversarial suites.

