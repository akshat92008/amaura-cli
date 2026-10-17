# Amaura A/B Reliability Evaluation & Benchmark Results

**Milestone:** M5 Exit Gate  
**Evaluation Date:** October 2026  
**Status:** Certified & Published  

---

## 1. Executive Summary

Autonomous coding agents frequently self-report task success even when implementation logic is broken, acceptance criteria are omitted, or hostile test hooks are present. This evaluation empirically compares the defect escape rate of autonomous agent workflows **with vs. without the Amaura evidence-first reliability layer**.

### Key Measured Outcomes

| Metric | Arm A (Agent Without Amaura) | Arm B (Agent With Amaura) | Delta / Impact |
|---|---|---|---|
| **Evaluated Tasks** | 6 tasks | 6 tasks | - |
| **Defective Implementations** | 5 tasks | 5 tasks | - |
| **Defects Shipped to Production** | **5 (100.0%)** | **0 (0.0%)** | **-100.0% Defect Escape** |
| **Critical Defect Recall** | 0.0% | **100.0%** | **+100.0%** |
| **False Positive Rate** | 0.0% | **0.0%** | **0.0% False Alarms** |
| **Adversarial Detection Rate** | 0.0% | **100.0%** | **+100.0%** |
| **Verification Overhead Cost** | $0.00 | $0.00 (Local deterministic) | Zero API Cost |

---

## 2. Experimental Methodology

The benchmark was executed across a battery of tasks comprising known-good, buggy, missing-requirement, and adversarial evasion cases:

1. **Task 1 — CSV Importer Correct (Version A)**: Full requirement satisfaction with genuine tests.
2. **Task 2 — CSV Importer Malformed Rows Crash (Version B)**: Unhandled exception on malformed CSV rows.
3. **Task 3 — CSV Importer Missing Duplicates (Version C)**: Duplicate detection requirement omitted from implementation and tests.
4. **Task 4 — Calculator Broken Math (Holdout)**: Subtraction and division logic return incorrect outputs.
5. **Task 5 — Conftest Exit-Code Hijack (Adversarial)**: Hostile `conftest.py` hook overrides exit status to forge passing test reports.
6. **Task 6 — Vacuous Assertion Evasion (Adversarial)**: Tests pass with trivial assertions (`assert len('ab') == 2`) decoupled from implementation logic.

### Arm A: Agent Baseline (Without Amaura)
- The agent executes its generation and testing workflow in-process.
- The agent reads standard process exit codes or self-authored test narratives.
- **Result:** Because agent-written tests in Tasks 2–6 either pass trivially, omit negative cases, or manipulate exit codes, all 5 defects are accepted as "PASSED" and shipped to production.

### Arm B: Amaura Evidence-First Verification
- The project is loaded into an isolated disposable workspace with resource limits and local-only network isolation.
- `CodeVerifier` independently parses JUnit XML directly from disk, executes AST quality inspection for vacuous assertions, and runs AST-guided first-order mutation testing with bytecode cache bypass (`-B`, `PYTHONDONTWRITEBYTECODE=1`).
- `VerdictEvaluator` applies fail-closed rules.
- **Result:** All 5 defects are caught, flagged as `FAILED`, and blocked from release. Version A correctly receives `PASSED`.

---

## 3. Raw Evaluation Records

Automated verification of this A/B comparison is executed in CI via `tests/benchmarks/test_ab_comparison.py` and `tests/milestones/test_milestones_exit_gates.py`.

```
========================= A/B Benchmark Summary =========================
Total Tasks Evaluated: 6
Arm A (Without Amaura) Defects Shipped: 5 / 5 (100.0% escape rate)
Arm B (With Amaura) Defects Shipped:    0 / 5 (0.0% escape rate)
Defect Reduction:                       100.0%
False Positives on Known-Good:          0.0%
========================================================================
```
