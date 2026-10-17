# Verdict Policy & Evaluation Rules

Amaura enforces deterministic verdict evaluation. It strictly rejects ungrounded AI confidence scores.

## Status Vocabularies

### Check Statuses
- `passed`: Check executed successfully with exit code 0.
- `failed`: Check failed or exited with non-zero status.
- `error`: Check encountered execution errors or verifier crashes.
- `timed_out`: Check exceeded allocated timeout budget.
- `not_run`: Check was planned but not executed.

### Claim Statuses
- `supported`: Defined evidence threshold met with verified tests.
- `contradicted`: Credible evidence conflicts with the claim.
- `inconclusive`: Evidence is insufficient, ambiguous, or contains gaps.
- `not_checked`: No suitable check was performed.
- `not_applicable`: Check does not apply to this scope.

## Core Rules
1. **Critical Failure Precedence**: A single failed mandatory acceptance check cannot be overridden by passing cosmetic checks.
2. **Missing Check Fail-Closed**: A missing mandatory check is evaluated as `INCONCLUSIVE` (or `FAILED` in strict profile).
3. **Vacuous Test Rejection**: Empty tests or `assert True` assertions are flagged as verification gaps.
