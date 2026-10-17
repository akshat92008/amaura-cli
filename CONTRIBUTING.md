# Contributing to Amaura

Thank you for contributing to Amaura Verify!

Amaura is an evidence-first reliability layer for AI agents. Because the integrity of the verification verdict is critical, all contributions must adhere to strict verification standards.

---

## 1. Ten Core Engineering Rules

Every pull request, verifier enhancement, or policy update must satisfy these ten non-negotiable rules:

1. **Rule 1 (No Self-Approval):** No agent may approve its own work solely through its own assertion. Agent-authored tests and self-reported metrics are treated as untrusted hypotheses.
2. **Rule 2 (No Silent Passes):** No missing check or unexecuted verification may silently count as passed.
3. **Rule 3 (Evidence Precedence):** No final verdict may override contradictory evidence without documented, verifiable resolution.
4. **Rule 4 (Rerun Required for Repairs):** No repair or patch is considered successful until all relevant checks are rerun in a clean environment.
5. **Rule 5 (Evidence Immutability):** No raw evidence is silently overwritten by a later attempt. All verification attempts generate immutable, ordered records.
6. **Rule 6 (Regression Testing):** No release without regression tests for existing verdict behavior.
7. **Rule 7 (Deterministic Verification):** Verification results must be reproducible given identical source trees, task specifications, and environment parameters.
8. **Rule 8 (Strict Containment):** Code execution under verification must strictly operate within designated disposable workspaces without host contamination.
9. **Rule 9 (Default Isolated Networking):** Outbound network access is prohibited by default during verification unless explicitly authorized by policy.
10. **Rule 10 (Release Gate Integrity):** Release gate requires 100% defect recall on builder-labeled and holdout suites, and 0% false positive rate on known-good implementations before any production release.

---

## 2. Local Development Workflow

### Prerequisites
- Python >= 3.11
- `uv` package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)

### Setup Environment
```bash
git clone https://github.com/akshat92008/amaura-cli.git
cd amaura-cli
uv sync --all-groups
```

### Pre-Commit Quality Checks
All checks must pass before opening a pull request:

1. **Linting (ruff):**
   ```bash
   uv run ruff check .
   ```

2. **Type Checking (mypy):**
   ```bash
   uv run mypy src --ignore-missing-imports
   ```

3. **Automated Test Suite (pytest with coverage):**
   ```bash
   uv run pytest -v --cov=amaura --cov-report=term-missing
   ```

4. **Reliability Benchmark & Release Gate (Rule 10):**
   ```bash
   uv run amaura benchmark --suite all
   ```
   **Acceptance Criteria:**
   - Defect Recall: `100.0%`
   - Critical Defect Recall: `100.0%`
   - False Positive Rate: `0.0%`
   - Adversarial Evasion Detection: `100.0%`
   - Release Gate Status: `PASSED`

---

## 3. Pull Request Guidelines

- **Atomic Commits**: Keep commits focused and logically structured.
- **Test Coverage**: Any new feature or bugfix must include corresponding unit, integration, and adversarial probe tests.
- **No Hardcoded Secrets**: Ensure test files never contain active credentials or real API tokens.
