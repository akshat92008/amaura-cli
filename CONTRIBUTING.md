# Contributing to Amaura

Thank you for contributing to Amaura Verify!

## Core Engineering Rules

Before submitting pull requests or modifying verification rules, ensure compliance with Amaura's non-negotiable rules:

1. **No agent may approve its own work solely through its own assertion.**
2. **No missing check may silently count as passed.**
3. **No final verdict may override contradictory evidence without documented resolution.**
4. **No repair is considered successful until relevant checks are rerun.**
5. **No raw evidence is silently overwritten by a later attempt.**
6. **No release without regression tests for existing verdict behavior.**

## Development Workflow

1. Install dependencies:
   ```bash
   uv sync
   ```
2. Run test suites:
   ```bash
   uv run pytest -v
   ```
3. Run linter:
   ```bash
   uv run ruff check .
   ```
4. Run reliability benchmark:
   ```bash
   uv run amaura benchmark
   ```
   All critical defect recalls must remain at 100% and false positive rates must remain 0%.
