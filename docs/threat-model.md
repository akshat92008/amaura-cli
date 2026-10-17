# Amaura Threat Model & Security Evaluation Matrix

This document defines the threat model for the Amaura CLI verification engine, detailing the attacker profiles, in-scope threats, concrete security controls, and the automated test probes that explicitly evaluate them.

---

## 1. Attacker Profiles & Assumptions

1. **Untrusted AI Agent / Code Under Test**: Generates code, tests, and task outputs. May hallucinate passing results, craft evasive tests, or execute malicious hooks (`conftest.py`, `sitecustomize.py`).
2. **Adversarial Developer / Dependency**: Injects malicious dependencies, exit-code hijackers, or test-skipping annotations designed to forge a `PASSED` verification verdict.
3. **Local Operator / Malicious Environment**: May attempt to tamper with previous verification runs or falsify task specifications.

---

## 2. Threat Catalog & Evaluation Matrix

Each threat below is explicitly evaluated by automated test suites in `tests/security/test_adversarial_probes.py` and `tests/security/test_security.py`:

| Threat ID | Threat Description | Security Control | Automated Test Probe |
|---|---|---|---|
| **T-01** | **Conftest Exit-Code Hijack**: A hostile `conftest.py` hook (`pytest_sessionfinish`, `pytest_unconfigure`) overrides exit codes or manipulates reports to pass failing code. | Independent JUnit XML parsing, AST detection of adversarial hooks (`detect_adversarial_conftest_hooks`), and fail-closed exit code validation. | `test_adversarial_conftest_exit_code_hijack`, `test_adversarial_conftest_unconfigure_hijack` |
| **T-02** | **Vacuous & Trivial Tests**: Passing tests that assert nothing (e.g. `assert True`, `assert 1 == 1`, empty test bodies). | AST assertion analyzer (`inspect_test_function_assertions`) flags trivial constants and comparisons as verification gaps. | `test_vacuous_assertion_detection`, `test_empty_test_function_flagged` |
| **T-03** | **Mutant Survival / Test Decoupling**: Tests pass without exercising actual implementation logic (e.g. `assert len("ab") == 2`). | First-order AST mutation testing (`_verify_acceptance` with candidate mutations and pycache bypass); surviving mutants fail verification. | `test_placeholder_test_fails_on_mutation`, `test_mutant_kills_detected` |
| **T-04** | **Conftest Outcome Forgery**: Custom test hooks intercepting report objects to forge test passes. | Strict hook attribute inspection (`outcome`, `exitstatus`) and JUnit XML node validation. | `test_adversarial_conftest_report_manipulation` |
| **T-05** | **Path Traversal & Host File Access**: Test code attempting to access `/etc/passwd` or write outside workspace root. | Strict workspace root validation (`validate_path_within_workspace`) and pruned external symlinks in `isolated_workspace`. | `test_path_traversal_detection`, `test_symlink_escape_prevented` |
| **T-06** | **Symlink Loops & Disk Exhaustion**: Circular symlinks causing recursive copy crashes, or oversized projects exhausting disk space. | `isolated_workspace` pre-copy size check (100MB cap) and cycle detection via resolved path canonicalization. | `test_symlink_loop_handling`, `test_workspace_size_cap_enforced` |
| **T-07** | **Network Exfiltration**: Subprocess attempting to communicate with external command-and-control servers in `local_only` mode. | Network guard intercepting socket calls (`socket.connect`, `socket.connect_ex`). | `test_network_isolation_guard` |
| **T-08** | **Secret & Credential Leakage**: Execution logs containing API keys, database URLs, or cloud tokens. | Automated high-entropy and pattern-based secret redaction (`RedactionService`). | `test_redaction_secrets`, `test_redaction_comprehensive_tokens` |
| **T-09** | **Resource Exhaustion & Hangs**: Infinite loops or memory allocation bombs attempting to hang the verification pipeline. | POSIX resource limits (`setrlimit` on CPU, address space, file size, processes) and process group termination (`os.killpg`). | `test_process_timeout_enforcement`, `test_e2e_cli_timeout_handling` |
| **T-10** | **Evidence Tampering & Ledger Rewriting**: Modifying past run records or truncating the evidence chain. | Cryptographic hash chaining (`ledger_chain.jsonl`), manifest integrity checks, and inter-process file locking. | `test_ledger_chain_tamper_detection`, `test_manifest_tamper_flagged` |
| **T-11** | **Task Specification Forgery**: Modifying task requirements after agreement without altering the expected hash. | Deterministic task canonicalization and SHA-256 hash verification (`TaskSpec.compute_hash`). | `test_task_hash_verification`, `test_task_tamper_fails_gate` |
| **T-12** | **Fail-Closed Missing Check Bypass**: Missing mandatory acceptance checks attempting to default to `PASSED`. | Fail-closed evaluation policy (`fail_closed_on_missing_check`) converts untested requirements to `OverallVerdict.FAILED`. | `test_missing_mandatory_check_fails_closed` |
