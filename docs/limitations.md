# Amaura CLI — Known Limitations & System Boundaries

This document discloses the structural limitations, scope boundaries, and threat assumptions of the Amaura CLI verification platform.

---

## 1. Sandboxing & Isolation Boundaries

- **Process-Level Confinement vs. MicroVMs**:
  Amaura isolates subprocesses using POSIX namespaces/process groups, restrictive resource limits (`setrlimit`), environment scrubbing, and user-space socket hooking. While this completely contains benign failures, accidental leaks, and Python test harness manipulation, it is **not a hardware-isolated hypervisor** (such as AWS Firecracker, gVisor, or Docker rootless containers). Malicious code executing arbitrary C extensions with kernel privilege escalation is outside the sandbox's guarantee. In high-risk environments, Amaura itself should run inside an ephemeral container.
- **Network Hooking Scope**:
  The network guard intercepts standard POSIX Python socket connections (`socket.connect`, `socket.connect_ex`). Compiled binary extensions that make raw system calls directly (`syscall(SYS_connect, ...)`) can bypass Python-level monkeypatching unless enforced by kernel eBPF or seccomp-bpf filters.

---

## 2. Verification & Mutation Scope

- **First-Order Mutation Testing**:
  To prevent combinatorial explosion on large repositories, Amaura's mutation engine executes lightweight first-order mutations (arithmetic operators, comparisons, boolean literals) on targeted source files directly imported by the test suite, capped at 5 mutants per file. It does not perform higher-order multi-point mutation or symbolic execution.
- **Static Assertion Analysis**:
  The AST test analyzer uses static inspection to detect vacuous assertions (`assert True`, trivial literals) and known test framework delegation (`unittest.TestCase`, `pytest.raises`, helper delegation). Deeply nested custom assertion frameworks or dynamic reflection may trigger false positives unless tests are explicitly marked with `@pytest.mark.requirement("<REQ-ID>")`.
- **Target Language Ecosystem**:
  `CodeVerifier` is optimized for Python project verification (JUnit XML, AST, pytest). Verification of other languages (Rust, Go, TypeScript) requires specialized verifier plugins implementing the `BaseVerifier` interface.

---

## 3. Cryptographic Ledger & Trust Model

- **Local Hash Chain**:
  The evidence ledger uses a SHA-256 blockchain (`ledger_chain.jsonl`) with inter-process file locking. This guarantees that concurrent processes cannot overwrite records and detects accidental deletions or tampering. However, because the ledger is stored locally without a hardware Secure Enclave, remote KMS digital signature, or decentralized timestamping authority, an operator with full filesystem write privileges could theoretically recompute the entire chain from block 0. Future versions will support remote ledger anchoring.

---

## 4. Requirement Inference & Semantic Novelty

- **Semantic vs. Syntactic Verification**:
  Amaura verifies that code satisfies explicit, verifiable requirements through reproducible tests and deterministic checks. It does not certify subjective qualities such as user interface elegance, architectural beauty, or scientific research novelty without human domain expert review.
- **Task Specification Quality**:
  Amaura's verification plan is derived from the frozen task specification (`task.md`). If the task specification is underspecified, ambiguous, or lacks testable criteria, Amaura will flag requirement gaps or yield an `INCONCLUSIVE` verdict.
