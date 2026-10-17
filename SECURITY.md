# Amaura Security Policy & Sandbox Architecture

## 1. Security Model & Architecture

Amaura independently executes untrusted agent code, tests, datasets, and scripts. Because AI-generated artifacts may contain unintentional bugs or deliberate evasion techniques, Amaura enforces defense-in-depth isolation across the entire verification pipeline.

### Core Security Guarantees

1. **Workspace Isolation & Path Containment (C2, C9)**
   - All verification occurs in disposable, isolated temporary workspaces created via `isolated_workspace`.
   - The workspace enforces a pre-copy size bound (default 100MB) to prevent disk exhaustion attacks.
   - Symlinks are strictly validated: external symlinks pointing outside the workspace and cyclic directory links are detected and pruned.
   - Every file access is validated via `validate_path_within_workspace`, which raises `ExecutionSecurityError` if any path resolves outside the active workspace directory.

2. **Subprocess Confinement & Resource Limits (C3, C4, C5)**
   - All subprocess commands are executed with argument vectors (`shell=False`) to eliminate shell injection vulnerabilities.
   - Command validation blocks raw interactive interpreter bypasses and dangerous patterns while preserving valid tool arguments.
   - Restrictive POSIX resource limits (`setrlimit`) are applied to child processes:
     - CPU time limit: enforced per-check timeout.
     - Virtual memory (address space): capped at 1GB by default.
     - Maximum open file descriptors: capped at 256.
     - Maximum child processes: capped at 64 to prevent fork bombs.
     - Maximum file output size: capped at 50MB.
   - Subprocesses are spawned in dedicated process groups (`preexec_fn=os.setsid`) and terminated gracefully with SIGTERM followed by SIGKILL to ensure no orphan processes survive.
   - Subprocess stdout/stderr streams are read incrementally with bounded memory caps to prevent OOM memory exhaustion.

3. **Environment Sanitization (C10)**
   - The execution environment is scrubbed using a strict allowlist (`clean_env`).
   - Host secrets, database URLs, cloud credentials, tokens, and untrusted environment variables (`PYTHONPATH`, `VIRTUAL_ENV`, `LD_PRELOAD`, `PYTHONSTARTUP`) are completely stripped.
   - Target environments default to isolated execution with `PYTHONDONTWRITEBYTECODE=1` to prevent bytecode manipulation.

4. **Network Guard (C1)**
   - When running in default `local_only` mode, network access is strictly prohibited.
   - Socket connection attempts are intercepted and rejected across all primitives (`socket.connect`, `socket.connect_ex`) before packets leave user space.

5. **Fail-Closed Verification & Dependency Enforcement (A3, Rule 2)**
   - Missing, unparseable, or tampered JUnit XML reports never evaluate to success.
   - A missing tool, failed subprocess, or missing dependency immediately fails closed to `FAILED` or `ERROR`.
   - Missing mandatory acceptance checks prevent a `PASSED` verdict.

6. **Automated Secret Redaction (B8)**
   - Sensitive credentials and tokens are scrubbed from stdout, stderr, and evidence records before persistence.
   - Redaction patterns cover OpenAI keys (`sk-...`), Anthropic keys (`sk-ant-...`), Stripe secret keys (`sk_live_...`), Google AIza API keys, GitHub personal access tokens (`ghp_...`), AWS access keys (`AKIA...`), JSON Web Tokens (JWTs), and database credentials.

7. **Tamper-Evident Ledger Integrity (B1–B6)**
   - Run audit packages are cryptographically anchored using SHA-256 manifest hashes and chained block hashes (`ledger_chain.jsonl`).
   - Inter-process file locking prevents race conditions, and any deletion or tampering of historical records is flagged immediately as an `EvidenceIntegrityError`.

---

## 2. Security Boundaries & Limitations

- **Containerization**: Amaura's default sandbox uses POSIX process confinement, isolated directories, and environment filtering. While this defeats untrusted user-space Python scripts, it is not a hardware-virtualized hypervisor (e.g., Firecracker / gVisor). For untrusted root-level code or kernel exploit payloads, Amaura should be deployed inside a dedicated container or VM.
- **Dynamic Network Services**: In `hybrid` mode, external network calls are permitted if explicitly configured in policy.

---

## 3. Vulnerability Reporting

If you identify a security defect, bypass, or vulnerability in Amaura's sandboxing or verification engine, please report it privately:

- **Email**: `security@amauralabs.org`
- **PGP Key**: Available upon request.
- **Coordinated Disclosure**: We aim to acknowledge reports within 24 hours and provide patches within 7 business days. Please do not disclose vulnerabilities publicly prior to patched release.
