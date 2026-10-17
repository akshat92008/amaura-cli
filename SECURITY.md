# Security Policy

## Security Model & Protections

Amaura handles untrusted code, agent outputs, datasets, documents, and potentially sensitive files. The following security principles are strictly enforced:

1. **Least Privilege**: Only files within the workspace are accessible. External network access is disabled by default in `local_only` mode.
2. **Workspace Isolation**: Execution operates within disposable workspaces or isolated Git worktrees.
3. **No Shell Interpolation**: All subprocess executions use argument lists (`shell=False`) to prevent command injection.
4. **Secret Redaction**: API keys, tokens, authorization headers, and private keys are scrubbed from logs and evidence before persistence.
5. **Fail-Closed Execution**: Verifier crashes, timeouts, or missing dependencies never evaluate to success.
6. **Path Traversal Containment**: Path validation ensures operations cannot resolve outside the active workspace.

## Reporting Vulnerabilities

To report a vulnerability or security concern, please contact: `security@amauralabs.org`.
Do not disclose vulnerabilities publicly until a patch has been published.
