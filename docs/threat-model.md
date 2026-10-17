# Threat Model

Amaura is explicitly evaluated against the following threats:

1. **Prompt Injection in Artifacts**: Untrusted source files attempting to instruct the reviewer or override security policies.
2. **Malicious Scripts from Agents**: Attempts to execute destructive commands (e.g. `rm -rf /`, `sudo`) or spawn unauthorized reverse shells.
3. **Path Traversal Attacks**: Attempts to read or modify files outside the designated workspace root (`../../etc/passwd`).
4. **Secret Exfiltration**: Accidental logging or transmission of API keys, tokens, or credentials in stdout/stderr.
5. **Manipulated Exit Codes & Fabricated Output**: An agent claiming commands ran when execution logs show no evidence.
6. **Vacuous or Misleading Tests**: Passing test suites that assert nothing (`assert True`) or skip the required behavior.
7. **Tampered Evidence**: Unauthorized modification of past evidence files or test logs.
