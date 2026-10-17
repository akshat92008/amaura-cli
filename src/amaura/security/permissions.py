"""Command and permission validation for safe verification execution."""

import re
import shlex
from pathlib import Path

from amaura.config import SecurityConfig
from amaura.errors import ExecutionSecurityError


def validate_command(command: list[str] | str, security_config: SecurityConfig | None = None) -> list[str]:
    """Validates that a command does not violate security constraints (C4).
    Uses strict token and word-boundary matching to prevent false positives on substrings like 'sudoku'.
    Also inspects inline python -c scripts to prevent trivial bypasses.
    """
    config = security_config or SecurityConfig()

    if isinstance(command, str):
        parts = shlex.split(command)
    else:
        parts = list(command)

    if not parts:
        raise ExecutionSecurityError("Command cannot be empty")

    disallowed_binaries = {"sudo", "su", "nc", "ncat", "telnet", "curl", "wget"}

    # 1. Check primary binary
    binary = Path(parts[0]).name.lower()
    if binary in disallowed_binaries:
        raise ExecutionSecurityError(f"Execution of binary '{binary}' is prohibited by security policy")

    # 2. Check for disallowed binaries and forbidden command patterns using word boundaries
    cmd_str = " ".join(parts)
    for forbidden in config.restricted_command_patterns:
        # Match using word boundary so 'sudo' does not match 'test_sudoku_solver'
        # Multi-word patterns like 'rm -rf /' or 'nc -e' match accurately
        pattern = rf"(?i)\b{re.escape(forbidden)}\b" if re.match(r"^[a-zA-Z0-9_\-]+$", forbidden) else rf"(?i){re.escape(forbidden)}"
        if re.search(pattern, cmd_str):
            raise ExecutionSecurityError(f"Forbidden command pattern detected: '{forbidden}'")

    # 3. Check for subcommands or wrapped invocations (e.g. sh -c, bash -c, env)
    for token in parts[1:]:
        token_name = Path(token).name.lower()
        if token_name in disallowed_binaries:
            raise ExecutionSecurityError(f"Prohibited binary '{token_name}' detected in command arguments")

    # 4. Inspect python -c scripts to prevent trivial bypass of restricted commands
    if binary in {"python", "python3"} and "-c" in parts:
        c_idx = parts.index("-c")
        if c_idx + 1 < len(parts):
            inline_script = parts[c_idx + 1]
            for forbidden in disallowed_binaries:
                if re.search(rf"(?i)\b{re.escape(forbidden)}\b", inline_script):
                    raise ExecutionSecurityError(f"Forbidden command pattern in inline python script: '{forbidden}'")

    return parts
