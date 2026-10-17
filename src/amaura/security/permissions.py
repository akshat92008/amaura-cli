"""Command and permission validation for safe verification execution."""

import shlex

from amaura.config import SecurityConfig
from amaura.errors import ExecutionSecurityError


def validate_command(command: list[str] | str, security_config: SecurityConfig | None = None) -> list[str]:
    """Validates that a command does not violate security constraints.
    Returns normalized command list.
    """
    config = security_config or SecurityConfig()

    if isinstance(command, str):
        # Prevent shell piping or chaining exploits if raw string was passed
        parts = shlex.split(command)
    else:
        parts = list(command)

    if not parts:
        raise ExecutionSecurityError("Command cannot be empty")

    cmd_str = " ".join(parts).lower()
    for forbidden in config.restricted_command_patterns:
        if forbidden.lower() in cmd_str:
            raise ExecutionSecurityError(f"Forbidden command pattern detected: '{forbidden}'")

    # Restrict dangerous binaries
    binary = parts[0].lower()
    disallowed_binaries = {"sudo", "su", "nc", "ncat", "telnet"}
    if binary in disallowed_binaries:
        raise ExecutionSecurityError(f"Execution of binary '{binary}' is prohibited by security policy")

    return parts
