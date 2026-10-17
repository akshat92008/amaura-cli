"""Safe isolated subprocess execution."""

import os
import subprocess
import time
from pathlib import Path

from pydantic import BaseModel

from amaura.config import BudgetConfig, SecurityConfig
from amaura.security.permissions import validate_command
from amaura.security.redaction import redact_secrets


class ProcessResult(BaseModel):
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    error: str | None = None


def run_safe_process(
    command: list[str] | str,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout_seconds: int | None = None,
    security_config: SecurityConfig | None = None,
    budget_config: BudgetConfig | None = None,
) -> ProcessResult:
    """Executes a command safely without shell expansion, enforcing timeouts, environment sanitization,
    secret redaction, and bounded output capture.
    """
    sec = security_config or SecurityConfig()
    bud = budget_config or BudgetConfig()

    cmd_parts = validate_command(command, sec)

    effective_timeout = timeout_seconds if timeout_seconds is not None else bud.default_timeout_seconds
    effective_timeout = min(effective_timeout, sec.max_timeout_seconds)

    # Sanitize environment
    clean_env = dict(os.environ)
    for forbidden_var in sec.forbidden_env_vars:
        clean_env.pop(forbidden_var, None)

    # Disable network if privacy_mode is LOCAL_ONLY or sec.allow_network is False
    if sec.privacy_mode.value == "local_only" or not sec.allow_network:
        # Enforce offline behavior flags in common tools
        clean_env["NO_PROXY"] = "*"
        clean_env["PIP_NO_INDEX"] = "1"
        clean_env["PIP_OFFLINE"] = "1"

    if env:
        clean_env.update(env)

    start_t = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd_parts,
            cwd=str(cwd.resolve()),
            env=clean_env,
            capture_output=True,
            timeout=effective_timeout,
            text=True,
            shell=False,  # strictly non-shell
        )
        duration_ms = int((time.perf_counter() - start_t) * 1000)

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        # Enforce max capture limits
        if len(stdout) > bud.max_output_capture_bytes:
            stdout = stdout[:bud.max_output_capture_bytes] + "\n...[TRUNCATED_DUE_TO_SIZE]"
        if len(stderr) > bud.max_output_capture_bytes:
            stderr = stderr[:bud.max_output_capture_bytes] + "\n...[TRUNCATED_DUE_TO_SIZE]"

        if sec.redact_secrets:
            stdout = redact_secrets(stdout)
            stderr = redact_secrets(stderr)

        return ProcessResult(
            command=cmd_parts,
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=False,
        )

    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.perf_counter() - start_t) * 1000)
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")

        if sec.redact_secrets:
            out = redact_secrets(out)
            err = redact_secrets(err)

        return ProcessResult(
            command=cmd_parts,
            exit_code=-1,
            stdout=out,
            stderr=err + f"\nProcess timed out after {effective_timeout}s",
            duration_ms=duration_ms,
            timed_out=True,
            error=f"TimeoutExpired ({effective_timeout}s)",
        )
    except Exception as exc:
        duration_ms = int((time.perf_counter() - start_t) * 1000)
        return ProcessResult(
            command=cmd_parts,
            exit_code=-1,
            stdout="",
            stderr=str(exc),
            duration_ms=duration_ms,
            timed_out=False,
            error=str(exc),
        )
