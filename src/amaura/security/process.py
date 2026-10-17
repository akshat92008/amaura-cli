"""Safe isolated subprocess execution with process group cleanup and strict environment allowlists."""

import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from amaura.config import BudgetConfig, SecurityConfig
from amaura.security.permissions import validate_command
from amaura.security.redaction import redact_secrets

# Strict allowlist of safe system environment variables.
# All unapproved caller environment variables (API keys, DB URLs, secret tokens) are stripped.
SAFE_ENV_ALLOWLIST = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "TERM",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
}


class ProcessResult(BaseModel):
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    error: Optional[str] = None


def run_safe_process(
    command: list[str] | str,
    cwd: Path,
    env: Optional[dict[str, str]] = None,
    timeout_seconds: Optional[int] = None,
    security_config: Optional[SecurityConfig] = None,
    budget_config: Optional[BudgetConfig] = None,
) -> ProcessResult:
    """Executes a command in an isolated process group with a strict environment allowlist,
    clean process-tree termination on timeout, secret redaction, and bounded capture.
    """
    sec = security_config or SecurityConfig()
    bud = budget_config or BudgetConfig()

    cmd_parts = validate_command(command, sec)

    effective_timeout = timeout_seconds if timeout_seconds is not None else bud.default_timeout_seconds
    effective_timeout = min(effective_timeout, sec.max_timeout_seconds)

    # 1. Enforce strict environment allowlist
    clean_env: dict[str, str] = {}
    for var_name in SAFE_ENV_ALLOWLIST:
        if var_name in os.environ and var_name not in ("HOME", "USERPROFILE"):
            clean_env[var_name] = os.environ[var_name]

    # Ensure minimal working PATH if stripped
    if "PATH" not in clean_env:
        clean_env["PATH"] = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

    # Isolate HOME to prevent untrusted code from reading caller credentials (e.g. ~/.aws, ~/.ssh)
    sandbox_home = Path(tempfile.gettempdir()) / f"amaura_sandbox_home_{os.getpid()}"
    sandbox_home.mkdir(parents=True, exist_ok=True)
    clean_env["HOME"] = str(sandbox_home.resolve())
    clean_env["USERPROFILE"] = str(sandbox_home.resolve())

    # Enforce offline behavior flags, proxy dead-ends, and socket connect interception when network is disabled
    if sec.privacy_mode.value == "local_only" or not sec.allow_network:
        # Direct all HTTP/HTTPS requests to an invalid local port to fail fast
        clean_env["http_proxy"] = "http://127.0.0.1:0"
        clean_env["https_proxy"] = "http://127.0.0.1:0"
        clean_env["all_proxy"] = "http://127.0.0.1:0"
        clean_env["HTTP_PROXY"] = "http://127.0.0.1:0"
        clean_env["HTTPS_PROXY"] = "http://127.0.0.1:0"
        clean_env["ALL_PROXY"] = "http://127.0.0.1:0"
        clean_env["NO_PROXY"] = ""
        clean_env["PIP_NO_INDEX"] = "1"
        clean_env["PIP_OFFLINE"] = "1"

        # Inject socket blocking hook for python processes
        guard_file = sandbox_home / "sitecustomize.py"
        guard_code = (
            "import socket\n"
            "_orig_connect = socket.socket.connect\n"
            "def _blocked_connect(self, address):\n"
            "    raise PermissionError('Amaura Security Policy: Network connection is strictly prohibited in local_only mode.')\n"
            "socket.socket.connect = _blocked_connect\n"
        )
        guard_file.write_text(guard_code, encoding="utf-8")
        clean_env["PYTHONSTARTUP"] = str(guard_file.resolve())
        existing_pp = clean_env.get("PYTHONPATH", "")
        clean_env["PYTHONPATH"] = f"{sandbox_home.resolve()}:{existing_pp}" if existing_pp else str(sandbox_home.resolve())

    if env:
        clean_env.update(env)

    start_t = time.perf_counter()
    proc: Optional[subprocess.Popen] = None
    try:
        # Run in a new session / process group so child processes can be killed together
        proc = subprocess.Popen(
            cmd_parts,
            cwd=str(cwd.resolve()),
            env=clean_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            start_new_session=True,  # Creates process group on POSIX
        )

        try:
            stdout, stderr = proc.communicate(timeout=effective_timeout)
            duration_ms = int((time.perf_counter() - start_t) * 1000)
            exit_code = proc.returncode

            stdout = stdout or ""
            stderr = stderr or ""

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
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                timed_out=False,
            )

        except subprocess.TimeoutExpired:
            # Terminate the entire process group to avoid orphan processes
            duration_ms = int((time.perf_counter() - start_t) * 1000)
            if hasattr(os, "killpg"):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            else:
                proc.kill()

            stdout, stderr = proc.communicate()
            stdout = stdout or ""
            stderr = (stderr or "") + f"\nProcess group timed out after {effective_timeout}s and was terminated."

            if sec.redact_secrets:
                stdout = redact_secrets(stdout)
                stderr = redact_secrets(stderr)

            return ProcessResult(
                command=cmd_parts,
                exit_code=-1,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                timed_out=True,
                error=f"TimeoutExpired ({effective_timeout}s)",
            )

    except Exception as exc:
        duration_ms = int((time.perf_counter() - start_t) * 1000)
        if proc and proc.poll() is None:
            if hasattr(os, "killpg"):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
            else:
                proc.kill()

        return ProcessResult(
            command=cmd_parts,
            exit_code=-1,
            stdout="",
            stderr=str(exc),
            duration_ms=duration_ms,
            timed_out=False,
            error=str(exc),
        )
