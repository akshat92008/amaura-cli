"""Safe isolated subprocess execution with process group cleanup and strict environment allowlists."""

import os
import platform
import select
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from amaura.config import BudgetConfig, SecurityConfig
from amaura.errors import ExecutionSecurityError
from amaura.security.permissions import validate_command
from amaura.security.redaction import redact_secrets

# Strict allowlist of safe system environment variables.
# Note: PYTHONPATH and VIRTUAL_ENV are explicitly excluded (C10) to prevent host environment pollution.
SAFE_ENV_ALLOWLIST = {
    "PATH",
    "LANG",
    "LC_ALL",
    "TERM",
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


def build_kernel_isolation_command(
    cmd_parts: list[str],
    cwd: Path,
    sandbox_home: Path,
    allowed_roots: list[str],
    sensitive_paths: list[str],
    security_config: SecurityConfig,
) -> list[str]:
    """Wraps process command line with OS-level kernel isolation (sandbox-exec on Darwin, bwrap/unshare on Linux)."""
    os_type = platform.system().lower()

    if os_type == "darwin" and shutil.which("sandbox-exec"):
        profile_rules = [
            "(version 1)",
            "(allow default)",
        ]
        # 1. Kernel Network Denial (C1, Rule 9)
        if security_config.privacy_mode.value == "local_only" or not security_config.allow_network:
            profile_rules.append("(deny network*)")

        # 2. Kernel Sensitive Host Path Read Denial (C2, Rule 8)
        for sp in sensitive_paths:
            sp_res = str(Path(sp).resolve())
            profile_rules.append(f'(deny file-read* (subpath "{sp_res}"))')
            if sp_res.startswith("/private/"):
                sym = sp_res.replace("/private", "")
                profile_rules.append(f'(deny file-read* (subpath "{sym}"))')
            elif sp_res.startswith("/etc/"):
                profile_rules.append(f'(deny file-read* (subpath "/private{sp_res}"))')

        # 3. Kernel Filesystem Write Restrictions (C2, Rule 8)
        profile_rules.append("(deny file-write*)")
        for ar in allowed_roots:
            ar_res = str(Path(ar).resolve())
            profile_rules.append(f'(allow file-write* (subpath "{ar_res}"))')
            if ar_res.startswith("/private/"):
                profile_rules.append(f'(allow file-write* (subpath "{ar_res.replace("/private", "")}"))')

        # Allow writes to standard dev outputs and designated temp subpaths
        profile_rules.append('(allow file-write* (subpath "/dev"))')
        profile_rules.append('(allow file-write* (subpath "/private/var/folders"))')
        profile_rules.append('(allow file-write* (subpath "/var/folders"))')

        profile_str = "".join(profile_rules)
        return ["/usr/bin/sandbox-exec", "-p", profile_str] + cmd_parts

    elif os_type == "linux":
        bwrap = shutil.which("bwrap")
        if bwrap:
            bwrap_cmd = [
                bwrap,
                "--ro-bind", "/", "/",
                "--dev", "/dev",
                "--proc", "/proc",
                "--tmpfs", "/tmp",
            ]
            if security_config.privacy_mode.value == "local_only" or not security_config.allow_network:
                bwrap_cmd.append("--unshare-net")
            for ar in allowed_roots:
                ar_p = str(Path(ar).resolve())
                bwrap_cmd.extend(["--bind", ar_p, ar_p])
            for sp in sensitive_paths:
                sp_p = str(Path(sp).resolve())
                bwrap_cmd.extend(["--tmpfs", sp_p])
            return bwrap_cmd + ["--"] + cmd_parts
        elif shutil.which("unshare") and (security_config.privacy_mode.value == "local_only" or not security_config.allow_network):
            return ["unshare", "-rn"] + cmd_parts

    return cmd_parts


def run_safe_process(
    command: list[str] | str,
    cwd: Path,
    env: Optional[dict[str, str]] = None,
    timeout_seconds: Optional[int] = None,
    security_config: Optional[SecurityConfig] = None,
    budget_config: Optional[BudgetConfig] = None,
    allowed_write_paths: Optional[list[Path]] = None,
) -> ProcessResult:
    """Executes a command in an isolated process group with a strict environment allowlist,
    clean process-tree termination, secret redaction, and bounded capture.
    """
    sec = security_config or SecurityConfig()
    bud = budget_config or BudgetConfig()

    cmd_parts = validate_command(command, sec)

    effective_timeout = timeout_seconds if timeout_seconds is not None else bud.default_timeout_seconds
    effective_timeout = min(effective_timeout, sec.max_timeout_seconds)

    # 1. Enforce forbidden_env_vars check (C10)
    forbidden_set = {v.upper() for v in sec.forbidden_env_vars}
    if env:
        for k in env:
            if k.upper() in forbidden_set:
                raise ExecutionSecurityError(f"Forbidden environment variable attempted: '{k}'")

    # 2. Enforce strict environment allowlist (C10: no PYTHONPATH or VIRTUAL_ENV pass-through)
    clean_env: dict[str, str] = {}
    for var_name in SAFE_ENV_ALLOWLIST:
        if var_name in os.environ:
            clean_env[var_name] = os.environ[var_name]

    # Ensure minimal working PATH if stripped
    if "PATH" not in clean_env:
        clean_env["PATH"] = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

    # Strip any variable from host matching forbidden_env_vars
    for k in list(clean_env.keys()):
        if k.upper() in forbidden_set:
            del clean_env[k]

    # 3. Create isolated, unpredictably named temporary sandbox home and TMPDIR (C7)
    sandbox_tmp_dir = tempfile.TemporaryDirectory(prefix="amaura_sandbox_")
    sandbox_home = Path(sandbox_tmp_dir.name).resolve()
    clean_env["HOME"] = str(sandbox_home)
    clean_env["USERPROFILE"] = str(sandbox_home)
    clean_env["TMPDIR"] = str(sandbox_home)
    clean_env["PYTHONDONTWRITEBYTECODE"] = "1"

    # 4. Enforce offline behavior flags, proxy dead-ends, and socket connect interception (C1, C2)
    resolved_cwd = cwd.resolve()
    host_home = str(Path(os.environ.get("HOME", "/")).resolve())
    sensitive_host_paths = [
        f"{host_home}/.ssh",
        f"{host_home}/.aws",
        f"{host_home}/.gitconfig",
        f"{host_home}/.netrc",
        f"{host_home}/.gnupg",
        f"{host_home}/.config",
        f"{host_home}/.bashrc",
        f"{host_home}/.zshrc",
        f"{host_home}/.probe_cloud_credentials",
        "/etc/shadow",
        "/etc/master.passwd",
    ]

    if sec.privacy_mode.value == "local_only" or not sec.allow_network:
        clean_env["http_proxy"] = "http://127.0.0.1:0"
        clean_env["https_proxy"] = "http://127.0.0.1:0"
        clean_env["all_proxy"] = "http://127.0.0.1:0"
        clean_env["HTTP_PROXY"] = "http://127.0.0.1:0"
        clean_env["HTTPS_PROXY"] = "http://127.0.0.1:0"
        clean_env["ALL_PROXY"] = "http://127.0.0.1:0"
        clean_env["NO_PROXY"] = ""
        clean_env["PIP_NO_INDEX"] = "1"
        clean_env["PIP_OFFLINE"] = "1"

    # Build explicit write root boundaries (C2)
    allowed_roots: list[str] = [
        str(resolved_cwd),
        str(sandbox_home),
    ]
    if allowed_write_paths:
        for p in allowed_write_paths:
            allowed_roots.append(str(Path(p).resolve()))
    for arg in cmd_parts:
        if arg.startswith("--junitxml="):
            xml_path_str = arg.split("=", 1)[1]
            try:
                allowed_roots.append(str(Path(xml_path_str).resolve().parent))
            except Exception:
                pass

    network_guard_snippet = ""
    if sec.privacy_mode.value == "local_only" or not sec.allow_network:
        network_guard_snippet = """
# --- C1: Network Lockdown (Rule 9) ---
def _blocked_network(*args, **kwargs):
    raise PermissionError("Amaura Security Policy: Network operations are strictly prohibited in local_only mode (Rule 9).")

socket.socket.connect = _blocked_network
socket.socket.connect_ex = _blocked_network
socket.socket.bind = _blocked_network
socket.socket.sendto = _blocked_network
if hasattr(socket.socket, "sendmsg"):
    socket.socket.sendmsg = _blocked_network
socket.create_connection = _blocked_network
socket.getaddrinfo = _blocked_network
socket.gethostbyname = _blocked_network
socket.gethostbyname_ex = _blocked_network
"""

    # Write sitecustomize.py for network lockdown (C1) and filesystem isolation (C2)
    guard_file = sandbox_home / "sitecustomize.py"
    guard_code = f"""# Amaura Security Sandbox (sitecustomize.py)
import builtins
import io
import os
import socket
import sys
from pathlib import Path
{network_guard_snippet}
# --- C2: Filesystem Isolation ---
_ALLOWED_WRITE_ROOTS = [{", ".join(repr(r) for r in allowed_roots)}]
_SENSITIVE_HOST_READ_PATHS = [{", ".join(repr(p) for p in sensitive_host_paths)}]

_orig_open = builtins.open
_orig_os_open = os.open
_orig_unlink = os.unlink
_orig_remove = os.remove
_orig_rmdir = os.rmdir
_orig_mkdir = os.mkdir

def _is_allowed_write(path_arg):
    try:
        if isinstance(path_arg, int):
            return True
        p_str = str(path_arg)
        if p_str in (os.devnull, "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/zero"):
            return True
        p = Path(path_arg).resolve()
        if str(p) in (os.devnull, "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/zero"):
            return True
        for root_str in _ALLOWED_WRITE_ROOTS:
            try:
                p.relative_to(root_str)
                return True
            except ValueError:
                pass
        return False
    except Exception:
        return False

def _is_sensitive_read(path_arg):
    try:
        p_str = str(Path(path_arg).resolve())
        for sens in _SENSITIVE_HOST_READ_PATHS:
            if p_str == sens or p_str.startswith(sens + os.sep):
                return True
        return False
    except Exception:
        return False

def _safe_builtins_open(file, mode='r', *args, **kwargs):
    mode_str = str(mode)
    is_write = any(c in mode_str for c in ('w', 'a', 'x', '+'))
    if is_write and not _is_allowed_write(file):
        raise PermissionError(f"Amaura Security Policy: Write access outside workspace is prohibited: '{{file}}'")
    if not is_write and _is_sensitive_read(file):
        raise PermissionError(f"Amaura Security Policy: Read access to sensitive host file is prohibited: '{{file}}'")
    return _orig_open(file, mode, *args, **kwargs)

def _safe_os_open(path, flags, *args, **kwargs):
    is_write = (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)) != 0
    if is_write and not _is_allowed_write(path):
        raise PermissionError(f"Amaura Security Policy: Write access outside workspace is prohibited: '{{path}}'")
    if not is_write and _is_sensitive_read(path):
        raise PermissionError(f"Amaura Security Policy: Read access to sensitive host file is prohibited: '{{path}}'")
    return _orig_os_open(path, flags, *args, **kwargs)

def _safe_unlink(path, *args, **kwargs):
    if not _is_allowed_write(path):
        raise PermissionError(f"Amaura Security Policy: File deletion outside workspace is prohibited: '{{path}}'")
    return _orig_unlink(path, *args, **kwargs)

def _safe_remove(path, *args, **kwargs):
    if not _is_allowed_write(path):
        raise PermissionError(f"Amaura Security Policy: File deletion outside workspace is prohibited: '{{path}}'")
    return _orig_remove(path, *args, **kwargs)

def _safe_rmdir(path, *args, **kwargs):
    if not _is_allowed_write(path):
        raise PermissionError(f"Amaura Security Policy: Directory deletion outside workspace is prohibited: '{{path}}'")
    return _orig_rmdir(path, *args, **kwargs)

def _safe_mkdir(path, *args, **kwargs):
    if not _is_allowed_write(path):
        raise PermissionError(f"Amaura Security Policy: Directory creation outside workspace is prohibited: '{{path}}'")
    return _orig_mkdir(path, *args, **kwargs)

builtins.open = _safe_builtins_open
io.open = _safe_builtins_open
os.open = _safe_os_open
os.unlink = _safe_unlink
os.remove = _safe_remove
os.rmdir = _safe_rmdir
os.mkdir = _safe_mkdir
"""
    guard_file.write_text(guard_code, encoding="utf-8")

    # Set PYTHONPATH to load sitecustomize from sandbox_home and tested code from cwd
    clean_env["PYTHONPATH"] = f"{sandbox_home.resolve()}:{resolved_cwd}"

    if env:
        clean_env.update(env)

    # 5. POSIX Resource Limits (C3)
    def _apply_rlimits():
        try:
            import resource
            # CPU time limit (seconds)
            resource.setrlimit(resource.RLIMIT_CPU, (effective_timeout + 5, effective_timeout + 10))
            # File size limit (50 MB)
            resource.setrlimit(resource.RLIMIT_FSIZE, (50 * 1024 * 1024, 100 * 1024 * 1024))
            # Address space / virtual memory (2 GB)
            mem = 2 * 1024 * 1024 * 1024
            if hasattr(resource, "RLIMIT_AS"):
                resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            # Process count
            if hasattr(resource, "RLIMIT_NPROC"):
                resource.setrlimit(resource.RLIMIT_NPROC, (256, 512))
        except Exception:
            pass

    exec_cmd = build_kernel_isolation_command(
        cmd_parts=cmd_parts,
        cwd=resolved_cwd,
        sandbox_home=sandbox_home,
        allowed_roots=allowed_roots,
        sensitive_paths=sensitive_host_paths,
        security_config=sec,
    )

    start_t = time.perf_counter()
    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            exec_cmd,
            cwd=str(resolved_cwd),
            env=clean_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,  # Binary capture for accurate chunked reading (C5)
            shell=False,
            start_new_session=True,  # Process group on POSIX
            preexec_fn=_apply_rlimits,  # Apply CPU, file size, memory rlimits (C3) # noqa: PLW1509
        )

        stdout_bytes = bytearray()
        stderr_bytes = bytearray()
        limit = bud.max_output_capture_bytes
        timed_out = False
        exceeded_size = False

        from typing import Any
        rlist: list[Any] = [p for p in (proc.stdout, proc.stderr) if p is not None]
        deadline = start_t + effective_timeout

        # Bounded streaming read loop without buffering unbounded output into RAM (C5)
        while rlist:
            now = time.perf_counter()
            remaining = deadline - now
            if remaining <= 0:
                timed_out = True
                break

            readable, _, _ = select.select(rlist, [], [], min(remaining, 0.1))
            if not readable:
                if proc.poll() is not None:
                    # Drain any remaining bytes
                    for stream_pipe in rlist:
                        if stream_pipe:
                            data = stream_pipe.read(65536)
                            if data:
                                if stream_pipe is proc.stdout:
                                    stdout_bytes.extend(data)
                                else:
                                    stderr_bytes.extend(data)
                    break
                continue

            for pipe in readable:
                if pipe:
                    data = pipe.read(65536)
                    if not data:
                        rlist.remove(pipe)
                        continue
                    if pipe is proc.stdout:
                        if len(stdout_bytes) < limit:
                            stdout_bytes.extend(data)
                        else:
                            exceeded_size = True
                    else:
                        if len(stderr_bytes) < limit:
                            stderr_bytes.extend(data)
                        else:
                            exceeded_size = True

            if exceeded_size:
                # Terminate process group immediately if output exceeds budget limit (C5)
                if hasattr(os, "killpg"):
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        pass
                break

        duration_ms = int((time.perf_counter() - start_t) * 1000)

        if timed_out:
            if hasattr(os, "killpg"):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
            else:
                proc.kill()
            proc.wait(timeout=2)
            exit_code = -1
        else:
            try:
                exit_code = proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if hasattr(os, "killpg"):
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        pass
                exit_code = proc.wait()

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if exceeded_size or len(stdout_bytes) >= limit:
            stdout = stdout[:limit] + "\n...[TRUNCATED_DUE_TO_SIZE]"
        if len(stderr_bytes) >= limit:
            stderr = stderr[:limit] + "\n...[TRUNCATED_DUE_TO_SIZE]"

        if timed_out:
            stderr += f"\nProcess group timed out after {effective_timeout}s and was terminated."

        if sec.redact_secrets:
            stdout = redact_secrets(stdout)
            stderr = redact_secrets(stderr)

        return ProcessResult(
            command=cmd_parts,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            error=f"TimeoutExpired ({effective_timeout}s)" if timed_out else None,
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

    finally:
        # C5: Always clean up entire process group on exit, not just on timeout
        if proc and proc.pid:
            if hasattr(os, "killpg"):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            else:
                try:
                    proc.kill()
                except Exception:
                    pass

        # C7: Always clean up predictable temporary sandbox_home
        try:
            sandbox_tmp_dir.cleanup()
        except Exception:
            pass


def run_agent_process(
    command: list[str] | str,
    cwd: Path,
    env: Optional[dict[str, str]] = None,
    timeout_seconds: Optional[int] = None,
    allow_network: bool = True,
    budget_config: Optional[BudgetConfig] = None,
    security_config: Optional[SecurityConfig] = None,
) -> ProcessResult:
    """Executes an external agent process without the restrictive verification sandbox (F2).

    Preserves the host environment, real HOME directory, API keys (e.g., OPENAI_API_KEY,
    ANTHROPIC_API_KEY, GEMINI_API_KEY), and allows outbound network connections, while
    retaining process group lifecycle management, timeout enforcement, output bounding,
    and secret redaction.
    """
    sec = security_config or SecurityConfig()
    bud = budget_config or BudgetConfig()

    cmd_parts = [command] if isinstance(command, str) else list(command)

    effective_timeout = timeout_seconds if timeout_seconds is not None else bud.default_timeout_seconds
    effective_timeout = min(effective_timeout, sec.max_timeout_seconds)

    # Agent runs with host environment preserved (keys, HOME, etc.)
    agent_env = os.environ.copy()

    if not allow_network:
        agent_env["http_proxy"] = "http://127.0.0.1:0"
        agent_env["https_proxy"] = "http://127.0.0.1:0"
        agent_env["all_proxy"] = "http://127.0.0.1:0"
        agent_env["HTTP_PROXY"] = "http://127.0.0.1:0"
        agent_env["HTTPS_PROXY"] = "http://127.0.0.1:0"
        agent_env["ALL_PROXY"] = "http://127.0.0.1:0"

    if env:
        agent_env.update(env)

    start_t = time.perf_counter()
    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            cmd_parts,
            cwd=str(cwd.resolve()),
            env=agent_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            start_new_session=True,  # Process group on POSIX
        )

        stdout_bytes = bytearray()
        stderr_bytes = bytearray()
        limit = bud.max_output_capture_bytes
        timed_out = False
        exceeded_size = False

        rlist = [p for p in (proc.stdout, proc.stderr) if p is not None]
        deadline = start_t + effective_timeout

        while rlist:
            now = time.perf_counter()
            remaining = deadline - now
            if remaining <= 0:
                timed_out = True
                break

            readable, _, _ = select.select(rlist, [], [], min(remaining, 0.1))
            if not readable:
                if proc.poll() is not None:
                    for stream_pipe in rlist:
                        if stream_pipe:
                            data = stream_pipe.read(65536)
                            if data:
                                if stream_pipe is proc.stdout:
                                    stdout_bytes.extend(data)
                                else:
                                    stderr_bytes.extend(data)
                    break
                continue

            for stream_pipe in readable:
                if not stream_pipe:
                    continue
                data = stream_pipe.read(65536)
                if not data:
                    rlist.remove(stream_pipe)
                else:
                    if stream_pipe is proc.stdout:
                        if len(stdout_bytes) < limit:
                            stdout_bytes.extend(data[: limit - len(stdout_bytes)])
                        else:
                            exceeded_size = True
                    else:
                        if len(stderr_bytes) < limit:
                            stderr_bytes.extend(data[: limit - len(stderr_bytes)])
                        else:
                            exceeded_size = True

        if timed_out and proc.poll() is None:
            if hasattr(os, "killpg"):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            else:
                proc.kill()
            exit_code = -1
        else:
            exit_code = proc.wait()

        duration_ms = int((time.perf_counter() - start_t) * 1000)

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if exceeded_size:
            stderr += f"\n[Output truncated: exceeded {limit} bytes limit]"

        if timed_out:
            stderr += f"\nAgent process group timed out after {effective_timeout}s and was terminated."

        if sec.redact_secrets:
            stdout = redact_secrets(stdout)
            stderr = redact_secrets(stderr)

        return ProcessResult(
            command=cmd_parts,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            error=f"TimeoutExpired ({effective_timeout}s)" if timed_out else None,
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

    finally:
        if proc and proc.pid:
            if hasattr(os, "killpg"):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            else:
                try:
                    proc.kill()
                except Exception:
                    pass
