"""Provenance tracking for execution and verification evidence."""

import platform
import sys
from datetime import UTC, datetime

from amaura.models.evidence import Provenance


def build_provenance(
    source: str,
    method: str,
    independent: bool = False,
    extra_env: dict[str, str] | None = None,
) -> Provenance:
    """Builds a rich Provenance record recording platform, Python version, tool metadata and timestamp."""
    env_info = {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "python_version": sys.version.split()[0],
    }
    if extra_env:
        env_info.update(extra_env)

    return Provenance(
        source=source,
        method=method,
        tool_version="amaura-0.1.0",
        timestamp=datetime.now(UTC).isoformat(),
        environment=env_info,
        independent=independent,
    )
