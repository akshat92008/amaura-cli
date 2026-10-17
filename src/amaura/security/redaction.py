"""Secret detection and redaction utilities for evidence and logs."""

import re
from re import Pattern

# Patterns identifying common secrets
SECRET_PATTERNS: list[tuple[str, Pattern]] = [
    ("OPENAI_KEY", re.compile(r"sk-[a-zA-Z0-9_-]{20,}")),
    ("GENERIC_API_KEY", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})['\"]?")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----")),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr][_-][a-zA-Z0-9]{20,}")),
    ("SLACK_TOKEN", re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}")),
    ("PASSWORD_FIELD", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?")),
]


def redact_secrets(text: str) -> str:
    """Redacts potential credentials, keys, and tokens from text before recording."""
    if not text:
        return text

    sanitized = text
    for secret_type, pattern in SECRET_PATTERNS:
        if secret_type == "GENERIC_API_KEY" or secret_type == "PASSWORD_FIELD":
            def repl(m, st=secret_type):
                full = m.group(0)
                val = m.group(2)
                return full.replace(val, f"[REDACTED_{st}]")
            sanitized = pattern.sub(repl, sanitized)
        else:
            sanitized = pattern.sub(f"[REDACTED_{secret_type}]", sanitized)

    return sanitized
