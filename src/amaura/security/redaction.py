"""Secret detection and redaction utilities for evidence and logs."""

import re
from re import Pattern

# Comprehensive secret patterns matching credentials, tokens, DB connection strings, and keys
SECRET_PATTERNS: list[tuple[str, Pattern]] = [
    ("OPENAI_KEY", re.compile(r"sk-[a-zA-Z0-9_-]{20,}")),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr][_-][a-zA-Z0-9]{20,}")),
    ("HUGGINGFACE_TOKEN", re.compile(r"hf_[a-zA-Z0-9]{30,}")),
    ("SUPABASE_KEY", re.compile(r"sbp_[a-zA-Z0-9]{20,}")),
    ("RAZORPAY_KEY", re.compile(r"rzp_(?:test|live)_[a-zA-Z0-9]{14,}")),
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("SLACK_TOKEN", re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----")),
    (
        "DATABASE_URL_PASSWORD",
        re.compile(r"(?i)(?:postgres|postgresql|mysql|mongodb|redis):\/\/(?:[^:@\s]+):([^@\s]+)@"),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})"),
    ),
    (
        "GENERIC_API_KEY",
        re.compile(
            r"(?i)(?:api[_-]?key|secret[_-]?key)"
            r"\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{12,})['\"]?"
        ),
    ),
    (
        "AWS_SECRET_KEY",
        re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{20,})['\"]?"),
    ),
    (
        "GENERIC_CREDENTIAL",
        re.compile(
            r"(?i)(?:access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd)"
            r"\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{12,})['\"]?"
        ),
    ),
]


def redact_secrets(text: str) -> str:
    """Redacts potential credentials, keys, database connection passwords, and tokens from text before recording."""
    if not text:
        return text

    sanitized = text
    for secret_type, pattern in SECRET_PATTERNS:
        if secret_type in ("DATABASE_URL_PASSWORD", "BEARER_TOKEN", "GENERIC_API_KEY", "GENERIC_CREDENTIAL", "AWS_SECRET_KEY"):
            def repl(m: re.Match, st: str = secret_type) -> str:
                full = m.group(0)
                val = m.group(1)
                return full.replace(val, f"[REDACTED_{st}]")
            sanitized = pattern.sub(repl, sanitized)
        else:
            sanitized = pattern.sub(f"[REDACTED_{secret_type}]", sanitized)

    return sanitized
