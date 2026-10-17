"""Unit tests for secret detection and redaction."""

from amaura.security.redaction import redact_secrets


def test_redact_github_token():
    text = "Authorization: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    sanitized = redact_secrets(text)
    assert "ghp_1234567890" not in sanitized
    assert "[REDACTED_GITHUB_TOKEN]" in sanitized


def test_redact_api_key():
    text = "api_key = 'abcdef1234567890abcdef'"
    sanitized = redact_secrets(text)
    assert "abcdef1234567890abcdef" not in sanitized
    assert "[REDACTED_GENERIC_API_KEY]" in sanitized


def test_redact_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    sanitized = redact_secrets(text)
    assert "MIIEow" not in sanitized
    assert "[REDACTED_PRIVATE_KEY]" in sanitized


def test_clean_text_untouched():
    text = "All 15 tests passed in 0.42s"
    assert redact_secrets(text) == text
