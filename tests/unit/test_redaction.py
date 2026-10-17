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


def test_redact_database_url_password():
    text = "Connecting to postgres://postgres:supersecretpass123@localhost:5432/production_db"
    sanitized = redact_secrets(text)
    assert "supersecretpass123" not in sanitized
    assert "[REDACTED_DATABASE_URL_PASSWORD]" in sanitized


def test_redact_huggingface_token():
    text = "export HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz0123456789"
    sanitized = redact_secrets(text)
    assert "hf_abcdefghijklmnopqrstuvwxyz0123456789" not in sanitized
    assert "[REDACTED_HUGGINGFACE_TOKEN]" in sanitized


def test_redact_supabase_and_razorpay_keys():
    text = "sbp_key = 'sbp_1234567890abcdef1234567890', rzp = 'rzp_test_1234567890abcd'"
    sanitized = redact_secrets(text)
    assert "sbp_1234567890abcdef1234567890" not in sanitized
    assert "rzp_test_1234567890abcd" not in sanitized
    assert "[REDACTED_SUPABASE_KEY]" in sanitized
    assert "[REDACTED_RAZORPAY_KEY]" in sanitized


def test_redact_bearer_token_and_password():
    text = "Authorization: Bearer secrettoken1234567890abcdef and password = 'mysecretpassword123'"
    sanitized = redact_secrets(text)
    assert "secrettoken1234567890abcdef" not in sanitized
    assert "mysecretpassword123" not in sanitized
    assert "[REDACTED_BEARER_TOKEN]" in sanitized
    assert "[REDACTED_GENERIC_CREDENTIAL]" in sanitized


def test_clean_text_untouched():
    text = "All 15 tests passed in 0.42s"
    assert redact_secrets(text) == text
