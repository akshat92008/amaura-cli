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


def test_redact_stripe_google_and_jwt():
    stripe_key = "sk_" + "live_1234567890abcdef12345678"
    google_key = "AIza" + "SyDa-1234567890abcdef1234567890abc"
    jwt_tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0"
    short_pw = "password = 'pass'"
    text = f"Keys: {stripe_key}, {google_key}, {jwt_tok}, {short_pw}"
    sanitized = redact_secrets(text)

    assert stripe_key not in sanitized
    assert google_key not in sanitized
    assert jwt_tok not in sanitized
    assert "'pass'" not in sanitized
    assert "[REDACTED_STRIPE_KEY]" in sanitized
    assert "[REDACTED_GOOGLE_API_KEY]" in sanitized
    assert "[REDACTED_JWT_TOKEN]" in sanitized
    assert "[REDACTED_GENERIC_CREDENTIAL]" in sanitized


def test_evidence_collector_redacts_secrets_automatically():
    from amaura.evidence.collector import EvidenceCollector
    collector = EvidenceCollector("run_test_123")
    secret = "sk_" + "live_1234567890abcdef12345678"
    item = collector.add_evidence(check_id="chk_1", content=f"Output with {secret}")

    assert secret not in item.content
    assert "[REDACTED_STRIPE_KEY]" in item.content

