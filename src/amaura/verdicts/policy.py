"""Verification policy definitions and fail-closed evaluation rules."""

from amaura.config import PolicyProfile, VerificationPolicyConfig


class VerdictPolicy:
    """Encapsulates deterministic, explicit evaluation rules for verification."""

    def __init__(self, config: VerificationPolicyConfig | None = None):
        self.config = config or VerificationPolicyConfig()

    @property
    def profile(self) -> PolicyProfile:
        return self.config.profile

    def can_pass_with_missing_check(self) -> bool:
        """Never allow a missing mandatory check to silently count as passing."""
        return False

    def can_override_critical_defect(self) -> bool:
        """A large number of passing cosmetic checks cannot override a critical defect."""
        return False
