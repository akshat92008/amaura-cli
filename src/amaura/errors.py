"""Typed exceptions for the Amaura verification system."""



class AmauraError(Exception):
    """Base exception for all Amaura runtime and verification errors."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class TaskSpecificationError(AmauraError):
    """Raised when a task specification is invalid, ambiguous, or tampered."""


class VerificationError(AmauraError):
    """Raised when verification cannot proceed or encounters a fatal flaw."""


class PolicyViolationError(AmauraError):
    """Raised when an operation violates active verification or security policy."""


class ExecutionSecurityError(AmauraError):
    """Raised when an action violates security constraints (path traversal, forbidden cmd, etc.)."""


class ExecutionTimeoutError(AmauraError):
    """Raised when an execution check exceeds its allocated time budget."""


class AdapterError(AmauraError):
    """Raised when an agent adapter fails contract validation or execution."""


class EvidenceIntegrityError(AmauraError):
    """Raised when evidence hash mismatch, missing artifact, or tampering is detected."""


class BenchmarkError(AmauraError):
    """Raised when benchmark runner encounters evaluation failures."""
