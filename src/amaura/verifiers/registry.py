"""Registry for domain-specific verifiers."""

from amaura.config import AmauraConfig
from amaura.verifiers.base import BaseVerifier
from amaura.verifiers.calculations import CalculationVerifier
from amaura.verifiers.citations import CitationVerifier
from amaura.verifiers.code import CodeVerifier
from amaura.verifiers.data import DataVerifier
from amaura.verifiers.documents import DocumentVerifier
from amaura.verifiers.experiments import ExperimentVerifier


class VerifierRegistry:
    """Registry managing available verification engines."""

    def __init__(self, config: AmauraConfig):
        self.config = config
        self._verifiers: dict[str, BaseVerifier] = {
            "code": CodeVerifier(config),
            "data": DataVerifier(config),
            "calculations": CalculationVerifier(config),
            "citations": CitationVerifier(config),
            "documents": DocumentVerifier(config),
            "experiments": ExperimentVerifier(config),
        }

    def get(self, name: str) -> BaseVerifier:
        return self._verifiers.get(name, self._verifiers["code"])

    def register(self, name: str, verifier: BaseVerifier) -> None:
        self._verifiers[name] = verifier
