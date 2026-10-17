"""Registry of supported agent adapters."""


from amaura.agents.adapters.artifact_only import ArtifactOnlyAdapter
from amaura.agents.adapters.local_cli import LocalCLIAdapter
from amaura.agents.adapters.mock_agent import MockAgentAdapter
from amaura.agents.base import BaseAgentAdapter
from amaura.errors import AdapterError


class AgentRegistry:
    """Manages available agent adapters."""

    def __init__(self):
        self._adapters: dict[str, BaseAgentAdapter] = {
            "artifact_only": ArtifactOnlyAdapter(),
            "local_cli": LocalCLIAdapter(),
            "mock_agent": MockAgentAdapter(),
        }

    def get(self, name: str) -> BaseAgentAdapter:
        if name not in self._adapters:
            raise AdapterError(
                f"Unknown agent adapter: '{name}'. Available adapters: {sorted(self._adapters.keys())}"
            )
        return self._adapters[name]

    def list_adapters(self) -> list[BaseAgentAdapter]:
        return list(self._adapters.values())

    def register(self, adapter: BaseAgentAdapter) -> None:
        self._adapters[adapter.name] = adapter
