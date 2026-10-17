"""Registry of supported agent adapters."""


from amaura.agents.adapters.artifact_only import ArtifactOnlyAdapter
from amaura.agents.adapters.local_cli import LocalCLIAdapter
from amaura.agents.adapters.mock_agent import MockAgentAdapter
from amaura.agents.base import BaseAgentAdapter


class AgentRegistry:
    """Manages available agent adapters."""

    def __init__(self):
        self._adapters: dict[str, BaseAgentAdapter] = {
            "artifact_only": ArtifactOnlyAdapter(),
            "local_cli": LocalCLIAdapter(),
            "mock_agent": MockAgentAdapter(),
        }

    def get(self, name: str) -> BaseAgentAdapter:
        return self._adapters.get(name, self._adapters["artifact_only"])

    def list_adapters(self) -> list[BaseAgentAdapter]:
        return list(self._adapters.values())

    def register(self, adapter: BaseAgentAdapter) -> None:
        self._adapters[adapter.name] = adapter
