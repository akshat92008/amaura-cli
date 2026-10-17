"""Registry of supported agent adapters."""


from amaura.agents.adapters.artifact_only import ArtifactOnlyAdapter
from amaura.agents.adapters.local_cli import LocalCLIAdapter
from amaura.agents.adapters.mock_agent import MockAgentAdapter
from amaura.agents.adapters.model import ModelAgentAdapter
from amaura.agents.base import AgentCapability, BaseAgentAdapter
from amaura.errors import AdapterError


class AgentRegistry:
    """Manages available agent adapters and capability discovery (F4)."""

    def __init__(self):
        self._adapters: dict[str, BaseAgentAdapter] = {
            "artifact_only": ArtifactOnlyAdapter(),
            "local_cli": LocalCLIAdapter(),
            "mock_agent": MockAgentAdapter(),
            "model": ModelAgentAdapter(),
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

    def find_by_capability(self, capability: AgentCapability | str) -> list[BaseAgentAdapter]:
        """Discovers all adapters supporting the specified capability (F4)."""
        cap_val = capability.value if isinstance(capability, AgentCapability) else str(capability)
        return [
            adapter
            for adapter in self._adapters.values()
            if any(
                (c.value if isinstance(c, AgentCapability) else str(c)) == cap_val
                for c in adapter.capabilities
            )
        ]

    def get_all_capabilities(self) -> dict[str, list[AgentCapability]]:
        """Returns a mapping of adapter names to their supported capabilities (F4)."""
        return {name: adapter.capabilities for name, adapter in self._adapters.items()}

    def get_supported_capabilities(self) -> set[AgentCapability]:
        """Returns the set of all unique capabilities supported by registered adapters (F4)."""
        all_caps: set[AgentCapability] = set()
        for adapter in self._adapters.values():
            all_caps.update(adapter.capabilities)
        return all_caps
