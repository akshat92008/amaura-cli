"""Pluggable agent adapters."""

from amaura.agents.adapters.artifact_only import ArtifactOnlyAdapter
from amaura.agents.adapters.local_cli import LocalCLIAdapter
from amaura.agents.adapters.mock_agent import MockAgentAdapter
from amaura.agents.base import AgentCapability, AgentRunResult, BaseAgentAdapter
from amaura.agents.registry import AgentRegistry

__all__ = [
    "AgentCapability",
    "AgentRegistry",
    "AgentRunResult",
    "ArtifactOnlyAdapter",
    "BaseAgentAdapter",
    "LocalCLIAdapter",
    "MockAgentAdapter",
]
