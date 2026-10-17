"""Contract tests for pluggable agent adapters (F4)."""

from enum import Enum
from pathlib import Path

import pytest

from amaura.agents.adapters.artifact_only import ArtifactOnlyAdapter
from amaura.agents.adapters.local_cli import LocalCLIAdapter
from amaura.agents.adapters.mock_agent import MockAgentAdapter
from amaura.agents.adapters.model import ModelAgentAdapter
from amaura.agents.base import AgentCapability, AgentRunResult, AgentUsage, BaseAgentAdapter
from amaura.agents.registry import AgentRegistry
from amaura.errors import AdapterError
from amaura.models.task import Requirement, RiskLevel, TaskSpec


def _make_sample_task(task_id: str = "T-100") -> TaskSpec:
    return TaskSpec(
        task_id=task_id,
        instruction="Implement string reverse function.",
        requirements=[
            Requirement(
                id="REQ-001",
                description="reverse_str returns reversed string",
                mandatory=True,
                risk_level=RiskLevel.MEDIUM,
                acceptance_criteria=["reverse_str('abc') == 'cba'"],
            )
        ],
        constraints=["Standard library only"],
        assumptions=["ASCII input"],
        acceptance_criteria=["All tests pass"],
    )


def test_agent_capability_enum():
    """F5: AgentCapability must be an Enum and string subclass."""
    assert issubclass(AgentCapability, Enum)
    assert issubclass(AgentCapability, str)
    assert isinstance(AgentCapability.CODE_EDIT, Enum)
    assert isinstance(AgentCapability.CODE_EDIT, str)
    assert AgentCapability.CODE_EDIT == "code_edit"
    assert AgentCapability.MODEL_INFERENCE == "model_inference"


def test_agent_adapter_contract_metadata():
    """All registered adapters must satisfy the BaseAgentAdapter contract."""
    registry = AgentRegistry()
    adapters = registry.list_adapters()
    assert len(adapters) >= 4

    for adapter in adapters:
        assert isinstance(adapter, BaseAgentAdapter)
        assert isinstance(adapter.name, str) and adapter.name
        assert isinstance(adapter.version, str) and adapter.version
        assert isinstance(adapter.execution_mode, str) and adapter.execution_mode
        assert isinstance(adapter.limitations, list)
        assert isinstance(adapter.capabilities, list)
        # Every capability must be an AgentCapability enum
        for cap in adapter.capabilities:
            assert isinstance(cap, AgentCapability)


def test_agent_registry_capability_discovery():
    """F4: AgentRegistry supports capability discovery queries."""
    registry = AgentRegistry()

    # Find by capability
    code_edit_adapters = registry.find_by_capability(AgentCapability.CODE_EDIT)
    names = [a.name for a in code_edit_adapters]
    assert "local_cli" in names
    assert "mock_agent" in names
    assert "model" in names
    assert "artifact_only" not in names

    audit_adapters = registry.find_by_capability(AgentCapability.AUDIT_ONLY)
    audit_names = [a.name for a in audit_adapters]
    assert "artifact_only" in audit_names

    model_adapters = registry.find_by_capability(AgentCapability.MODEL_INFERENCE)
    assert any(a.name == "model" for a in model_adapters)

    # String argument capability discovery
    str_discovery = registry.find_by_capability("model_inference")
    assert any(a.name == "model" for a in str_discovery)

    # get_all_capabilities
    all_caps = registry.get_all_capabilities()
    assert "artifact_only" in all_caps
    assert AgentCapability.AUDIT_ONLY in all_caps["artifact_only"]

    # get_supported_capabilities
    supported = registry.get_supported_capabilities()
    assert AgentCapability.CODE_EDIT in supported
    assert AgentCapability.AUDIT_ONLY in supported
    assert AgentCapability.MODEL_INFERENCE in supported


def test_artifact_only_contract(tmp_path: Path):
    """F3: ArtifactOnlyAdapter performs passive audit with modified_files = []."""
    (tmp_path / "existing.py").write_text("x = 1\n")
    adapter = ArtifactOnlyAdapter()
    task = _make_sample_task()

    result = adapter.execute(task, tmp_path)
    assert isinstance(result, AgentRunResult)
    assert result.adapter_name == "artifact_only"
    assert result.success is True
    assert result.modified_files == []  # Must be empty for passive audit (F3)
    assert "Audited 1 existing" in result.output


def test_local_cli_missing_command_raises(tmp_path: Path):
    """F1: LocalCLIAdapter without command raises AdapterError rather than dummy echo."""
    adapter = LocalCLIAdapter(cli_command=None)
    task = _make_sample_task()

    with pytest.raises(AdapterError) as exc_info:
        adapter.execute(task, tmp_path)
    assert "requires an explicit agent CLI command" in str(exc_info.value)


def test_local_cli_task_delivery_and_modified_files(tmp_path: Path):
    """F1, F3: LocalCLIAdapter delivers task.md, env vars, placeholder substitution, and tracks modified files."""
    # Command that creates a new file based on task.md existence
    script = (
        "import os, sys\n"
        "task_file = os.environ.get('AMAURA_TASK_FILE')\n"
        "assert task_file and os.path.exists(task_file)\n"
        "with open('result.py', 'w') as f:\n"
        "    f.write('def reverse_str(s): return s[::-1]\\n')\n"
    )
    cmd = ["python3", "-c", script]

    adapter = LocalCLIAdapter(cli_command=cmd)
    task = _make_sample_task("TASK-DELIVERY-1")

    res = adapter.execute(task, tmp_path)
    assert res.success is True
    assert "result.py" in res.modified_files
    # task.md is written before pre-snapshot, so only agent's creations are tracked
    assert (tmp_path / "task.md").is_file()
    assert (tmp_path / "result.py").is_file()


def test_mock_agent_modified_files(tmp_path: Path):
    """MockAgentAdapter tracks modified files from mock actions."""
    def action(ws: Path):
        (ws / "mock_file.txt").write_text("mock content\n")

    adapter = MockAgentAdapter(action=action)
    task = _make_sample_task()
    res = adapter.execute(task, tmp_path)
    assert res.success is True
    assert "mock_file.txt" in res.modified_files


def test_model_agent_usage_accounting_and_execution(tmp_path: Path):
    """F4: ModelAgentAdapter tracks usage accounting and updates workspace."""
    adapter = ModelAgentAdapter(
        model_name="mock-gpt",
        generator_fn=lambda prompt, task: {
            "solution.py": "def reverse_str(s): return s[::-1]\n",
            "test_solution.py": "from solution import reverse_str\ndef test_rev(): assert reverse_str('abc') == 'cba'\n",
        },
    )
    task = _make_sample_task("TASK-MODEL-1")
    res = adapter.execute(task, tmp_path)

    assert res.success is True
    assert "solution.py" in res.modified_files
    assert "test_solution.py" in res.modified_files
    assert res.usage is not None
    assert isinstance(res.usage, AgentUsage)
    assert res.usage.prompt_tokens > 0
    assert res.usage.completion_tokens > 0
    assert res.usage.total_tokens == res.usage.prompt_tokens + res.usage.completion_tokens
    assert res.usage.estimated_cost_usd > 0.0
    assert (tmp_path / "solution.py").is_file()
