# Agent Adapter Contract & Integration Specification

Amaura provides a standardized adapter abstraction layer that enables independent verification across any agent architecture, external coding CLI, or foundation model runtime.

---

## 1. Supported Adapter Types

Amaura includes four standard adapter implementations:

1. **`artifact_only` (`ArtifactOnlyAdapter`)**:
   - Audits existing pre-generated code or files in a workspace without invoking external processes or models.
   - Ideal for CI/CD audit gates, pull request checks, and post-generation evaluation.
2. **`local_cli` (`LocalCLIAdapter`)**:
   - Orchestrates an installed coding assistant CLI (e.g. Aider, Cline, Claude Code, custom internal scripts) in an isolated workspace.
   - Passes task specifications via CLI arguments/stdin, monitors subprocess execution, and tracks modified files.
3. **`model` (`ModelAgentAdapter`)**:
   - Integrates directly with foundation model APIs or local LLM inference engines (e.g. Ollama, vLLM, OpenAI, Anthropic).
   - Generates code completions, applies file modifications, and tracks usage telemetry (`AgentUsage`).
4. **`mock` (`MockAgentAdapter`)**:
   - Deterministic test adapter used for offline regression testing and benchmark verification.

---

## 2. Core Adapter Interface

Every agent adapter inherits from `BaseAgentAdapter` (`src/amaura/agents/base.py`):

```python
class AgentCapability(str, Enum):
    CODE_GENERATION = "code_generation"
    FILE_EDITING = "file_editing"
    COMMAND_EXECUTION = "command_execution"
    TEST_RUNNING = "test_running"
    REPAIR = "repair"


class AgentUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0


class AgentRunResult(BaseModel):
    success: bool
    agent_name: str
    output: str = ""
    modified_files: list[Path] = Field(default_factory=list)
    execution_time_ms: int = 0
    error_message: Optional[str] = None
    usage: Optional[AgentUsage] = None


class BaseAgentAdapter(ABC):
    name: str
    version: str = "1.0.0"
    execution_mode: str = "isolated_subprocess"
    capabilities: list[AgentCapability] = []
    limitations: list[str] = []

    def supports(self, capability: AgentCapability) -> bool:
        """Checks if the adapter supports a specified capability."""
        return capability in self.capabilities

    @abstractmethod
    def execute(self, task: TaskSpec, workspace_dir: Path) -> AgentRunResult:
        """Executes the agent against task within the isolated workspace."""
        pass
```

---

## 3. Capability Discovery & Contract Verification

- Adapters register with `AgentRegistry` and are discovered dynamically via `amaura agents`.
- Each adapter must declare explicit `AgentCapability` enum flags.
- All adapters are rigorously validated against the contract test suite in `tests/unit/test_agent_contract.py`, ensuring:
  - Valid metadata (`name`, `version`, `execution_mode`).
  - Standardized `execute()` signature returning a valid `AgentRunResult`.
  - Non-crashing behavior on missing binaries or invalid configurations.
  - Proper tracking of `modified_files` and `usage` statistics.
