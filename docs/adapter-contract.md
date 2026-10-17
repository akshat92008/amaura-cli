# Agent Adapter Contract

Amaura supports three integration patterns:

1. **Artifact-Only Adapter**: Audits existing work without executing external models or agents.
2. **Local CLI Adapter**: Operates an installed coding CLI in an isolated workspace copy.
3. **Model Adapter**: Directly calls a local inference runtime (e.g. Ollama/vLLM) with zero-cost guarantees.

## Adapter Interface
Every adapter inherits from `BaseAgentAdapter`:
- `name: str`
- `version: str`
- `capabilities: list[str]`
- `execution_mode: str`
- `limitations: list[str]`
- `execute(task: TaskSpec, workspace_dir: Path) -> AgentRunResult`
