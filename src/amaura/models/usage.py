"""Agent usage and token accounting models (F4)."""

from pydantic import BaseModel


class AgentUsage(BaseModel):
    """Token and cost usage accounting for agent runs (F4)."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
