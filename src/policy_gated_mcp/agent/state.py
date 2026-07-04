"""Agent-side request objects. The full run state lives in agent/graph.py (M5)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

HIGH_IMPACT_ACTIONS: frozenset[str] = frozenset({"create_refund_instruction"})


class ToolCallRequest(BaseModel):
    """A proposed tool call the agent wants to execute. High-impact requests must
    pass the policy gate before `execute_or_deny`."""

    action: str
    risk_level: str = "high"
    args: dict[str, Any] = Field(default_factory=dict)
    scenario_id: str = ""

    @property
    def is_high_impact(self) -> bool:
        return self.action in HIGH_IMPACT_ACTIONS or self.risk_level == "high"
