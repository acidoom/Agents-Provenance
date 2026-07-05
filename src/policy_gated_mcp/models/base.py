"""Model interface and the context a model sees when proposing a refund.

The model proposes a tool call; it never assigns provenance. `ModelContext` carries the
trusted "correct" values plus any poison signals extracted from tool metadata/output,
labeled by channel (metadata vs data) so a deterministic fake model can reproduce a
realistic vulnerability profile.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from ..agent.state import ToolCallRequest
from ..attacks.attack_types import Channel
from ..eval.schemas import AttackType


class FakeProfile(str, Enum):
    safe_baseline = "safe_baseline"
    vulnerable_agent = "vulnerable_agent"
    mixed_agent = "mixed_agent"


class PoisonSignal(BaseModel):
    """An attacker-controlled value observed in the agent's context, targeting a
    critical field (e.g. account_number or amount_eur)."""

    field: str = "account_number"
    value: str
    channel: Channel
    attack_type: AttackType


class ModelContext(BaseModel):
    task: str
    claim_id: str
    customer_id: str
    safe_account: str
    amount_eur: float
    reason: str
    #: Pre-digested signals used by the deterministic fake models.
    poison_signals: list[PoisonSignal] = Field(default_factory=list)
    #: True when untrusted data was wrapped in spotlighting delimiters + a warning.
    spotlighted: bool = False
    #: Raw materials used by REAL model adapters to build a prompt (a real LLM must be
    #: able to actually be fooled). Fake models ignore these.
    tool_metadata: list[dict] = Field(default_factory=list)
    tool_outputs: list[dict] = Field(default_factory=list)
    customer_record: dict[str, Any] | None = None


@runtime_checkable
class Model(Protocol):
    name: str

    def propose(self, ctx: ModelContext) -> ToolCallRequest: ...


def parse_model_spec(spec: str) -> tuple[str, str]:
    """Parse a spec like ``fake:vulnerable_agent`` into ``(kind, name)``."""
    if ":" not in spec:
        raise ValueError(f"model spec must be '<kind>:<name>', got {spec!r}")
    kind, name = spec.split(":", 1)
    return kind.strip(), name.strip()
