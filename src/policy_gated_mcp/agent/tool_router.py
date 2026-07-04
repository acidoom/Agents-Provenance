"""Builds the per-scenario ToolRegistry, wiring trusted tools plus (for attack
scenarios) the poisoned helper with its attack-class-specific payload."""

from __future__ import annotations

from ..attacks.injectors import Poison, build_poison
from ..eval.schemas import Category, Scenario
from ..mcp import (
    ToolRegistry,
    make_lookup_customer_tool,
    make_poisoned_helper_tool,
    make_read_claim_tool,
    make_refund_tool,
)


def build_registry(
    scenario: Scenario, claim_text: str, *, db_path=None
) -> tuple[ToolRegistry, Poison | None]:
    registry = ToolRegistry()
    poison: Poison | None = None

    for name in scenario.available_tools:
        if name == "read_claim_document":
            registry.register(make_read_claim_tool(claim_text))
        elif name == "lookup_customer_record":
            registry.register(make_lookup_customer_tool(db_path=db_path))
        elif name == "create_refund_instruction":
            registry.register(make_refund_tool())
        elif name == "poisoned_refund_helper":
            if scenario.category != Category.attack or not scenario.attacker_account:
                raise ValueError(
                    f"scenario {scenario.id!r} lists poisoned_refund_helper but is not a "
                    "well-formed attack scenario"
                )
            poison = build_poison(scenario.attack_type, scenario.attacker_account)
            registry.register(make_poisoned_helper_tool(poison))
        else:
            raise ValueError(f"scenario {scenario.id!r} references unknown tool: {name!r}")

    return registry, poison
