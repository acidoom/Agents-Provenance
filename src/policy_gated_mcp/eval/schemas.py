"""Evaluation schemas: scenarios, enums, and scored results."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator

from ..policy.decisions import PolicyOutcome


class Category(str, Enum):
    benign = "benign"
    attack = "attack"


class AttackType(str, Enum):
    benign = "benign"
    # Required classes (FR-6 A–D)
    tool_description_poisoning = "tool_description_poisoning"
    tool_output_poisoning = "tool_output_poisoning"
    argument_substitution = "argument_substitution"
    amount_substitution = "amount_substitution"
    cross_tool_contamination = "cross_tool_contamination"
    # Optional extras
    retrieval_injection = "retrieval_injection"
    metadata_poisoning = "metadata_poisoning"
    tool_name_confusion = "tool_name_confusion"
    canary_exfiltration = "canary_exfiltration"


class DefenseMode(str, Enum):
    none = "none"
    spotlighting = "spotlighting"
    provenance_opa = "provenance_opa"
    spotlighting_plus_provenance_opa = "spotlighting_plus_provenance_opa"

    @property
    def uses_gate(self) -> bool:
        return self in {DefenseMode.provenance_opa, DefenseMode.spotlighting_plus_provenance_opa}

    @property
    def uses_spotlighting(self) -> bool:
        return self in {DefenseMode.spotlighting, DefenseMode.spotlighting_plus_provenance_opa}


ALL_DEFENSES: list[DefenseMode] = [
    DefenseMode.none,
    DefenseMode.spotlighting,
    DefenseMode.provenance_opa,
    DefenseMode.spotlighting_plus_provenance_opa,
]


class Scenario(BaseModel):
    """A single evaluation case loaded from YAML/JSON (FR-1)."""

    id: str
    name: str
    category: Category
    task: str
    claim_id: str
    customer_id: str
    claim_fixture: str
    attack_type: AttackType = AttackType.benign
    expected_safe_account: str
    attacker_account: str | None = None
    attacker_amount_eur: float | None = None
    #: A synthetic secret the attacker tries to exfiltrate (via a free-text arg).
    canary_token: str | None = None
    expected_policy_outcome: PolicyOutcome
    available_tools: list[str]
    expected_attack_success: bool | None = None
    max_amount_eur: float = 10000.0
    notes: str | None = None

    @model_validator(mode="after")
    def _check_category_consistency(self) -> Scenario:
        if self.category == Category.attack:
            if self.attack_type == AttackType.benign:
                raise ValueError(f"attack scenario {self.id!r} must set a non-benign attack_type")
            if not (self.attacker_account or self.attacker_amount_eur or self.canary_token):
                raise ValueError(
                    f"attack scenario {self.id!r} must set an objective: attacker_account, "
                    "attacker_amount_eur, and/or canary_token"
                )
        else:
            if self.attack_type != AttackType.benign:
                raise ValueError(
                    f"benign scenario {self.id!r} must have attack_type: benign "
                    f"(got {self.attack_type.value})"
                )
        return self


class EvalResult(BaseModel):
    """One scored run: (scenario × defense × model). Serialized to results.jsonl."""

    scenario_id: str
    scenario_name: str = ""
    category: Category
    attack_type: AttackType
    model_profile: str
    defense_mode: DefenseMode
    proposed_action: str | None = None
    proposed_account: str | None = None
    proposed_amount: float | None = None
    executed: bool = False
    executed_account: str | None = None
    executed_amount: float | None = None
    policy_outcome: PolicyOutcome | None = None
    policy_engine: str | None = None
    attack_success: bool | None = None
    benign_success: bool | None = None
    false_positive: bool | None = None
    #: Canary-exfiltration attacks: did the secret reach the executed tool call?
    exfiltration_success: bool | None = None
    deny_reasons: list[str] = Field(default_factory=list)
    review_reasons: list[str] = Field(default_factory=list)
    trace_path: str | None = None
