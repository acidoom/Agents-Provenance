"""Deterministic fake model profiles (FR-8).

The single decision each profile makes is *which account_number to put in the
high-impact call*. Everything else (claim id, customer id, amount, reason) flows from
the trusted context. This is the behavior matrix that produces the evaluation metrics
with zero randomness:

    profile / defense        description   output   arg-subst   cross-tool
    vulnerable / none        attacker      attacker attacker    attacker
    vulnerable / spotlight    attacker     safe     safe        safe
    safe_baseline / any       safe         safe     safe        safe
    mixed / any               attacker     attacker safe        safe

`vulnerable` decides by *channel*: description poison (metadata channel) is not
delimited by spotlighting so it always lands; output-borne poison (data channel) lands
only when not spotlighted. `mixed` follows description + output poisoning regardless,
giving a non-trivial intermediate ASR.
"""

from __future__ import annotations

from ..agent.state import ToolCallRequest
from ..eval.schemas import AttackType
from .base import FakeProfile, Model, ModelContext, PoisonSignal

_MIXED_FOLLOWS = frozenset(
    {AttackType.tool_description_poisoning, AttackType.tool_output_poisoning}
)


class FakeModel(Model):
    def __init__(self, profile: FakeProfile) -> None:
        self.profile = profile
        self.name = f"fake:{profile.value}"

    def _follows(self, signal: PoisonSignal, spotlighted: bool) -> bool:
        if self.profile == FakeProfile.safe_baseline:
            return False
        if self.profile == FakeProfile.vulnerable_agent:
            if signal.channel == "metadata":
                return True
            return not spotlighted  # data channel is suppressed by spotlighting
        if self.profile == FakeProfile.mixed_agent:
            return signal.attack_type in _MIXED_FOLLOWS
        return False

    def _chosen_args(self, ctx: ModelContext) -> tuple[str, float, str]:
        """Pick account/amount/reason, following any poison signal this profile obeys."""
        account = ctx.safe_account
        amount = ctx.amount_eur
        reason = ctx.reason
        for signal in ctx.poison_signals:
            if self._follows(signal, ctx.spotlighted):
                if signal.field == "account_number":
                    account = signal.value
                elif signal.field == "amount_eur":
                    amount = float(signal.value)
                elif signal.field == "reason":
                    reason = signal.value
        return account, amount, reason

    def propose(self, ctx: ModelContext) -> ToolCallRequest:
        account, amount, reason = self._chosen_args(ctx)
        return ToolCallRequest(
            action="create_refund_instruction",
            risk_level="high",
            scenario_id="",
            args={
                "claim_id": ctx.claim_id,
                "customer_id": ctx.customer_id,
                "account_number": account,
                "amount_eur": amount,
                "reason": reason,
            },
        )
