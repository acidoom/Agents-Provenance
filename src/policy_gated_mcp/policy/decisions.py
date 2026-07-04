"""Policy decision schema and the single source of truth for outcome precedence.

Both policy engines (the OPA CLI adapter and the native Python mirror) emit the same
raw Rego-shaped decision document, then call `PolicyDecision.from_rego` so that the
allow/deny/review precedence is derived identically no matter which engine ran.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class PolicyOutcome(str, Enum):
    allow = "allow"
    deny = "deny"
    review = "review"


class PolicyDecision(BaseModel):
    outcome: PolicyOutcome
    allow: bool
    require_human_review: bool = False
    deny_reasons: list[str] = Field(default_factory=list)
    review_reasons: list[str] = Field(default_factory=list)
    policy_id: str = "refund.rego"
    input_hash: str = ""
    engine: str = ""

    @classmethod
    def from_rego(
        cls,
        decision: dict,
        *,
        policy_id: str = "refund.rego",
        input_hash: str = "",
        engine: str = "",
    ) -> PolicyDecision:
        """Derive a decision from a raw Rego document.

        Precedence is deny > review > allow > default-deny: any deny reason denies;
        otherwise a review flag/reason routes to human review; otherwise an explicit
        allow allows; anything else is denied by default.
        """
        raw_allow = bool(decision.get("allow", False))
        deny_reasons = sorted(set(decision.get("deny_reasons") or []))
        review_reasons = sorted(set(decision.get("review_reasons") or []))
        require_review = bool(decision.get("require_human_review", False))

        if deny_reasons:
            outcome, allow = PolicyOutcome.deny, False
        elif require_review or review_reasons:
            outcome, allow = PolicyOutcome.review, False
        elif raw_allow:
            outcome, allow = PolicyOutcome.allow, True
        else:
            outcome, allow = PolicyOutcome.deny, False

        return cls(
            outcome=outcome,
            allow=allow,
            require_human_review=require_review,
            deny_reasons=deny_reasons,
            review_reasons=review_reasons,
            policy_id=policy_id,
            input_hash=input_hash,
            engine=engine,
        )
