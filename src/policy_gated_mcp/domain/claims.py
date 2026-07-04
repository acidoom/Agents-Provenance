"""Structured claim fields extracted from a claim document."""

from __future__ import annotations

from pydantic import BaseModel

#: Fields whose provenance the policy gate cares about for a high-impact refund.
CRITICAL_FIELDS: tuple[str, ...] = (
    "claim_id",
    "customer_id",
    "account_number",
    "amount_eur",
    "reason",
)


class ClaimFields(BaseModel):
    """The trusted-block fields of a claim. `beneficiary_account` maps to the
    `account_number` argument of the high-impact refund tool."""

    claim_id: str
    customer_id: str
    refund_amount_eur: float
    beneficiary_account: str
    reason: str
