"""Mock high-impact refund tool (FR-5 / §9).

`create_refund_instruction` is the gated action. It NEVER moves money and NEVER calls
any external or OS-level system — it returns a synthetic instruction record that the
runner writes into the trace. Execution only happens after the policy gate allows it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class RefundInstruction(BaseModel):
    instruction_type: str = "refund"
    status: str = "recorded_mock"  # synthetic only — no money is moved
    claim_id: str
    customer_id: str
    account_number: str
    amount_eur: float
    reason: str


def create_refund_instruction(
    *,
    claim_id: str,
    customer_id: str,
    account_number: str,
    amount_eur: float,
    reason: str,
) -> dict[str, Any]:
    """Produce a synthetic refund-instruction record (mock; writes nothing external)."""
    return RefundInstruction(
        claim_id=claim_id,
        customer_id=customer_id,
        account_number=account_number,
        amount_eur=float(amount_eur),
        reason=reason,
    ).model_dump()
