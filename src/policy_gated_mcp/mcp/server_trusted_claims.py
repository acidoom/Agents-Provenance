"""Trusted (benign) tool providers: claim reader, verified-customer lookup, and the
high-impact refund action."""

from __future__ import annotations

import json
from pathlib import Path

from ..domain.customer_db import lookup_customer_record
from ..domain.refund import create_refund_instruction
from ..provenance.models import SourceType, TrustLevel
from .tool_metadata import ToolMetadata, ToolResult
from .tool_registry import Tool


def make_read_claim_tool(claim_text: str, *, source: str = "trusted_claims_server") -> Tool:
    """Returns the raw claim document. Fields become trusted only via the extractor."""
    meta = ToolMetadata(
        name="read_claim_document",
        description="Reads the raw claim document text for a given claim id.",
        input_schema={"claim_id": "string"},
        source=source,
        risk_level="low",
    )

    def _run(claim_id: str) -> ToolResult:
        return ToolResult(
            tool="read_claim_document",
            output=claim_text,
            text=claim_text,
            source_type=SourceType.mcp_tool_output_untrusted,
            trust_level=TrustLevel.untrusted,
        )

    return Tool(metadata=meta, func=_run)


def make_lookup_customer_tool(
    *, db_path: str | Path | None = None, source: str = "trusted_customer_server"
) -> Tool:
    """Returns the verified customer record; verified_account is a trusted source."""
    meta = ToolMetadata(
        name="lookup_customer_record",
        description="Returns the verified customer record (verified_account, status).",
        input_schema={"customer_id": "string"},
        source=source,
        risk_level="low",
    )

    def _run(customer_id: str) -> ToolResult:
        lk = lookup_customer_record(customer_id, db_path=db_path)
        if not lk.found:
            return ToolResult(
                tool="lookup_customer_record",
                output=lk.model_dump(),
                text=lk.error or "not found",
                source_type=SourceType.verified_database,
                trust_level=TrustLevel.trusted,
                error=lk.error,
            )
        assert lk.record is not None
        return ToolResult(
            tool="lookup_customer_record",
            output=lk.record.model_dump(),
            text=f"verified_account={lk.record.verified_account} status={lk.record.status}",
            source_type=SourceType.verified_database,
            trust_level=TrustLevel.trusted,
        )

    return Tool(metadata=meta, func=_run)


def make_refund_tool(*, source: str = "refund_action_server") -> Tool:
    """The HIGH-IMPACT action. The runtime must gate this call via the policy engine."""
    meta = ToolMetadata(
        name="create_refund_instruction",
        description=(
            "Creates a refund instruction (HIGH-IMPACT, synthetic/mock). Must pass the "
            "provenance policy gate before execution."
        ),
        input_schema={
            "claim_id": "string",
            "customer_id": "string",
            "account_number": "string",
            "amount_eur": "number",
            "reason": "string",
        },
        source=source,
        risk_level="high",
    )

    def _run(
        *,
        claim_id: str,
        customer_id: str,
        account_number: str,
        amount_eur: float,
        reason: str,
    ) -> ToolResult:
        record = create_refund_instruction(
            claim_id=claim_id,
            customer_id=customer_id,
            account_number=account_number,
            amount_eur=amount_eur,
            reason=reason,
        )
        return ToolResult(
            tool="create_refund_instruction",
            output=record,
            text=json.dumps(record),
            source_type=SourceType.test_fixture,
            trust_level=TrustLevel.trusted,
        )

    return Tool(metadata=meta, func=_run)
