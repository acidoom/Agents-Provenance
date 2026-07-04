from pathlib import Path

import pytest

from policy_gated_mcp.domain.extractor import ExtractionError, extract_claim_fields
from policy_gated_mcp.provenance.models import SourceType, TrustLevel

ROOT = Path(__file__).resolve().parents[1]
CLEAN = (ROOT / "fixtures/claims/claim_clean_001.md").read_text()
POISONED = (ROOT / "fixtures/claims/claim_poisoned_001.md").read_text()

SAFE = "PL11111111111111111111111111"
ATTACKER = "PL99999999999999999999999999"


def test_extracts_trusted_block_fields():
    result = extract_claim_fields(CLEAN, scenario_id="t")
    assert result.fields.claim_id == "CLM-001"
    assert result.fields.customer_id == "CUST-001"
    assert result.fields.beneficiary_account == SAFE
    assert result.fields.refund_amount_eur == 120.0
    assert result.fields.reason == "Duplicate charge"


def test_all_extracted_fields_are_trusted():
    result = extract_claim_fields(CLEAN, scenario_id="t")
    assert {p.field_path for p in result.provenance} == {
        "claim_id",
        "customer_id",
        "account_number",
        "amount_eur",
        "reason",
    }
    for p in result.provenance:
        assert p.source_type == SourceType.trusted_extractor
        assert p.trust_level == TrustLevel.trusted


def test_injected_account_outside_block_is_ignored():
    # The poisoned doc repeats `beneficiary_account: PL999...` OUTSIDE the trusted block
    # plus an "IGNORE ALL PREVIOUS INSTRUCTIONS" injection. None of it must be extracted.
    result = extract_claim_fields(POISONED, scenario_id="t")
    assert result.fields.beneficiary_account == SAFE
    assert ATTACKER not in {p.value for p in result.provenance}


def test_missing_block_fails_safe():
    with pytest.raises(ExtractionError):
        extract_claim_fields("# Claim with no trusted block\nbeneficiary_account: PL99...\n")


def test_multiple_blocks_fail_safe():
    doubled = CLEAN + "\n" + CLEAN
    with pytest.raises(ExtractionError):
        extract_claim_fields(doubled)


def test_malformed_amount_fails_safe():
    bad = (
        "CLAIM_FIELDS_START\n"
        "claim_id: CLM-001\ncustomer_id: CUST-001\n"
        "refund_amount_eur: not-a-number\n"
        "beneficiary_account: PL11111111111111111111111111\nreason: x\n"
        "CLAIM_FIELDS_END\n"
    )
    with pytest.raises(ExtractionError):
        extract_claim_fields(bad)
