import pytest

from policy_gated_mcp.provenance.ledger import ProvenanceLedger
from policy_gated_mcp.provenance.models import SourceType, TrustLevel

SAFE = "PL11111111111111111111111111"
ATTACKER = "PL99999999999999999999999999"
OTHER = "PL22222222222222222222222222"


def _benign_ledger() -> ProvenanceLedger:
    led = ProvenanceLedger(scenario_id="benign")
    led.observe(
        field="account_number", value=SAFE, source_type=SourceType.trusted_extractor,
        source_id="claim:block", created_by="trusted_extractor",
    )
    led.observe(
        field="account_number", value=SAFE, source_type=SourceType.verified_database,
        source_id="db:CUST-001", created_by="lookup_customer_record",
    )
    return led


def test_records_observations():
    led = _benign_ledger()
    assert len(led.observations_for("account_number")) == 2
    assert led.trusted_values("account_number") == {SAFE}


def test_trusted_value_resolves_to_trusted_provenance():
    led = _benign_ledger()
    entries = led.resolve_argument("account_number", SAFE)
    assert len(entries) == 1
    e = entries[0]
    assert e.field_path == "args.account_number"
    assert e.trust_level == TrustLevel.trusted
    # verified_database is preferred over trusted_extractor when both vouch.
    assert e.source_type == SourceType.verified_database


def test_untrusted_only_value_resolves_to_untrusted():
    led = _benign_ledger()
    led.observe(
        field="account_number", value=ATTACKER,
        source_type=SourceType.mcp_tool_output_untrusted,
        source_id="tool:poisoned_refund_helper", created_by="poisoned_refund_helper",
    )
    entries = led.resolve_argument("account_number", ATTACKER)
    assert len(entries) == 1
    assert entries[0].source_type == SourceType.mcp_tool_output_untrusted
    assert entries[0].trust_level != TrustLevel.trusted


def test_invented_value_resolves_to_llm_inference():
    led = _benign_ledger()
    entries = led.resolve_argument("account_number", "PL00000000000000000000000000")
    assert len(entries) == 1
    assert entries[0].source_type == SourceType.llm_inference


def test_conflict_when_proposed_differs_from_trusted():
    led = _benign_ledger()
    conflicts = led.conflicts_for("account_number", ATTACKER)
    assert conflicts and conflicts[0]["reason"] == "proposed_differs_from_trusted"


def test_conflict_when_two_trusted_sources_disagree():
    led = ProvenanceLedger()
    led.observe(field="account_number", value=SAFE, source_type=SourceType.trusted_extractor,
                source_id="claim", created_by="trusted_extractor")
    led.observe(field="account_number", value=OTHER, source_type=SourceType.verified_database,
                source_id="db", created_by="lookup_customer_record")
    conflicts = led.conflicts_for("account_number", SAFE)
    assert conflicts and conflicts[0]["reason"] == "multiple_trusted_values"


def test_no_conflict_in_clean_benign_case():
    led = _benign_ledger()
    assert led.conflicts_for("account_number", SAFE) == []


def test_rejects_untrusted_source_labeled_trusted():
    led = ProvenanceLedger()
    with pytest.raises(ValueError, match="cannot have trust_level=trusted"):
        led.observe(
            field="account_number", value=ATTACKER,
            source_type=SourceType.mcp_tool_output_untrusted,
            source_id="tool", created_by="attacker",
            trust_level=TrustLevel.trusted,
        )


def test_build_policy_input_benign_shape():
    led = _benign_ledger()
    args = {
        "claim_id": "CLM-001", "customer_id": "CUST-001",
        "account_number": SAFE, "amount_eur": 120.0, "reason": "Duplicate charge",
    }
    doc = led.build_policy_input("create_refund_instruction", args)
    assert doc["action"] == "create_refund_instruction"
    assert doc["conflicts"] == []
    acct = [p for p in doc["provenance"] if p["field_path"] == "args.account_number"]
    assert acct and acct[0]["trust_level"] == "trusted"
    assert acct[0]["source_type"] == "verified_database"


def test_build_policy_input_attack_has_untrusted_and_conflict():
    led = _benign_ledger()
    led.observe(
        field="account_number", value=ATTACKER,
        source_type=SourceType.mcp_tool_output_untrusted,
        source_id="tool:poisoned", created_by="poisoned_refund_helper",
    )
    args = {
        "claim_id": "CLM-001", "customer_id": "CUST-001",
        "account_number": ATTACKER, "amount_eur": 120.0, "reason": "Duplicate charge",
    }
    doc = led.build_policy_input("create_refund_instruction", args)
    acct = [p for p in doc["provenance"] if p["field_path"] == "args.account_number"]
    assert acct and acct[0]["source_type"] == "mcp_tool_output_untrusted"
    assert not any(p["trust_level"] == "trusted" for p in acct)
    assert doc["conflicts"]
