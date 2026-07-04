from pathlib import Path

import pytest

from policy_gated_mcp.eval.loader import load_scenarios
from policy_gated_mcp.eval.schemas import AttackType, Category

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"


def test_loads_seed_scenarios():
    scns = load_scenarios(SCENARIOS)
    ids = {s.id for s in scns}
    assert len(scns) >= 4
    assert {"benign_001", "tool_description_poisoning_001", "tool_output_poisoning_001"} <= ids


def test_scenarios_sorted_and_unique():
    scns = load_scenarios(SCENARIOS)
    ids = [s.id for s in scns]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))


def test_benign_scenarios_have_benign_attack_type():
    for s in load_scenarios(SCENARIOS):
        if s.category == Category.benign:
            assert s.attack_type == AttackType.benign
            assert s.attacker_account is None


def test_attack_scenarios_declare_attacker_account():
    for s in load_scenarios(SCENARIOS):
        if s.category == Category.attack:
            assert s.attacker_account, s.id
            assert s.attack_type != AttackType.benign, s.id


def test_referenced_claim_fixtures_exist():
    for s in load_scenarios(SCENARIOS):
        assert (ROOT / s.claim_fixture).exists(), s.claim_fixture


def test_duplicate_scenario_ids_rejected(tmp_path):
    body = (
        "id: dup\nname: X\ncategory: benign\ntask: t\nclaim_id: C\ncustomer_id: U\n"
        "claim_fixture: f\nattack_type: benign\nexpected_safe_account: X\n"
        "expected_policy_outcome: allow\navailable_tools: [read_claim_document]\n"
    )
    (tmp_path / "a.yaml").write_text(body)
    (tmp_path / "b.yaml").write_text(body)
    with pytest.raises(ValueError, match="duplicate scenario id"):
        load_scenarios(tmp_path)


def test_attack_scenario_without_attacker_account_rejected(tmp_path):
    bad = (
        "id: bad_attack\nname: X\ncategory: attack\ntask: t\nclaim_id: C\ncustomer_id: U\n"
        "claim_fixture: f\nattack_type: tool_output_poisoning\nexpected_safe_account: X\n"
        "expected_policy_outcome: deny\navailable_tools: [read_claim_document]\n"
    )
    (tmp_path / "bad.yaml").write_text(bad)
    with pytest.raises(ValueError, match="attacker_account"):
        load_scenarios(tmp_path)
