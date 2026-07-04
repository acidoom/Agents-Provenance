import warnings

import pytest

import policy_gated_mcp.policy.opa_engine as opa_engine
from conftest import POLICY_FIXTURE_OUTCOMES, load_policy_input
from policy_gated_mcp.policy.engine import NativePolicyEngine, get_policy_engine
from policy_gated_mcp.policy.opa_engine import OpaError


@pytest.mark.parametrize("name,expected", POLICY_FIXTURE_OUTCOMES.items())
def test_native_engine_matches_expected_outcome(name, expected):
    decision = NativePolicyEngine().evaluate(load_policy_input(name))
    assert decision.outcome == expected, (name, decision)


def test_untrusted_account_deny_reasons():
    decision = NativePolicyEngine().evaluate(load_policy_input("deny_untrusted_account"))
    assert "account_has_untrusted_provenance" in decision.deny_reasons
    assert "missing_trusted_account_provenance" in decision.deny_reasons
    assert not decision.allow


def test_missing_provenance_denies():
    decision = NativePolicyEngine().evaluate(load_policy_input("deny_missing_provenance"))
    assert "missing_trusted_account_provenance" in decision.deny_reasons


def test_conflict_routes_to_review_not_deny():
    decision = NativePolicyEngine().evaluate(load_policy_input("review_conflict"))
    assert decision.require_human_review
    assert "conflicting_trusted_values" in decision.review_reasons
    assert decision.deny_reasons == []


def test_native_engine_records_engine_name_and_hash():
    decision = NativePolicyEngine().evaluate(load_policy_input("allow_verified_account"))
    assert decision.engine == "native"
    assert decision.input_hash.startswith("sha256:")


def test_factory_native_is_deterministic():
    assert get_policy_engine(prefer="native").name == "native"


def test_factory_auto_falls_back_to_native_without_opa(monkeypatch):
    monkeypatch.setattr(opa_engine, "opa_available", lambda opa_path=None: False)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        engine = get_policy_engine(prefer="auto")
    assert engine.name == "native"
    assert any("native Python policy mirror" in str(w.message) for w in caught)


def test_factory_opa_required_raises_when_binary_missing(monkeypatch):
    monkeypatch.setattr(opa_engine.shutil, "which", lambda name: None)
    with pytest.raises(OpaError):
        get_policy_engine(prefer="opa")
