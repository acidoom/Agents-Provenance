import json
from pathlib import Path

import pytest

from policy_gated_mcp.policy.decisions import PolicyOutcome

ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = ROOT / "policy"
POLICY_INPUTS = ROOT / "fixtures" / "policy_inputs"

#: Expected policy outcome for every fixture — shared by the native, OPA, and parity tests.
POLICY_FIXTURE_OUTCOMES = {
    "allow_verified_account": PolicyOutcome.allow,
    "allow_trusted_extractor_account": PolicyOutcome.allow,
    "deny_untrusted_account": PolicyOutcome.deny,
    "deny_llm_inferred_account": PolicyOutcome.deny,
    "deny_missing_provenance": PolicyOutcome.deny,
    "deny_invalid_amount": PolicyOutcome.deny,
    "deny_test_fixture_account": PolicyOutcome.deny,
    "review_conflict": PolicyOutcome.review,
}


def load_policy_input(name: str) -> dict:
    return json.loads((POLICY_INPUTS / f"{name}.json").read_text())


@pytest.fixture
def repo_root() -> Path:
    return ROOT
