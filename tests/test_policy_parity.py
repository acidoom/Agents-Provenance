"""Differential test: the OPA CLI and the native mirror must agree on every fixture.

This is what keeps refund.rego and policy/engine.py from silently drifting. Skipped
when `opa` is absent; runs for real in CI where opa is installed.
"""

import pytest

from conftest import POLICY_DIR, POLICY_FIXTURE_OUTCOMES, load_policy_input
from policy_gated_mcp.policy.engine import NativePolicyEngine
from policy_gated_mcp.policy.opa_engine import OpaPolicyEngine, opa_available

pytestmark = pytest.mark.opa

if not opa_available():
    pytest.skip("opa binary not installed (run `make install-opa`)", allow_module_level=True)


def _key(decision):
    return (
        decision.outcome,
        decision.allow,
        decision.require_human_review,
        sorted(decision.deny_reasons),
        sorted(decision.review_reasons),
    )


@pytest.mark.parametrize("name", list(POLICY_FIXTURE_OUTCOMES))
def test_opa_and_native_agree(name):
    policy_input = load_policy_input(name)
    native = NativePolicyEngine().evaluate(policy_input)
    opa = OpaPolicyEngine(POLICY_DIR).evaluate(policy_input)
    assert _key(native) == _key(opa), f"{name}: native={native} opa={opa}"
