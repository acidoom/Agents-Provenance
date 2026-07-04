"""OPA/Rego integration tests. Skipped entirely when the `opa` binary is absent."""

import shutil
import subprocess

import pytest

from conftest import POLICY_DIR, POLICY_FIXTURE_OUTCOMES, load_policy_input
from policy_gated_mcp.policy.opa_engine import OpaPolicyEngine, opa_available

pytestmark = pytest.mark.opa

if not opa_available():
    pytest.skip("opa binary not installed (run `make install-opa`)", allow_module_level=True)


@pytest.mark.parametrize("name,expected", POLICY_FIXTURE_OUTCOMES.items())
def test_opa_engine_matches_expected_outcome(name, expected):
    decision = OpaPolicyEngine(POLICY_DIR).evaluate(load_policy_input(name))
    assert decision.outcome == expected, (name, decision)
    assert decision.engine == "opa"


def test_opa_rego_unit_tests_pass():
    proc = subprocess.run(
        [shutil.which("opa"), "test", str(POLICY_DIR)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
