"""Real MCP-SDK transport tests. Skipped unless the `mcp` extra is installed, so CI's
`.[dev]` install and the default keyless path are unaffected."""

from pathlib import Path

import pytest

pytest.importorskip("mcp")

from policy_gated_mcp.eval.runner import run_single  # noqa: E402
from policy_gated_mcp.eval.schemas import DefenseMode  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"

# (scenario, defense) cases spanning allow / deny / attack-succeeds outcomes.
CASES = [
    ("benign_001", DefenseMode.provenance_opa),
    ("tool_output_poisoning_001", DefenseMode.provenance_opa),
    ("tool_description_poisoning_001", DefenseMode.provenance_opa),
    ("amount_substitution_001", DefenseMode.none),
    ("canary_exfiltration_001", DefenseMode.provenance_opa),
]


def _result(sid, defense, transport):
    return run_single(
        sid,
        defense,
        "fake:vulnerable_agent",
        scenarios_dir=SCENARIOS,
        engine_pref="native",
        base_dir=ROOT,
        transport=transport,
    ).result


@pytest.mark.parametrize("sid,defense", CASES)
def test_mcp_transport_matches_inprocess(sid, defense):
    ip = _result(sid, defense, "inprocess")
    mc = _result(sid, defense, "mcp")
    # Same tools + same provenance over a real MCP session => identical outcomes.
    assert mc.executed == ip.executed
    assert mc.policy_outcome == ip.policy_outcome
    assert mc.executed_account == ip.executed_account
    assert mc.attack_success == ip.attack_success
    assert mc.exfiltration_success == ip.exfiltration_success
