"""Interactive Streamlit demo for Policy-Gated MCP.

Run it (after `pip install -e ".[demo]"` or `uv sync --extra demo`):

    streamlit run demo/app.py            # or:  make demo

Pick a scenario and toggle the defense mode — the same tool-poisoning attack goes from
"attacker account executed" (no defense) to "denied by the provenance gate", with the
provenance ledger and the OPA/native policy decision shown inline. Everything is
synthetic and deterministic; no API keys or network required.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from policy_gated_mcp.eval.loader import load_scenarios
from policy_gated_mcp.eval.runner import run_eval, run_single
from policy_gated_mcp.eval.schemas import ALL_DEFENSES, Category, DefenseMode, EvalResult
from policy_gated_mcp.eval.scoring import aggregate, attack_class_breakdown
from policy_gated_mcp.policy.opa_engine import opa_available

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = ROOT / "scenarios"

MODEL_PROFILES = ["fake:vulnerable_agent", "fake:mixed_agent", "fake:safe_baseline"]
TRUST_BADGE = {"trusted": "✅ trusted", "untrusted": "🚨 untrusted"}

st.set_page_config(page_title="Policy-Gated MCP", page_icon="🛡️", layout="wide")


@st.cache_data
def scenarios():
    return load_scenarios(SCENARIOS_DIR)


def engine_options() -> list[str]:
    return ["native", "auto"] + (["opa"] if opa_available() else [])


def verdict_badge(result: EvalResult) -> tuple[str, str]:
    """Return (streamlit-level, message) for the outcome banner."""
    if result.category == Category.attack:
        if result.attack_success:
            return "error", "🔴 ATTACK SUCCEEDED — the attacker-controlled account was executed."
        return "success", "🛡️ Attack blocked / neutralized — attacker account never executed."
    if result.benign_success:
        return "success", "✅ Benign task completed with the correct account."
    return (
        "warning",
        "⚠️ Benign task not completed — blocked or sent to human review (false positive).",
    )


def short_result(result: EvalResult) -> str:
    if result.category == Category.attack:
        return "🔴 attack succeeded" if result.attack_success else "🛡️ blocked"
    return "✅ completed" if result.benign_success else "⚠️ blocked/review"


def poisoned_content(trace: dict) -> tuple[str | None, str | None]:
    """Extract the poisoned tool description and output from a run trace, if any."""
    description = output = None
    for meta in trace.get("tool_metadata_shown", []):
        if meta.get("name") == "poisoned_refund_helper":
            description = meta.get("description")
    for out in trace.get("tool_outputs", []):
        if out.get("tool") == "poisoned_refund_helper":
            output = out.get("text")
    return description, output


def provenance_table(trace: dict, field: str | None = None) -> pd.DataFrame:
    rows = []
    for obs in trace.get("provenance_observations", []):
        if field and obs["field_path"] != field:
            continue
        rows.append(
            {
                "field": obs["field_path"],
                "value": obs["value"],
                "origin (source_type)": obs["source_type"],
                "trust": TRUST_BADGE.get(obs["trust_level"], f"❔ {obs['trust_level']}"),
                "recorded by": obs["created_by"],
            }
        )
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------------------
st.title("🛡️ Policy-Gated MCP")
st.caption(
    "Tool-poisoning red-team + provenance/OPA policy defense. An LLM may *propose* a "
    "high-impact tool call, but a provenance-aware gate denies it when a critical argument "
    "traces back to an untrusted source. All data is synthetic."
)

scns = scenarios()
by_id = {s.id: s for s in scns}

with st.sidebar:
    st.header("Controls")
    attack_ids = [s.id for s in scns if s.category == Category.attack]
    benign_ids = [s.id for s in scns if s.category == Category.benign]
    group = st.radio("Scenario type", ["Attack", "Benign"], horizontal=True)
    options = attack_ids if group == "Attack" else benign_ids
    scenario_id = st.selectbox("Scenario", options)
    defense = st.radio("Defense mode", [d.value for d in ALL_DEFENSES], index=0)
    model_spec = st.radio("Model profile", MODEL_PROFILES, index=0)
    engine = st.radio("Policy engine", engine_options(), index=0)
    st.divider()
    st.caption(
        f"{len(benign_ids)} benign · {len(attack_ids)} attack scenarios · "
        f"opa {'detected' if opa_available() else 'not installed (native mirror)'}"
    )

scenario = by_id[scenario_id]
defense_mode = DefenseMode(defense)

tab_run, tab_eval = st.tabs(["▶️ Single run", "📊 Full evaluation"])

# --------------------------------------------------------------------------------------
# Single run
# --------------------------------------------------------------------------------------
with tab_run:
    st.markdown(f"**Task:** {scenario.task}")
    try:
        run = run_single(
            scenario_id,
            defense_mode,
            model_spec,
            scenarios_dir=SCENARIOS_DIR,
            engine_pref=engine,
            base_dir=ROOT,
        )
    except Exception as exc:  # noqa: BLE001 - surface any runtime error in the UI
        st.exception(exc)
        st.stop()

    result = run.result
    trace = run.trace

    level, message = verdict_badge(result)
    getattr(st, level)(message)

    c1, c2, c3 = st.columns(3)
    c1.metric("Proposed account", result.proposed_account or "—")
    c2.metric("Executed account", result.executed_account or "— (not executed)")
    outcome = result.policy_outcome.value if result.policy_outcome else "no gate (executes)"
    c3.metric("Policy outcome", outcome)

    left, right = st.columns(2)

    with left:
        st.subheader("What the agent saw")
        description, output = poisoned_content(trace)
        if description or output:
            st.markdown("Attacker-controlled `poisoned_refund_helper`:")
            if description:
                st.markdown("*Tool description (metadata channel):*")
                st.code(description, language="text")
            if output:
                st.markdown("*Tool output (data channel):*")
                st.code(output, language="json")
        else:
            st.info("No poisoned tool in this scenario — benign flow.")
        if defense_mode.uses_spotlighting and trace.get("spotlighted_helper_output"):
            st.markdown("*Spotlighting wraps untrusted data:*")
            st.code(trace["spotlighted_helper_output"], language="text")

    with right:
        st.subheader("Why the gate decided")
        acct = provenance_table(trace, field="args.account_number")
        if acct.empty:
            acct = provenance_table(trace)
        st.markdown("Provenance of the proposed **`account_number`**:")
        st.dataframe(acct, hide_index=True, width="stretch")

        decision = trace.get("policy_decision")
        if decision:
            if decision["deny_reasons"]:
                st.error("Deny reasons: " + ", ".join(decision["deny_reasons"]))
            if decision["review_reasons"]:
                st.warning("Review reasons: " + ", ".join(decision["review_reasons"]))
            if decision["outcome"] == "allow":
                st.success("Allowed: account has trusted provenance, valid amount, no conflict.")
            st.caption(f"engine: {decision['engine']}  ·  policy: {decision['policy_id']}")
        else:
            st.caption("No policy gate in this defense mode — the proposal executes directly.")

    st.divider()
    st.subheader("Same scenario across every defense mode")
    st.caption("Flip the architecture on and watch the identical attack stop landing.")
    compare = []
    for dm in ALL_DEFENSES:
        r = run_single(
            scenario_id,
            dm,
            model_spec,
            scenarios_dir=SCENARIOS_DIR,
            engine_pref=engine,
            base_dir=ROOT,
        ).result
        compare.append(
            {
                "defense": dm.value,
                "proposed": r.proposed_account,
                "executed": r.executed_account or "—",
                "policy": (r.policy_outcome.value if r.policy_outcome else "no gate"),
                "result": short_result(r),
            }
        )
    st.dataframe(pd.DataFrame(compare), hide_index=True, width="stretch")

    with st.expander("Full audit trace (JSON)"):
        st.json(trace)

# --------------------------------------------------------------------------------------
# Full evaluation
# --------------------------------------------------------------------------------------
with tab_eval:
    st.caption(
        "Run every scenario against every defense with the selected model. "
        "Metrics: ASR (attack success), BTSR (benign task success), FPR, review rate."
    )
    if st.button("Run full evaluation", type="primary"):
        with st.spinner("Running…"), tempfile.TemporaryDirectory() as tmp:
            summary = run_eval(
                SCENARIOS_DIR,
                model_spec,
                list(ALL_DEFENSES),
                Path(tmp) / "eval",
                engine_pref=engine,
                base_dir=ROOT,
            )
        metrics = aggregate(summary.results)
        rows = []
        for dm in ALL_DEFENSES:
            m = metrics.get(dm.value)
            if not m:
                continue
            rows.append(
                {
                    "defense": dm.value,
                    "ASR": m["asr"],
                    "BTSR": m["btsr"],
                    "FPR": m["fpr"],
                    "review": m["review_rate"],
                    "utility": m["utility_retention"],
                }
            )
        mdf = pd.DataFrame(rows).set_index("defense")
        st.markdown(f"**{len(summary.results)} runs** · model `{model_spec}`")
        st.dataframe(
            mdf.style.format("{:.0%}", subset=["ASR", "BTSR", "FPR", "review"]).format(
                "{:.2f}", subset=["utility"]
            ),
            width="stretch",
        )
        st.markdown("**Attack success rate by defense**")
        st.bar_chart(mdf[["ASR", "BTSR"]])

        st.markdown("**Attack-class breakdown (ASR)**")
        breakdown = attack_class_breakdown(summary.results)
        bdf = pd.DataFrame(breakdown).T.fillna(0.0)
        st.dataframe(
            bdf.style.format("{:.0%}"),
            width="stretch",
        )
    else:
        st.info("Click **Run full evaluation** to compute the aggregate metrics.")
