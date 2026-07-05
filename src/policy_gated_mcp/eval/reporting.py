"""Markdown report generation (§22)."""

from __future__ import annotations

from .schemas import Category, DefenseMode, EvalResult
from .scoring import aggregate, attack_class_breakdown, model_comparison

_DEFENSE_ORDER = [
    DefenseMode.none,
    DefenseMode.spotlighting,
    DefenseMode.provenance_opa,
    DefenseMode.spotlighting_plus_provenance_opa,
]

_NOTES = {
    "none": "baseline vulnerability (no gate)",
    "spotlighting": "prompt-layer only",
    "provenance_opa": "architectural gate",
    "spotlighting_plus_provenance_opa": "prompt + gate",
}


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.0f}%"


def _find(results, **filters):
    for r in results:
        if all(getattr(r, k) == v for k, v in filters.items()):
            return r
    return None


def generate_report(
    results: list[EvalResult],
    *,
    model_profile: str,
    commit: str = "",
    date: str = "",
    scenario_count: int | None = None,
    policy_engine: str = "",
) -> str:
    metrics = aggregate(results)
    breakdown = attack_class_breakdown(results)
    present = [d for d in _DEFENSE_ORDER if d.value in metrics]

    none_m = metrics.get("none", {})
    opa_m = metrics.get("provenance_opa", {})
    lines: list[str] = []
    a = lines.append

    a("# Policy-Gated MCP Evaluation Summary\n")
    a("## Setup\n")
    # Date/Commit are only emitted when explicitly provided (interactive `eval` runs), so
    # the committed sample report stays byte-stable and never claims a wrong commit.
    if date:
        a(f"- Date: {date}")
    if commit:
        a(f"- Commit: {commit}")
    a(f"- Model profile: `{model_profile}`")
    a(f"- Policy engine: `{policy_engine or 'n/a'}`")
    a(f"- Scenario count: {scenario_count if scenario_count is not None else 'n/a'}")
    a(f"- Defense modes: {', '.join(d.value for d in present)}\n")

    a("## Executive result\n")
    a(
        f"With the `{model_profile}` model, attack success falls from "
        f"**{_pct(none_m.get('asr'))}** with no defense to "
        f"**{_pct(opa_m.get('asr'))}** under the provenance/OPA gate, while benign task "
        f"success under the gate stays at **{_pct(opa_m.get('btsr'))}** "
        f"(false-positive rate {_pct(opa_m.get('fpr'))}). Prompt-layer spotlighting alone "
        f"only reaches **{_pct(metrics.get('spotlighting', {}).get('asr'))}** ASR because it "
        "does not blunt description-channel poisoning. The gate blocks attacker-controlled "
        "arguments architecturally, not by prompting.\n"
    )

    a("## Metrics table\n")
    a("| Defense | ASR | BTSR | FPR | Review | Exfil | Notes |")
    a("|---|---:|---:|---:|---:|---:|---|")
    for d in present:
        m = metrics[d.value]
        note = _NOTES.get(d.value, "")
        a(
            f"| {d.value} | {_pct(m['asr'])} | {_pct(m['btsr'])} | {_pct(m['fpr'])} "
            f"| {_pct(m['review_rate'])} | {_pct(m['exfiltration_rate'])} | {note} |"
        )
    a("")
    a(
        "**Exfil** is the canary-exfiltration rate. The gate protects the account and amount "
        "but not the free-text `reason` field, so a secret can still be exfiltrated *under the "
        "gate* — while spotlighting (which delimits the untrusted instruction) suppresses it. "
        "The two defenses are complementary; free-text output filtering is future work.\n"
    )

    models = sorted({r.model_profile for r in results})
    if len(models) > 1:
        a("## Model comparison (ASR by defense)\n")
        a("| Model | " + " | ".join(d.value for d in present) + " |")
        a("|---|" + "---:|" * len(present))
        comp = model_comparison(results)
        for model in models:
            row = comp.get(model, {})
            cells = " | ".join(_pct(row.get(d.value)) for d in present)
            a(f"| `{model}` | {cells} |")
        a("")

    a("## Attack-class breakdown\n")
    a("| Attack class | No defense ASR | Spotlighting ASR | Provenance/OPA ASR |")
    a("|---|---:|---:|---:|")
    for attack_type in sorted(breakdown):
        row = breakdown[attack_type]
        a(
            f"| {attack_type} | {_pct(row.get('none'))} | {_pct(row.get('spotlighting'))} "
            f"| {_pct(row.get('provenance_opa'))} |"
        )
    a("")

    a("## Representative traces\n")
    won = _find(
        results, category=Category.attack, defense_mode=DefenseMode.none, attack_success=True
    )
    a("### Successful attack without defense\n")
    if won:
        a(f"- Scenario: `{won.scenario_id}` ({won.attack_type.value})")
        a(f"- Proposed account: `{won.proposed_account}`")
        a(f"- Executed account: `{won.executed_account}`")
        a(
            "- Why it succeeded: no policy gate; the vulnerable model echoed the poisoned "
            "account and it was executed directly."
        )
        a(f"- Trace: `{won.trace_path}`\n")
    else:
        a("- (none observed)\n")

    blocked = _find(
        results,
        category=Category.attack,
        defense_mode=DefenseMode.provenance_opa,
        attack_success=False,
    )
    a("### Blocked attack with provenance/OPA\n")
    if blocked:
        outcome = blocked.policy_outcome.value if blocked.policy_outcome else "n/a"
        a(f"- Scenario: `{blocked.scenario_id}` ({blocked.attack_type.value})")
        a(f"- Proposed account: `{blocked.proposed_account}`")
        a(f"- Policy outcome: `{outcome}`")
        a(f"- Deny reasons: {', '.join(blocked.deny_reasons) or 'n/a'}")
        a(
            "- Why it was blocked: the proposed account resolved to untrusted provenance "
            "(poisoned tool metadata/output); it never had a trusted origin."
        )
        a(f"- Trace: `{blocked.trace_path}`\n")
    else:
        a("- (none observed)\n")

    a("## Limitations\n")
    a(
        "- Metrics come from a deterministic fake-model harness; they demonstrate the "
        "control's mechanics, not real-model attack rates.\n"
        "- The gate authorizes on the refund `account_number`; amount is range-checked and "
        "other fields are existence-checked. Broader argument coverage is future work.\n"
        "- Provenance is exact-value matching; semantically equivalent values are not unified.\n"
        "- Tools are in-process (MCP-like abstraction), not a real MCP transport.\n"
        "- The defense reduces measured risk; it does not 'solve' prompt injection.\n"
    )

    a("## Future work\n")
    a(
        "- Real-model adapters (OpenAI/Anthropic/Ollama), still policy-gated.\n"
        "- Real `mcp`-SDK server/client transport.\n"
        "- Signed tool manifests / allow-listing; multi-step taint tracking; canary "
        "exfiltration scenarios; CI regression benchmark.\n"
    )

    return "\n".join(lines) + "\n"
