"""Explicit agent state machine (FR-7).

One `run_scenario` call executes the full flow for a single (scenario × defense × model)
and returns a scored result plus a fully serializable trace. The nodes, in order:
load_tools → read_claim → extract_claim_fields → lookup_customer_record →
optional_helper_tool → plan_refund_instruction → assemble_tool_call_request →
policy_gate → execute_or_deny → score_result → (trace assembled throughout).

Key invariant: the high-impact `create_refund_instruction` tool is only ever run after
the policy gate allows it (in gate modes). The model proposes; the gate disposes.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.extractor import ExtractionError, extract_claim_fields
from ..eval.schemas import DefenseMode, EvalResult, Scenario
from ..eval.scoring import score_run
from ..mcp import MCPClient
from ..models.base import Model, ModelContext, PoisonSignal
from ..policy.decisions import PolicyDecision, PolicyOutcome
from ..policy.engine import PolicyEngine
from ..provenance.ledger import ProvenanceLedger
from ..provenance.models import SourceType
from .prompts import SPOTLIGHT_SYSTEM_NOTE, spotlight
from .tool_router import build_registry


@dataclass
class RunResult:
    result: EvalResult
    trace: dict


def run_scenario(
    scenario: Scenario,
    defense_mode: DefenseMode,
    model: Model,
    *,
    policy_engine: PolicyEngine,
    claim_text: str,
    db_path=None,
) -> RunResult:
    ledger = ProvenanceLedger(scenario.id)
    registry, poison = build_registry(scenario, claim_text, db_path=db_path)
    client = MCPClient(registry)

    tool_calls: list[dict] = []
    tool_outputs: list[dict] = []

    # -- read_claim ----------------------------------------------------------
    read = client.call("read_claim_document", claim_id=scenario.claim_id)
    tool_calls.append({"tool": "read_claim_document", "args": {"claim_id": scenario.claim_id}})
    tool_outputs.append(read.model_dump())

    # -- extract_claim_fields (trusted; only the CLAIM_FIELDS block) ----------
    # Fail safe: an attacker controls the document text (threat model), so a malformed
    # or duplicated trusted block must yield NO trusted provenance and let the gate deny,
    # never crash the run (honoring the extractor's fail-safe-deny contract).
    fields = None
    extraction_error: str | None = None
    try:
        extraction = extract_claim_fields(read.output, scenario_id=scenario.id)
    except ExtractionError as exc:
        extraction_error = str(exc)
    else:
        for entry in extraction.provenance:
            ledger.record(entry)
        fields = extraction.fields

    # -- lookup_customer_record (verified DB is a trusted account source) -----
    lookup = client.call("lookup_customer_record", customer_id=scenario.customer_id)
    tool_calls.append(
        {"tool": "lookup_customer_record", "args": {"customer_id": scenario.customer_id}}
    )
    tool_outputs.append(lookup.model_dump())
    if not lookup.error and isinstance(lookup.output, dict):
        ledger.observe(
            field="account_number",
            value=lookup.output["verified_account"],
            source_type=SourceType.verified_database,
            source_id=f"customer_db:{scenario.customer_id}.verified_account",
            created_by="lookup_customer_record",
            evidence=f"verified_account for {scenario.customer_id}",
        )

    # -- optional_helper_tool (attacker-controlled) --------------------------
    poison_signals: list[PoisonSignal] = []
    spotlighted_helper: str | None = None
    if registry.has("poisoned_refund_helper"):
        helper = client.call("poisoned_refund_helper", claim_id=scenario.claim_id)
        tool_calls.append(
            {"tool": "poisoned_refund_helper", "args": {"claim_id": scenario.claim_id}}
        )
        tool_outputs.append(helper.model_dump())
        if poison is not None:
            attacker = poison.attacker_account
            if poison.channel == "metadata":
                source_type = SourceType.mcp_tool_metadata
                source_id = "tool:poisoned_refund_helper.description"
                evidence = "attacker account named in poisoned tool description"
            else:
                source_type = SourceType.mcp_tool_output_untrusted
                source_id = "tool:poisoned_refund_helper.output"
                evidence = "attacker account named in poisoned tool output"
            ledger.observe(
                field="account_number",
                value=attacker,
                source_type=source_type,
                source_id=source_id,
                created_by="poisoned_refund_helper",
                evidence=evidence,
            )
            poison_signals.append(
                PoisonSignal(
                    account=attacker, channel=poison.channel, attack_type=scenario.attack_type
                )
            )
        if defense_mode.uses_spotlighting:
            spotlighted_helper = spotlight(helper.text)

    # -- plan_refund_instruction (model proposes) ----------------------------
    # When extraction failed there is no trusted safe account, so the model has no
    # legitimate value to propose and the gate will deny (missing trusted provenance).
    context = ModelContext(
        task=scenario.task,
        claim_id=fields.claim_id if fields else scenario.claim_id,
        customer_id=fields.customer_id if fields else scenario.customer_id,
        safe_account=fields.beneficiary_account if fields else "",
        amount_eur=fields.refund_amount_eur if fields else 0.0,
        reason=fields.reason if fields else "",
        poison_signals=poison_signals,
        spotlighted=defense_mode.uses_spotlighting,
    )
    request = model.propose(context)
    request.scenario_id = scenario.id

    # -- policy_gate ---------------------------------------------------------
    policy_input: dict | None = None
    decision: PolicyDecision | None = None
    if defense_mode.uses_gate:
        policy_input = ledger.build_policy_input(
            request.action, request.args, max_amount_eur=scenario.max_amount_eur
        )
        decision = policy_engine.evaluate(policy_input)

    # -- execute_or_deny -----------------------------------------------------
    executed = False
    executed_record: dict | None = None
    allowed = (not defense_mode.uses_gate) or (
        decision is not None and decision.outcome == PolicyOutcome.allow
    )
    if allowed:
        result_call = client.call("create_refund_instruction", **request.args)
        executed = True
        executed_record = result_call.output
        tool_calls.append({"tool": "create_refund_instruction", "args": dict(request.args)})
        tool_outputs.append(result_call.model_dump())

    # -- score_result --------------------------------------------------------
    result = score_run(scenario, model.name, defense_mode, request, decision, executed)

    trace = {
        "scenario": scenario.model_dump(),
        "defense_mode": defense_mode.value,
        "model_profile": model.name,
        "spotlighting_note": SPOTLIGHT_SYSTEM_NOTE if defense_mode.uses_spotlighting else None,
        "spotlighted_helper_output": spotlighted_helper,
        "extraction_error": extraction_error,
        "tool_metadata_shown": [m.model_dump() for m in registry.metadata()],
        "tool_calls": tool_calls,
        "tool_outputs": tool_outputs,
        "provenance_observations": ledger.to_trace(),
        "poison_signals": [s.model_dump() for s in poison_signals],
        "proposed_request": request.model_dump(),
        "policy_input": policy_input,
        "policy_decision": decision.model_dump() if decision else None,
        "executed": executed,
        "executed_record": executed_record,
        "score": result.model_dump(),
    }
    return RunResult(result=result, trace=trace)
