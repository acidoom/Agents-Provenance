"""Policy engine interface + native Python mirror of refund.rego + engine factory.

The native mirror exists so the harness runs deterministically with no external
dependency, and doubles as a differential oracle: tests/test_policy_parity asserts the
OPA CLI and this mirror produce identical decisions for every fixture, so the two can
never silently drift.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..provenance.hashing import hash_value
from .decisions import PolicyDecision

# Must match policy/refund.rego exactly.
TRUSTED_ACCOUNT_SOURCES = {"trusted_extractor", "verified_database", "human_approval"}
UNTRUSTED_SOURCES = {
    "mcp_tool_metadata",
    "mcp_tool_output_untrusted",
    "llm_inference",
    "unknown",
    "user_request",
}
DEFAULT_MAX_AMOUNT = 10000

#: repo-root/policy — the directory holding refund.rego.
DEFAULT_POLICY_DIR = Path(__file__).resolve().parents[3] / "policy"
POLICY_ID = "refund.rego"


@runtime_checkable
class PolicyEngine(Protocol):
    name: str

    def evaluate(self, policy_input: dict) -> PolicyDecision: ...


def raw_decision(policy_input: dict) -> dict:
    """Pure-Python evaluation of refund.rego. Returns the raw Rego-shaped document."""
    action = policy_input.get("action")
    args = policy_input.get("args", {}) or {}
    provenance = policy_input.get("provenance", []) or []
    conflicts = policy_input.get("conflicts", []) or []
    limit = policy_input.get("max_amount_eur", DEFAULT_MAX_AMOUNT)

    is_refund = action == "create_refund_instruction"

    account_prov = [p for p in provenance if p.get("field_path") == "args.account_number"]
    account_has_trusted = any(
        p.get("source_type") in TRUSTED_ACCOUNT_SOURCES and p.get("trust_level") == "trusted"
        for p in account_prov
    )
    account_has_untrusted = any(p.get("source_type") in UNTRUSTED_SOURCES for p in account_prov)

    amount = args.get("amount_eur")
    valid_amount = isinstance(amount, (int, float)) and not isinstance(amount, bool)
    valid_amount = valid_amount and amount > 0 and amount <= limit

    args_present = (
        bool(args.get("claim_id"))
        and bool(args.get("customer_id"))
        and bool(args.get("account_number"))
    )
    has_conflict = len(conflicts) > 0

    deny_reasons: list[str] = []
    if is_refund and not account_has_trusted:
        deny_reasons.append("missing_trusted_account_provenance")
    if account_has_untrusted:
        deny_reasons.append("account_has_untrusted_provenance")
    if is_refund and not valid_amount:
        deny_reasons.append("invalid_amount")
    if is_refund and not args_present:
        deny_reasons.append("missing_required_args")

    review_reasons: list[str] = []
    if has_conflict and account_has_trusted and not account_has_untrusted:
        review_reasons.append("conflicting_trusted_values")

    require_human_review = (
        is_refund
        and has_conflict
        and account_has_trusted
        and not account_has_untrusted
        and valid_amount
    )

    allow = (
        is_refund
        and args_present
        and valid_amount
        and account_has_trusted
        and not account_has_untrusted
        and not has_conflict
    )

    return {
        "allow": allow,
        "deny_reasons": deny_reasons,
        "review_reasons": review_reasons,
        "require_human_review": require_human_review,
    }


class NativePolicyEngine(PolicyEngine):
    name = "native"

    def evaluate(self, policy_input: dict) -> PolicyDecision:
        return PolicyDecision.from_rego(
            raw_decision(policy_input),
            policy_id=f"{POLICY_ID} (native-mirror)",
            input_hash=hash_value(policy_input),
            engine=self.name,
        )


def get_policy_engine(
    prefer: str | None = None,
    *,
    policy_dir: str | Path | None = None,
    warn: bool = True,
) -> PolicyEngine:
    """Return a policy engine.

    prefer: ``auto`` (default) uses OPA if on PATH else the native mirror + a warning;
    ``opa`` requires the binary (raises if absent); ``native`` forces the mirror.
    Falls back to the ``POLICY_ENGINE`` env var when ``prefer`` is None.
    """
    prefer = (prefer or os.environ.get("POLICY_ENGINE", "auto")).lower()
    policy_dir = Path(policy_dir or DEFAULT_POLICY_DIR)

    if prefer == "native":
        return NativePolicyEngine()

    from .opa_engine import OpaPolicyEngine, opa_available

    if prefer == "opa":
        return OpaPolicyEngine(policy_dir)

    # auto
    if opa_available():
        return OpaPolicyEngine(policy_dir)
    if warn:
        warnings.warn(
            "opa binary not found on PATH; using the native Python policy mirror. "
            "Install it with `make install-opa` to enforce via the real OPA/Rego engine.",
            stacklevel=2,
        )
    return NativePolicyEngine()
