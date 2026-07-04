# Provenance-gated refund policy (Rego v1, OPA >= 1.0).
#
# Input shape (produced by ProvenanceLedger.build_policy_input):
#   {
#     "action": "create_refund_instruction",
#     "risk_level": "high",
#     "max_amount_eur": 10000,
#     "args": {claim_id, customer_id, account_number, amount_eur, reason},
#     "provenance": [{field_path, source_type, trust_level, ...}, ...],
#     "conflicts": [ ... ]
#   }
#
# Decision fields consumed by the harness: allow, deny_reasons, review_reasons,
# require_human_review. Outcome precedence (deny > review > allow > default-deny) is
# applied identically in Python by PolicyDecision.from_rego.
package mcp.refund

import rego.v1

trusted_account_sources := {"trusted_extractor", "verified_database", "human_approval"}

untrusted_sources := {
	"mcp_tool_metadata",
	"mcp_tool_output_untrusted",
	"llm_inference",
	"unknown",
	"user_request",
}

default allow := false

default require_human_review := false

# The per-request cap, defaulting to 10000 when the input omits it.
default amount_limit := 10000

amount_limit := input.max_amount_eur if input.max_amount_eur

# --- allow ------------------------------------------------------------------
allow if {
	input.action == "create_refund_instruction"
	args_present
	valid_amount
	account_has_trusted_provenance
	not account_has_untrusted_provenance
	count(input.conflicts) == 0
}

# --- helper predicates ------------------------------------------------------
args_present if {
	input.args.claim_id != ""
	input.args.customer_id != ""
	input.args.account_number != ""
}

valid_amount if {
	input.args.amount_eur > 0
	input.args.amount_eur <= amount_limit
}

account_has_trusted_provenance if {
	some p in input.provenance
	p.field_path == "args.account_number"
	trusted_account_sources[p.source_type]
	p.trust_level == "trusted"
}

account_has_untrusted_provenance if {
	some p in input.provenance
	p.field_path == "args.account_number"
	untrusted_sources[p.source_type]
}

# --- human review -----------------------------------------------------------
# A conflict among trusted sources (with no untrusted taint) is not an attack — it is
# a data ambiguity a human should resolve. Attacker cases carry untrusted provenance
# and are denied below, so they never reach review.
require_human_review if {
	input.action == "create_refund_instruction"
	count(input.conflicts) > 0
	account_has_trusted_provenance
	not account_has_untrusted_provenance
	valid_amount
}

review_reasons contains "conflicting_trusted_values" if {
	count(input.conflicts) > 0
	account_has_trusted_provenance
	not account_has_untrusted_provenance
}

# --- deny reasons -----------------------------------------------------------
deny_reasons contains "missing_trusted_account_provenance" if {
	input.action == "create_refund_instruction"
	not account_has_trusted_provenance
}

deny_reasons contains "account_has_untrusted_provenance" if {
	account_has_untrusted_provenance
}

deny_reasons contains "invalid_amount" if {
	input.action == "create_refund_instruction"
	not valid_amount
}

deny_reasons contains "missing_required_args" if {
	input.action == "create_refund_instruction"
	not args_present
}
