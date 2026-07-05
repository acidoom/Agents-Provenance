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
# The gate authorizes on the GATED fields args.account_number and args.amount_eur: each
# must have trusted provenance and no untrusted provenance. Decision fields consumed by
# the harness: allow, deny_reasons, review_reasons, require_human_review. Outcome
# precedence (deny > review > allow > default-deny) is applied identically in Python by
# PolicyDecision.from_rego.
package mcp.refund

import rego.v1

trusted_sources := {"trusted_extractor", "verified_database", "human_approval"}

untrusted_sources := {
	"mcp_tool_metadata",
	"mcp_tool_output_untrusted",
	"llm_inference",
	"user_request",
	"test_fixture",
	"unknown",
}

default allow := false

default require_human_review := false

# The per-request cap, defaulting to 10000 when the input omits it.
default amount_limit := 10000

amount_limit := input.max_amount_eur if input.max_amount_eur

# --- generic field-provenance helpers ---------------------------------------
field_has_trusted(f) if {
	some p in input.provenance
	p.field_path == f
	trusted_sources[p.source_type]
	p.trust_level == "trusted"
}

field_has_untrusted(f) if {
	some p in input.provenance
	p.field_path == f
	untrusted_sources[p.source_type]
}

account_has_trusted_provenance if field_has_trusted("args.account_number")

account_has_untrusted_provenance if field_has_untrusted("args.account_number")

amount_has_trusted_provenance if field_has_trusted("args.amount_eur")

amount_has_untrusted_provenance if field_has_untrusted("args.amount_eur")

all_gated_trusted if {
	account_has_trusted_provenance
	amount_has_trusted_provenance
}

any_gated_untrusted if account_has_untrusted_provenance

any_gated_untrusted if amount_has_untrusted_provenance

# --- allow ------------------------------------------------------------------
allow if {
	input.action == "create_refund_instruction"
	args_present
	valid_amount
	all_gated_trusted
	not any_gated_untrusted
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

# --- human review -----------------------------------------------------------
# A conflict among trusted sources (with no untrusted taint) is a data ambiguity a human
# should resolve; attacker cases carry untrusted provenance and are denied below.
require_human_review if {
	input.action == "create_refund_instruction"
	count(input.conflicts) > 0
	all_gated_trusted
	not any_gated_untrusted
	valid_amount
}

review_reasons contains "conflicting_trusted_values" if {
	count(input.conflicts) > 0
	all_gated_trusted
	not any_gated_untrusted
}

# --- deny reasons -----------------------------------------------------------
deny_reasons contains "missing_trusted_account_provenance" if {
	input.action == "create_refund_instruction"
	not account_has_trusted_provenance
}

deny_reasons contains "account_has_untrusted_provenance" if account_has_untrusted_provenance

deny_reasons contains "missing_trusted_amount_provenance" if {
	input.action == "create_refund_instruction"
	not amount_has_trusted_provenance
}

deny_reasons contains "amount_has_untrusted_provenance" if amount_has_untrusted_provenance

deny_reasons contains "invalid_amount" if {
	input.action == "create_refund_instruction"
	not valid_amount
}

deny_reasons contains "missing_required_args" if {
	input.action == "create_refund_instruction"
	not args_present
}
