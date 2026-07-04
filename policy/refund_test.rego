# Rego unit tests for the refund policy. Run with: opa test policy -v
package mcp.refund_test

import data.mcp.refund
import rego.v1

_trusted_prov(src) := [{
	"field_path": "args.account_number",
	"source_type": src,
	"trust_level": "trusted",
}]

_input(prov, conflicts, amount) := {
	"action": "create_refund_instruction",
	"max_amount_eur": 10000,
	"args": {
		"claim_id": "CLM-001",
		"customer_id": "CUST-001",
		"account_number": "PL11111111111111111111111111",
		"amount_eur": amount,
		"reason": "Duplicate charge",
	},
	"provenance": prov,
	"conflicts": conflicts,
}

test_allow_verified_database if {
	refund.allow with input as _input(_trusted_prov("verified_database"), [], 120)
}

test_allow_trusted_extractor if {
	refund.allow with input as _input(_trusted_prov("trusted_extractor"), [], 120)
}

test_deny_untrusted_tool_output if {
	inp := _input(
		[{
			"field_path": "args.account_number",
			"source_type": "mcp_tool_output_untrusted",
			"trust_level": "untrusted",
		}],
		[{"reason": "proposed_differs_from_trusted"}],
		120,
	)
	not refund.allow with input as inp
	refund.deny_reasons.account_has_untrusted_provenance with input as inp
	not refund.require_human_review with input as inp
}

test_deny_llm_inferred if {
	inp := _input(
		[{
			"field_path": "args.account_number",
			"source_type": "llm_inference",
			"trust_level": "untrusted",
		}],
		[],
		120,
	)
	not refund.allow with input as inp
	refund.deny_reasons.account_has_untrusted_provenance with input as inp
}

test_deny_missing_provenance if {
	inp := _input([], [], 120)
	not refund.allow with input as inp
	refund.deny_reasons.missing_trusted_account_provenance with input as inp
}

test_review_conflict_between_trusted_sources if {
	inp := _input(_trusted_prov("trusted_extractor"), [{"reason": "multiple_trusted_values"}], 120)
	not refund.allow with input as inp
	refund.require_human_review with input as inp
	refund.review_reasons.conflicting_trusted_values with input as inp
}

test_deny_invalid_amount if {
	inp := _input(_trusted_prov("verified_database"), [], 25000)
	not refund.allow with input as inp
	refund.deny_reasons.invalid_amount with input as inp
}
