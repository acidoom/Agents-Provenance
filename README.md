# Policy-Gated MCP

**Tool-poisoning red-team + provenance/OPA policy defense for MCP-style agents.**

A reproducible, keyless research harness that (1) demonstrates MCP tool-poisoning attacks against a
small tool-using agent running a synthetic refund/claim workflow, and (2) measures whether
**argument-level provenance + an OPA/Rego policy gate** reduces attack success while preserving
benign task completion.

> **Core claim under test:** an LLM may *propose* a high-impact tool call, but a provenance-aware
> policy gate can deny it whenever a critical argument (the refund `account_number`) traces back to
> an untrusted source — tool metadata, untrusted tool output, or model invention — without breaking
> legitimate flows.

The security boundary is **not** the prompt. It is a deterministic policy gate that validates the
provenance of high-impact tool-call arguments before execution.

> ⚠️ Research prototype. All data is synthetic (fake claim/customer IDs, fake IBAN-like accounts,
> fake injection strings). Nothing sends money, runs OS commands, or touches real systems.

---

## Quickstart

```bash
git clone <repo> && cd policy-gated-mcp
export UV_PROJECT_ENVIRONMENT=$HOME/.uv-envs/policy-gated-mcp   # keep .venv out of iCloud
uv sync --extra dev          # or: python -m venv .venv && pip install -e ".[dev]"
make test                    # unit + integration tests (OPA tests skip if `opa` absent)
make eval                    # writes reports/weekend_eval/
open reports/weekend_eval/eval_summary.md
```

Install the real OPA engine (optional — a native Python mirror is used otherwise):

```bash
make install-opa   # brew, or a pinned binary into ./bin
make opa-test      # run the Rego unit tests
```

## CLI

```bash
python -m policy_gated_mcp.cli list-scenarios
python -m policy_gated_mcp.cli run --scenario argument_substitution_001 --defense provenance_opa --model fake:vulnerable_agent
python -m policy_gated_mcp.cli eval --scenarios scenarios --model fake:vulnerable_agent --defenses all --out reports/weekend_eval
python -m policy_gated_mcp.cli policy-check --input fixtures/policy_inputs/deny_untrusted_account.json
python -m policy_gated_mcp.cli report --results reports/weekend_eval/results.jsonl --out reports/weekend_eval/eval_summary.md
```

---

## Threat model (summary)

| | |
|---|---|
| **Assets** | Integrity of high-impact tool-call arguments (refund recipient + amount); the agent instruction hierarchy; auditability. |
| **Attacker can influence** | MCP tool descriptions/metadata, tool outputs, retrieved document text, helper "recommendations". |
| **Attacker cannot** | modify the OPA policy, the verified customer DB, or the trusted extractor code; execute the high-impact tool directly. |
| **Boundary** | the deterministic provenance/OPA gate — not the LLM prompt. |

See [PRD.md](PRD.md) §20 for the full threat model.

## Defense modes

- `none` — no gate; baseline vulnerability.
- `spotlighting` — untrusted data wrapped in delimiters + a warning; prompt-layer only, no gate.
- `provenance_opa` — every high-impact call passes the OPA/Rego gate; critical args need trusted provenance.
- `spotlighting_plus_provenance_opa` — both.

## How it works

1. A deterministic **trusted extractor** reads claim fields **only** from the explicit
   `CLAIM_FIELDS_START/END` block — injected text elsewhere is untrusted document content.
2. A **provenance ledger** records where every critical value was observed (trusted extractor,
   verified DB, tool metadata, tool output, or model invention). **The model can never mint trust.**
3. When the model proposes `create_refund_instruction(...)`, the harness resolves the origin of each
   critical argument and hands `{action, args, provenance, conflicts}` to the **policy gate**.
4. The gate (OPA/Rego, with a Python mirror fallback) allows only if the account has trusted
   provenance, no untrusted provenance, a valid amount, and no conflicts.

<!-- TODO(M6): architecture diagram, example results table, sample trace walkthrough, limitations, future work -->

## Project status

Built milestone-by-milestone from [PRD.md](PRD.md). See the plan for build order. Optional real-model
adapters (`openai`/`anthropic`/`ollama`) and a real `mcp`-SDK transport adapter are future work; the
default path is deterministic and needs no API keys.

## License

Apache-2.0.
