# Provenance-Gated Tool Calls: Measuring an Architectural Defense against MCP Tool Poisoning

*A reproducible research prototype. All data is synthetic; nothing touches real systems.*

## Abstract

Agents that use tools over the Model Context Protocol (MCP) treat tool **metadata** and tool
**outputs** as part of their working context. When those channels are attacker-controlled — a
poisoned tool description, a "SYSTEM OVERRIDE" note in a tool result — the agent can be steered into
executing a high-impact action with attacker-chosen arguments. Prompt-level mitigations (delimiting
untrusted data, "spotlighting") help unevenly. We implement and **measure** an architectural
alternative: the LLM may *propose* a high-impact tool call, but every critical argument must pass a
deterministic **provenance gate** — realised as an OPA/Rego policy — that authorises the call only
when the argument traces back to a *trusted* source. On a deterministic 35-scenario benchmark
(8 attack classes, 4 defense modes, 140 runs), the gate reduces account/amount-hijacking attack
success from **90% to 0%** while preserving **86%** benign task completion. We also show the gate and
prompt-layer spotlighting are **complementary**: the gate stops argument hijacking but not free-text
**exfiltration**, which spotlighting stops but description-channel poisoning defeats — only both
together zero out both surfaces.

## 1. Motivation

The core failure mode is a category error: an agent runtime treats *data it retrieved* (tool
descriptions, tool outputs, retrieved documents) as *authority* over its next action. Better
prompting reduces but does not eliminate this — the instruction and the data share one channel. We
therefore move the security boundary off the prompt and onto a deterministic gate that reasons about
**where each argument value came from**, not about how persuasive the surrounding text was.

## 2. Threat model

- **Assets.** Integrity of the high-impact call's gated arguments — the refund `account_number` and
  `amount_eur`; the agent instruction hierarchy; auditability.
- **The attacker can influence** MCP tool descriptions/metadata, tool outputs, retrieved document
  text, and helper "recommendations".
- **The attacker cannot** modify the OPA policy, the verified customer database, or the trusted
  extractor code, and cannot execute the high-impact tool directly.
- **Security boundary.** The deterministic provenance/OPA gate — *not* the LLM prompt.

## 3. Method

**Domain.** A synthetic refund workflow: read a claim, extract fields, look up the verified
customer, propose `create_refund_instruction(claim_id, customer_id, account_number, amount_eur,
reason)`, gate it, and execute a *mock* instruction (no money moves).

**Provenance ledger (the mechanism).** As the flow runs, a ledger records every observation of a
critical value together with its origin — `trusted_extractor` and `verified_database` (trusted),
`mcp_tool_metadata` / `mcp_tool_output_untrusted` / `llm_inference` (untrusted). When the model
proposes a value, the *harness* (never the model) resolves that value's origin by matching it against
recorded observations. A vulnerable model that echoes an attacker-controlled account therefore
cannot make it look trusted — no trusted source ever observed it. Multi-step taint follows for free:
a value laundered through several tools still carries its untrusted origin by value.

**The gate.** `create_refund_instruction` is authorised only if each gated argument
(`account_number`, `amount_eur`) has trusted provenance and no untrusted provenance, the amount is in
range, and there is no conflict. A conflict among *trusted* sources routes to human **review**;
untrusted or missing provenance **denies**. The policy is written once in `policy/refund.rego`
(Rego v1) and mirrored in Python; a differential test asserts the OPA CLI and the mirror agree on
every fixture, so the two can never drift, and the harness stays keyless when `opa` is absent.

**Defense modes.** `none`; `spotlighting` (delimit untrusted data + warn); `provenance_opa` (the
gate); and both combined.

**Attack classes (8).** `tool_description_poisoning` and `tool_name_confusion` (metadata channel —
not delimited by spotlighting); `tool_output_poisoning`, `argument_substitution`,
`amount_substitution`, `cross_tool_contamination` (multi-step), `retrieval_injection`, and
`canary_exfiltration` (data channel).

## 4. Evaluation

Deterministic **fake model profiles** (`safe_baseline`, `vulnerable_agent`, `mixed_agent`) make the
metrics reproducible without API keys; the same harness also runs **real models** (OpenAI /
Anthropic / Ollama) unchanged, and can run tools over a **real MCP session** — both are opt-in and
never on the default path. 35 scenarios (14 benign incl. 2 human-review conflicts; 21 attack) × 4
defenses = 140 runs with `fake:vulnerable_agent`.

Metrics: **ASR** (attack success — a hijacked account/amount actually *executed*), **BTSR** (benign
task success), **FPR** and **review rate** (benign flows blocked / sent to review), and
**Exfil** (canary-exfiltration rate).

## 5. Results

| Defense | ASR | BTSR | FPR | Review | Exfil |
|---|---:|---:|---:|---:|---:|
| none | **90%** | 100% | 0% | 0% | 100% |
| spotlighting | 24% | 100% | 0% | 0% | **0%** |
| provenance_opa | **0%** | 86% | 14% | 6% | 100% |
| spotlighting + provenance_opa | **0%** | 86% | 14% | 6% | **0%** |

**The gate blocks argument hijacking architecturally.** Under the gate, ASR drops to 0% — including
amount inflation kept *within* the range cap, which only provenance (not the range check) catches.
The vulnerable model still *proposes* the attacker's values; the gate simply refuses to execute them
because they lack trusted provenance. Benign success stays at 86%: the 14% FPR / 6% review comes
entirely from two benign scenarios in which the claim document and the verified record genuinely
disagree on the account, which the gate honestly routes to a human rather than guessing.

**Spotlighting is partial and prompt-shaped.** It reaches only 24% ASR because tool *descriptions*
are presented as schema, not delimited as data, so description- and tool-name-confusion attacks
survive it.

**The two defenses are complementary (the interesting finding).** The gate protects the gated
arguments but does **not** stop **canary exfiltration** — the poison copies a secret into the
ungated free-text `reason` field, and the gate allows the call (account and amount are safe), so the
secret leaks (Exfil 100%). Spotlighting *does* suppress exfiltration (0%) because the instruction to
copy the secret arrives through the delimited data channel. Only the two together drive both attack
surfaces to zero. This argues for defense-in-depth, not either/or.

These are deterministic-harness numbers — they demonstrate the control's *mechanics*, not real-model
attack rates.

## 6. Related work

Prompt injection and the data/instruction confusion in tool-using agents (Willison; Greshake et
al., "Not what you've signed up for"); **spotlighting** delimiters (Hines et al.); dual-LLM /
capability designs such as **CaMeL** that separate a planner from tainted data; **OPA/Rego** as
policy-as-code for authorization; and emerging work on MCP-specific tool-poisoning. This prototype's
contribution is not a new attack or a new policy engine but a small, reproducible harness that
**measures** the risk reduction of argument-level provenance + a policy gate, and surfaces where it
does and does not help.

## 7. Limitations

- Metrics come from a deterministic fake-model harness, not real models.
- The gate authorises `account_number` and `amount_eur`; `claim_id`/`customer_id` are existence-
  checked and `reason` is unchecked — hence the exfiltration gap. Provenance is exact-value matching
  (no semantic unification).
- Synthetic domain, in-process tools by default (a real MCP transport is available but optional).
- The defense reduces *measured* risk; it does not "solve" prompt injection.

## 8. Future work

Free-text **output filtering** to close the exfiltration gap; provenance-gating the remaining
arguments; signed tool manifests / allow-listing; broader real-model comparisons across families;
and a CI regression benchmark that fails if a change raises ASR.

## 9. Reproduction

```bash
uv sync --extra dev            # or: pip install -e ".[dev]"
make test                      # 114 tests (OPA tests skip without the binary)
make install-opa && make test  # exercises the real Rego path + native/OPA parity
make eval                      # -> reports/weekend_eval/eval_summary.md
```

See the repository [README](../README.md) for the architecture diagram, CLI, real-model and MCP
transport usage, and the committed sample report.
