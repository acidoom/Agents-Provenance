"""Provenance ledger — the crux of the defense.

The ledger records every observation of a critical value *and the origin it came from*
as the agent flow runs. When the model proposes a high-impact tool call, the ledger —
never the model — resolves where each proposed argument value actually came from
(value-origin resolution) and builds the deterministic policy input. Because trust is
assigned by matching the proposed value against *recorded observations from trusted
components*, a vulnerable model that echoes an attacker-controlled account cannot make
that account look trusted: no trusted source ever observed it.
"""

from __future__ import annotations

from typing import Any

from ..domain.claims import CRITICAL_FIELDS
from .hashing import hash_value
from .models import (
    TRUSTED_SOURCE_TYPES,
    UNTRUSTED_SOURCE_TYPES,
    ProvenanceEntry,
    SourceType,
    TrustLevel,
)

#: The single field the refund policy authorizes on. Others are existence/range checked.
GATED_FIELD = "account_number"

#: Preference order when several trusted sources vouch for the same value.
_TRUSTED_PRIORITY = {
    SourceType.human_approval: 3,
    SourceType.verified_database: 2,
    SourceType.trusted_extractor: 1,
}


class ProvenanceLedger:
    def __init__(self, scenario_id: str = "") -> None:
        self.scenario_id = scenario_id
        self._observations: list[ProvenanceEntry] = []

    # -- recording -----------------------------------------------------------

    def observe(
        self,
        *,
        field: str,
        value: Any,
        source_type: SourceType,
        source_id: str,
        created_by: str,
        trust_level: TrustLevel | None = None,
        evidence: str = "",
        confidence: float = 1.0,
    ) -> ProvenanceEntry:
        """Record that ``created_by`` saw ``value`` for ``field`` from ``source_type``."""
        entry = ProvenanceEntry.observe(
            field_path=field,
            value=value,
            source_type=source_type,
            source_id=source_id,
            created_by=created_by,
            scenario_id=self.scenario_id,
            trust_level=trust_level,
            evidence=evidence,
            confidence=confidence,
        )
        self._validate_consistency(entry)
        self._observations.append(entry)
        return entry

    @staticmethod
    def _validate_consistency(entry: ProvenanceEntry) -> None:
        """Reject impossible trust labels — e.g. an untrusted source claiming `trusted`.

        This is the mechanical guard behind FR-10: no caller (and certainly not the
        model) can record an untrusted-origin value as trusted.
        """
        if entry.source_type in UNTRUSTED_SOURCE_TYPES and entry.trust_level == TrustLevel.trusted:
            raise ValueError(
                f"invalid provenance: source_type={entry.source_type.value} "
                f"cannot have trust_level=trusted"
            )
        if (
            entry.trust_level == TrustLevel.trusted
            and entry.source_type not in TRUSTED_SOURCE_TYPES
            and entry.source_type != SourceType.test_fixture
        ):
            raise ValueError(
                f"invalid provenance: source_type={entry.source_type.value} "
                f"is not a trusted origin but was labeled trusted"
            )

    # -- queries -------------------------------------------------------------

    @property
    def observations(self) -> list[ProvenanceEntry]:
        return list(self._observations)

    def observations_for(self, field: str) -> list[ProvenanceEntry]:
        return [o for o in self._observations if o.field_path == field]

    def trusted_values(self, field: str) -> set[str]:
        return {o.value for o in self.observations_for(field) if o.is_trusted}

    # -- value-origin resolution --------------------------------------------

    def resolve_argument(self, field: str, proposed_value: Any) -> list[ProvenanceEntry]:
        """Resolve provenance for a *proposed* argument value.

        Returns entries whose ``field_path`` is ``args.<field>``:
        - a trusted entry iff some trusted source observed exactly this value;
        - an untrusted entry iff some untrusted source observed exactly this value;
        - a synthetic ``llm_inference`` entry iff no source observed it (model invented it).
        """
        target = f"args.{field}"
        proposed = str(proposed_value)
        matches = [o for o in self.observations_for(field) if o.value == proposed]
        trusted = [o for o in matches if o.is_trusted]
        untrusted = [o for o in matches if not o.is_trusted]

        entries: list[ProvenanceEntry] = []
        if trusted:
            best = max(trusted, key=lambda o: _TRUSTED_PRIORITY.get(o.source_type, 0))
            entries.append(best.model_copy(update={"field_path": target}))
        if untrusted:
            entries.append(untrusted[0].model_copy(update={"field_path": target}))
        if not matches:
            entries.append(
                ProvenanceEntry.observe(
                    field_path=target,
                    value=proposed,
                    source_type=SourceType.llm_inference,
                    source_id=f"llm_inference:{field}",
                    created_by="agent_model",
                    scenario_id=self.scenario_id,
                    evidence="value not observed from any recorded source",
                )
            )
        return entries

    def conflicts_for(self, field: str, proposed_value: Any) -> list[dict]:
        """Detect conflicting trusted assertions for a critical field.

        - Two+ trusted sources disagree on the value → ambiguity (routes to review).
        - A trusted source asserts a value different from the proposed one → the
          proposed value was substituted (attacker case; combined with untrusted
          provenance this denies).
        """
        proposed = str(proposed_value)
        tvals = self.trusted_values(field)
        if len(tvals) > 1:
            return [
                {
                    "field_path": f"args.{field}",
                    "reason": "multiple_trusted_values",
                    "trusted_values": sorted(tvals),
                    "proposed": proposed,
                }
            ]
        if tvals and proposed not in tvals:
            return [
                {
                    "field_path": f"args.{field}",
                    "reason": "proposed_differs_from_trusted",
                    "trusted_values": sorted(tvals),
                    "proposed": proposed,
                }
            ]
        return []

    # -- policy input export -------------------------------------------------

    def build_policy_input(self, action: str, args: dict[str, Any], *, risk_level: str = "high") -> dict:
        """Produce the deterministic OPA/native policy input document (FR-12)."""
        provenance: list[dict] = []
        for field in CRITICAL_FIELDS:
            if field in args:
                for entry in self.resolve_argument(field, args[field]):
                    provenance.append(self._entry_to_input(entry))

        conflicts: list[dict] = []
        if GATED_FIELD in args:
            conflicts = self.conflicts_for(GATED_FIELD, args[GATED_FIELD])

        return {
            "action": action,
            "risk_level": risk_level,
            "args": args,
            "provenance": provenance,
            "conflicts": conflicts,
        }

    # Backwards-friendly alias matching the PRD wording.
    export_opa_input = build_policy_input

    @staticmethod
    def _entry_to_input(entry: ProvenanceEntry) -> dict:
        return {
            "field_path": entry.field_path,
            "value": entry.value,
            "value_hash": entry.value_hash,
            "source_type": entry.source_type.value,
            "trust_level": entry.trust_level.value,
            "source_id": entry.source_id,
            "created_by": entry.created_by,
            "confidence": entry.confidence,
            "evidence": entry.evidence,
        }

    def to_trace(self) -> list[dict]:
        return [self._entry_to_input(o) for o in self._observations]

    def input_hash(self, policy_input: dict) -> str:
        return hash_value(policy_input)
