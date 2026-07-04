"""Provenance data model: source types, trust levels, and immutable observations.

A ProvenanceEntry answers "where did this exact value come from, and how much do we
trust that origin?". Entries are *recorded by trusted harness components only* (the
extractor, the verified DB, the tool layer). The language model never constructs a
ProvenanceEntry, which is what structurally prevents it from minting trust (FR-10).
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .hashing import hash_value


class SourceType(str, Enum):
    user_request = "user_request"
    trusted_extractor = "trusted_extractor"
    verified_database = "verified_database"
    mcp_tool_metadata = "mcp_tool_metadata"
    mcp_tool_output_untrusted = "mcp_tool_output_untrusted"
    llm_inference = "llm_inference"
    human_approval = "human_approval"
    test_fixture = "test_fixture"
    unknown = "unknown"


class TrustLevel(str, Enum):
    trusted = "trusted"
    untrusted = "untrusted"
    derived = "derived"
    ambiguous = "ambiguous"
    unknown = "unknown"


#: Source types that count as a *trusted origin* for a critical value (e.g. account number).
TRUSTED_SOURCE_TYPES: frozenset[SourceType] = frozenset(
    {SourceType.trusted_extractor, SourceType.verified_database, SourceType.human_approval}
)

#: Source types that are never sufficient authority for a high-impact critical value.
UNTRUSTED_SOURCE_TYPES: frozenset[SourceType] = frozenset(
    {
        SourceType.mcp_tool_metadata,
        SourceType.mcp_tool_output_untrusted,
        SourceType.llm_inference,
        SourceType.unknown,
    }
)

#: Default trust level attached when a value is *observed* from a given source type.
DEFAULT_TRUST: dict[SourceType, TrustLevel] = {
    SourceType.user_request: TrustLevel.untrusted,
    SourceType.trusted_extractor: TrustLevel.trusted,
    SourceType.verified_database: TrustLevel.trusted,
    SourceType.mcp_tool_metadata: TrustLevel.untrusted,
    SourceType.mcp_tool_output_untrusted: TrustLevel.untrusted,
    SourceType.llm_inference: TrustLevel.untrusted,
    SourceType.human_approval: TrustLevel.trusted,
    SourceType.test_fixture: TrustLevel.trusted,
    SourceType.unknown: TrustLevel.unknown,
}


class ProvenanceEntry(BaseModel):
    """One observation of a value at a field path, tagged with its origin and trust."""

    model_config = ConfigDict(frozen=False, extra="forbid")

    field_path: str
    value: str
    value_hash: str = ""
    source_type: SourceType
    source_id: str
    trust_level: TrustLevel
    created_by: str
    scenario_id: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: str = ""

    @model_validator(mode="after")
    def _ensure_hash(self) -> "ProvenanceEntry":
        if not self.value_hash:
            self.value_hash = hash_value(self.value)
        return self

    @classmethod
    def observe(
        cls,
        *,
        field_path: str,
        value: Any,
        source_type: SourceType,
        source_id: str,
        created_by: str,
        scenario_id: str = "",
        trust_level: TrustLevel | None = None,
        confidence: float = 1.0,
        evidence: str = "",
    ) -> "ProvenanceEntry":
        """Record an observation, defaulting trust from the source type."""
        return cls(
            field_path=field_path,
            value=str(value),
            source_type=source_type,
            source_id=source_id,
            trust_level=trust_level or DEFAULT_TRUST[source_type],
            created_by=created_by,
            scenario_id=scenario_id,
            confidence=confidence,
            evidence=evidence,
        )

    @property
    def is_trusted(self) -> bool:
        return self.trust_level == TrustLevel.trusted and self.source_type in TRUSTED_SOURCE_TYPES
