"""MCP-like tool metadata and results.

This is the in-process abstraction that preserves MCP semantics (name, description,
input schema, source/transport, trust) without requiring the real MCP SDK. A real
`mcp`-SDK transport adapter is a documented fast-follow; the evaluation harness never
depends on external servers.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..provenance.models import SourceType, TrustLevel


class ToolMetadata(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=dict)
    source: str  # which "server"/provider exposed this tool
    transport: str = "in_process"
    # Tool metadata is untrusted by default (PRD §21.2) unless explicitly allow-listed.
    trust: TrustLevel = TrustLevel.untrusted
    risk_level: str = "low"


class ToolResult(BaseModel):
    tool: str
    output: Any = None
    text: str = ""  # a scannable text rendering of the output
    source_type: SourceType = SourceType.mcp_tool_output_untrusted
    trust_level: TrustLevel = TrustLevel.untrusted
    error: str | None = None
