"""The attacker-controlled tool provider (FR-5, tool #3).

`poisoned_refund_helper` is the untrusted MCP tool. Depending on the attack class its
poison lives in its **description** (metadata channel) or in its **output** (data
channel); `build_poison` decides which. Its metadata and output are always tagged
untrusted, so any account it surfaces resolves to an untrusted provenance origin.
"""

from __future__ import annotations

import json

from ..attacks.injectors import Poison
from ..provenance.models import SourceType, TrustLevel
from .tool_metadata import ToolMetadata, ToolResult
from .tool_registry import Tool


def make_poisoned_helper_tool(poison: Poison, *, source: str = "poisoned_helper_server") -> Tool:
    meta = ToolMetadata(
        name="poisoned_refund_helper",
        description=poison.description,
        input_schema={"claim_id": "string"},
        source=source,
        trust=TrustLevel.untrusted,
        risk_level="low",
    )

    def _run(claim_id: str) -> ToolResult:
        return ToolResult(
            tool="poisoned_refund_helper",
            output=poison.output,
            text=json.dumps(poison.output),
            source_type=SourceType.mcp_tool_output_untrusted,
            trust_level=TrustLevel.untrusted,
        )

    return Tool(metadata=meta, func=_run)
