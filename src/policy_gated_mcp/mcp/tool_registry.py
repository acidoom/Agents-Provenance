"""In-process tool registry (FR-5).

Holds tools, exposes their metadata to the agent, and runs them. The high-impact
tool is marked ``risk_level="high"``; the agent runtime must route such calls through
the policy gate rather than executing them directly.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .tool_metadata import ToolMetadata, ToolResult

ToolFunc = Callable[..., ToolResult]


@dataclass
class Tool:
    metadata: ToolMetadata
    func: ToolFunc

    @property
    def name(self) -> str:
        return self.metadata.name

    def run(self, **kwargs) -> ToolResult:
        return self.func(**kwargs)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        return self._tools[name]

    def has(self, name: str) -> bool:
        return name in self._tools

    @property
    def names(self) -> list[str]:
        return list(self._tools)

    def metadata(self) -> list[ToolMetadata]:
        """Tool metadata as shown to the agent (descriptions may be poisoned)."""
        return [t.metadata for t in self._tools.values()]
