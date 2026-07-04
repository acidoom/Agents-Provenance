"""Minimal MCP-like client. Lists tool metadata and calls tools by name.

A thin seam that a real `mcp`-SDK transport could later implement without changing the
agent runtime."""

from __future__ import annotations

from .tool_metadata import ToolMetadata, ToolResult
from .tool_registry import ToolRegistry


class MCPClient:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def list_tools(self) -> list[ToolMetadata]:
        return self.registry.metadata()

    def call(self, name: str, **kwargs) -> ToolResult:
        return self.registry.get(name).run(**kwargs)
