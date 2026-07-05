"""Real MCP-SDK transport (optional `mcp` extra).

Exposes the scenario's tools as a genuine MCP server and calls them over the real MCP
protocol via the SDK's in-memory client/server session — so attacks land over the actual
protocol (tool listing, JSON serialization, tool calls) without the flakiness of a
subprocess/stdio server. The default harness uses the in-process ToolRegistry; this is an
opt-in `--transport mcp` alternative that must produce identical outcomes.

The async MCP session runs on a dedicated background event loop; the anyio session context
is entered and exited inside a single long-lived task (releasing on a stop event) so its
task-group invariants hold, while `call()`/`list_tools()` submit work to that loop and
block for the result — giving the harness a synchronous client.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

from .tool_metadata import ToolResult
from .tool_registry import ToolRegistry

_JSON_TYPES = {"number": "number", "integer": "integer", "boolean": "boolean"}


def _json_schema(input_schema: dict[str, Any]) -> dict:
    props = {
        key: {"type": _JSON_TYPES.get(str(val), "string")} for key, val in input_schema.items()
    }
    return {"type": "object", "properties": props}


def build_mcp_server(registry: ToolRegistry):
    """Wrap a ToolRegistry as a real lowlevel MCP server."""
    import mcp.types as types
    from mcp.server.lowlevel import Server

    server = Server("policy-gated-mcp")

    @server.list_tools()
    async def _list_tools():
        return [
            types.Tool(
                name=m.name,
                description=m.description,
                inputSchema=_json_schema(m.input_schema),
            )
            for m in registry.metadata()
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict):
        result = registry.get(name).run(**arguments)
        # Wrap output + text in a JSON envelope so any output shape round-trips losslessly.
        envelope = json.dumps({"output": result.output, "text": result.text})
        return [types.TextContent(type="text", text=envelope)]

    return server


class MCPTransportClient:
    """Synchronous client over a real in-memory MCP session. Matches MCPClient's surface
    (list_tools / call) so the agent runtime is transport-agnostic."""

    def __init__(self, registry: ToolRegistry, *, timeout: float = 15.0) -> None:
        self._registry = registry
        self._timeout = timeout
        self._session = None
        self._stop: asyncio.Event | None = None
        self._ready = threading.Event()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._session_future = asyncio.run_coroutine_threadsafe(self._run_session(), self._loop)
        if not self._ready.wait(timeout=timeout):
            raise RuntimeError("MCP session did not become ready")

    async def _run_session(self) -> None:
        from mcp.shared.memory import create_connected_server_and_client_session

        server = build_mcp_server(self._registry)
        self._stop = asyncio.Event()
        async with create_connected_server_and_client_session(server) as session:
            self._session = session
            self._ready.set()
            await self._stop.wait()

    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=self._timeout)

    def list_tools(self):
        return self._run(self._session.list_tools()).tools

    def call(self, name: str, **kwargs) -> ToolResult:
        result = self._run(self._session.call_tool(name, kwargs))
        text = result.content[0].text if result.content else ""
        if getattr(result, "isError", False):
            return ToolResult(tool=name, output=None, text=text, error=text)
        payload = json.loads(text)
        return ToolResult(tool=name, output=payload["output"], text=payload.get("text", ""))

    def close(self) -> None:
        if self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
            try:
                self._session_future.result(timeout=self._timeout)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=self._timeout)

    def __enter__(self) -> MCPTransportClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:  # best-effort safety net if close() was not called
        try:
            if self._thread.is_alive():
                self.close()
        except Exception:  # noqa: BLE001
            pass
