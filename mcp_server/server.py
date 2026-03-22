"""MCP server — stdio transport for Claude Code, Cursor, Windsurf, etc.

Implements the Model Context Protocol (MCP) over stdin/stdout using
JSON-RPC 2.0 messages. No external MCP SDK required.

Protocol flow:
1. Client sends `initialize` → server returns capabilities + tools
2. Client sends `tools/list` → server returns tool definitions
3. Client sends `tools/call` → server executes tool and returns result
"""

from __future__ import annotations

import json
import sys
from typing import Any

import structlog

from mcp_server.schemas import get_tool_definitions
from mcp_server.tools import ToolHandlers

log = structlog.get_logger("mcp_server")

SERVER_INFO = {
    "name": "agentic-ai-security",
    "version": "0.1.0",
}

CAPABILITIES = {
    "tools": {},
}


class MCPServer:
    """MCP server over stdio transport (JSON-RPC 2.0)."""

    def __init__(self, rules_dir: str = "rules") -> None:
        self.handlers = ToolHandlers(rules_dir)
        self._running = False

    def run(self) -> None:
        """Main server loop — reads JSON-RPC from stdin, writes to stdout."""
        self._running = True
        log.info("mcp_server_starting")

        while self._running:
            try:
                line = sys.stdin.readline()
                if not line:
                    break  # EOF

                line = line.strip()
                if not line:
                    continue

                request = json.loads(line)
                response = self._handle_request(request)

                if response is not None:
                    self._send(response)

            except json.JSONDecodeError as e:
                self._send_error(None, -32700, f"Parse error: {e}")
            except KeyboardInterrupt:
                break
            except Exception as e:
                log.error("server_error", error=str(e))
                self._send_error(None, -32603, f"Internal error: {e}")

        log.info("mcp_server_stopped")

    def _handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Handle a single JSON-RPC request."""
        method = request.get("method", "")
        params = request.get("params", {})
        req_id = request.get("id")

        match method:
            # ── Lifecycle ──────────────────────────────────────────────
            case "initialize":
                return self._result(req_id, {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": SERVER_INFO,
                    "capabilities": CAPABILITIES,
                })

            case "initialized":
                return None  # Notification, no response

            case "shutdown":
                self._running = False
                return self._result(req_id, {})

            # ── Tools ─────────────────────────────────────────────────
            case "tools/list":
                tools = get_tool_definitions()
                return self._result(req_id, {"tools": tools})

            case "tools/call":
                tool_name = params.get("name", "")
                arguments = params.get("arguments", {})

                log.info("tool_call", tool=tool_name)
                result = self.handlers.handle(tool_name, arguments)

                # MCP tools/call returns content array
                if "error" in result:
                    return self._result(req_id, {
                        "content": [{"type": "text", "text": json.dumps(result)}],
                        "isError": True,
                    })

                return self._result(req_id, {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                })

            # ── Resources / Prompts (not implemented) ──────────────────
            case "resources/list":
                return self._result(req_id, {"resources": []})

            case "prompts/list":
                return self._result(req_id, {"prompts": []})

            # ── Ping ───────────────────────────────────────────────────
            case "ping":
                return self._result(req_id, {})

            # ── Unknown ────────────────────────────────────────────────
            case _:
                return self._send_error(req_id, -32601, f"Method not found: {method}")

    def _result(self, req_id: Any, result: Any) -> dict[str, Any]:
        """Build a JSON-RPC success response."""
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }

    def _send_error(self, req_id: Any, code: int, message: str) -> dict[str, Any]:
        """Build a JSON-RPC error response."""
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }

    def _send(self, response: dict[str, Any]) -> None:
        """Write a JSON-RPC response to stdout."""
        output = json.dumps(response)
        sys.stdout.write(output + "\n")
        sys.stdout.flush()


def run_server(rules_dir: str = "rules") -> None:
    """Entry point to start the MCP server."""
    server = MCPServer(rules_dir)
    server.run()
