# -*- coding: utf-8 -*-
"""
GoverningProxy — P9 MCP proxy server entry point.

Wraps an MCP server (default: proxy/toy_server.py) with the P7+P8
governance stack. Exposes the same tools to the upstream MCP client,
intercepting each tool call through MCPInterceptor before forwarding.

Sprint 1 behaviour on governance HALT:
  The tool response encodes the governance outcome as a structured
  string (GOVERNANCE_HALT / GOVERNANCE_DENY). Sprint 4 will replace
  this with a proper out-of-band APBRequired notification sent to the
  client before the tool response is delivered.

Usage:
  python -m proxy.governed_server                           # default server
  python -m proxy.governed_server --server proxy/toy_server.py
  python -m proxy.governed_server --server path/to/server.py --agent H1
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

# Ensure project root is on the path when run as __main__
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mcp import StdioServerParameters
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP

from agent.principal import PrincipalRegistry, generate_keypair, Principal
from proxy.mcp_interceptor import MCPInterceptor
from proxy.protocol_extension import APBRequired


# ---------------------------------------------------------------------------
# Default principal for the governed session (demo / tests)
# ---------------------------------------------------------------------------

def _default_registry() -> tuple[PrincipalRegistry, str, bytes]:
    """Build a single-principal registry for demo use.

    Returns (registry, H_id, private_key_bytes).
    In production, the registry would be loaded from a trust store.
    """
    from datetime import datetime, timezone
    sk_bytes, pk_bytes = generate_keypair()
    H_id = "H_demo"
    principal = Principal(
        H_id=H_id,
        public_key=pk_bytes,
        registered_at=datetime.now(timezone.utc).isoformat(),
    )
    registry = PrincipalRegistry()
    registry.add(principal)
    return registry, H_id, sk_bytes


# ---------------------------------------------------------------------------
# Governed tool call helper
# ---------------------------------------------------------------------------

async def _governed_call(
    session: ClientSession,
    interceptor: MCPInterceptor,
    tool_name: str,
    args: dict,
) -> str:
    """Run governance check then forward to the real server (or halt)."""
    decision, payload = interceptor.intercept_tool_call(tool_name, args)

    if decision == "ADMIT":
        result = await session.call_tool(tool_name, args)
        return "".join(getattr(c, "text", "") for c in result.content)

    if decision == "APB_REQUIRED":
        apb_req: APBRequired = payload
        # Sprint 1: encode halt in the tool result.
        # Sprint 4 will send p9/apbRequired out-of-band and await response.
        D = apb_req.evidence_summary.get("D_hat", 0.0)
        cause = apb_req.evidence_summary.get("cause", "?")
        return (
            f"[GOVERNANCE_HALT] "
            f"evidence_id={apb_req.evidence_id} "
            f"cause={cause} "
            f"D_hat={D:.3f}"
        )

    # DENY
    return f"[GOVERNANCE_DENY] {payload}"


# ---------------------------------------------------------------------------
# GoverningProxy
# ---------------------------------------------------------------------------

class GoverningProxy:
    """MCP proxy: wraps a real MCP server with P9 governance.

    For Sprint 1, hardcodes the five P7 tools from toy_server.py.
    Sprint 3 will add dynamic tool discovery and mirroring.
    """

    def __init__(
        self,
        server_path: str,
        interceptor: MCPInterceptor,
    ) -> None:
        self.server_path = server_path
        self.interceptor = interceptor

    async def run(self) -> None:
        """Start the proxy. Blocks until the upstream client disconnects."""
        params = StdioServerParameters(
            command=sys.executable,
            args=[self.server_path],
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                self.interceptor.reset()
                proxy = self._build_fastmcp(session)
                await proxy.run_async(transport="stdio")

    def _build_fastmcp(self, session: ClientSession) -> FastMCP:
        """Build a FastMCP server mirroring the real server's 5 tools."""
        proxy = FastMCP("p9-governed-proxy")
        interceptor = self.interceptor

        @proxy.tool()
        async def read_file(path: str) -> str:
            """Read a file by path."""
            return await _governed_call(
                session, interceptor, "read_file", {"path": path}
            )

        @proxy.tool()
        async def query_api(endpoint: str) -> str:
            """Query an external API."""
            return await _governed_call(
                session, interceptor, "query_api", {"endpoint": endpoint}
            )

        @proxy.tool()
        async def write_data(target: str, payload: str) -> str:
            """Write or patch data to storage."""
            return await _governed_call(
                session, interceptor, "write_data",
                {"target": target, "payload": payload},
            )

        @proxy.tool()
        async def delete_record(record_id: str) -> str:
            """Permanently delete a record."""
            return await _governed_call(
                session, interceptor, "delete_record", {"record_id": record_id}
            )

        @proxy.tool()
        async def admin_action(action: str) -> str:
            """Privileged system-level operation."""
            return await _governed_call(
                session, interceptor, "admin_action", {"action": action}
            )

        return proxy


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="P9 governed MCP proxy")
    p.add_argument(
        "--server",
        default=os.path.join(_ROOT, "proxy", "toy_server.py"),
        help="Path to the real MCP server script (default: proxy/toy_server.py)",
    )
    p.add_argument(
        "--agent",
        default="H_demo",
        help="Principal H_id to use for governance (default: H_demo)",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    registry, H_id, _sk = _default_registry()
    interceptor = MCPInterceptor(registry=registry, H_id=H_id)
    proxy = GoverningProxy(server_path=args.server, interceptor=interceptor)
    asyncio.run(proxy.run())


if __name__ == "__main__":
    main()
