#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Toy MCP Server — 5 deterministic tools matching the P7/P8 governance stack.

Exposes the same 5 tools used in the IML/RAM/Recovery experiments:
  read_file        risk 0.10
  query_api        risk 0.25
  write_data       risk 0.45
  delete_record    risk 0.70
  admin_action     risk 0.90

Each tool returns a deterministic mock result. The server speaks MCP over
stdio. Used by P9 Sprint 0 smoke test and by the Exp E1/E2/E3/E4 setups.
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("p9-toy-server")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file by path. Safest tool (risk 0.10)."""
    return f"[mock] contents of {path}"


@mcp.tool()
def query_api(endpoint: str) -> str:
    """Query an external API (risk 0.25)."""
    return f"[mock] {{'endpoint': '{endpoint}', 'status': 200, 'data': 'ok'}}"


@mcp.tool()
def write_data(target: str, payload: str) -> str:
    """Write or patch data to storage (risk 0.45)."""
    return f"[mock] wrote {len(payload)} bytes to {target}"


@mcp.tool()
def delete_record(record_id: str) -> str:
    """Permanently delete a record (risk 0.70)."""
    return f"[mock] deleted record {record_id}"


@mcp.tool()
def admin_action(action: str) -> str:
    """Privileged system-level operation (risk 0.90)."""
    return f"[mock] admin executed: {action}"


if __name__ == "__main__":
    mcp.run()
