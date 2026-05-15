# -*- coding: utf-8 -*-
"""
Async stdio transport helpers for MCP JSON-RPC.

MCP stdio transport sends each message as a single JSON object terminated
by a newline (\\n). These helpers wrap asyncio StreamReader/StreamWriter
to provide a clean message-level interface.

Used by GoverningProxy when doing raw stream interception (Sprint 3+).
For Sprint 1 the FastMCP-based server handles framing internally; these
helpers are exposed for completeness and E1/E3 experiments.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any


async def read_message(reader: asyncio.StreamReader) -> dict[str, Any] | None:
    """Read one JSON-RPC message from `reader`.

    Returns the parsed dict, or None on EOF.
    Raises json.JSONDecodeError if the line is not valid JSON.
    """
    try:
        line = await reader.readline()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return None
    if not line:
        return None
    return json.loads(line.decode("utf-8").rstrip("\n"))


async def write_message(
    writer: asyncio.StreamWriter, msg: dict[str, Any]
) -> None:
    """Write one JSON-RPC message to `writer` (newline-terminated)."""
    payload = json.dumps(msg, separators=(",", ":")) + "\n"
    writer.write(payload.encode("utf-8"))
    await writer.drain()


async def pipe_messages(
    src: asyncio.StreamReader,
    dst: asyncio.StreamWriter,
    *,
    filter_fn: Any = None,
) -> None:
    """Forward messages from `src` to `dst` until EOF.

    If `filter_fn` is provided it receives each parsed dict and must
    return the (possibly modified) dict to forward, or None to drop.
    """
    while True:
        msg = await read_message(src)
        if msg is None:
            break
        if filter_fn is not None:
            msg = filter_fn(msg)
            if msg is None:
                continue
        await write_message(dst, msg)
