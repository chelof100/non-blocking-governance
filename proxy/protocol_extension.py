# -*- coding: utf-8 -*-
"""
P9 Protocol Extension — custom JSON-RPC messages for APB governance.

Three message types extend the MCP protocol:

  p9/apbRequired  (proxy → client, notification)
      Sent when a tool call triggers a persistent governance HALT.
      Proxy cannot forward the tool call until the client responds.

  p9/apbResponse  (client → proxy, notification)
      Client provides a signed APB for the pending governance event
      identified by evidence_id.

  p9/apbRejected  (proxy → client, notification)
      Proxy rejects the APB if it fails V1-V4 verification.
      The client may retry with a corrected APB.

Transparency invariance (T9.1): standard MCP clients that do not
implement this extension will ignore these notifications and see the
blocked tool call as an error. Agent behaviour is observationally
equivalent on the non-HALT path regardless.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

_VERSION = "p9/1.0"

_METHOD_MAP: dict[str, type] = {}   # populated at module load via _register


def _register(cls: type) -> type:
    _METHOD_MAP[cls._METHOD] = cls  # type: ignore[attr-defined]
    return cls


# ---------------------------------------------------------------------------
# APBRequired  (proxy → client)
# ---------------------------------------------------------------------------

@_register
@dataclass
class APBRequired:
    """Proxy → client: governance HALT, APB needed before tool executes."""

    _METHOD = "p9/apbRequired"

    tool_name: str
    args: dict[str, Any]
    evidence_id: str
    evidence_summary: dict[str, Any]   # serialized SystemEvidenceBlock
    version: str = field(default=_VERSION, init=False, compare=False)

    def to_jsonrpc(self) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "method": self._METHOD,
            "params": {
                "version": self.version,
                "evidence_id": self.evidence_id,
                "tool_name": self.tool_name,
                "args": self.args,
                "evidence_summary": self.evidence_summary,
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_jsonrpc())

    @classmethod
    def from_jsonrpc(cls, msg: dict[str, Any]) -> "APBRequired":
        p = msg["params"]
        return cls(
            tool_name=p["tool_name"],
            args=p["args"],
            evidence_id=p["evidence_id"],
            evidence_summary=p["evidence_summary"],
        )


# ---------------------------------------------------------------------------
# APBResponse  (client → proxy)
# ---------------------------------------------------------------------------

@_register
@dataclass
class APBResponse:
    """Client → proxy: signed APB in response to APBRequired."""

    _METHOD = "p9/apbResponse"

    evidence_id: str
    apb_json: str   # APB.to_json() output

    def to_jsonrpc(self) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "method": self._METHOD,
            "params": {
                "evidence_id": self.evidence_id,
                "apb_json": self.apb_json,
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_jsonrpc())

    @classmethod
    def from_jsonrpc(cls, msg: dict[str, Any]) -> "APBResponse":
        p = msg["params"]
        return cls(
            evidence_id=p["evidence_id"],
            apb_json=p["apb_json"],
        )


# ---------------------------------------------------------------------------
# APBRejected  (proxy → client)
# ---------------------------------------------------------------------------

@_register
@dataclass
class APBRejected:
    """Proxy → client: APB rejected (V1-V4 failure). Client may retry."""

    _METHOD = "p9/apbRejected"

    evidence_id: str
    reason: str

    def to_jsonrpc(self) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "method": self._METHOD,
            "params": {
                "evidence_id": self.evidence_id,
                "reason": self.reason,
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_jsonrpc())

    @classmethod
    def from_jsonrpc(cls, msg: dict[str, Any]) -> "APBRejected":
        p = msg["params"]
        return cls(
            evidence_id=p["evidence_id"],
            reason=p["reason"],
        )


# ---------------------------------------------------------------------------
# Dispatch helper
# ---------------------------------------------------------------------------

def parse_p9_message(
    msg: dict[str, Any],
) -> APBRequired | APBResponse | APBRejected | None:
    """Parse a P9 extension message. Returns None for non-P9 messages."""
    method = msg.get("method", "")
    cls = _METHOD_MAP.get(method)
    if cls is None:
        return None
    return cls.from_jsonrpc(msg)
