"""escrow_store.py — P10 §3.1

Persistent store for suspended tool calls (escrow entries).

E_escrow = (tool_call, args, context, D_hat, t_halt)

EscrowEntry  — immutable snapshot of a suspended tool call
EscrowStore  — in-memory CRUD + JSON file persistence (save / load)
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def _new_escrow_id() -> str:
    return uuid.uuid4().hex[:16]


@dataclass(frozen=True)
class EscrowEntry:
    """Immutable record of a tool call suspended at t_halt.

    escrow_id : opaque key (UUID4 hex[:16])
    tool_call : MCP tool name
    args      : original call arguments
    context   : session metadata (trace_hash, session_id, …)
    D_hat     : drift estimator at the moment of HALT
    t_halt    : ISO 8601 UTC timestamp of the HALT
    """

    escrow_id: str
    tool_call: str
    args: dict
    context: dict
    D_hat: float
    t_halt: str

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "escrow_id": self.escrow_id,
            "tool_call": self.tool_call,
            "args":      self.args,
            "context":   self.context,
            "D_hat":     self.D_hat,
            "t_halt":    self.t_halt,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict) -> "EscrowEntry":
        return cls(
            escrow_id=d["escrow_id"],
            tool_call=d["tool_call"],
            args=dict(d["args"]),
            context=dict(d["context"]),
            D_hat=float(d["D_hat"]),
            t_halt=d["t_halt"],
        )

    @classmethod
    def from_json(cls, s: str) -> "EscrowEntry":
        return cls.from_dict(json.loads(s))

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        tool_call: str,
        args: dict,
        context: dict,
        D_hat: float,
        t_halt: str,
        escrow_id: Optional[str] = None,
    ) -> "EscrowEntry":
        return cls(
            escrow_id=escrow_id if escrow_id is not None else _new_escrow_id(),
            tool_call=tool_call,
            args=args,
            context=context,
            D_hat=D_hat,
            t_halt=t_halt,
        )


class EscrowStore:
    """In-memory store for suspended tool calls, with JSON file persistence.

    put(entry)            — add or overwrite entry
    get(escrow_id)        — retrieve; KeyError if missing
    remove(escrow_id)     — pop and return; KeyError if missing
    list_entries()        — all entries as list
    save(path)            — dump store to JSON file (atomic write)
    load(path)            — load from JSON file (replaces current state)

    Thread-safety: not guaranteed; callers must coordinate if concurrent.
    """

    def __init__(self) -> None:
        self._store: dict[str, EscrowEntry] = {}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def put(self, entry: EscrowEntry) -> None:
        self._store[entry.escrow_id] = entry

    def get(self, escrow_id: str) -> EscrowEntry:
        """Raises KeyError if not found."""
        return self._store[escrow_id]

    def remove(self, escrow_id: str) -> EscrowEntry:
        """Removes and returns entry. Raises KeyError if not found."""
        return self._store.pop(escrow_id)

    def list_entries(self) -> list[EscrowEntry]:
        return list(self._store.values())

    def __len__(self) -> int:
        return len(self._store)

    def __contains__(self, escrow_id: str) -> bool:
        return escrow_id in self._store

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Serialize all entries to a JSON file (atomic overwrite)."""
        data = [entry.to_dict() for entry in self._store.values()]
        target = Path(path)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(target)

    def load(self, path: str | Path) -> None:
        """Replace current store state from a JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._store = {d["escrow_id"]: EscrowEntry.from_dict(d) for d in data}

    @classmethod
    def from_file(cls, path: str | Path) -> "EscrowStore":
        """Create a new EscrowStore loaded from a JSON file."""
        store = cls()
        store.load(path)
        return store
