"""
Trace model — τ ∈ Σ*
Formal object: execution trace as sequence of events.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, List
import json
import time
import uuid


@dataclass
class Event:
    agent: str                  # "A" | "B" | "C"
    action: str                 # "tool_call" | "delegation" | "response"
    tool: Optional[str]         # tool name (alphabet Σ)
    depth: int                  # delegation depth at this event
    metadata: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self):
        return asdict(self)


class Trace:
    def __init__(self, trace_id: str = None):
        self.trace_id = trace_id or str(uuid.uuid4())[:8]
        self.events: List[Event] = []

    def add(self, event: Event):
        self.events.append(event)

    def tools(self) -> List[str]:
        return [e.tool for e in self.events if e.tool is not None]

    def depths(self) -> List[int]:
        return [e.depth for e in self.events]

    def __len__(self):
        return len(self.events)

    def to_dict(self):
        return {
            "trace_id": self.trace_id,
            "length": len(self.events),
            "events": [e.to_dict() for e in self.events]
        }

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
