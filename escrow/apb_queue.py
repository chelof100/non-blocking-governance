"""apb_queue.py — P10 §3.3

Deferred approval queue for pending governance decisions.

APBQueue
  • Priority   : D_hat DESC (highest risk first), then t_halt ASC (oldest first)
  • Dedup      : by event_id — same governance event cannot be enqueued twice
  • Resolution : V1-V5 (verify_apb) + V6 (v6_check) before any RESUME/DENY
  • Persistence: save/load to JSON — supports multi-session APB resolution

Custom exceptions
  DuplicateEventError  — event_id already in the queue
  APBVerificationError — V1-V5 check failed
  TimeoutExpiredError  — V6 check failed (APB signed after t_halt + T_timeout)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from agent.principal import PrincipalRegistry
from escrow.escrow_store import EscrowEntry, EscrowStore
from escrow.timeout_policy import FallbackMode, TimeoutPolicy, v6_check
from stack.apb import APB, GovernanceDecision
from stack.apb_verifier import verify_apb


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DuplicateEventError(Exception):
    """Same governance event enqueued twice (same event_id)."""
    def __init__(self, event_id: str) -> None:
        super().__init__(f"event_id {event_id!r} already in queue")
        self.event_id = event_id


class APBVerificationError(Exception):
    """APB failed V1-V5 verification."""
    def __init__(self, result: str, detail: str) -> None:
        super().__init__(f"APB verification failed [{result}]: {detail}")
        self.result = result
        self.detail = detail


class TimeoutExpiredError(Exception):
    """APB arrived after the escrow deadline — V6 predicate failed."""
    def __init__(self, escrow_id: str, apb_t_e: str, deadline: str) -> None:
        super().__init__(
            f"V6 failed for escrow {escrow_id!r}: "
            f"APB signed at {apb_t_e!r}, deadline was {deadline!r}"
        )
        self.escrow_id = escrow_id
        self.apb_t_e = apb_t_e
        self.deadline = deadline


# ---------------------------------------------------------------------------
# Priority key
# ---------------------------------------------------------------------------

def _priority_key(entry: EscrowEntry):
    """Sort key: D_hat DESC (negate), t_halt ASC (oldest first)."""
    t = datetime.fromisoformat(entry.t_halt.replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return (-entry.D_hat, t)


# ---------------------------------------------------------------------------
# APBQueue
# ---------------------------------------------------------------------------

class APBQueue:
    """Priority queue of pending governance decisions.

    Thread-safety: not guaranteed; callers must coordinate if concurrent.

    Internal state:
      _store               : EscrowStore — holds all pending EscrowEntries
      _event_to_escrow     : dict[event_id, escrow_id] — enqueue dedup
      _escrow_to_event     : dict[escrow_id, event_id] — O(1) cleanup on resolve
      _resolved_event_ids  : set[event_id] — V5 replay defense across calls
    """

    def __init__(self, store: Optional[EscrowStore] = None) -> None:
        self._store: EscrowStore = store if store is not None else EscrowStore()
        self._event_to_escrow: dict[str, str] = {}
        self._escrow_to_event: dict[str, str] = {}
        self._resolved_event_ids: set[str] = set()

    # ------------------------------------------------------------------
    # Enqueue
    # ------------------------------------------------------------------

    def enqueue(self, entry: EscrowEntry, event_id: str) -> str:
        """Add entry to the queue. Returns escrow_id.

        Raises DuplicateEventError if event_id is already pending.
        """
        if event_id in self._event_to_escrow:
            raise DuplicateEventError(event_id)
        self._store.put(entry)
        self._event_to_escrow[event_id] = entry.escrow_id
        self._escrow_to_event[entry.escrow_id] = event_id
        return entry.escrow_id

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def peek(self) -> Optional[EscrowEntry]:
        """Return highest-priority pending entry without removing it."""
        entries = self._store.list_entries()
        if not entries:
            return None
        return min(entries, key=_priority_key)

    def list_pending(self) -> list[EscrowEntry]:
        """All pending entries ordered by priority (highest risk first)."""
        return sorted(self._store.list_entries(), key=_priority_key)

    def __len__(self) -> int:
        return len(self._store)

    def __contains__(self, escrow_id: str) -> bool:
        return escrow_id in self._store

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(
        self,
        escrow_id: str,
        apb: APB,
        registry: PrincipalRegistry,
        policy: TimeoutPolicy,
        max_age_seconds: float = 300.0,
    ) -> tuple[GovernanceDecision, EscrowEntry]:
        """Verify APB (V1-V6) and resolve the pending entry.

        Returns (GovernanceDecision, EscrowEntry) on success.

        Raises:
          KeyError              — escrow_id not in queue
          APBVerificationError  — V1-V5 failed
          TimeoutExpiredError   — V6 failed (APB arrived after deadline)
        """
        entry = self._store.get(escrow_id)   # KeyError if missing

        # V1-V5: existing verifier (stack/apb_verifier.py — frozen from P9)
        report = verify_apb(
            apb,
            registry,
            max_age_seconds=max_age_seconds,
            seen_event_ids=self._resolved_event_ids,
        )
        if not report.is_valid:
            raise APBVerificationError(report.result.value, report.detail)

        # V6: τ_apb ≤ t_halt + T_timeout
        if not v6_check(apb.E_s.t_e, entry.t_halt, policy.T_timeout):
            deadline_dt = (
                datetime.fromisoformat(entry.t_halt.replace("Z", "+00:00"))
                + timedelta(seconds=policy.T_timeout)
            )
            raise TimeoutExpiredError(escrow_id, apb.E_s.t_e, deadline_dt.isoformat())

        # All checks passed — remove from queue
        self._store.remove(escrow_id)
        event_id = self._escrow_to_event.pop(escrow_id, None)
        if event_id is not None:
            self._event_to_escrow.pop(event_id, None)
        # _resolved_event_ids already updated by verify_apb (passed as seen_event_ids)

        return GovernanceDecision(apb.D_h.decision), entry

    # ------------------------------------------------------------------
    # Timeout sweep
    # ------------------------------------------------------------------

    def apply_timeouts(
        self,
        policy: TimeoutPolicy,
        now: Optional[datetime] = None,
    ) -> list[tuple[EscrowEntry, FallbackMode]]:
        """Remove and return all expired entries with their fallback action.

        Does not modify entries that are still within TTL.
        """
        expired: list[tuple[EscrowEntry, FallbackMode]] = []
        for entry in list(self._store.list_entries()):   # snapshot to allow removal
            if policy.is_expired(entry, now=now):
                fallback = policy.apply_fallback(entry)
                self._store.remove(entry.escrow_id)
                event_id = self._escrow_to_event.pop(entry.escrow_id, None)
                if event_id is not None:
                    self._event_to_escrow.pop(event_id, None)
                expired.append((entry, fallback))
        return expired

    # ------------------------------------------------------------------
    # Persistence (multi-session APB resolution — P10 §3.3)
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Persist queue state to JSON (atomic overwrite)."""
        data = {
            "entries":             [e.to_dict() for e in self._store.list_entries()],
            "event_to_escrow":     self._event_to_escrow,
            "escrow_to_event":     self._escrow_to_event,
            "resolved_event_ids":  list(self._resolved_event_ids),
        }
        target = Path(path)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(target)

    def load(self, path: str | Path) -> None:
        """Replace current queue state from a JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._store = EscrowStore()
        for d in data["entries"]:
            self._store.put(EscrowEntry.from_dict(d))
        self._event_to_escrow    = data.get("event_to_escrow", {})
        self._escrow_to_event    = data.get("escrow_to_event", {})
        self._resolved_event_ids = set(data.get("resolved_event_ids", []))

    @classmethod
    def from_file(cls, path: str | Path) -> "APBQueue":
        """Create a new APBQueue loaded from a JSON file."""
        q = cls()
        q.load(path)
        return q
