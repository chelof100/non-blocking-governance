"""timeout_policy.py — P10 §3.2

Timeout enforcement and V6 predicate for escrow entries.

FallbackMode  — what to do when T_timeout expires without APB
TimeoutPolicy — TTL configuration + expiry check + fallback resolution
v6_check()    — standalone V6 predicate: τ_apb ≤ t_halt + T_timeout
               (imported by apb_verifier in Sprint 2+)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional

from escrow.escrow_store import EscrowEntry


def _parse_iso(s: str) -> datetime:
    """Parse ISO 8601 UTC string → timezone-aware datetime."""
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# FallbackMode
# ---------------------------------------------------------------------------

class FallbackMode(str, Enum):
    """Action taken when T_timeout expires without a valid APB.

    DENY     — do not execute; preserves "no authority, no action" (default)
    ADMIT    — execute accepting risk; only for low-risk tools
    ESCALATE — route to backup principal for out-of-band resolution
    """
    DENY     = "DENY"
    ADMIT    = "ADMIT"
    ESCALATE = "ESCALATE"


# ---------------------------------------------------------------------------
# TimeoutPolicy
# ---------------------------------------------------------------------------

@dataclass
class TimeoutPolicy:
    """TTL configuration for a suspended escrow entry.

    T_timeout : seconds from t_halt before fallback is triggered
    fallback  : action when timeout fires (default: DENY)
    """

    T_timeout: float
    fallback: FallbackMode = FallbackMode.DENY

    def is_expired(
        self,
        entry: EscrowEntry,
        now: Optional[datetime] = None,
    ) -> bool:
        """True if (now − t_halt) > T_timeout."""
        if now is None:
            now = _now_utc()
        t_halt = _parse_iso(entry.t_halt)
        deadline = t_halt + timedelta(seconds=self.T_timeout)
        return now > deadline

    def apply_fallback(self, entry: EscrowEntry) -> FallbackMode:
        """Return the configured fallback mode (entry provided for future policy hooks)."""
        return self.fallback


# ---------------------------------------------------------------------------
# V6 predicate (standalone — imported by apb_verifier in Sprint 2+)
# ---------------------------------------------------------------------------

def v6_check(apb_t_e: str, t_halt: str, T_timeout: float) -> bool:
    """V6 predicate: τ_apb ≤ t_halt + T_timeout.

    Returns True  — APB was signed before the escrow deadline; accept.
    Returns False — APB arrived after timeout; reject even if V1-V5 pass.

    Boundary is inclusive (≤): an APB signed exactly at t_halt + T_timeout
    is still valid.

    Args:
        apb_t_e   : APB signing timestamp (ISO 8601 UTC string, from E_s.t_e)
        t_halt    : escrow entry HALT timestamp (ISO 8601 UTC string)
        T_timeout : allowed window in seconds
    """
    tau_apb  = _parse_iso(apb_t_e)
    deadline = _parse_iso(t_halt) + timedelta(seconds=T_timeout)
    return tau_apb <= deadline
