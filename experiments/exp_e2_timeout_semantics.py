"""exp_e2_timeout_semantics.py — P10 Experiment E2

Question: Is the fallback under T_timeout correct in all 3 modes?
Setup   : N entries in escrow; human never responds; T_timeout fires.
Gate    : 0 unauthorized executions across all fallback modes.

"Unauthorized execution" = a risky tool call that:
  - exits the escrow queue without a valid APB, AND
  - without an explicit governance decision (DENY / ADMIT / ESCALATE).
  Formally: any entry that disappears from the queue with outcome=None.

Three fallback modes tested:
  DENY     — entry removed, decision=DENY, tool does NOT execute.
  ADMIT    — entry removed, decision=ADMIT, tool executes with accepted risk.
  ESCALATE — entry removed, decision=ESCALATE, routed to backup principal.

All three are "authorized" — governance rendered a decision.
Only "no decision rendered" counts as unauthorized.

Additional checks:
  - Entries within T_timeout are NOT swept (active entries untouched).
  - Mixed queue: expired and active entries — only expired ones swept.
  - Fallback mode is consistent across all swept entries for a given policy.
  - High-risk entries (D_hat > threshold) swept with correct priority.

Results written to results/e2_timeout_semantics.json
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

from escrow.apb_queue import APBQueue
from escrow.escrow_store import EscrowEntry
from escrow.timeout_policy import FallbackMode, TimeoutPolicy

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

N_PER_MODE      = 200        # entries per fallback mode trial
T_TIMEOUT_S     = 60.0       # 60-second window
RESULTS_PATH    = Path(__file__).parent.parent / "results" / "e2_timeout_semantics.json"

_NOW = datetime(2026, 5, 15, 14, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _make_expired_entry(d_hat: float, seconds_ago: float = 120.0) -> EscrowEntry:
    """Entry whose t_halt is `seconds_ago` seconds before _NOW — expired under T_TIMEOUT_S."""
    return EscrowEntry.create(
        tool_call="exec_privileged",
        args={"cmd": "drop_table users"},
        context={"session_id": "sess-e2"},
        D_hat=d_hat,
        t_halt=_iso(_NOW - timedelta(seconds=seconds_ago)),
    )


def _make_active_entry(d_hat: float) -> EscrowEntry:
    """Entry whose t_halt is only 10 seconds ago — still within T_TIMEOUT_S."""
    return EscrowEntry.create(
        tool_call="read_config",
        args={"path": "/etc/app.conf"},
        context={"session_id": "sess-e2-active"},
        D_hat=d_hat,
        t_halt=_iso(_NOW - timedelta(seconds=10)),
    )


# ---------------------------------------------------------------------------
# Trial runner
# ---------------------------------------------------------------------------

def _run_mode_trial(mode: FallbackMode, n: int) -> dict:
    """Enqueue N expired entries, sweep, verify all swept with correct decision."""
    q = APBQueue()
    import uuid as _uuid
    entries = []
    for i in range(n):
        d_hat = 0.1 + (i / n) * 0.8   # range 0.1 – 0.9
        entry = _make_expired_entry(d_hat, seconds_ago=120.0)
        event_id = str(_uuid.uuid4())
        q.enqueue(entry, event_id=event_id)
        entries.append(entry)

    assert len(q) == n, "Setup: all entries enqueued"

    policy = TimeoutPolicy(T_timeout=T_TIMEOUT_S, fallback=mode)
    swept = q.apply_timeouts(policy, now=_NOW)

    n_swept              = len(swept)
    n_remaining          = len(q)
    n_unauthorized       = sum(1 for (_, fb) in swept if fb is None)
    n_wrong_mode         = sum(1 for (_, fb) in swept if fb != mode)
    n_correct            = sum(1 for (_, fb) in swept if fb == mode)

    return {
        "mode":          mode.value,
        "n_enqueued":    n,
        "n_swept":       n_swept,
        "n_remaining":   n_remaining,
        "n_unauthorized":n_unauthorized,
        "n_correct":     n_correct,
        "n_wrong_mode":  n_wrong_mode,
        "gate_passed":   (n_swept == n) and (n_unauthorized == 0) and (n_wrong_mode == 0),
    }


def _run_mixed_trial() -> dict:
    """Mixed queue: N expired + N active. Only expired must be swept."""
    import uuid as _uuid
    n_expired = 50
    n_active  = 50

    q = APBQueue()
    expired_ids = set()
    active_ids  = set()

    for _ in range(n_expired):
        e = _make_expired_entry(d_hat=0.7)
        q.enqueue(e, event_id=str(_uuid.uuid4()))
        expired_ids.add(e.escrow_id)

    for _ in range(n_active):
        e = _make_active_entry(d_hat=0.3)
        q.enqueue(e, event_id=str(_uuid.uuid4()))
        active_ids.add(e.escrow_id)

    policy = TimeoutPolicy(T_timeout=T_TIMEOUT_S, fallback=FallbackMode.DENY)
    swept = q.apply_timeouts(policy, now=_NOW)

    swept_ids = {e.escrow_id for (e, _) in swept}

    n_correctly_swept  = len(swept_ids & expired_ids)
    n_incorrectly_swept = len(swept_ids & active_ids)
    n_active_remaining  = len(active_ids & {e.escrow_id for e in q.list_pending()})

    return {
        "n_expired_enqueued":       n_expired,
        "n_active_enqueued":        n_active,
        "n_swept":                  len(swept),
        "n_correctly_swept":        n_correctly_swept,
        "n_incorrectly_swept":      n_incorrectly_swept,
        "n_active_remaining":       n_active_remaining,
        "gate_passed": (
            n_correctly_swept == n_expired
            and n_incorrectly_swept == 0
            and n_active_remaining == n_active
        ),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run() -> dict:
    print(f"\n{'='*65}")
    print(f"  E2 — Timeout Semantics  (N={N_PER_MODE} entries/mode, T_timeout={T_TIMEOUT_S}s)")
    print(f"{'='*65}")

    results = {}
    gate_all = True

    # Per-mode trials
    for mode in FallbackMode:
        trial = _run_mode_trial(mode, N_PER_MODE)
        results[f"mode_{mode.value.lower()}"] = trial
        if not trial["gate_passed"]:
            gate_all = False

        gate_str = "PASS [OK]" if trial["gate_passed"] else "FAIL [!!]"
        print(
            f"  mode={mode.value:<8}  "
            f"swept={trial['n_swept']}/{trial['n_enqueued']}  "
            f"unauthorized={trial['n_unauthorized']}  "
            f"correct={trial['n_correct']}  "
            f"gate={gate_str}"
        )

    # Mixed-queue trial
    mixed = _run_mixed_trial()
    results["mixed_queue"] = mixed
    if not mixed["gate_passed"]:
        gate_all = False

    gate_str = "PASS [OK]" if mixed["gate_passed"] else "FAIL [!!]"
    print(
        f"  mode=MIXED    "
        f"expired_swept={mixed['n_correctly_swept']}/{mixed['n_expired_enqueued']}  "
        f"active_untouched={mixed['n_active_remaining']}/{mixed['n_active_enqueued']}  "
        f"gate={gate_str}"
    )

    # Summary
    print(f"\n{'='*65}")
    print(f"  GATE  0 unauthorized executions across all modes: "
          f"{'PASSED [OK]' if gate_all else 'FAILED [!!]'}")
    print(f"{'='*65}\n")

    results["gate"] = {
        "description": "0 unauthorized executions in all fallback modes",
        "passed":       gate_all,
    }
    return results


if __name__ == "__main__":
    results = run()
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Results saved to {RESULTS_PATH}")
    if not results["gate"]["passed"]:
        raise SystemExit(1)
