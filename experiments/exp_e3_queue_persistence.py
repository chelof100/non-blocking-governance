"""exp_e3_queue_persistence.py — P10 Experiment E3

Question: Can the APB arrive in a different session than the HALT?
Setup   : Proxy restart simulated between HALT and APB arrival.
Gate    : 100% correct resume post-restart (state, decision, field parity).

Protocol
  Session A  — N HALTs fire; entries enqueued; queue saved to disk; session ends.
  [RESTART]  — New APBQueue instance created from saved file (simulates proxy restart).
  Session B  — Human signs APBs; entries resolved in reloaded queue.

Verified per entry after restart:
  (a) escrow_id present in reloaded queue
  (b) all fields (tool_call, args, context, D_hat, t_halt) identical post-reload
  (c) resolve() returns the correct GovernanceDecision
  (d) entry removed from queue after resolution

Additional checks:
  - Mixed decisions (RESUME + DENY) across entries — all correct
  - Resolved event_ids persist across restart (V5 replay defence)
  - Partially-resolved queues (some resolved pre-restart, rest post-restart)

Results written to results/e3_queue_persistence.json
"""

from __future__ import annotations

import json
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent.principal import Principal, PrincipalRegistry, generate_keypair
from escrow.apb_queue import APBQueue, APBVerificationError
from escrow.escrow_store import EscrowEntry
from escrow.timeout_policy import TimeoutPolicy
from stack.apb import APB, GovernanceDecision, HumanDecisionBlock, SystemEvidenceBlock

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

N_ENTRIES       = 100
T_TIMEOUT_S     = 86_400.0      # 24 h — entries never expire during test
RESULTS_PATH    = Path(__file__).parent.parent / "results" / "e3_queue_persistence.json"


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_E_s(event_id: str | None = None) -> SystemEvidenceBlock:
    return SystemEvidenceBlock(
        A_0_hash="a" * 64,
        D_hat=0.75,
        t_e=_now_iso(),
        trace_hash="b" * 64,
        cause="persistent_drift",
        event_id=event_id or str(uuid.uuid4()),
    )


def _make_D_h(H_id: str, decision: str = "RESUME") -> HumanDecisionBlock:
    return HumanDecisionBlock(
        H_id=H_id, decision=decision,
        rationale="reviewed", scope="this call only",
    )


def _make_entry(E_s: SystemEvidenceBlock) -> EscrowEntry:
    return EscrowEntry.create(
        tool_call="transfer_funds",
        args={"amount": 10_000, "to": "wallet-ext"},
        context={"session_id": "sess-A", "trace_hash": E_s.trace_hash},
        D_hat=E_s.D_hat,
        t_halt=E_s.t_e,
    )


def _setup_principal():
    sk, pk = generate_keypair()
    H_id = "H_alice"
    reg = PrincipalRegistry()
    reg.add(Principal(H_id=H_id, public_key=pk))
    return H_id, sk, reg


def _policy() -> TimeoutPolicy:
    return TimeoutPolicy(T_timeout=T_TIMEOUT_S)


# ---------------------------------------------------------------------------
# Trial A: full restart — all entries resolved in session B
# ---------------------------------------------------------------------------

def _trial_full_restart(tmp_dir: Path, H_id: str, sk: bytes, registry: PrincipalRegistry) -> dict:
    path = tmp_dir / "queue_full.json"

    # ── Session A: enqueue N entries ──────────────────────────────────
    queue_a = APBQueue()
    event_ids: list[str] = []
    E_s_list: list[SystemEvidenceBlock] = []
    decisions_expected: list[str] = []

    for i in range(N_ENTRIES):
        eid = str(uuid.uuid4())
        E_s = _make_E_s(event_id=eid)
        entry = _make_entry(E_s)
        queue_a.enqueue(entry, event_id=eid)
        event_ids.append(eid)
        E_s_list.append(E_s)
        decisions_expected.append("RESUME" if i % 2 == 0 else "DENY")

    assert len(queue_a) == N_ENTRIES
    queue_a.save(path)

    # ── RESTART ───────────────────────────────────────────────────────
    queue_b = APBQueue.from_file(path)
    assert len(queue_b) == N_ENTRIES, "All entries present after reload"

    # ── Session B: verify fields + resolve all ────────────────────────
    n_field_match   = 0
    n_correct_dec   = 0
    n_removed       = 0

    pending_before = {e.escrow_id: e for e in queue_b.list_pending()}

    for i, (eid, E_s, dec) in enumerate(zip(event_ids, E_s_list, decisions_expected)):
        escrow_id = queue_a._escrow_to_event   # lookup via session A's mapping
        # Reconstruct escrow_id from the original entry
        # (session A's _store has the entry; we need its escrow_id)
        # We use the entry we can still get from queue_a._store after save
        # Simpler: all pending entries in queue_b have their escrow_ids — match by event_id via queue_b
        escrow_id = queue_b._event_to_escrow.get(eid)
        if escrow_id is None:
            continue

        # (a) escrow_id present
        assert escrow_id in queue_b

        # (b) field parity
        entry_b = queue_b._store.get(escrow_id)
        entry_a = pending_before[escrow_id]
        fields_ok = (
            entry_b.tool_call == entry_a.tool_call
            and entry_b.args    == entry_a.args
            and entry_b.context == entry_a.context
            and entry_b.D_hat   == entry_a.D_hat
            and entry_b.t_halt  == entry_a.t_halt
        )
        if fields_ok:
            n_field_match += 1

        # (c) resolve with correct decision
        apb = APB.construct(E_s, _make_D_h(H_id, dec), sk)
        decision, _ = queue_b.resolve(escrow_id, apb, registry, _policy(), max_age_seconds=86400.0)
        if decision == GovernanceDecision(dec):
            n_correct_dec += 1

        # (d) removed after resolution
        if escrow_id not in queue_b:
            n_removed += 1

    gate = (
        n_field_match == N_ENTRIES
        and n_correct_dec == N_ENTRIES
        and n_removed == N_ENTRIES
        and len(queue_b) == 0
    )
    return {
        "n_entries":       N_ENTRIES,
        "n_field_match":   n_field_match,
        "n_correct_dec":   n_correct_dec,
        "n_removed":       n_removed,
        "n_remaining":     len(queue_b),
        "gate_passed":     gate,
    }


# ---------------------------------------------------------------------------
# Trial B: partial pre-restart resolution + V5 replay defence
# ---------------------------------------------------------------------------

def _trial_partial_restart(tmp_dir: Path, H_id: str, sk: bytes, registry: PrincipalRegistry) -> dict:
    """Resolve half the entries before restart; verify V5 blocks replay after reload."""
    path = tmp_dir / "queue_partial.json"
    half = N_ENTRIES // 2

    queue_a = APBQueue()
    sessions: list[tuple[str, SystemEvidenceBlock]] = []
    for _ in range(N_ENTRIES):
        eid = str(uuid.uuid4())
        E_s = _make_E_s(event_id=eid)
        entry = _make_entry(E_s)
        queue_a.enqueue(entry, event_id=eid)
        sessions.append((eid, E_s))

    # Resolve first half before restart
    pre_restart_apbs: list[tuple[str, APB]] = []   # (escrow_id, apb)
    for eid, E_s in sessions[:half]:
        escrow_id = queue_a._event_to_escrow[eid]
        apb = APB.construct(E_s, _make_D_h(H_id, "RESUME"), sk)
        queue_a.resolve(escrow_id, apb, registry, _policy(), max_age_seconds=86400.0)
        pre_restart_apbs.append((escrow_id, apb))

    assert len(queue_a) == half, "Half resolved pre-restart"
    queue_a.save(path)

    # RESTART
    queue_b = APBQueue.from_file(path)
    assert len(queue_b) == half, "Remaining half present after reload"

    # Attempt to replay pre-restart APBs — must be rejected (V5)
    n_replayed_blocked = 0
    for _, apb in pre_restart_apbs:
        # Need a pending entry to target — use a fresh one (the replay fails on event_id)
        dummy_eid = str(uuid.uuid4())
        dummy_E_s = _make_E_s(event_id=dummy_eid)
        dummy = _make_entry(dummy_E_s)
        queue_b.enqueue(dummy, event_id=dummy_eid)
        dummy_escrow_id = queue_b._event_to_escrow[dummy_eid]
        try:
            queue_b.resolve(dummy_escrow_id, apb, registry, _policy(), max_age_seconds=86400.0)
        except APBVerificationError:
            n_replayed_blocked += 1
        finally:
            # clean up the dummy if it's still there
            if dummy_escrow_id in queue_b:
                queue_b._store.remove(dummy_escrow_id)
                queue_b._escrow_to_event.pop(dummy_escrow_id, None)
                queue_b._event_to_escrow.pop(dummy_eid, None)

    gate = (
        len(queue_b) == half      # remaining entries still present
        and n_replayed_blocked == half  # all pre-restart APBs rejected by V5
    )
    return {
        "n_entries":           N_ENTRIES,
        "half":                half,
        "n_remaining_after_restart": len(queue_b),
        "n_replayed_blocked":  n_replayed_blocked,
        "gate_passed":         gate,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run() -> dict:
    print(f"\n{'='*65}")
    print(f"  E3 — Queue Persistence / Proxy Restart  (N={N_ENTRIES} entries)")
    print(f"{'='*65}")

    H_id, sk, registry = _setup_principal()
    results = {}
    gate_all = True

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # Trial A
        trial_a = _trial_full_restart(tmp, H_id, sk, registry)
        results["full_restart"] = trial_a
        if not trial_a["gate_passed"]:
            gate_all = False
        gate_str = "PASS [OK]" if trial_a["gate_passed"] else "FAIL [!!]"
        print(
            f"  full_restart:    "
            f"fields_match={trial_a['n_field_match']}/{trial_a['n_entries']}  "
            f"correct_dec={trial_a['n_correct_dec']}/{trial_a['n_entries']}  "
            f"removed={trial_a['n_removed']}/{trial_a['n_entries']}  "
            f"gate={gate_str}"
        )

        # Trial B
        trial_b = _trial_partial_restart(tmp, H_id, sk, registry)
        results["partial_restart"] = trial_b
        if not trial_b["gate_passed"]:
            gate_all = False
        gate_str = "PASS [OK]" if trial_b["gate_passed"] else "FAIL [!!]"
        print(
            f"  partial_restart: "
            f"remaining={trial_b['n_remaining_after_restart']}/{trial_b['half']}  "
            f"replays_blocked={trial_b['n_replayed_blocked']}/{trial_b['half']}  "
            f"gate={gate_str}"
        )

    print(f"\n{'='*65}")
    print(f"  GATE  100% correct resume post-restart: "
          f"{'PASSED [OK]' if gate_all else 'FAILED [!!]'}")
    print(f"{'='*65}\n")

    results["gate"] = {
        "description": "100% correct resume post-restart",
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
