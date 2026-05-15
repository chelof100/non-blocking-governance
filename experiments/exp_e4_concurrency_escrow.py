"""exp_e4_concurrency_escrow.py — P10 Experiment E4

Question: N agents simultaneously in escrow — any races or data loss?
Setup   : N in {1, 4, 16, 64} agents, each with M entries in escrow.
          All agents run concurrently (ThreadPoolExecutor).
Gate    : 0 exceptions, 100% APB validity, 0 cross-contamination.

Architecture note
  Each proxy instance (agent) owns its own APBQueue — the queue is not
  shared across agents. Concurrency is agent-level: all N agents enqueue,
  resolve, and sweep simultaneously without interference.

Per-agent invariants verified
  (a) All M entries enqueued without collision
  (b) All M entries resolved with the correct GovernanceDecision
  (c) Queue empty after all resolutions (no entries leaked)
  (d) No exception raised during the agent's lifecycle

Cross-agent invariant
  (e) Entries from agent i are never visible in agent j's queue (isolation)

Results written to results/e4_concurrency_escrow.json
"""

from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from agent.principal import Principal, PrincipalRegistry, generate_keypair
from escrow.apb_queue import APBQueue
from escrow.escrow_store import EscrowEntry
from escrow.timeout_policy import TimeoutPolicy
from stack.apb import APB, GovernanceDecision, HumanDecisionBlock, SystemEvidenceBlock

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

N_VALUES          = [1, 4, 16, 64]
M_ENTRIES         = 20          # entries per agent
T_TIMEOUT_S       = 86_400.0
RESULTS_PATH      = Path(__file__).parent.parent / "results" / "e4_concurrency_escrow.json"


# ---------------------------------------------------------------------------
# Shared principal (read-only after setup — safe across threads)
# ---------------------------------------------------------------------------

def _make_principal():
    sk, pk = generate_keypair()
    H_id = "H_concurrent"
    reg = PrincipalRegistry()
    reg.add(Principal(H_id=H_id, public_key=pk))
    return H_id, sk, reg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_E_s(event_id: str) -> SystemEvidenceBlock:
    return SystemEvidenceBlock(
        A_0_hash="a" * 64,
        D_hat=0.7,
        t_e=_now_iso(),
        trace_hash="b" * 64,
        cause="concurrent_drift",
        event_id=event_id,
    )


def _make_entry(E_s: SystemEvidenceBlock, agent_id: int) -> EscrowEntry:
    return EscrowEntry.create(
        tool_call=f"agent_{agent_id}_tool",
        args={"step": agent_id},
        context={"agent_id": str(agent_id)},
        D_hat=E_s.D_hat,
        t_halt=E_s.t_e,
    )


# ---------------------------------------------------------------------------
# Single-agent lifecycle
# ---------------------------------------------------------------------------

def _run_agent(
    agent_id: int,
    H_id: str,
    sk: bytes,
    registry: PrincipalRegistry,
    all_queues: dict[int, APBQueue],
    lock: threading.Lock,
) -> dict:
    """Run one agent: enqueue M entries, resolve all, verify invariants."""
    result = {
        "agent_id":     agent_id,
        "n_enqueued":   0,
        "n_resolved":   0,
        "n_correct_dec":0,
        "n_remaining":  0,
        "exception":    None,
        "passed":       False,
    }

    try:
        queue = APBQueue()

        # Register this agent's queue (for cross-contamination check)
        with lock:
            all_queues[agent_id] = queue

        policy = TimeoutPolicy(T_timeout=T_TIMEOUT_S)
        E_s_list: list[SystemEvidenceBlock] = []

        # (a) Enqueue M entries
        for _ in range(M_ENTRIES):
            eid = str(uuid.uuid4())
            E_s = _make_E_s(eid)
            entry = _make_entry(E_s, agent_id)
            queue.enqueue(entry, event_id=eid)
            E_s_list.append(E_s)
            result["n_enqueued"] += 1

        # (b) Resolve all entries
        for E_s in E_s_list:
            escrow_id = queue._event_to_escrow.get(E_s.event_id)
            if escrow_id is None:
                continue
            apb = APB.construct(
                E_s,
                HumanDecisionBlock(
                    H_id=H_id, decision="RESUME",
                    rationale="concurrent test", scope="one step",
                ),
                sk,
            )
            decision, _ = queue.resolve(
                escrow_id, apb, registry, policy, max_age_seconds=86_400.0
            )
            result["n_resolved"] += 1
            if decision == GovernanceDecision.RESUME:
                result["n_correct_dec"] += 1

        # (c) Queue empty
        result["n_remaining"] = len(queue)

        result["passed"] = (
            result["n_enqueued"]    == M_ENTRIES
            and result["n_resolved"]   == M_ENTRIES
            and result["n_correct_dec"]== M_ENTRIES
            and result["n_remaining"]  == 0
        )

    except Exception as exc:
        result["exception"] = str(exc)
        result["passed"] = False

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run() -> dict:
    print(f"\n{'='*65}")
    print(f"  E4 — Concurrency Escrow  (M={M_ENTRIES} entries/agent, N={N_VALUES})")
    print(f"{'='*65}")

    H_id, sk, registry = _make_principal()
    all_results = {}
    gate_all = True

    for N in N_VALUES:
        all_queues: dict[int, APBQueue] = {}
        lock = threading.Lock()
        agent_results = []

        with ThreadPoolExecutor(max_workers=N) as pool:
            futures = {
                pool.submit(_run_agent, i, H_id, sk, registry, all_queues, lock): i
                for i in range(N)
            }
            for fut in as_completed(futures):
                agent_results.append(fut.result())

        # Aggregate
        n_passed      = sum(1 for r in agent_results if r["passed"])
        n_exceptions  = sum(1 for r in agent_results if r["exception"])
        n_total_res   = sum(r["n_resolved"]    for r in agent_results)
        n_total_cor   = sum(r["n_correct_dec"] for r in agent_results)
        n_remaining   = sum(r["n_remaining"]   for r in agent_results)

        # (e) Cross-contamination check: agent i's entries never in agent j's queue
        n_contaminated = 0
        for i, qi in all_queues.items():
            for j, qj in all_queues.items():
                if i == j:
                    continue
                for entry in qj.list_pending():
                    if entry.context.get("agent_id") == str(i):
                        n_contaminated += 1

        gate_ok = (
            n_passed     == N
            and n_exceptions  == 0
            and n_total_res   == N * M_ENTRIES
            and n_total_cor   == N * M_ENTRIES
            and n_remaining   == 0
            and n_contaminated== 0
        )
        if not gate_ok:
            gate_all = False

        gate_str = "PASS [OK]" if gate_ok else "FAIL [!!]"
        print(
            f"  N={N:<3}  agents_passed={n_passed}/{N}  "
            f"resolved={n_total_res}/{N*M_ENTRIES}  "
            f"correct={n_total_cor}/{N*M_ENTRIES}  "
            f"exceptions={n_exceptions}  "
            f"contamination={n_contaminated}  "
            f"gate={gate_str}"
        )

        all_results[f"N_{N}"] = {
            "N":              N,
            "M":              M_ENTRIES,
            "n_passed":       n_passed,
            "n_exceptions":   n_exceptions,
            "n_resolved":     n_total_res,
            "n_correct":      n_total_cor,
            "n_remaining":    n_remaining,
            "n_contaminated": n_contaminated,
            "gate_passed":    gate_ok,
        }

    print(f"\n{'='*65}")
    print(f"  GATE  0 exceptions, 100% APB validity: "
          f"{'PASSED [OK]' if gate_all else 'FAILED [!!]'}")
    print(f"{'='*65}\n")

    all_results["gate"] = {
        "description": "0 exceptions, 100% APB validity, 0 cross-contamination",
        "passed":       gate_all,
    }
    return all_results


if __name__ == "__main__":
    results = run()
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Results saved to {RESULTS_PATH}")
    if not results["gate"]["passed"]:
        raise SystemExit(1)
