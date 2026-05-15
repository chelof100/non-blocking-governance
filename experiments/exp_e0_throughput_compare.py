"""exp_e0_throughput_compare.py — P10 Experiment E0 ★

Question: How much does throughput improve with escrow vs blocking under HALT load?
Gate    : P10 throughput > P9 throughput at all halt_rates > 0

Two metrics measured separately (do NOT conflate):
  1. Δ_resume   — latency from APB arrival to task resumption
                  (measured from real EscrowEntry.from_json + EscrowStore.get)
  2. Continuity — throughput of non-blocked tasks during the escrow period
                  (P9=0 tasks/s while blocked; P10=unaffected)

Simulation model
  Each agent processes N tasks; each task takes T_TASK_S logical seconds.
  A fraction `halt_rate` of tasks trigger a governance HALT.
  APB resolution takes T_APB_S logical seconds (human response latency).

  P9 (blocking):
    On HALT: agent stops for T_APB_S — no other tasks advance.
    total_time = N * T_TASK_S + N * halt_rate * T_APB_S
    throughput = N / total_time

  P10 (non-blocking escrow):
    On HALT: Δ_escrow overhead (measured), agent continues immediately.
    Risky tasks resolve at t_halt + T_APB_S + Δ_resume (overlaps safe tasks).
    safe_throughput = (N * (1-r)) / (N * T_TASK_S + N*r * Δ_escrow)  ← unaffected by T_APB
    total_throughput = N / max(N*T_TASK_S + N*r*Δ_escrow, max_apb_deadline + Δ_resume)

Results written to results/e0_throughput_compare.json
"""

from __future__ import annotations

import json
import random
import statistics
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from escrow.escrow_store import EscrowEntry, EscrowStore

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

N_AGENTS          = 100
N_TASKS_PER_AGENT = 200
HALT_RATES        = [0.0, 0.1, 0.2, 0.4, 0.6, 0.8]

# Logical time constants (seconds) — represent realistic human-in-loop latencies
T_TASK_S          = 0.010   # 10 ms per task (e.g. one LLM-routed tool call)
T_APB_S           = 2.000   # 2 s APB response (human reviews and signs)

N_DELTA_SAMPLES   = 5_000   # cycles to measure Δ_escrow and Δ_resume
RESULTS_PATH      = Path(__file__).parent.parent / "results" / "e0_throughput_compare.json"

SEED              = 42


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_entry() -> EscrowEntry:
    return EscrowEntry.create(
        tool_call="exec_privileged",
        args={"cmd": "rm -rf /var/data", "confirm": True},
        context={"session_id": uuid.uuid4().hex[:8], "trace_hash": "c" * 64},
        D_hat=0.75,
        t_halt=_now_iso(),
    )


def _percentile(data: list[float], p: float) -> float:
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


# ---------------------------------------------------------------------------
# Measure real Δ_escrow and Δ_resume
# ---------------------------------------------------------------------------

def measure_delta_escrow(n: int) -> dict:
    """Wall-clock time to serialize one EscrowEntry (put into escrow)."""
    lats = []
    store = EscrowStore()
    for _ in range(n):
        entry = _make_entry()
        t0 = time.perf_counter()
        store.put(entry)
        lats.append(time.perf_counter() - t0)
    ms = [x * 1_000 for x in lats]
    return {
        "mean_ms": round(statistics.mean(ms), 6),
        "p50_ms":  round(_percentile(ms, 50), 6),
        "p95_ms":  round(_percentile(ms, 95), 6),
        "p99_ms":  round(_percentile(ms, 99), 6),
    }


def measure_delta_resume(n: int) -> dict:
    """Wall-clock time to deserialize + get from EscrowStore (resume from escrow)."""
    store = EscrowStore()
    entries = [_make_entry() for _ in range(n)]
    for e in entries:
        store.put(e)

    lats = []
    for e in entries:
        t0 = time.perf_counter()
        _ = store.get(e.escrow_id)
        lats.append(time.perf_counter() - t0)
    ms = [x * 1_000 for x in lats]
    return {
        "mean_ms": round(statistics.mean(ms), 6),
        "p50_ms":  round(_percentile(ms, 50), 6),
        "p95_ms":  round(_percentile(ms, 95), 6),
        "p99_ms":  round(_percentile(ms, 99), 6),
    }


# ---------------------------------------------------------------------------
# Simulation models (logical time — no actual sleep)
# ---------------------------------------------------------------------------

def _simulate_p9_agent(n_tasks: int, halt_rate: float, rng: random.Random) -> dict:
    """P9: HALT blocks the entire agent for T_APB_S logical seconds."""
    t = 0.0
    n_halts = 0
    for _ in range(n_tasks):
        t += T_TASK_S
        if rng.random() < halt_rate:
            t += T_APB_S
            n_halts += 1
    throughput = n_tasks / t if t > 0 else 0.0
    return {
        "total_time_s":    round(t, 6),
        "n_halts":         n_halts,
        "throughput_tps":  round(throughput, 4),
        # Metric 2: safe-task continuity during any HALT = 0 (agent blocked)
        "safe_tps_during_halt": 0.0,
    }


def _simulate_p10_agent(
    n_tasks: int,
    halt_rate: float,
    delta_escrow_s: float,
    delta_resume_s: float,
    rng: random.Random,
) -> dict:
    """P10: HALT suspends only the risky tool call; agent continues other tasks.

    The agent timeline advances by T_TASK_S per task plus Δ_escrow on each HALT.
    APBs resolve independently; end-time = max(agent_done, last_apb + Δ_resume).
    """
    t = 0.0
    n_halts = 0
    apb_deadlines: list[float] = []
    n_safe = 0

    for _ in range(n_tasks):
        t += T_TASK_S
        if rng.random() < halt_rate:
            t += delta_escrow_s       # put into escrow — tiny overhead
            apb_deadlines.append(t + T_APB_S)
            n_halts += 1
        else:
            n_safe += 1

    agent_done = t
    if apb_deadlines:
        t_final = max(agent_done, max(apb_deadlines) + delta_resume_s)
    else:
        t_final = agent_done

    throughput_total = n_tasks / t_final if t_final > 0 else 0.0

    # Metric 2: safe-task throughput during escrow window
    # Safe tasks advance at 1/T_TASK_S regardless of pending HALTs
    safe_tps = (1.0 / T_TASK_S) if T_TASK_S > 0 else float("inf")

    return {
        "total_time_s":             round(t_final, 6),
        "n_halts":                  n_halts,
        "throughput_tps":           round(throughput_total, 4),
        # Metric 2: safe tasks unaffected — constant
        "safe_tps_during_halt":     round(safe_tps, 4),
    }


# ---------------------------------------------------------------------------
# Aggregate over N agents
# ---------------------------------------------------------------------------

def _aggregate(runs: list[dict]) -> dict:
    tps    = [r["throughput_tps"]    for r in runs]
    halts  = [r["n_halts"]           for r in runs]
    safe   = [r["safe_tps_during_halt"] for r in runs]
    return {
        "throughput_mean_tps":   round(statistics.mean(tps),   4),
        "throughput_p50_tps":    round(_percentile(tps, 50),   4),
        "throughput_p5_tps":     round(_percentile(tps, 5),    4),  # tail
        "n_halts_mean":          round(statistics.mean(halts), 2),
        "safe_tps_during_halt":  round(statistics.mean(safe),  4),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run() -> dict:
    print(f"\n{'='*70}")
    print(f"  E0 — Throughput Comparison: P9 (blocking) vs P10 (non-blocking escrow)")
    print(f"  Agents={N_AGENTS}  Tasks/agent={N_TASKS_PER_AGENT}  T_task={T_TASK_S*1000:.0f}ms  T_apb={T_APB_S:.1f}s")
    print(f"{'='*70}")

    # --- Measure real Δ_escrow and Δ_resume ---
    print("\n  Measuring delta_escrow (put) and delta_resume (get) ...")
    d_escrow = measure_delta_escrow(N_DELTA_SAMPLES)
    d_resume = measure_delta_resume(N_DELTA_SAMPLES)
    delta_escrow_s = d_escrow["p95_ms"] / 1_000   # use P95 as conservative estimate
    delta_resume_s = d_resume["p95_ms"] / 1_000

    print(f"    delta_escrow  mean={d_escrow['mean_ms']:.4f} ms  P95={d_escrow['p95_ms']:.4f} ms")
    print(f"    delta_resume  mean={d_resume['mean_ms']:.4f} ms  P95={d_resume['p95_ms']:.4f} ms")

    # --- Simulate both models across halt rates ---
    rows = []
    rng = random.Random(SEED)

    print(f"\n  {'halt_rate':>10}  {'P9_tps':>10}  {'P10_total_tps':>14}  "
          f"{'P10_safe_tps':>13}  {'ratio':>7}  {'gate':>6}")
    print(f"  {'-'*10}  {'-'*10}  {'-'*14}  {'-'*13}  {'-'*7}  {'-'*6}")

    gate_passed_all = True
    for r in HALT_RATES:
        p9_runs  = [_simulate_p9_agent(N_TASKS_PER_AGENT, r, rng)  for _ in range(N_AGENTS)]
        p10_runs = [_simulate_p10_agent(N_TASKS_PER_AGENT, r, delta_escrow_s, delta_resume_s, rng)
                    for _ in range(N_AGENTS)]

        p9_agg  = _aggregate(p9_runs)
        p10_agg = _aggregate(p10_runs)

        p9_tps  = p9_agg["throughput_mean_tps"]
        p10_tps = p10_agg["throughput_mean_tps"]
        ratio   = (p10_tps / p9_tps) if p9_tps > 0 else float("inf")

        gate_ok = (r == 0.0) or (p10_tps >= p9_tps)
        if not gate_ok:
            gate_passed_all = False

        safe_tps = p10_agg["safe_tps_during_halt"]
        gate_str = "PASS [OK]" if gate_ok else "FAIL [!!]"

        print(
            f"  {r:>10.1f}  {p9_tps:>10.2f}  {p10_tps:>14.2f}  "
            f"{safe_tps:>13.2f}  {ratio:>7.3f}x  {gate_str}"
        )

        rows.append({
            "halt_rate":                r,
            "p9_throughput_tps":        p9_tps,
            "p10_throughput_total_tps": p10_tps,
            "p10_safe_tps_during_halt": safe_tps,
            "p9_n_halts_mean":          p9_agg["n_halts_mean"],
            "p10_n_halts_mean":         p10_agg["n_halts_mean"],
            "speedup_ratio":            round(ratio, 4),
            "gate_passed":              gate_ok,
        })

    print(f"\n{'='*70}")
    gate_str = "PASSED [OK]" if gate_passed_all else "FAILED [!!]"
    print(f"  GATE  P10 throughput > P9 throughput (all halt_rates > 0): {gate_str}")
    print(f"\n  Metric 1 (delta_resume):   P95 = {d_resume['p95_ms']:.4f} ms")
    print(f"  Metric 2 (continuity): P10 safe tasks continue at {rows[1]['p10_safe_tps_during_halt']:.1f} tps")
    print(f"                         P9  safe tasks during HALT =  0.0 tps  (blocked)")
    print(f"{'='*70}\n")

    return {
        "config": {
            "N_agents":            N_AGENTS,
            "N_tasks_per_agent":   N_TASKS_PER_AGENT,
            "T_task_s":            T_TASK_S,
            "T_apb_s":             T_APB_S,
            "halt_rates":          HALT_RATES,
            "seed":                SEED,
        },
        "delta_escrow":  d_escrow,
        "delta_resume":  d_resume,
        "rows":          rows,
        "gate": {
            "description": "P10 throughput >= P9 throughput at all halt_rates > 0",
            "passed":       gate_passed_all,
        },
    }


if __name__ == "__main__":
    results = run()
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Results saved to {RESULTS_PATH}")
    if not results["gate"]["passed"]:
        raise SystemExit(1)
