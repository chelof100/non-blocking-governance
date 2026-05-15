"""exp_e1_escrow_overhead.py — P10 Experiment E1

Question: How much does escrow serialization/deserialization cost?
Setup   : 10 000 escrow/resume cycles — measure Δ_escrow end-to-end
Gate    : P95 Δ_escrow < 1 ms

Measurements
  put          : EscrowStore.put(entry) — in-memory insert
  serialize    : EscrowEntry.to_json()  — to JSON string
  deserialize  : EscrowEntry.from_json()— from JSON string
  roundtrip    : serialize + deserialize (full escrow/resume cycle)
  save_1       : EscrowStore.save() with 1 entry
  save_100     : EscrowStore.save() with 100 entries
  load_1       : EscrowStore.load() after 1-entry save
  load_100     : EscrowStore.load() after 100-entry save

Results written to results/e1_escrow_overhead.json
"""

from __future__ import annotations

import json
import statistics
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from escrow.escrow_store import EscrowEntry, EscrowStore

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

N_CYCLES       = 10_000
GATE_P95_MS    = 1.0       # must be < 1 ms
RESULTS_PATH   = Path(__file__).parent.parent / "results" / "e1_escrow_overhead.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_entry() -> EscrowEntry:
    return EscrowEntry.create(
        tool_call="send_payment",
        args={"to": "wallet-abc", "amount": 50_000, "currency": "USD"},
        context={
            "session_id": uuid.uuid4().hex[:8],
            "trace_hash": "a" * 64,
            "A_0_hash":   "b" * 64,
        },
        D_hat=0.72,
        t_halt=_now_iso(),
    )


def _percentile(data: list[float], p: float) -> float:
    data_sorted = sorted(data)
    k = (len(data_sorted) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(data_sorted) - 1)
    return data_sorted[lo] + (data_sorted[hi] - data_sorted[lo]) * (k - lo)


def _stats(latencies_s: list[float]) -> dict:
    ms = [x * 1_000 for x in latencies_s]
    return {
        "n":        len(ms),
        "mean_ms":  round(statistics.mean(ms), 4),
        "p50_ms":   round(_percentile(ms, 50), 4),
        "p95_ms":   round(_percentile(ms, 95), 4),
        "p99_ms":   round(_percentile(ms, 99), 4),
        "max_ms":   round(max(ms), 4),
    }


# ---------------------------------------------------------------------------
# Benchmark functions
# ---------------------------------------------------------------------------

def bench_roundtrip(n: int) -> list[float]:
    """serialize + deserialize — full Δ_escrow cycle."""
    entry = _make_entry()
    lats = []
    for _ in range(n):
        t0 = time.perf_counter()
        s = entry.to_json()
        EscrowEntry.from_json(s)
        lats.append(time.perf_counter() - t0)
    return lats


def bench_serialize(n: int) -> list[float]:
    entry = _make_entry()
    lats = []
    for _ in range(n):
        t0 = time.perf_counter()
        entry.to_json()
        lats.append(time.perf_counter() - t0)
    return lats


def bench_deserialize(n: int) -> list[float]:
    entry = _make_entry()
    s = entry.to_json()
    lats = []
    for _ in range(n):
        t0 = time.perf_counter()
        EscrowEntry.from_json(s)
        lats.append(time.perf_counter() - t0)
    return lats


def bench_put(n: int) -> list[float]:
    """In-memory EscrowStore.put."""
    lats = []
    store = EscrowStore()
    for _ in range(n):
        entry = _make_entry()
        t0 = time.perf_counter()
        store.put(entry)
        lats.append(time.perf_counter() - t0)
    return lats


def bench_file_save(n_entries: int, n_trials: int = 500) -> list[float]:
    """EscrowStore.save() to a temp file."""
    store = EscrowStore()
    for _ in range(n_entries):
        store.put(_make_entry())
    lats = []
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "escrow.json"
        for _ in range(n_trials):
            t0 = time.perf_counter()
            store.save(path)
            lats.append(time.perf_counter() - t0)
    return lats


def bench_file_load(n_entries: int, n_trials: int = 500) -> list[float]:
    """EscrowStore.load() from a temp file."""
    store = EscrowStore()
    for _ in range(n_entries):
        store.put(_make_entry())
    lats = []
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "escrow.json"
        store.save(path)
        store2 = EscrowStore()
        for _ in range(n_trials):
            t0 = time.perf_counter()
            store2.load(path)
            lats.append(time.perf_counter() - t0)
    return lats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run() -> dict:
    print(f"\n{'='*60}")
    print(f"  E1 — Escrow Overhead  (N={N_CYCLES:,} cycles)")
    print(f"{'='*60}")

    results = {}

    benches = [
        ("roundtrip",     lambda: bench_roundtrip(N_CYCLES)),
        ("serialize",     lambda: bench_serialize(N_CYCLES)),
        ("deserialize",   lambda: bench_deserialize(N_CYCLES)),
        ("put_inmemory",  lambda: bench_put(N_CYCLES)),
        ("file_save_1",   lambda: bench_file_save(n_entries=1)),
        ("file_save_100", lambda: bench_file_save(n_entries=100)),
        ("file_load_1",   lambda: bench_file_load(n_entries=1)),
        ("file_load_100", lambda: bench_file_load(n_entries=100)),
    ]

    max_label = max(len(k) for k, _ in benches)
    for label, fn in benches:
        lats = fn()
        st = _stats(lats)
        results[label] = st
        gate_str = ""
        if label == "roundtrip":
            passed = st["p95_ms"] < GATE_P95_MS
            gate_str = f"  <- gate {'PASS [OK]' if passed else 'FAIL [!!]'} (P95 < {GATE_P95_MS} ms)"
        print(
            f"  {label:<{max_label}}  "
            f"mean={st['mean_ms']:.4f} ms  "
            f"P50={st['p50_ms']:.4f} ms  "
            f"P95={st['p95_ms']:.4f} ms  "
            f"P99={st['p99_ms']:.4f} ms  "
            f"max={st['max_ms']:.4f} ms"
            f"{gate_str}"
        )

    # Gate assertion
    p95_roundtrip = results["roundtrip"]["p95_ms"]
    gate_passed = p95_roundtrip < GATE_P95_MS
    print(f"\n{'='*60}")
    print(f"  GATE  P95 delta_escrow (roundtrip) = {p95_roundtrip:.4f} ms")
    print(f"  GATE  {'PASSED [OK]' if gate_passed else 'FAILED [!!]'}  (threshold = {GATE_P95_MS} ms)")
    print(f"{'='*60}\n")

    results["gate"] = {
        "metric":    "P95 roundtrip serialize+deserialize",
        "threshold_ms": GATE_P95_MS,
        "value_ms":  p95_roundtrip,
        "passed":    gate_passed,
    }

    return results


if __name__ == "__main__":
    results = run()
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Results saved to {RESULTS_PATH}")
    if not results["gate"]["passed"]:
        raise SystemExit(1)
