# P10 — Non-Blocking Governance

[![Zenodo DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.20214654-blue)](https://doi.org/10.5281/zenodo.20214654)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Agent Governance Series · Paper 10 · Phase II**
>
> *P10 introduces escrow-based non-blocking governance for human-mediated agent oversight.*

---

## The Problem

Paper 9 (MCP Governance Proxy) demonstrates that protocol-layer governance works — but at a cost: when the proxy emits `p9/apbRequired`, agent execution **blocks indefinitely** until a human signs the APB. P9 explicitly declared this:

> *"APBRequired prioritises safety over liveness. Paper 10 will formalise timeout semantics, escrow-state serialisation, and deferred-approval queues so that governance events can be resolved asynchronously without halting the agent pipeline."*

P10 fulfils that commitment.

## Contribution

**Escrow-based non-blocking governance**: on a HALT, the suspended tool call's state is serialised into a persistent escrow entry and deposited in a priority queue. The agent session continues immediately. When the APB arrives — in the same session or a different one — the call is resumed from the exact preserved state.

## Three Theorems

| Theorem | Statement |
|---------|-----------|
| **T10.1** Non-Blocking Soundness | No risky tool call executes without a valid APB (V1–V6) or explicit policy-authorised fallback; at-most-once execution semantics |
| **T10.2** Timeout Consistency | Fallback decision under timeout is locally equivalent to an explicit governance decision for the suspended call |
| **T10.3** Escrow Liveness ⭐ | First liveness theorem in the series: if the human signs within `t_sign ≤ t_halt + T_timeout`, the suspended call resumes within bounded latency Δ_resume |

T10.3 is the **first liveness theorem** in the series (P0–P9 prove only safety properties).

## Six Experiments

| Exp | Question | Result |
|-----|----------|--------|
| **E0** ⭐ | Throughput P9 vs P10 under load | **81× speedup** at 80% halt rate; 10.7× at 10%; safe-task throughput unaffected |
| **E1** | Escrow serialize/deserialize overhead | P95 = **6.4 µs** — 156× below 1 ms gate |
| **E2** | Timeout semantics (3 fallback modes) | **0 unauthorized executions** across DENY / ADMIT / ESCALATE |
| **E3** | Queue persistence across session restart | **100% correct resume** post-restart; 100% V5 replay defence |
| **E4** | N agents concurrent escrow | **0 exceptions**, 100% APB validity (N=64, 1280 resolutions) |
| **E5** | Adversarial: replay, post-timeout, forgery, tampering | A1/A2/A3a: **0% adversary success**; A3b: implementation gap documented (R10.1) |

## V6 Predicate

P10 introduces **V6** — the timeout enforcement predicate:

```
V6(APB, e, π) ≜ τ_apb ≤ t_halt + T_timeout
```

V6 stacks on top of V1–V5 (from P8/P9). An APB passing V1–V5 but failing V6 is rejected. Together, V1–V6 form the complete verification chain for the async governance setting.

## Usage Example

```python
from stack.apb import GovernanceDecision
from escrow.escrow_store import EscrowEntry
from escrow.apb_queue import APBQueue
from escrow.timeout_policy import TimeoutPolicy, FallbackMode

# --- Session A: HALT path ---
policy    = TimeoutPolicy(T_timeout=300.0, fallback=FallbackMode.DENY)
queue     = APBQueue()
entry     = EscrowEntry.create(
    tool_call="write_data",
    args={"table": "users", "row": {...}},
    context={"session_id": "sess-42"},
    D_hat=drift_estimate, t_halt=utc_now_iso(),
)
escrow_id = queue.enqueue(entry, event_id=governance_event.event_id)
queue.save("escrow/session_42.json")    # persist across sessions

# --- Session B: APB arrival (same or different session) ---
queue            = APBQueue.from_file("escrow/session_42.json")
decision, entry  = queue.resolve(
    escrow_id, apb, principal_registry, policy
)
if decision == GovernanceDecision.RESUME:
    execute_tool(entry.tool_call, entry.args)
```

Between `enqueue` and `resolve`, the agent session is not blocked.

## Repository Structure

```
non-blocking-governance/
  stack/          FROZEN — P7+P8+P9 governance stack (92 tests)
  proxy/          FROZEN — P9 MCP Governance Proxy
  client/         FROZEN — P9 MCP agent client
  agent/          FROZEN
  iml/            FROZEN
  baselines/      FROZEN
  escrow/         NEW P10 — escrow_store.py, timeout_policy.py, apb_queue.py
  experiments/    E0–E5 (throughput, overhead, timeout, persistence, concurrency, adversarial)
  paper/          main.tex (15 pages, 0 errors)
  results/        E0–E5 JSON results
  tests/          156 tests — 92 inherited (P7–P9) + 64 new P10
```

## Frozen Baseline

This repository inherits the P9 stack as a frozen baseline:
- **156 tests** passing (92 inherited P7–P9 + 64 new P10)
- No modifications to frozen stack components

## Series Position

```
Phase II — Governance of Governance
  P8  ✅  Who authorizes?         → APB, ed25519, identity binding
  P9  ✅  How does it deploy?     → MCP Proxy, zero-modification
  P10 ✅  What if human is away?  → Escrow + timeout + async APB
  P11 💡  Depth-k formal?         → Multi-Hop Originator Invariance
  P12 💡  Multi-org scale?        → Distributed APB (Merkle log)
```

**P9 made governance safe but blocking. P10 shows it can be safe and live.**

## Related Papers

| Paper | DOI | GitHub |
|-------|-----|--------|
| P8 — Identity-Bound Governance | [10.5281/zenodo.20157139](https://doi.org/10.5281/zenodo.20157139) | [chelof100/identity-bound-governance](https://github.com/chelof100/identity-bound-governance) |
| P9 — MCP-Native Governance | [10.5281/zenodo.20162878](https://doi.org/10.5281/zenodo.20162878) | [chelof100/mcp-governed-agents](https://github.com/chelof100/mcp-governed-agents) |
| P10 — Non-Blocking Governance | [10.5281/zenodo.20214654](https://doi.org/10.5281/zenodo.20214654) | this repo |

## License

MIT
