# P10 — Non-Blocking Governance

> **Agent Governance Series · Paper 10 · Phase II**
> 
> *P10 introduces escrow-based non-blocking governance for human-mediated agent oversight.*

---

## The Problem

Paper 9 (MCP Governance Proxy) demonstrates that protocol-layer governance works. But it has a critical operational limitation: when the proxy emits `p9/apbRequired`, agent execution **blocks indefinitely** until a human signs the APB. Under real-world load (1000 agents × 62 HALTs/session), this is not operationally viable.

P9 explicitly declares this: *"APBRequired prioritises safety over liveness."*

**P10 resolves this tension**: governance that is simultaneously **safe** (no authority, no action) **and** liveness-guaranteed (agent resumes when APB arrives).

## Three Theorems

| Theorem | Statement |
|---------|-----------|
| **T10.1** Non-Blocking Soundness | Escrow preserves the safety guarantee under async APB resolution |
| **T10.2** Timeout Consistency | Fallback behaviour under timeout is coherent with post-HALT state |
| **T10.3** Escrow Liveness ⭐ | Agent resumes from exact `t_halt` state when APB arrives within `T_timeout` |

T10.3 is the first **liveness theorem** in the series (P0–P9 prove only safety properties).

## Repository Structure

```
non-blocking-governance/
  stack/          FROZEN — P7+P8+P9 governance stack (92 tests)
  proxy/          FROZEN — P9 MCP Governance Proxy
  client/         FROZEN — P9 MCP agent client
  agent/          FROZEN
  iml/            FROZEN
  baselines/      FROZEN
  tests/          92 inherited tests (P7+P8+P9) — baseline
  escrow/         NEW P10 — escrow store, timeout policy
  queue/          NEW P10 — deferred approval queue
  experiments/    E0 (★ throughput P9 vs P10) through E5
  paper/          main.tex
  results/
```

## Frozen Baseline

This repository inherits the P9 stack as a frozen baseline:
- **92 tests** (61 from P7+P8, 31 from P9) — all passing
- Stack: IML + RAM + Recovery Loop + APB + MCP Proxy
- No modifications to frozen components

## Series Position

```
Phase II — Governance of Governance
  P8  ✅  Who authorizes?     → APB, ed25519, identity binding
  P9  ✅  How does it deploy? → MCP Proxy, zero-modification
  P10 🔄  What if human unavailable? → Escrow + timeout + async APB
  P11 💡  Depth-k formal?    → Multi-Hop Originator Invariance
  P12 💡  Multi-org scale?   → Distributed APB (post-P11)
```

P9 committed explicitly: *"Paper 10 will formalise timeout semantics, escrow-state serialisation, and deferred-approval queues."*

## Related Papers

| Paper | DOI | GitHub |
|-------|-----|--------|
| P8 — Identity-Bound Governance | 10.5281/zenodo.20157139 | [chelof100/identity-bound-governance](https://github.com/chelof100/identity-bound-governance) |
| P9 — MCP-Native Governance | Zenodo pending | [chelof100/mcp-governed-agents](https://github.com/chelof100/mcp-governed-agents) |

## License

MIT
