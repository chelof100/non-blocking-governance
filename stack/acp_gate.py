# -*- coding: utf-8 -*-
"""
ACP Gate — InMemory admission control for P7 experiments.

Replicates P1 Experiment 13 (Bounded Coordination Window) in Python/LangGraph.
Uses evaluate-then-mutate contract (ACP-RISK-3.0 §4): ledger updated AFTER
the decision is emitted.

Risk accumulation rules:
  Rule 1: pattern_count > rule1_threshold → RS += bonus_rule1  (+20)
  Rule 3: pattern_count >= rule3_threshold → RS += bonus_rule3  (+15)

Decision thresholds:
  ADMIT:    effective_rs < admit_threshold   (46)
  ESCALATE: admit_threshold <= rs < deny_threshold  (46–69)
  DENY:     effective_rs >= deny_threshold   (70)

With write_data baseline RS=45 and default thresholds:
  request 1 (count=0): RS=45 → ADMIT
  request 2 (count=1): RS=45 → ADMIT
  request 3 (count=2): Rule3 fires → RS=60 → ESCALATE
  request 4 (count=3): Rule1+Rule3 fire → RS=80 → DENY
→ CW_appr = 2 per agent → CW_appr = 2N for N agents
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class Decision(Enum):
    ADMIT     = "ADMIT"
    ESCALATE  = "ESCALATE"
    DENY      = "DENY"


@dataclass
class ACPRecord:
    agent_id:  str
    tool:      str
    rs_base:   float
    rs_eff:    float
    decision:  Decision
    count_pre: int   # pattern count BEFORE mutation (evaluate-then-mutate)


class ACPGate:
    """
    InMemory ACP admission gate. Stateful per agent_id.

    PatternKey = (agent_id, tool) — agent-scoped, per P1 §7.
    """

    def __init__(
        self,
        rule1_threshold:  int   = 2,    # count > N → Rule1 fires
        rule3_threshold:  int   = 2,    # count >= N → Rule3 fires
        bonus_rule1:      float = 20.0,
        bonus_rule3:      float = 15.0,
        admit_threshold:  float = 46.0,
        deny_threshold:   float = 70.0,
    ):
        self._r1_thr  = rule1_threshold
        self._r3_thr  = rule3_threshold
        self._b1      = bonus_rule1
        self._b3      = bonus_rule3
        self._admit   = admit_threshold
        self._deny    = deny_threshold
        self._counts:  Dict[Tuple[str, str], int]          = {}
        self._ledger:  Dict[str, List[ACPRecord]]          = {}
        self._denied:  Dict[str, bool]                     = {}

    # ── Public API ─────────────────────────────────────────────────────────────

    def evaluate(self, agent_id: str, tool: str, rs_base: float) -> ACPRecord:
        """
        Evaluate one tool call for agent_id.
        Evaluate-then-mutate: read count, decide, then increment.
        """
        key      = (agent_id, tool)
        count    = self._counts.get(key, 0)
        count_pre = count

        # Already permanently denied
        if self._denied.get(agent_id, False):
            rec = ACPRecord(
                agent_id=agent_id, tool=tool,
                rs_base=rs_base, rs_eff=rs_base,
                decision=Decision.DENY, count_pre=count_pre,
            )
            self._append_ledger(agent_id, rec)
            return rec

        # Compute effective RS (evaluate phase)
        rs_eff = rs_base
        if count >= self._r3_thr:
            rs_eff += self._b3
        if count > self._r1_thr:
            rs_eff += self._b1

        # Decision
        if rs_eff < self._admit:
            decision = Decision.ADMIT
        elif rs_eff < self._deny:
            decision = Decision.ESCALATE
        else:
            decision = Decision.DENY
            self._denied[agent_id] = True

        # Mutate phase: increment count AFTER decision
        self._counts[key] = count + 1

        rec = ACPRecord(
            agent_id=agent_id, tool=tool,
            rs_base=rs_base, rs_eff=rs_eff,
            decision=decision, count_pre=count_pre,
        )
        self._append_ledger(agent_id, rec)
        return rec

    def admits_for(self, agent_id: str) -> int:
        """Count ADMIT decisions for this agent."""
        return sum(
            1 for r in self._ledger.get(agent_id, [])
            if r.decision == Decision.ADMIT
        )

    def total_admits(self) -> int:
        return sum(self.admits_for(aid) for aid in self._ledger)

    def is_denied(self, agent_id: str) -> bool:
        return self._denied.get(agent_id, False)

    def ledger(self, agent_id: Optional[str] = None) -> list:
        if agent_id:
            return list(self._ledger.get(agent_id, []))
        return [r for records in self._ledger.values() for r in records]

    def reset(self):
        self._counts.clear()
        self._ledger.clear()
        self._denied.clear()

    # ── Internal ───────────────────────────────────────────────────────────────

    def _append_ledger(self, agent_id: str, rec: ACPRecord):
        if agent_id not in self._ledger:
            self._ledger[agent_id] = []
        self._ledger[agent_id].append(rec)
