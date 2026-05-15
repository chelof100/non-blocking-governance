# -*- coding: utf-8 -*-
"""
Recovery Loop — translates P6 pseudocode to executable Python.

From P6 §9 (Recovery Loop Definition):
  1. Signal Extraction:    identify unresolved variables U(t)
  2. IML Trigger:          IML detects drift/gap, emits recovery trigger
  3. State Augmentation:   acquire additional observations or reduce scope
  4. Reconstruction:       recompute authority from augmented state
  5. Resolution:           RESUME or remain HALT / ESCALATE

Theorem (Conditional Liveness): if all authority-defining variables
eventually become observable, the system exits HALT and resumes.
"""
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from stack.ram_gate import (
    RAMGate, RAMDecision, Authority, COMPONENTS, REQUIRED, UNDEFINED,
    _real_state, _get_proven_state, _ram_authority,
)


class ResumeDecision(Enum):
    RESUME    = "RESUME"    # authority resolved, execution can continue
    HALT      = "HALT"      # could not resolve in max_attempts
    ESCALATE  = "ESCALATE"  # DENY detected during reconstruction (permanent)


@dataclass
class RecoveryAttempt:
    attempt:        int
    unresolved:     List[str]           # U(t) — components missing
    coverage_used:  float
    authority:      Authority
    augmented:      bool


@dataclass
class RecoveryResult:
    decision:  ResumeDecision
    attempts:  List[RecoveryAttempt] = field(default_factory=list)
    halt_steps: int = 0


class RecoveryLoop:
    """
    Recovery Loop implementation per P6 §9.

    Integrates with IML (drift signal) and RAM Gate.
    Each HALT event triggers up to max_attempts recovery iterations.
    Each iteration increases state coverage (delta_coverage per attempt).
    """

    def __init__(
        self,
        max_attempts:    int   = 5,
        base_coverage:   float = 0.30,   # initial observability in HALT context
        delta_coverage:  float = 0.15,   # coverage gained per attempt
        seed:            int   = 42,
    ):
        self._max_attempts    = max_attempts
        self._base_coverage   = base_coverage
        self._delta_coverage  = delta_coverage
        self._rng             = random.Random(seed)
        self._history:        List[RecoveryResult] = []

    def run(
        self,
        halt_decision:  RAMDecision,
        iml_D_hat:      float,
        tool:           str,
        risk_score:     float,
        drift_level:    float = 0.0,
    ) -> RecoveryResult:
        """
        Execute Recovery Loop for a HALT event.

        Args:
            halt_decision: The RAMDecision that triggered HALT.
            iml_D_hat:     Current IML composite drift signal.
            tool:          Tool being attempted.
            risk_score:    Tool RS value.
            drift_level:   Current drift level (from IML).

        Returns:
            RecoveryResult with RESUME / HALT / ESCALATE.
        """
        attempts = []

        # ── Step 1: Signal Extraction ─────────────────────────────────────────
        unresolved = [
            c for c in REQUIRED
            if halt_decision.state_proven.get(c) is UNDEFINED
        ]

        # ── Step 2: IML Trigger ───────────────────────────────────────────────
        # High IML drift → reduce augmentation effectiveness
        augmentation_efficiency = max(0.3, 1.0 - iml_D_hat)

        for attempt_n in range(1, self._max_attempts + 1):
            # ── Step 3: State Augmentation ─────────────────────────────────────
            cov = min(
                1.0,
                self._base_coverage
                + attempt_n * self._delta_coverage * augmentation_efficiency,
            )

            # Re-sample state with increased coverage
            real   = _real_state(tool, risk_score, drift_level, self._rng)
            proven = _get_proven_state(real, cov, self._rng)

            # ── Step 4: Reconstruction Attempt ─────────────────────────────────
            auth = _ram_authority(proven)

            still_unresolved = [
                c for c in REQUIRED if proven.get(c) is UNDEFINED
            ]
            was_augmented = len(still_unresolved) < len(unresolved)

            rec_attempt = RecoveryAttempt(
                attempt=attempt_n,
                unresolved=still_unresolved,
                coverage_used=cov,
                authority=auth,
                augmented=was_augmented,
            )
            attempts.append(rec_attempt)

            # ── Step 5: Resolution ─────────────────────────────────────────────
            if auth == Authority.EXECUTE:
                result = RecoveryResult(
                    decision=ResumeDecision.RESUME,
                    attempts=attempts,
                    halt_steps=attempt_n,
                )
                self._history.append(result)
                return result

            if auth == Authority.DENY:
                result = RecoveryResult(
                    decision=ResumeDecision.ESCALATE,
                    attempts=attempts,
                    halt_steps=attempt_n,
                )
                self._history.append(result)
                return result

            # auth == HALT: continue loop

        # Max attempts exhausted — remain HALT
        result = RecoveryResult(
            decision=ResumeDecision.HALT,
            attempts=attempts,
            halt_steps=self._max_attempts,
        )
        self._history.append(result)
        return result

    def stats(self) -> Dict:
        total     = len(self._history)
        if total == 0:
            return {"total": 0, "resume_rate": 0, "escalate_rate": 0,
                    "halt_rate": 0, "avg_attempts": 0}
        resumes   = sum(1 for r in self._history if r.decision == ResumeDecision.RESUME)
        escalates = sum(1 for r in self._history if r.decision == ResumeDecision.ESCALATE)
        halts     = sum(1 for r in self._history if r.decision == ResumeDecision.HALT)
        avg_att   = sum(r.halt_steps for r in self._history) / total
        return {
            "total":         total,
            "resume_rate":   round(resumes  / total, 4),
            "escalate_rate": round(escalates / total, 4),
            "halt_rate":     round(halts    / total, 4),
            "avg_attempts":  round(avg_att,           2),
        }
