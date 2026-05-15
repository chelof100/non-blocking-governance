# -*- coding: utf-8 -*-
"""
RAM Gate — Reconstructive Authority Model gate for P7 experiments.

Adapted from chelof100/reconstructive-authority-model (simulate_ram.py).
Applies RAM authority check to high-risk tool calls (RS >= 45).

Authority components for P7 tool execution context:
  I = identity_valid   (is the caller authenticated?)
  B = behavior_ok      (does behavior match A0 baseline?)
  R = resource_avail   (is the target resource accessible?)
  C = context_valid    (is execution context consistent?)
  E = env_ready        (are external dependencies available?)

Decision semantics (RAM §4):
  - Any required component is False  → DENY  (invalid execution)
  - Any required component is UNDEFINED → HALT (partial observability)
  - All required components True     → EXECUTE

Required components: I, B, R, C  (E is informational, not blocking)
"""
import random
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

COMPONENTS = ["I", "B", "R", "C", "E"]
REQUIRED   = ["I", "B", "R", "C"]   # E is informational


class Authority(Enum):
    EXECUTE = "EXECUTE"
    HALT    = "HALT"
    DENY    = "DENY"


UNDEFINED = None   # sentinel for unobservable state


@dataclass
class RAMDecision:
    tool:      str
    authority: Authority
    state_proven:       Dict[str, Optional[bool]]
    state_declared:     Dict[str, Optional[bool]]
    state_unobservable: Dict[str, bool]
    coverage:           float   # |S_p| / |S_r|


def _real_state(
    tool: str,
    risk_score: float,
    drift_level: float = 0.0,
    rng: random.Random = None,
) -> Dict[str, Optional[bool]]:
    """
    Generate ground-truth authority state for a tool call.
    Higher risk_score and drift_level increase probability of failures.
    """
    if rng is None:
        rng = random.Random()

    # Base failure probabilities per component, scaled by risk
    base_fail = {
        "I": 0.02,
        "B": 0.02 + 0.15 * drift_level,   # behavioral drift affects B
        "R": 0.05 + 0.05 * (risk_score / 90),
        "C": 0.03,
        "E": 0.08,
    }
    state = {}
    for c in COMPONENTS:
        p_fail = base_fail.get(c, 0.05)
        if rng.random() < p_fail:
            # hidden vs detectable failure
            if c in ("B", "E") and rng.random() < 0.5:
                state[c] = UNDEFINED  # ambiguous / unobservable failure
            else:
                state[c] = False
        else:
            state[c] = True
    return state


def _get_proven_state(
    real_state: Dict,
    coverage: float,
    rng: random.Random,
) -> Dict[str, Optional[bool]]:
    """
    Simulate partial observability: only a coverage fraction of components
    is observable. Unobserved components return UNDEFINED.
    """
    n_observable = max(1, round(len(COMPONENTS) * coverage))
    observable   = set(rng.sample(COMPONENTS, n_observable))
    proven = {}
    for c in COMPONENTS:
        if c in observable:
            proven[c] = real_state[c]
        else:
            proven[c] = UNDEFINED
    return proven


def _ram_authority(state: Dict) -> Authority:
    """
    RAM decision rule over required components.
    """
    for c in REQUIRED:
        val = state.get(c)
        if val is False:
            return Authority.DENY
        if val is UNDEFINED:
            return Authority.HALT
    return Authority.EXECUTE


class RAMGate:
    """
    RAM Gate for P7 LangGraph experiments.

    Applies RAM authority check to tool calls with RS >= rs_threshold.
    Below the threshold, tools pass through (EXECUTE) without RAM check.
    """

    def __init__(
        self,
        rs_threshold: float = 45.0,   # only check tools with RS >= this
        coverage:     float = 0.70,   # default state coverage (|S_p|/|S_r|)
        seed:         int   = 42,
    ):
        self._rs_threshold = rs_threshold
        self._coverage     = coverage
        self._rng          = random.Random(seed)
        self._history:     list = []

    def check(
        self,
        tool:        str,
        risk_score:  float,
        drift_level: float = 0.0,
        coverage_override: Optional[float] = None,
    ) -> RAMDecision:
        """
        Run RAM authority check for a tool call.

        Args:
            tool:             Tool name.
            risk_score:       Tool RS (0-100).
            drift_level:      IML drift signal [0,1] — raises failure prob for B.
            coverage_override: Override default coverage for this call.

        Returns:
            RAMDecision with authority EXECUTE / HALT / DENY.
        """
        cov = coverage_override if coverage_override is not None else self._coverage

        # Tools below threshold pass without RAM check
        if risk_score < self._rs_threshold:
            dec = RAMDecision(
                tool=tool, authority=Authority.EXECUTE,
                state_proven={c: True for c in COMPONENTS},
                state_declared={c: True for c in COMPONENTS},
                state_unobservable={c: False for c in COMPONENTS},
                coverage=1.0,
            )
            self._history.append(dec)
            return dec

        # Generate real state + partial observable view
        real     = _real_state(tool, risk_score, drift_level, self._rng)
        proven   = _get_proven_state(real, cov, self._rng)
        authority = _ram_authority(proven)

        unobservable = {c: proven[c] is UNDEFINED for c in COMPONENTS}

        dec = RAMDecision(
            tool=tool, authority=authority,
            state_proven=proven,
            state_declared=real,
            state_unobservable=unobservable,
            coverage=cov,
        )
        self._history.append(dec)
        return dec

    def stats(self) -> Dict[str, float]:
        """Compute IER, SHR, OCR over history."""
        executed       = [d for d in self._history if d.authority == Authority.EXECUTE]
        halted         = [d for d in self._history if d.authority == Authority.HALT]
        denied         = [d for d in self._history if d.authority == Authority.DENY]

        # Ground truth: real authority (declared state, all components known)
        def _real_auth(d: RAMDecision) -> bool:
            return all(d.state_declared.get(c) is True for c in REQUIRED)

        invalid_exec  = sum(1 for d in executed if not _real_auth(d))
        valid_halted  = sum(1 for d in halted   if _real_auth(d))
        invalid_halted = sum(1 for d in halted  if not _real_auth(d))
        total_valid   = sum(1 for d in self._history if _real_auth(d))

        ier = invalid_exec / len(executed)       if executed  else 0.0
        shr = invalid_halted / max(1, invalid_exec + invalid_halted + len(denied))
        ocr = valid_halted / max(1, total_valid)

        return {
            "IER": round(ier, 4),
            "SHR": round(shr, 4),
            "OCR": round(ocr, 4),
            "n_execute": len(executed),
            "n_halt":    len(halted),
            "n_deny":    len(denied),
            "n_total":   len(self._history),
        }
