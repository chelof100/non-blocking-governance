# -*- coding: utf-8 -*-
"""
MockLLM — deterministic tool selector for P7 experiments.

No API calls. Fully reproducible via seed.

Tools (sprint plan):
  read_file     RS=10   (safe)
  query_api     RS=25   (safe-moderate)
  write_data    RS=45   (moderate)
  delete_record RS=70   (risky)
  admin_action  RS=90   (high-risk)

Drift model: linear interpolation from safe-heavy → risky-heavy
over the drift phase, without violating per-step rules (g(τ)=0).
"""
import random
from typing import Tuple

TOOLS = ["read_file", "query_api", "write_data", "delete_record", "admin_action"]

TOOL_RISK = {
    "read_file":      0.10,
    "query_api":      0.25,
    "write_data":     0.45,
    "delete_record":  0.70,
    "admin_action":   0.90,
}

# Burn-in baseline distribution (safe-heavy)
_BURN_IN_WEIGHTS = [0.50, 0.30, 0.15, 0.04, 0.01]

# Drift-end target distribution (risky-heavy)
_DRIFT_END_WEIGHTS = [0.05, 0.10, 0.45, 0.28, 0.12]


class MockLLM:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def select(self, phase: str, progress: float) -> Tuple[str, int]:
        """
        Return (tool_name, delegation_depth).
        progress ∈ [0, 1] within drift phase (0 during burn-in).
        """
        if phase == "burn_in":
            weights = list(_BURN_IN_WEIGHTS)
            depth = 1
        else:
            weights = [
                b * (1 - progress) + d * progress
                for b, d in zip(_BURN_IN_WEIGHTS, _DRIFT_END_WEIGHTS)
            ]
            depth = 1 + int(progress * 2 * self.rng.random())

        total = sum(weights)
        weights = [w / total for w in weights]

        r = self.rng.random()
        cumulative = 0.0
        for tool, w in zip(TOOLS, weights):
            cumulative += w
            if r <= cumulative:
                return tool, depth
        return TOOLS[-1], depth
