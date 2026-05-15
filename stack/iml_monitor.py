# -*- coding: utf-8 -*-
"""
IML monitor for P7 — adapts the IML estimator to the 5 P7 tools.

Uses the same formulas as iml.deviation but with P7-specific
TOOL_RISK mapping and ALL_TOOLS ordering.

D̂(τ) = 0.40·D_t + 0.35·D_c + 0.25·D_l   (EMA-smoothed)
"""
from collections import Counter
from typing import List

import numpy as np
from scipy.spatial.distance import jensenshannon

from iml.trace import Trace

TOOL_RISK_P7 = {
    "read_file":      0.10,
    "query_api":      0.25,
    "write_data":     0.45,
    "delete_record":  0.70,
    "admin_action":   0.90,
}
ALL_TOOLS_P7 = list(TOOL_RISK_P7.keys())

_EPS = 1e-8


def _tool_dist(tools: List[str]) -> np.ndarray:
    counts = Counter(tools)
    vec = np.array([counts.get(t, 0) + _EPS for t in ALL_TOOLS_P7], dtype=float)
    return vec / vec.sum()


class AdmissionSnapshotP7:
    """A₀ snapshot built from P7 burn-in trace."""

    def __init__(self, burn_in_trace: Trace):
        tools  = burn_in_trace.tools()
        depths = burn_in_trace.depths()
        self.P0         = _tool_dist(tools)
        self.depth_mean = float(np.mean(depths)) if depths else 1.0
        self.depth_std  = float(np.std(depths))  if depths else 0.5


class IMLMonitor:
    """
    IML estimator for P7 experiments.
    Identical semantics to iml.IML but wired to P7 tool definitions.
    """

    def __init__(self, A0: AdmissionSnapshotP7):
        self.A0    = A0
        self._ema  = 0.0
        self._alpha = 0.15

    def D_t(self, trace: Trace) -> float:
        """JS divergence between current tool dist and A₀ baseline."""
        return float(jensenshannon(_tool_dist(trace.tools()), self.A0.P0))

    def D_c(self, trace: Trace) -> float:
        """Mean risk score of tools executed so far."""
        tools = trace.tools()
        if not tools:
            return 0.0
        return float(np.mean([TOOL_RISK_P7.get(t, 0.5) for t in tools]))

    def D_l(self, trace: Trace) -> float:
        """Normalized depth deviation from A₀ expected depth."""
        depths = trace.depths()
        if not depths:
            return 0.0
        delta = abs(float(np.mean(depths)) - self.A0.depth_mean)
        norm  = max(2 * self.A0.depth_std, 0.5)
        return float(min(delta / norm, 1.0))

    def compute(self, trace: Trace) -> float:
        """D̂(τ) with EMA smoothing."""
        raw = (0.40 * self.D_t(trace) +
               0.35 * self.D_c(trace) +
               0.25 * self.D_l(trace))
        self._ema = self._alpha * raw + (1 - self._alpha) * self._ema
        return self._ema
