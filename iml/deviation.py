"""
IML Deviation Estimator — D̂(τ, A₀)
Ground truth: D(τ, A₀) = inf_{x ∈ A₀} d(τ, x)  [intractable]
This module: computable approximation via 3 components.

Components:
  D_t : temporal drift (JS divergence over tool distribution)
  D_c : constraint proximity (fraction of near-boundary tool calls)
  D_l : lineage deviation (drift in delegation depth vs expected)
"""
import numpy as np
from scipy.spatial.distance import jensenshannon
from collections import Counter
from typing import List, Dict

from iml.trace import Trace


# ─── Tool risk mapping (Σ → risk score) ───────────────────────────────────────
TOOL_RISK = {
    "safe_read":      0.1,
    "safe_query":     0.1,
    "moderate_write": 0.5,
    "moderate_send":  0.6,
    "risky_execute":  0.85,
    "risky_delegate": 0.9,
}
ALL_TOOLS = list(TOOL_RISK.keys())


def _tool_distribution(tools: List[str], eps: float = 1e-8) -> np.ndarray:
    """Empirical distribution over ALL_TOOLS from a list of tool names."""
    counts = Counter(tools)
    vec = np.array([counts.get(t, 0) + eps for t in ALL_TOOLS], dtype=float)
    return vec / vec.sum()


# ─── Admission snapshot A₀ ────────────────────────────────────────────────────

class AdmissionSnapshot:
    """
    A₀ = (P_E₀, depth_expected, constraint_graph)
    Built from burn-in traces at t=0.
    """
    def __init__(self, burn_in_trace: Trace):
        tools = burn_in_trace.tools()
        depths = burn_in_trace.depths()

        self.P0: np.ndarray = _tool_distribution(tools)
        self.depth_mean: float = float(np.mean(depths)) if depths else 1.0
        self.depth_std: float = float(np.std(depths)) if depths else 0.5

    def describe(self):
        print(f"A₀ tool distribution: {dict(zip(ALL_TOOLS, self.P0.round(3)))}")
        print(f"A₀ delegation depth: mean={self.depth_mean:.2f}, std={self.depth_std:.2f}")


# ─── IML Estimator ────────────────────────────────────────────────────────────

class IML:
    """
    IML(τ; A₀) := D̂(τ, A₀)
    A functional estimator over trajectories.
    Input: τ (trace) + A₀ (admission snapshot)
    NOT a function of g(τ) — uses A₀ directly as reference.
    """

    def __init__(self, A0: AdmissionSnapshot, weights: Dict[str, float] = None):
        self.A0 = A0
        self.weights = weights or {
            "D_t": 0.40,   # temporal drift
            "D_c": 0.35,   # constraint proximity
            "D_l": 0.25,   # lineage deviation
        }
        self._ema_state: float = 0.0
        self._ema_alpha: float = 0.15  # smoothing factor

    def D_t(self, trace: Trace) -> float:
        """
        Temporal drift: JS divergence between current tool distribution
        and admission-time distribution P_E₀.
        JS ∈ [0, 1]
        """
        Pt = _tool_distribution(trace.tools())
        return float(jensenshannon(Pt, self.A0.P0))

    def D_c(self, trace: Trace) -> float:
        """
        Constraint proximity: average risk score of tools in trace.
        Higher = closer to constraint boundaries.
        """
        tools = trace.tools()
        if not tools:
            return 0.0
        risks = [TOOL_RISK.get(t, 0.5) for t in tools]
        return float(np.mean(risks))

    def D_l(self, trace: Trace) -> float:
        """
        Lineage deviation: normalized distance between observed delegation
        depth distribution and expected depth at admission.
        """
        depths = trace.depths()
        if not depths:
            return 0.0
        current_mean = float(np.mean(depths))
        delta = abs(current_mean - self.A0.depth_mean)
        # normalize by 2 std deviations (practical upper bound)
        norm = max(2 * self.A0.depth_std, 0.5)
        return float(min(delta / norm, 1.0))

    def compute(self, trace: Trace) -> float:
        """
        D̂(τ) = w_t·D_t + w_c·D_c + w_l·D_l  with EMA smoothing
        """
        raw = (
            self.weights["D_t"] * self.D_t(trace) +
            self.weights["D_c"] * self.D_c(trace) +
            self.weights["D_l"] * self.D_l(trace)
        )
        # Exponential moving average for smoothing
        self._ema_state = (
            self._ema_alpha * raw +
            (1 - self._ema_alpha) * self._ema_state
        )
        return self._ema_state

    def breakdown(self, trace: Trace) -> Dict[str, float]:
        """Return component-level breakdown for ablation analysis."""
        return {
            "D_t": self.D_t(trace),
            "D_c": self.D_c(trace),
            "D_l": self.D_l(trace),
            "D_hat": self.compute(trace),
        }
