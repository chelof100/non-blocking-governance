"""
Anomaly Detection Baseline — B2
JS divergence over tool distribution against rolling history.
No access to A₀ — uses empirical history as reference.
This is the standard anomaly detector, NOT IML.
Key difference: IML uses A₀ (normative); anomaly uses history (statistical).
"""
import numpy as np
from scipy.spatial.distance import jensenshannon
from collections import Counter, deque
from typing import List

from iml.trace import Trace
from iml.deviation import ALL_TOOLS


def _tool_distribution(tools: List[str], eps: float = 1e-8) -> np.ndarray:
    counts = Counter(tools)
    vec = np.array([counts.get(t, 0) + eps for t in ALL_TOOLS], dtype=float)
    return vec / vec.sum()


class AnomalyDetector:
    """
    Rolling-window anomaly detector.
    Compares recent window to full history.
    No normative reference — purely statistical.
    """

    def __init__(self, window_size: int = 30):
        self.window = deque(maxlen=window_size)
        self.history: List[str] = []
        self._ema_state: float = 0.0
        self._ema_alpha: float = 0.15

    def update(self, trace: Trace) -> float:
        tools = trace.tools()
        if not tools:
            return 0.0

        last_tool = tools[-1]
        self.window.append(last_tool)
        self.history.extend(tools)

        if len(self.history) < 10 or len(self.window) < 5:
            return 0.0

        P_window = _tool_distribution(list(self.window))
        P_history = _tool_distribution(self.history)

        raw = float(jensenshannon(P_window, P_history))
        self._ema_state = (
            self._ema_alpha * raw +
            (1 - self._ema_alpha) * self._ema_state
        )
        return self._ema_state
