# -*- coding: utf-8 -*-
"""
WindowedIMLMonitor — O(1) sliding-window IML estimator (P9 §4.8).

Problem with the baseline IMLMonitor:
  D_t, D_c, D_l all iterate over the complete execution trace.
  For a session of n tool calls, each governance check is O(n).
  At n = 1000, mean latency reaches ~185 us; at n = 2000, ~343 us.
  This violates the spirit of T9.2 (Halt Latency Bound), which promises
  bounded overhead regardless of session length.

Solution — sliding window:
  Keep only the last W events in the computation window.
  Full trace is retained for APB audit (trace_hash, cause) and governance
  accountability — no audit information is lost.
  Governance decisions are made on the W-event window, giving O(1) per call.

Formal connection (P9 Def 4.8):
  Let W = window size.
  D_t^W(tau) = JSD(dist(tau[-W:]), P_0)
  D_c^W(tau) = mean(risk(t) for t in tau[-W:])
  D_l^W(tau) = normalised depth deviation over tau[-W:]
  D_hat^W = 0.40*D_t^W + 0.35*D_c^W + 0.25*D_l^W  (EMA-smoothed)

Bounded overhead guarantee (P9 L9.2.2):
  Computation time per call is O(W), independent of |tau|.
  With W = 100, overhead is indistinguishable from the single-call baseline.

Usage:
  from stack.iml_monitor_windowed import WindowedIMLMonitor
  monitor = WindowedIMLMonitor(A0, window=100)
  # Drop-in replacement for IMLMonitor
"""
from __future__ import annotations

from collections import Counter, deque
from typing import Deque, List, Optional

import numpy as np
from scipy.spatial.distance import jensenshannon

from iml.trace import Event, Trace
from stack.iml_monitor import (
    AdmissionSnapshotP7,
    ALL_TOOLS_P7,
    TOOL_RISK_P7,
    IMLMonitor,
    _EPS,
)

_DEFAULT_WINDOW = 100


class _WindowBuffer:
    """Sliding window over the last W (tool, depth) pairs.

    Updated incrementally: each new event appends to a deque; the oldest
    is dropped when len > W.  Access via .tools and .depths is O(W).
    """

    def __init__(self, window: int) -> None:
        self._window = window
        self._tools:  Deque[str] = deque(maxlen=window)
        self._depths: Deque[int] = deque(maxlen=window)
        self._n_total: int = 0  # total events seen (for reporting)

    def update(self, tool: Optional[str], depth: int) -> None:
        if tool is not None:
            self._tools.append(tool)
        self._depths.append(depth)
        self._n_total += 1

    @property
    def tools(self) -> List[str]:
        return list(self._tools)

    @property
    def depths(self) -> List[int]:
        return list(self._depths)

    @property
    def n_total(self) -> int:
        return self._n_total

    @property
    def window_size(self) -> int:
        return self._window


def _tool_dist_from_list(tools: List[str]) -> np.ndarray:
    counts = Counter(tools)
    vec = np.array([counts.get(t, 0) + _EPS for t in ALL_TOOLS_P7], dtype=float)
    return vec / vec.sum()


class WindowedIMLMonitor(IMLMonitor):
    """Drop-in replacement for IMLMonitor with O(1) bounded overhead.

    Overrides D_t, D_c, D_l to operate on the last *window* events
    instead of the full trace.  compute() is inherited unchanged.

    The compute(trace) signature is preserved for API compatibility: the
    full Trace object is accepted (so the caller can still pass it for
    audit/hash purposes), but governance computation uses only the window.

    Args:
        A0:     Admission snapshot (baseline distribution, depth stats).
        window: Number of recent events to use for D̂ computation.
                Defaults to 100.  Set to None for unlimited (= IMLMonitor).
    """

    def __init__(self, A0: AdmissionSnapshotP7, window: int = _DEFAULT_WINDOW) -> None:
        super().__init__(A0)
        self._buf = _WindowBuffer(window)

    @property
    def window_size(self) -> int:
        return self._buf.window_size

    @property
    def n_events_seen(self) -> int:
        """Total events processed (including those outside the window)."""
        return self._buf.n_total

    # ------------------------------------------------------------------
    # Override D_t, D_c, D_l to use the window buffer instead of full trace
    # ------------------------------------------------------------------

    def D_t(self, trace: Trace) -> float:  # type: ignore[override]
        tools = self._buf.tools
        if not tools:
            return 0.0
        return float(jensenshannon(_tool_dist_from_list(tools), self.A0.P0))

    def D_c(self, trace: Trace) -> float:  # type: ignore[override]
        tools = self._buf.tools
        if not tools:
            return 0.0
        return float(np.mean([TOOL_RISK_P7.get(t, 0.5) for t in tools]))

    def D_l(self, trace: Trace) -> float:  # type: ignore[override]
        depths = self._buf.depths
        if not depths:
            return 0.0
        delta = abs(float(np.mean(depths)) - self.A0.depth_mean)
        norm = max(2 * self.A0.depth_std, 0.5)
        return float(min(delta / norm, 1.0))

    # ------------------------------------------------------------------
    # Override compute() to update the buffer before computing
    # ------------------------------------------------------------------

    def compute(self, trace: Trace) -> float:
        """Compute D_hat using the sliding window.

        Reads the LAST event from the trace (the newly added one) and
        pushes it into the window buffer, then computes D_hat using only
        the buffered events.  The full trace is used only for hashing.

        Performance: O(W) per call, independent of len(trace).
        """
        # Extract the most recent event from the trace
        if trace.events:
            last_event = trace.events[-1]
            self._buf.update(last_event.tool, last_event.depth)

        # D_t/D_c/D_l now operate on self._buf, not the full trace
        raw = (0.40 * self.D_t(trace) +
               0.35 * self.D_c(trace) +
               0.25 * self.D_l(trace))
        self._ema = self._alpha * raw + (1 - self._alpha) * self._ema
        return self._ema
