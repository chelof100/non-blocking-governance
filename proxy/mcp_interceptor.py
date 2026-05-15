# -*- coding: utf-8 -*-
"""
MCPInterceptor — core governance logic for P9.

Sits between an MCP client and an MCP server. For each tool call it:
  1. Updates the IML trace and drift estimate D̂.
  2. Runs the RAM Gate.
  3. If HALT: runs the Recovery Loop.
  4. If persistent HALT/ESCALATE: constructs E_s and emits APBRequired.
  5. If ADMIT: returns ("ADMIT", None) — caller forwards the call.

One MCPInterceptor per governed session (stateful; not thread-safe).

APBRequired workflow:
  - intercept_tool_call() returns ("APB_REQUIRED", APBRequired).
  - Caller transmits the APBRequired to the client out-of-band.
  - Client assembles D_h, signs, returns APBResponse.
  - Caller passes APBResponse to handle_apb_response().
  - On ("RESOLVED", GovernanceDecision.RESUME): caller forwards the
    pending tool call.
  - On ("RESOLVED", DENY/RECALIBRATE) or ("REJECTED", ...): caller
    returns an error to the client.

Key invariant (T9.1 Transparency Invariance):
  On the non-HALT path, the proxy's behaviour is observationally
  equivalent to a passthrough — the tool call reaches the server and
  the response is returned unchanged.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from agent.principal import PrincipalRegistry
from iml.trace import Event, Trace
from proxy.protocol_extension import APBRequired, APBResponse, APBRejected
from stack.apb import APB, GovernanceDecision, SystemEvidenceBlock, construct_evidence
from stack.apb_verifier import verify_apb
from stack.iml_monitor import AdmissionSnapshotP7, IMLMonitor
from stack.ram_gate import Authority, RAMGate
from stack.recovery_loop import RecoveryLoop, ResumeDecision


# Risk map mirrors proxy/toy_server.py (risk values × 100 for RAM Gate).
TOOL_RISK_01: dict[str, float] = {
    "read_file":     0.10,
    "query_api":     0.25,
    "write_data":    0.45,
    "delete_record": 0.70,
    "admin_action":  0.90,
}


class MCPInterceptor:
    """Governance interceptor for one MCP client session.

    Args:
        registry:       PrincipalRegistry used to verify incoming APBs.
        H_id:           Principal ID to cite in APBRequired messages.
        risk_map:       Tool-name → risk score [0,1]. Defaults to P7 map.
        ram_seed:       RNG seed for RAM Gate (for reproducibility).
        recovery_seed:  RNG seed for Recovery Loop.
    """

    def __init__(
        self,
        registry: PrincipalRegistry,
        H_id: str,
        risk_map: dict[str, float] | None = None,
        ram_gate: RAMGate | None = None,
        recovery_loop: RecoveryLoop | None = None,
        ram_seed: int = 42,
        recovery_seed: int = 42,
        # P9 multi-hop A2A extension (Def. 4.5 – 4.6 / T9.3)
        agent_id: str | None = None,
        delegation_chain: list[str] | None = None,
        # P9 §4.7 Authority Confinement: restrict which H_ids may authorize
        # governance events on this interceptor.  When set, handle_apb_response
        # rejects any APB whose D_h.H_id is not in this set, even if V1-V5 pass.
        # In A2A, set this to {originator_H_id} to enforce originator binding.
        allowed_H_ids: set[str] | None = None,
        # P9 §4.8 IML monitor override: pass a pre-constructed IMLMonitor
        # (e.g. WindowedIMLMonitor) to swap the drift estimator implementation.
        # When None (default), IMLMonitor is constructed internally.
        iml_monitor: "IMLMonitor | None" = None,
    ) -> None:
        self.registry = registry
        self.H_id = H_id
        self._risk_map = dict(risk_map or TOOL_RISK_01)
        # A2A delegation metadata: chain = [A_1, ..., A_n], originator = A_1
        self._agent_id = agent_id
        self._delegation_chain: list[str] = list(delegation_chain or [])
        # Authority confinement: if set, only these principals may authorize
        self._allowed_H_ids: set[str] | None = (
            set(allowed_H_ids) if allowed_H_ids is not None else None
        )

        # Per-session state — reset on initialize()
        self._trace = Trace()
        burn_in = Trace()                          # empty → conservative A_0
        self._A_0 = AdmissionSnapshotP7(burn_in)
        self._iml = iml_monitor if iml_monitor is not None else IMLMonitor(self._A_0)
        self._ram = ram_gate or RAMGate(rs_threshold=45.0, seed=ram_seed)
        self._recovery = recovery_loop or RecoveryLoop(seed=recovery_seed)

        # Pending APBRequired: evidence_id → (E_s, tool_name, args)
        self._pending: dict[str, tuple[SystemEvidenceBlock, str, dict]] = {}

        # Audit log (evidence_id → final outcome string)
        self.audit_log: list[dict[str, Any]] = []

    # -----------------------------------------------------------------------
    # Session lifecycle
    # -----------------------------------------------------------------------

    def reset(self) -> None:
        """Reset per-session state (call on MCP initialize)."""
        self._trace = Trace()
        burn_in = Trace()
        self._A_0 = AdmissionSnapshotP7(burn_in)
        self._iml = IMLMonitor(self._A_0)
        self._pending.clear()
        self.audit_log.clear()

    # -----------------------------------------------------------------------
    # Tool call interception
    # -----------------------------------------------------------------------

    def intercept_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> tuple[str, Any]:
        """Govern a tool call.

        Returns one of:
          ("ADMIT",        None)              — forward call to server
          ("APB_REQUIRED", APBRequired)       — halt; APB needed
          ("DENY",         str)               — permanent denial; reason str
        """
        risk_01 = self._risk_map.get(tool_name, 0.50)
        risk_100 = risk_01 * 100.0

        # 1. Update IML trace
        self._trace.add(Event(
            agent="A",
            action="tool_call",
            tool=tool_name,
            depth=0,
            metadata={"args": args},
        ))

        # 2. Compute drift
        D_hat = self._iml.compute(self._trace)

        # 3. RAM Gate
        ram_dec = self._ram.check(
            tool=tool_name,
            risk_score=risk_100,
            drift_level=D_hat,
        )

        if ram_dec.authority == Authority.EXECUTE:
            self._log("ADMIT", tool_name, D_hat)
            return ("ADMIT", None)

        if ram_dec.authority == Authority.DENY:
            reason = f"RAM DENY for {tool_name!r} (D_hat={D_hat:.3f})"
            self._log("DENY", tool_name, D_hat, detail=reason)
            return ("DENY", reason)

        # 4. Recovery Loop (HALT from RAM)
        recovery = self._recovery.run(
            halt_decision=ram_dec,
            iml_D_hat=D_hat,
            tool=tool_name,
            risk_score=risk_100,
            drift_level=D_hat,
        )

        if recovery.decision == ResumeDecision.RESUME:
            self._log("ADMIT_AFTER_RECOVERY", tool_name, D_hat)
            return ("ADMIT", None)

        # 5. Persistent HALT or ESCALATE → emit APBRequired
        cause = (
            "persistent_halt"
            if recovery.decision == ResumeDecision.HALT
            else "escalate"
        )
        t_e = datetime.now(timezone.utc).isoformat()
        E_s = construct_evidence(
            A_0=self._risk_map,
            D_hat=D_hat,
            trace=self._trace,
            cause=cause,
            t_e=t_e,
        )
        evidence_id = uuid.uuid4().hex[:16]
        self._pending[evidence_id] = (E_s, tool_name, args)

        # Build evidence_summary; include P9 delegation metadata when present.
        # (Def. 4.6 Multi-Hop APB Semantics: E_s.cause ⊇ {delegation_chain, originator})
        evidence_summary = E_s.to_dict()
        if self._delegation_chain:
            evidence_summary["delegation_chain"] = list(self._delegation_chain)
            evidence_summary["originator"] = self._delegation_chain[0]

        apb_req = APBRequired(
            tool_name=tool_name,
            args=args,
            evidence_id=evidence_id,
            evidence_summary=evidence_summary,
        )
        self._log("APB_REQUIRED", tool_name, D_hat, detail=evidence_id)
        return ("APB_REQUIRED", apb_req)

    # -----------------------------------------------------------------------
    # APB response handling
    # -----------------------------------------------------------------------

    def handle_apb_response(
        self,
        apb_response: APBResponse,
    ) -> tuple[str, Any]:
        """Process a client's APBResponse.

        Returns one of:
          ("RESOLVED",  GovernanceDecision)  — APB valid; carry out decision
          ("REJECTED",  str)                 — APB invalid; reason str
        """
        evidence_id = apb_response.evidence_id
        if evidence_id not in self._pending:
            reason = f"unknown evidence_id: {evidence_id!r}"
            return ("REJECTED", reason)

        E_s_expected, tool_name, _ = self._pending[evidence_id]

        # Parse APB
        try:
            apb = APB.from_json(apb_response.apb_json)
        except Exception as exc:
            reason = f"malformed APB JSON: {exc}"
            return ("REJECTED", reason)

        # Verify E_s match (prevents substitution attacks)
        if apb.E_s != E_s_expected:
            del self._pending[evidence_id]
            reason = "E_s in APB does not match issued evidence"
            return ("REJECTED", reason)

        # V1-V4 cryptographic verification
        report = verify_apb(apb, self.registry)
        if not report.is_valid:
            del self._pending[evidence_id]
            reason = f"APB verification failed: {report.result.value}"
            return ("REJECTED", reason)

        # P9 §4.7 Authority Confinement check — enforces that D_h.H_id is
        # one of the pre-approved principals for this interceptor.  This
        # prevents a sub-agent from substituting an alternative (but
        # legitimately registered) human authority in A2A delegation chains.
        if self._allowed_H_ids is not None:
            if apb.D_h.H_id not in self._allowed_H_ids:
                del self._pending[evidence_id]
                allowed_str = ", ".join(sorted(self._allowed_H_ids))
                reason = (
                    f"authority confinement violation: {apb.D_h.H_id!r} "
                    f"not in allowed_H_ids ({{{allowed_str}}})"
                )
                return ("REJECTED", reason)

        del self._pending[evidence_id]
        decision = GovernanceDecision(apb.D_h.decision)
        self._log(f"APB_RESOLVED:{decision.value}", tool_name, apb.E_s.D_hat)
        return ("RESOLVED", decision)

    # -----------------------------------------------------------------------
    # Accessors
    # -----------------------------------------------------------------------

    @property
    def pending_evidence_ids(self) -> list[str]:
        return list(self._pending.keys())

    @property
    def current_drift(self) -> float:
        """Last computed D̂ (0 if no calls yet)."""
        return float(self._iml._ema)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _log(
        self,
        outcome: str,
        tool_name: str,
        D_hat: float,
        detail: str = "",
    ) -> None:
        self.audit_log.append({
            "outcome": outcome,
            "tool": tool_name,
            "D_hat": round(D_hat, 4),
            "detail": detail,
        })
