# -*- coding: utf-8 -*-
"""MCPAgentClient — in-process MCP-governed agent session.

Simulates an MCP-aware agent client against a governed proxy (MCPInterceptor)
without spawning subprocesses. The agent selects tools via any callable
tool_selector(phase, progress) -> (tool_name, ...), and the governance layer
runs fully in-process via MCPInterceptor.

When governance halts the agent (APB_REQUIRED), the client automatically:
  1. Constructs a HumanDecisionBlock (D_h) with the configured decision.
  2. Signs an APB using the principal's ed25519 private key.
  3. Submits an APBResponse to the interceptor.
  4. Executes the tool if decision == RESUME.

This in-process design is appropriate for E2 (viability + APB correctness).
E1 already measured actual transport latency.

Rationale (P9 Decisions §6):
  "Cliente MCP propio en Python: determinismo > real-world demo."
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from proxy.mcp_interceptor import MCPInterceptor, TOOL_RISK_01
from proxy.protocol_extension import APBRequired, APBResponse
from stack.apb import APB, GovernanceDecision, HumanDecisionBlock, SystemEvidenceBlock
from stack.apb_verifier import verify_apb

# Default mock tool results (mirrors toy_server.py responses)
_MOCK_RESULTS: dict[str, Callable[[dict], str]] = {
    "read_file":     lambda a: f"[mock] contents of {a.get('path', 'file')}",
    "query_api":     lambda a: f"[mock] {{'endpoint': '{a.get('endpoint', '/')}', 'status': 200}}",
    "write_data":    lambda a: f"[mock] wrote to {a.get('target', 'storage')}",
    "delete_record": lambda a: f"[mock] deleted record {a.get('record_id', 'unknown')}",
    "admin_action":  lambda a: f"[mock] admin executed: {a.get('action', 'cmd')}",
}


def _default_executor(tool_name: str, args: dict) -> str:
    fn = _MOCK_RESULTS.get(tool_name)
    if fn is None:
        return f"[mock] unknown tool: {tool_name}"
    return fn(args)


class MCPAgentClient:
    """In-process MCP-governed agent session.

    Args:
        interceptor:     The MCPInterceptor governing this session.
        sk_bytes:        Ed25519 private key bytes for signing APBs.
        H_id:            Principal identifier for the HumanDecisionBlock.
        tool_executor:   fn(tool_name, args) -> str.  Defaults to mock results.
        auto_decision:   GovernanceDecision to use when auto-signing APBs.
                         "RESUME" (default), "DENY", or "RECALIBRATE".
        rationale:       Rationale string encoded in D_h.
        scope:           Scope string encoded in D_h.
    """

    def __init__(
        self,
        interceptor: MCPInterceptor,
        sk_bytes: bytes,
        H_id: str,
        tool_executor: Callable[[str, dict], str] | None = None,
        auto_decision: str = "RESUME",
        rationale: str = "Automated governance approval for experiment.",
        scope: str = "single tool call",
    ) -> None:
        self._interceptor = interceptor
        self._sk_bytes = sk_bytes
        self._H_id = H_id
        self._executor = tool_executor or _default_executor
        self._auto_decision = auto_decision
        self._rationale = rationale
        self._scope = scope

        self._steps: list[dict[str, Any]] = []
        self._step_counter = 0

    # -----------------------------------------------------------------------
    # Core interface
    # -----------------------------------------------------------------------

    def call_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Execute one governed tool call.

        Returns a step record dict with fields:
          step, tool, args, outcome, apb_valid, apb_decision,
          apb_evidence_id, result, D_hat_before, D_hat_after
        """
        self._step_counter += 1
        D_hat_before = self._interceptor.current_drift

        record: dict[str, Any] = {
            "step":           self._step_counter,
            "tool":           tool_name,
            "args":           args,
            "outcome":        None,
            "apb_valid":      None,
            "apb_decision":   None,
            "apb_evidence_id": None,
            "apb_rejected":   None,
            "result":         None,
            "D_hat_before":   round(D_hat_before, 4),
            "D_hat_after":    None,
        }

        # 1. Intercept
        outcome, payload = self._interceptor.intercept_tool_call(tool_name, args)
        record["outcome"] = outcome
        record["D_hat_after"] = round(self._interceptor.current_drift, 4)

        if outcome == "ADMIT":
            record["result"] = self._executor(tool_name, args)

        elif outcome == "APB_REQUIRED":
            record = self._handle_apb_required(record, payload, tool_name, args)

        elif outcome == "DENY":
            record["result"] = f"[DENY] {payload}"

        self._steps.append(record)
        return record

    # -----------------------------------------------------------------------
    # APB construction and response
    # -----------------------------------------------------------------------

    def _handle_apb_required(
        self,
        record: dict[str, Any],
        apb_req: APBRequired,
        tool_name: str,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        """Build, sign, submit APB; update record."""
        evidence_id = apb_req.evidence_id
        record["apb_evidence_id"] = evidence_id

        # Reconstruct E_s from evidence_summary (as transmitted over protocol).
        # Filter out P9 delegation metadata (delegation_chain, originator) that
        # may be present for A2A sessions but are not part of the base E_s schema.
        _E_S_FIELDS = frozenset(
            {"A_0_hash", "D_hat", "t_e", "trace_hash", "cause", "event_id"}
        )
        es_dict = {k: v for k, v in apb_req.evidence_summary.items()
                   if k in _E_S_FIELDS}
        E_s = SystemEvidenceBlock.from_dict(es_dict)

        # Build D_h
        D_h = HumanDecisionBlock(
            H_id=self._H_id,
            decision=self._auto_decision,
            rationale=self._rationale,
            scope=self._scope,
        )

        # Sign APB
        apb = APB.construct(E_s=E_s, D_h=D_h, private_key_bytes=self._sk_bytes)
        apb_json = apb.to_json()

        # Submit APBResponse
        apb_response = APBResponse(
            evidence_id=evidence_id,
            apb_json=apb_json,
        )
        status, result = self._interceptor.handle_apb_response(apb_response)

        if status == "RESOLVED":
            decision: GovernanceDecision = result
            record["apb_valid"]    = True
            record["apb_decision"] = decision.value

            # Verify locally for audit
            report = verify_apb(apb, self._interceptor.registry)
            record["apb_verified"] = report.is_valid

            if decision == GovernanceDecision.RESUME:
                record["result"] = self._executor(tool_name, args)
            else:
                record["result"] = f"[{decision.value}]"

        else:
            # REJECTED
            record["apb_valid"]    = False
            record["apb_rejected"] = result
            record["result"]       = f"[REJECTED] {result}"

        return record

    # -----------------------------------------------------------------------
    # Accessors and aggregates
    # -----------------------------------------------------------------------

    @property
    def step_log(self) -> list[dict[str, Any]]:
        return list(self._steps)

    @property
    def n_steps(self) -> int:
        return self._step_counter

    def summary(self) -> dict[str, Any]:
        """Aggregate statistics over all steps."""
        n_admit    = sum(1 for s in self._steps if s["outcome"] == "ADMIT")
        n_halt     = sum(1 for s in self._steps if s["outcome"] == "APB_REQUIRED")
        n_deny     = sum(1 for s in self._steps if s["outcome"] == "DENY")
        n_resume   = sum(1 for s in self._steps
                         if s.get("apb_decision") == "RESUME")
        n_apb_valid   = sum(1 for s in self._steps
                            if s.get("apb_valid") is True)
        n_apb_invalid = sum(1 for s in self._steps
                            if s.get("apb_valid") is False)
        n_verified    = sum(1 for s in self._steps
                            if s.get("apb_verified") is True)

        D_hats = [s["D_hat_after"] for s in self._steps
                  if s["D_hat_after"] is not None]
        D_hat_at_first_halt: float | None = None
        for s in self._steps:
            if s["outcome"] == "APB_REQUIRED":
                D_hat_at_first_halt = s["D_hat_after"]
                break

        return {
            "n_total":            self._step_counter,
            "n_admit":            n_admit,
            "n_halt":             n_halt,
            "n_deny":             n_deny,
            "n_resume":           n_resume,
            "n_apb_issued":       n_halt,
            "n_apb_valid":        n_apb_valid,
            "n_apb_invalid":      n_apb_invalid,
            "n_apb_verified":     n_verified,
            "D_hat_at_first_halt": D_hat_at_first_halt,
            "D_hat_final":        round(D_hats[-1], 4) if D_hats else 0.0,
            "T9_1_hold":          n_halt > 0 and n_resume == n_halt,
        }
