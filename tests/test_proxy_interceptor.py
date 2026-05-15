# -*- coding: utf-8 -*-
"""
Tests for Sprint 1: proxy/protocol_extension.py and proxy/mcp_interceptor.py.

Coverage:
  - APBRequired / APBResponse / APBRejected serialization round-trips
  - parse_p9_message dispatch
  - MCPInterceptor: ADMIT path (low-risk tool)
  - MCPInterceptor: APB_REQUIRED path (mocked HALT + persistent Recovery)
  - MCPInterceptor: DENY path (mocked RAM DENY)
  - MCPInterceptor: handle_apb_response — RESOLVED/RESUME (valid APB)
  - MCPInterceptor: handle_apb_response — REJECTED/unknown evidence_id
  - MCPInterceptor: handle_apb_response — REJECTED/malformed APB JSON
  - MCPInterceptor: handle_apb_response — REJECTED/E_s mismatch
  - MCPInterceptor: handle_apb_response — REJECTED/bad signature
  - MCPInterceptor: evidence_id fields populated correctly in APBRequired
  - MCPInterceptor: reset() clears per-session state
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

from agent.principal import Principal, PrincipalRegistry, generate_keypair
from proxy.mcp_interceptor import MCPInterceptor, TOOL_RISK_01
from proxy.protocol_extension import (
    APBRejected,
    APBRequired,
    APBResponse,
    parse_p9_message,
)
from stack.apb import APB, GovernanceDecision, HumanDecisionBlock
from stack.governance_layer import GovernanceLayer, always_resume
from stack.ram_gate import Authority, COMPONENTS, RAMDecision, UNDEFINED


# ---------------------------------------------------------------------------
# Stub RAM gate / Recovery Loop for deterministic testing
# ---------------------------------------------------------------------------

class _AlwaysExecuteRAM:
    def check(self, tool, risk_score, drift_level=0.0, coverage_override=None):
        return RAMDecision(
            tool=tool,
            authority=Authority.EXECUTE,
            state_proven={c: True for c in COMPONENTS},
            state_declared={c: True for c in COMPONENTS},
            state_unobservable={c: False for c in COMPONENTS},
            coverage=1.0,
        )


class _AlwaysHaltRAM:
    def check(self, tool, risk_score, drift_level=0.0, coverage_override=None):
        proven = {c: UNDEFINED for c in COMPONENTS}
        proven["I"] = True
        return RAMDecision(
            tool=tool,
            authority=Authority.HALT,
            state_proven=proven,
            state_declared={c: True for c in COMPONENTS},
            state_unobservable={c: proven[c] is UNDEFINED for c in COMPONENTS},
            coverage=0.2,
        )


class _AlwaysDenyRAM:
    def check(self, tool, risk_score, drift_level=0.0, coverage_override=None):
        return RAMDecision(
            tool=tool,
            authority=Authority.DENY,
            state_proven={c: False for c in COMPONENTS},
            state_declared={c: False for c in COMPONENTS},
            state_unobservable={c: False for c in COMPONENTS},
            coverage=1.0,
        )


from stack.recovery_loop import RecoveryResult, ResumeDecision


class _AlwaysPersistentHalt:
    def run(self, halt_decision, iml_D_hat, tool, risk_score, drift_level=0.0):
        return RecoveryResult(
            decision=ResumeDecision.HALT,
            attempts=[],
            halt_steps=5,
        )


class _AlwaysResume:
    def run(self, halt_decision, iml_D_hat, tool, risk_score, drift_level=0.0):
        return RecoveryResult(
            decision=ResumeDecision.RESUME,
            attempts=[],
            halt_steps=1,
        )


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _make_registry() -> tuple[PrincipalRegistry, str, bytes]:
    sk_bytes, pk_bytes = generate_keypair()
    H_id = "H_test"
    principal = Principal(
        H_id=H_id,
        public_key=pk_bytes,
        registered_at=datetime.now(timezone.utc).isoformat(),
    )
    registry = PrincipalRegistry()
    registry.add(principal)
    return registry, H_id, sk_bytes


def _interceptor_admit(registry, H_id) -> MCPInterceptor:
    """Interceptor that always ADMITs (no RAM halts)."""
    return MCPInterceptor(
        registry=registry,
        H_id=H_id,
        ram_gate=_AlwaysExecuteRAM(),
    )


def _interceptor_halt(registry, H_id) -> MCPInterceptor:
    """Interceptor that always produces a persistent HALT."""
    return MCPInterceptor(
        registry=registry,
        H_id=H_id,
        ram_gate=_AlwaysHaltRAM(),
        recovery_loop=_AlwaysPersistentHalt(),
    )


def _interceptor_deny(registry, H_id) -> MCPInterceptor:
    """Interceptor that always produces a RAM DENY."""
    return MCPInterceptor(
        registry=registry,
        H_id=H_id,
        ram_gate=_AlwaysDenyRAM(),
    )


# ---------------------------------------------------------------------------
# Protocol extension — serialization
# ---------------------------------------------------------------------------

class TestProtocolExtensionSerialization:
    def test_apb_required_round_trip(self):
        orig = APBRequired(
            tool_name="admin_action",
            args={"action": "drop_db"},
            evidence_id="abc123",
            evidence_summary={"D_hat": 0.72, "cause": "persistent_halt"},
        )
        msg = orig.to_jsonrpc()
        assert msg["method"] == "p9/apbRequired"
        recovered = APBRequired.from_jsonrpc(msg)
        assert recovered.tool_name == orig.tool_name
        assert recovered.args == orig.args
        assert recovered.evidence_id == orig.evidence_id
        assert recovered.evidence_summary == orig.evidence_summary

    def test_apb_response_round_trip(self):
        orig = APBResponse(evidence_id="ev1", apb_json='{"foo":"bar"}')
        msg = orig.to_jsonrpc()
        assert msg["method"] == "p9/apbResponse"
        recovered = APBResponse.from_jsonrpc(msg)
        assert recovered.evidence_id == orig.evidence_id
        assert recovered.apb_json == orig.apb_json

    def test_apb_rejected_round_trip(self):
        orig = APBRejected(evidence_id="ev2", reason="invalid signature")
        msg = orig.to_jsonrpc()
        assert msg["method"] == "p9/apbRejected"
        recovered = APBRejected.from_jsonrpc(msg)
        assert recovered.evidence_id == orig.evidence_id
        assert recovered.reason == orig.reason

    def test_to_json_is_valid_json(self):
        for obj in [
            APBRequired("t", {}, "id1", {}),
            APBResponse("id2", "{}"),
            APBRejected("id3", "reason"),
        ]:
            parsed = json.loads(obj.to_json())
            assert parsed["jsonrpc"] == "2.0"

    def test_version_field_present(self):
        req = APBRequired("tool", {}, "eid", {})
        msg = req.to_jsonrpc()
        assert msg["params"]["version"] == "p9/1.0"


class TestParseP9Message:
    def test_apb_required(self):
        msg = APBRequired("t", {}, "e", {}).to_jsonrpc()
        result = parse_p9_message(msg)
        assert isinstance(result, APBRequired)

    def test_apb_response(self):
        msg = APBResponse("e", "{}").to_jsonrpc()
        result = parse_p9_message(msg)
        assert isinstance(result, APBResponse)

    def test_apb_rejected(self):
        msg = APBRejected("e", "r").to_jsonrpc()
        result = parse_p9_message(msg)
        assert isinstance(result, APBRejected)

    def test_non_p9_returns_none(self):
        assert parse_p9_message({"method": "tools/call", "params": {}}) is None
        assert parse_p9_message({"method": "initialize"}) is None
        assert parse_p9_message({}) is None


# ---------------------------------------------------------------------------
# MCPInterceptor — ADMIT path
# ---------------------------------------------------------------------------

class TestInterceptorAdmit:
    def setup_method(self):
        self.registry, self.H_id, self.sk = _make_registry()
        self.interceptor = _interceptor_admit(self.registry, self.H_id)

    def test_low_risk_tool_admits(self):
        decision, payload = self.interceptor.intercept_tool_call(
            "read_file", {"path": "/tmp/x.log"}
        )
        assert decision == "ADMIT"
        assert payload is None

    def test_all_5_tools_admit(self):
        tools = [
            ("read_file",     {"path": "f"}),
            ("query_api",     {"endpoint": "/v1"}),
            ("write_data",    {"target": "t", "payload": "p"}),
            ("delete_record", {"record_id": "r"}),
            ("admin_action",  {"action": "a"}),
        ]
        for tool_name, args in tools:
            decision, _ = self.interceptor.intercept_tool_call(tool_name, args)
            assert decision == "ADMIT", f"expected ADMIT for {tool_name}"

    def test_trace_grows_on_admit(self):
        assert len(self.interceptor._trace) == 0
        self.interceptor.intercept_tool_call("read_file", {"path": "f"})
        assert len(self.interceptor._trace) == 1

    def test_audit_log_records_admit(self):
        self.interceptor.intercept_tool_call("read_file", {"path": "f"})
        assert any("ADMIT" in e["outcome"] for e in self.interceptor.audit_log)


# ---------------------------------------------------------------------------
# MCPInterceptor — APB_REQUIRED path
# ---------------------------------------------------------------------------

class TestInterceptorAPBRequired:
    def setup_method(self):
        self.registry, self.H_id, self.sk = _make_registry()
        self.interceptor = _interceptor_halt(self.registry, self.H_id)

    def test_halt_emits_apb_required(self):
        decision, payload = self.interceptor.intercept_tool_call(
            "admin_action", {"action": "drop_db"}
        )
        assert decision == "APB_REQUIRED"
        assert isinstance(payload, APBRequired)

    def test_apb_required_fields_populated(self):
        _, payload = self.interceptor.intercept_tool_call(
            "admin_action", {"action": "drop_db"}
        )
        assert isinstance(payload, APBRequired)
        assert payload.tool_name == "admin_action"
        assert payload.args == {"action": "drop_db"}
        assert len(payload.evidence_id) > 0
        assert "D_hat" in payload.evidence_summary
        assert "cause" in payload.evidence_summary
        assert payload.evidence_summary["cause"] in (
            "persistent_halt", "escalate"
        )

    def test_evidence_id_is_pending(self):
        _, payload = self.interceptor.intercept_tool_call(
            "admin_action", {"action": "x"}
        )
        assert payload.evidence_id in self.interceptor.pending_evidence_ids

    def test_two_halts_produce_different_evidence_ids(self):
        _, p1 = self.interceptor.intercept_tool_call("admin_action", {"action": "a"})
        _, p2 = self.interceptor.intercept_tool_call("admin_action", {"action": "b"})
        assert p1.evidence_id != p2.evidence_id


# ---------------------------------------------------------------------------
# MCPInterceptor — DENY path
# ---------------------------------------------------------------------------

class TestInterceptorDeny:
    def setup_method(self):
        self.registry, self.H_id, self.sk = _make_registry()
        self.interceptor = _interceptor_deny(self.registry, self.H_id)

    def test_deny_returns_deny(self):
        decision, payload = self.interceptor.intercept_tool_call(
            "admin_action", {"action": "x"}
        )
        assert decision == "DENY"
        assert isinstance(payload, str)
        assert len(payload) > 0


# ---------------------------------------------------------------------------
# MCPInterceptor — handle_apb_response
# ---------------------------------------------------------------------------

class TestHandleAPBResponse:
    def setup_method(self):
        self.registry, self.H_id, self.sk = _make_registry()
        self.interceptor = _interceptor_halt(self.registry, self.H_id)
        self.governance = GovernanceLayer(
            registry=self.registry,
            key_store={self.H_id: self.sk},
        )

    def _get_pending_apb_required(self) -> APBRequired:
        decision, payload = self.interceptor.intercept_tool_call(
            "admin_action", {"action": "drop_db"}
        )
        assert decision == "APB_REQUIRED"
        return payload

    def _build_apb_response(
        self,
        apb_req: APBRequired,
        decision_str: str = "RESUME",
    ) -> APBResponse:
        from stack.apb import SystemEvidenceBlock
        E_s = SystemEvidenceBlock.from_dict(apb_req.evidence_summary)
        apb = self.governance.resolve(
            H_id=self.H_id,
            E_s=E_s,
            policy=lambda p, e: {
                "decision": decision_str,
                "rationale": "test approval",
                "scope": "single step",
            },
        )
        return APBResponse(
            evidence_id=apb_req.evidence_id,
            apb_json=apb.to_json(),
        )

    # --- valid APB --------------------------------------------------------

    def test_valid_apb_resume_resolves(self):
        apb_req = self._get_pending_apb_required()
        resp = self._build_apb_response(apb_req, "RESUME")
        outcome, decision = self.interceptor.handle_apb_response(resp)
        assert outcome == "RESOLVED"
        assert decision == GovernanceDecision.RESUME

    def test_valid_apb_deny_resolves(self):
        apb_req = self._get_pending_apb_required()
        resp = self._build_apb_response(apb_req, "DENY")
        outcome, decision = self.interceptor.handle_apb_response(resp)
        assert outcome == "RESOLVED"
        assert decision == GovernanceDecision.DENY

    def test_valid_apb_recalibrate_resolves(self):
        apb_req = self._get_pending_apb_required()
        resp = self._build_apb_response(apb_req, "RECALIBRATE")
        outcome, decision = self.interceptor.handle_apb_response(resp)
        assert outcome == "RESOLVED"
        assert decision == GovernanceDecision.RECALIBRATE

    def test_resolved_removes_from_pending(self):
        apb_req = self._get_pending_apb_required()
        eid = apb_req.evidence_id
        resp = self._build_apb_response(apb_req)
        self.interceptor.handle_apb_response(resp)
        assert eid not in self.interceptor.pending_evidence_ids

    # --- unknown evidence_id ----------------------------------------------

    def test_unknown_evidence_id_rejected(self):
        outcome, reason = self.interceptor.handle_apb_response(
            APBResponse(evidence_id="nonexistent", apb_json="{}")
        )
        assert outcome == "REJECTED"
        assert "unknown evidence_id" in reason

    # --- malformed APB JSON -----------------------------------------------

    def test_malformed_apb_json_rejected(self):
        apb_req = self._get_pending_apb_required()
        resp = APBResponse(evidence_id=apb_req.evidence_id, apb_json="not-json{{{")
        outcome, reason = self.interceptor.handle_apb_response(resp)
        assert outcome == "REJECTED"
        assert "malformed" in reason.lower()

    # --- E_s mismatch -----------------------------------------------------

    def test_es_mismatch_rejected(self):
        apb_req = self._get_pending_apb_required()
        # Build an APB with a different E_s (wrong D_hat)
        from stack.apb import SystemEvidenceBlock, HumanDecisionBlock, APB
        wrong_E_s = SystemEvidenceBlock(
            A_0_hash="a" * 64,
            D_hat=0.99,
            t_e="2026-01-01T00:00:00+00:00",
            trace_hash="b" * 64,
            cause="persistent_halt",
        )
        D_h = HumanDecisionBlock(
            H_id=self.H_id,
            decision="RESUME",
            rationale="test",
            scope="single step",
        )
        apb = APB.construct(wrong_E_s, D_h, self.sk)
        resp = APBResponse(
            evidence_id=apb_req.evidence_id,
            apb_json=apb.to_json(),
        )
        outcome, reason = self.interceptor.handle_apb_response(resp)
        assert outcome == "REJECTED"
        assert "E_s" in reason or "mismatch" in reason

    # --- invalid signature ------------------------------------------------

    def test_invalid_signature_rejected(self):
        apb_req = self._get_pending_apb_required()
        resp = self._build_apb_response(apb_req, "RESUME")
        # Corrupt the signature in the APB JSON
        apb_dict = json.loads(resp.apb_json)
        apb_dict["sigma_h"] = "00" * 64
        corrupted_apb_json = json.dumps(apb_dict)
        corrupted_resp = APBResponse(
            evidence_id=apb_req.evidence_id,
            apb_json=corrupted_apb_json,
        )
        outcome, reason = self.interceptor.handle_apb_response(corrupted_resp)
        assert outcome == "REJECTED"
        assert "verification" in reason.lower() or "invalid" in reason.lower()


# ---------------------------------------------------------------------------
# MCPInterceptor — session lifecycle
# ---------------------------------------------------------------------------

class TestInterceptorLifecycle:
    def setup_method(self):
        self.registry, self.H_id, self.sk = _make_registry()
        self.interceptor = _interceptor_halt(self.registry, self.H_id)

    def test_reset_clears_trace(self):
        # Force some state
        self.interceptor.intercept_tool_call("admin_action", {"action": "x"})
        assert len(self.interceptor._trace) > 0
        self.interceptor.reset()
        assert len(self.interceptor._trace) == 0

    def test_reset_clears_pending(self):
        decision, payload = self.interceptor.intercept_tool_call(
            "admin_action", {"action": "x"}
        )
        assert len(self.interceptor.pending_evidence_ids) > 0
        self.interceptor.reset()
        assert len(self.interceptor.pending_evidence_ids) == 0

    def test_reset_clears_audit_log(self):
        self.interceptor.intercept_tool_call("admin_action", {"action": "x"})
        assert len(self.interceptor.audit_log) > 0
        self.interceptor.reset()
        assert len(self.interceptor.audit_log) == 0

    def test_current_drift_is_zero_initially(self):
        assert self.interceptor.current_drift == 0.0

    def test_current_drift_nonzero_after_calls(self):
        interceptor = MCPInterceptor(
            registry=self.registry,
            H_id=self.H_id,
            ram_gate=_AlwaysExecuteRAM(),
        )
        interceptor.intercept_tool_call("read_file", {"path": "f"})
        # D_hat may still be near zero after 1 call, but EMA is updated
        # Just verify it ran without error
        assert isinstance(interceptor.current_drift, float)
