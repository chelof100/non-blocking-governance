# -*- coding: utf-8 -*-
"""Tests for stack/governance_layer.py."""
import pytest

from agent.principal import Principal, PrincipalRegistry, generate_keypair
from stack.apb import GovernanceDecision, SystemEvidenceBlock
from stack.apb_verifier import verify_apb
from stack.governance_layer import (
    GovernanceError,
    GovernanceLayer,
    always_deny,
    always_resume,
    threshold_policy,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def setup():
    sk_a, pk_a = generate_keypair()
    sk_b, pk_b = generate_keypair()
    reg = PrincipalRegistry()
    reg.add(Principal(H_id="H_alice", public_key=pk_a))
    reg.add(Principal(H_id="H_bob", public_key=pk_b))
    keys = {"H_alice": sk_a, "H_bob": sk_b}
    return reg, keys


def _mk_E_s(D_hat: float = 0.34) -> SystemEvidenceBlock:
    from datetime import datetime, timezone
    return SystemEvidenceBlock(
        A_0_hash="a" * 64,
        D_hat=D_hat,
        t_e=datetime.now(timezone.utc).isoformat(),
        trace_hash="b" * 64,
        cause="persistent_drift",
    )


# ---------------------------------------------------------------------------
# resolve()
# ---------------------------------------------------------------------------

def test_resolve_produces_signed_apb(setup):
    reg, keys = setup
    G = GovernanceLayer(reg, keys)
    apb = G.resolve("H_alice", _mk_E_s(), always_resume())
    assert apb.D_h.H_id == "H_alice"
    assert apb.D_h.decision == GovernanceDecision.RESUME.value
    # Signature verifies under registered pk
    report = verify_apb(apb, reg, max_age_seconds=600.0)
    assert report.is_valid


def test_resolve_unknown_principal_raises(setup):
    reg, keys = setup
    G = GovernanceLayer(reg, keys)
    with pytest.raises(GovernanceError, match="unknown"):
        G.resolve("H_ghost", _mk_E_s(), always_resume())


def test_resolve_revoked_principal_raises(setup):
    from datetime import datetime, timedelta, timezone
    reg, keys = setup
    reg.revoke("H_alice")
    future_t_e = (datetime.now(timezone.utc) + timedelta(seconds=10)).isoformat()
    G = GovernanceLayer(reg, keys)
    E_s = SystemEvidenceBlock(
        A_0_hash="a" * 64, D_hat=0.3, t_e=future_t_e,
        trace_hash="b" * 64, cause="x",
    )
    with pytest.raises(GovernanceError, match="not active"):
        G.resolve("H_alice", E_s, always_resume())


def test_resolve_missing_private_key_raises(setup):
    reg, keys = setup
    keys_no_alice = {k: v for k, v in keys.items() if k != "H_alice"}
    G = GovernanceLayer(reg, keys_no_alice)
    with pytest.raises(GovernanceError, match="no private key"):
        G.resolve("H_alice", _mk_E_s(), always_resume())


def test_resolve_invalid_decision_raises(setup):
    reg, keys = setup
    G = GovernanceLayer(reg, keys)
    bad_policy = lambda p, e: {"decision": "BANANA", "rationale": "x", "scope": "x"}
    with pytest.raises(GovernanceError, match="invalid decision"):
        G.resolve("H_alice", _mk_E_s(), bad_policy)


def test_resolve_missing_decision_keys_raises(setup):
    reg, keys = setup
    G = GovernanceLayer(reg, keys)
    bad_policy = lambda p, e: {"decision": "RESUME"}
    with pytest.raises(GovernanceError, match="missing key"):
        G.resolve("H_alice", _mk_E_s(), bad_policy)


# ---------------------------------------------------------------------------
# resolve_halt() (E_s built from runtime state)
# ---------------------------------------------------------------------------

def test_resolve_halt_constructs_evidence(setup):
    reg, keys = setup
    G = GovernanceLayer(reg, keys)
    apb = G.resolve_halt(
        H_id="H_alice",
        A_0={"theta": 0.20},
        D_hat=0.42,
        trace={"events": []},
        cause="persistent_drift",
        policy=always_resume(),
    )
    assert apb.E_s.D_hat == 0.42
    assert apb.E_s.cause == "persistent_drift"
    assert verify_apb(apb, reg, max_age_seconds=600.0).is_valid


# ---------------------------------------------------------------------------
# Built-in policies
# ---------------------------------------------------------------------------

def test_always_deny_policy(setup):
    reg, keys = setup
    G = GovernanceLayer(reg, keys)
    apb = G.resolve("H_alice", _mk_E_s(), always_deny())
    assert apb.D_h.decision == GovernanceDecision.DENY.value


def test_threshold_policy_resume(setup):
    reg, keys = setup
    G = GovernanceLayer(reg, keys)
    apb = G.resolve("H_alice", _mk_E_s(D_hat=0.3), threshold_policy(0.5, 0.8))
    assert apb.D_h.decision == GovernanceDecision.RESUME.value


def test_threshold_policy_deny(setup):
    reg, keys = setup
    G = GovernanceLayer(reg, keys)
    apb = G.resolve("H_alice", _mk_E_s(D_hat=0.6), threshold_policy(0.5, 0.8))
    assert apb.D_h.decision == GovernanceDecision.DENY.value


def test_threshold_policy_recalibrate(setup):
    reg, keys = setup
    G = GovernanceLayer(reg, keys)
    apb = G.resolve("H_alice", _mk_E_s(D_hat=0.9), threshold_policy(0.5, 0.8))
    assert apb.D_h.decision == GovernanceDecision.RECALIBRATE.value


# ---------------------------------------------------------------------------
# End-to-end: G + verifier round trip (T8.1 / T8.2 / T8.3 scaffolding)
# ---------------------------------------------------------------------------

def test_e2e_resolve_and_verify_alice_decisions(setup):
    """Generate APBs for a sequence of decisions; all must verify cleanly."""
    reg, keys = setup
    G = GovernanceLayer(reg, keys)
    decisions = [
        ("H_alice", always_resume()),
        ("H_alice", always_deny()),
        ("H_bob", threshold_policy(0.5, 0.8)),
    ]
    for H_id, policy in decisions:
        apb = G.resolve(H_id, _mk_E_s(), policy)
        report = verify_apb(apb, reg, max_age_seconds=600.0)
        assert report.is_valid, f"failed for {H_id}: {report.detail}"
