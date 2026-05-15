# -*- coding: utf-8 -*-
"""Tests for stack/apb.py."""
import json

import pytest

from agent.principal import generate_keypair, load_public_key
from stack.apb import (
    APB,
    GovernanceDecision,
    HumanDecisionBlock,
    SystemEvidenceBlock,
    construct_evidence,
    hash_object,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Fixed event_id for deterministic tests (UUID4 format, version=4, variant=a)
_FIXED_EVENT_ID = "00000000-0000-4000-a000-000000000001"


def _mk_E_s() -> SystemEvidenceBlock:
    return SystemEvidenceBlock(
        A_0_hash="a" * 64,
        D_hat=0.345,
        t_e="2026-05-07T10:30:00+00:00",
        trace_hash="b" * 64,
        cause="persistent_drift",
        event_id=_FIXED_EVENT_ID,
    )


def _mk_D_h(H_id: str = "H_alice", decision: str = "RESUME") -> HumanDecisionBlock:
    return HumanDecisionBlock(
        H_id=H_id,
        decision=decision,
        rationale="manual review of drift trace; benign cause identified",
        scope="single resumption authorized for next 100 steps",
    )


# ---------------------------------------------------------------------------
# SystemEvidenceBlock
# ---------------------------------------------------------------------------

def test_E_s_canonical_is_deterministic():
    e1 = _mk_E_s()
    e2 = _mk_E_s()
    assert e1.to_canonical_bytes() == e2.to_canonical_bytes()


def test_E_s_canonical_sorted_keys():
    e = _mk_E_s()
    raw = e.to_canonical_bytes().decode()
    # RFC 8785: keys sorted by Unicode codepoint; event_id sorts after D_hat, before t_e
    keys_in_order = ["A_0_hash", "D_hat", "cause", "event_id", "t_e", "trace_hash"]
    found = [raw.index(f'"{k}":') for k in keys_in_order]
    assert found == sorted(found), "canonical JSON must have keys in sorted order"


def test_E_s_roundtrip_dict():
    e = _mk_E_s()
    e2 = SystemEvidenceBlock.from_dict(e.to_dict())
    assert e == e2


def test_E_s_is_frozen():
    e = _mk_E_s()
    with pytest.raises(Exception):
        e.D_hat = 0.999


# ---------------------------------------------------------------------------
# HumanDecisionBlock
# ---------------------------------------------------------------------------

def test_D_h_roundtrip():
    d = _mk_D_h()
    d2 = HumanDecisionBlock.from_dict(d.to_dict())
    assert d == d2


def test_D_h_is_frozen():
    d = _mk_D_h()
    with pytest.raises(Exception):
        d.decision = "DENY"


# ---------------------------------------------------------------------------
# APB construction & verification math
# ---------------------------------------------------------------------------

def test_apb_construct_signature_length():
    sk, pk = generate_keypair()
    apb = APB.construct(_mk_E_s(), _mk_D_h(), sk)
    assert len(apb.sigma_h) == 64


def test_apb_signature_verifies_with_pk():
    sk, pk = generate_keypair()
    apb = APB.construct(_mk_E_s(), _mk_D_h(), sk)
    pk_obj = load_public_key(pk)
    # Should not raise: signature valid against the canonical message
    pk_obj.verify(apb.sigma_h, apb.message_to_sign())


def test_apb_signature_fails_with_other_pk():
    sk_a, pk_a = generate_keypair()
    sk_b, pk_b = generate_keypair()
    apb = APB.construct(_mk_E_s(), _mk_D_h(), sk_a)
    pk_other = load_public_key(pk_b)
    with pytest.raises(Exception):
        pk_other.verify(apb.sigma_h, apb.message_to_sign())


def test_apb_invalid_signature_length_rejected():
    with pytest.raises(ValueError, match="64 bytes"):
        APB(E_s=_mk_E_s(), D_h=_mk_D_h(), sigma_h=b"too short")


def test_apb_is_frozen():
    sk, pk = generate_keypair()
    apb = APB.construct(_mk_E_s(), _mk_D_h(), sk)
    with pytest.raises(Exception):
        apb.sigma_h = b"\x00" * 64


# ---------------------------------------------------------------------------
# Tampering detection (foundation for T8.2)
# ---------------------------------------------------------------------------

def test_tampered_E_s_breaks_signature():
    sk, pk = generate_keypair()
    apb = APB.construct(_mk_E_s(), _mk_D_h(), sk)
    pk_obj = load_public_key(pk)

    # Build a tampered APB with modified E_s but original sigma_h
    tampered_E_s = SystemEvidenceBlock(
        A_0_hash="a" * 64,
        D_hat=0.999,                 # CHANGED
        t_e="2026-05-07T10:30:00+00:00",
        trace_hash="b" * 64,
        cause="persistent_drift",
    )
    tampered = APB(E_s=tampered_E_s, D_h=apb.D_h, sigma_h=apb.sigma_h)

    with pytest.raises(Exception):
        pk_obj.verify(tampered.sigma_h, tampered.message_to_sign())


def test_tampered_D_h_breaks_signature():
    sk, pk = generate_keypair()
    apb = APB.construct(_mk_E_s(), _mk_D_h(decision="RESUME"), sk)
    pk_obj = load_public_key(pk)

    tampered = APB(
        E_s=apb.E_s,
        D_h=_mk_D_h(decision="DENY"),  # CHANGED
        sigma_h=apb.sigma_h,
    )
    with pytest.raises(Exception):
        pk_obj.verify(tampered.sigma_h, tampered.message_to_sign())


# ---------------------------------------------------------------------------
# Serialization roundtrip
# ---------------------------------------------------------------------------

def test_apb_json_roundtrip_preserves_signature():
    sk, pk = generate_keypair()
    apb = APB.construct(_mk_E_s(), _mk_D_h(), sk)
    s = apb.to_json()
    apb2 = APB.from_json(s)
    assert apb == apb2
    # And the signature still verifies after roundtrip
    load_public_key(pk).verify(apb2.sigma_h, apb2.message_to_sign())


# ---------------------------------------------------------------------------
# construct_evidence (T8.4 helpers)
# ---------------------------------------------------------------------------

def test_construct_evidence_produces_E_s():
    fake_A0 = {"theta": 0.20, "alpha": 0.05}
    fake_trace = {"events": [1, 2, 3]}
    e = construct_evidence(fake_A0, 0.34, fake_trace, "persistent_drift")
    assert isinstance(e, SystemEvidenceBlock)
    assert e.D_hat == 0.34
    assert e.cause == "persistent_drift"
    assert len(e.A_0_hash) == 64
    assert len(e.trace_hash) == 64


def test_construct_evidence_deterministic_given_all_inputs():
    """All inputs including event_id must be fixed for determinism."""
    a0 = {"theta": 0.20}
    tr = {"events": [1, 2, 3]}
    eid = _FIXED_EVENT_ID
    e1 = construct_evidence(a0, 0.5, tr, "X", t_e="2026-01-01T00:00:00+00:00",
                            event_id=eid)
    e2 = construct_evidence(a0, 0.5, tr, "X", t_e="2026-01-01T00:00:00+00:00",
                            event_id=eid)
    assert e1 == e2


# ---------------------------------------------------------------------------
# GovernanceDecision enum
# ---------------------------------------------------------------------------

def test_governance_decision_values():
    assert GovernanceDecision.RESUME == "RESUME"
    assert GovernanceDecision.DENY == "DENY"
    assert GovernanceDecision.RECALIBRATE == "RECALIBRATE"
