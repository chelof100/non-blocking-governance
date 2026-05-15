# -*- coding: utf-8 -*-
"""Tests for stack/apb_verifier.py — covers the 4 attack vectors of Exp B."""
import time
from datetime import datetime, timedelta, timezone

import pytest

from agent.principal import (
    Principal,
    PrincipalRegistry,
    generate_keypair,
)
from stack.apb import (
    APB,
    HumanDecisionBlock,
    SystemEvidenceBlock,
)
from stack.apb_verifier import (
    VerificationResult,
    attribute,
    verify_apb,
    verify_signature,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def alice():
    sk, pk = generate_keypair()
    return {"H_id": "H_alice", "sk": sk, "pk": pk}


@pytest.fixture
def bob():
    sk, pk = generate_keypair()
    return {"H_id": "H_bob", "sk": sk, "pk": pk}


@pytest.fixture
def registry(alice, bob):
    reg = PrincipalRegistry()
    reg.add(Principal(H_id=alice["H_id"], public_key=alice["pk"]))
    reg.add(Principal(H_id=bob["H_id"], public_key=bob["pk"]))
    return reg


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mk_E_s(t_e: str = None) -> SystemEvidenceBlock:
    return SystemEvidenceBlock(
        A_0_hash="a" * 64,
        D_hat=0.345,
        t_e=t_e or _now_iso(),
        trace_hash="b" * 64,
        cause="persistent_drift",
    )


def _mk_D_h(H_id: str, decision: str = "RESUME") -> HumanDecisionBlock:
    return HumanDecisionBlock(
        H_id=H_id,
        decision=decision,
        rationale="manual review",
        scope="next 100 steps",
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_verify_valid_apb(alice, registry):
    apb = APB.construct(_mk_E_s(), _mk_D_h(alice["H_id"]), alice["sk"])
    report = verify_apb(apb, registry)
    assert report.is_valid
    assert report.result is VerificationResult.VALID


def test_verify_signature_only(alice):
    apb = APB.construct(_mk_E_s(), _mk_D_h(alice["H_id"]), alice["sk"])
    assert verify_signature(apb, alice["pk"]) is True


def test_attribute_returns_signer(alice, registry):
    apb = APB.construct(_mk_E_s(), _mk_D_h(alice["H_id"]), alice["sk"])
    assert attribute(apb, registry) == alice["H_id"]


# ---------------------------------------------------------------------------
# Attack vector 1: tamper E_s field by field (Exp B)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field,new_value", [
    ("A_0_hash", "c" * 64),
    ("D_hat", 0.999),
    ("t_e", "2030-01-01T00:00:00+00:00"),
    ("trace_hash", "d" * 64),
    ("cause", "different_reason"),
])
def test_tamper_E_s_field_breaks_verification(alice, registry, field, new_value):
    apb = APB.construct(_mk_E_s(), _mk_D_h(alice["H_id"]), alice["sk"])
    tampered_E_s_dict = apb.E_s.to_dict()
    tampered_E_s_dict[field] = new_value
    tampered = APB(
        E_s=SystemEvidenceBlock.from_dict(tampered_E_s_dict),
        D_h=apb.D_h,
        sigma_h=apb.sigma_h,
    )
    report = verify_apb(tampered, registry)
    assert not report.is_valid
    # Field tampering breaks the signature; t_e tampering may also trip
    # replay if the new value is far in the future.
    assert report.result in {
        VerificationResult.INVALID_SIGNATURE,
        VerificationResult.REPLAY,
    }


# ---------------------------------------------------------------------------
# Attack vector 2: forge sigma_h without sk_i
# ---------------------------------------------------------------------------

def test_forge_signature_with_random_key_fails(alice, registry):
    """Sign with a key that isn't alice's; verifier should reject (T8.3)."""
    fake_sk, _ = generate_keypair()
    apb = APB.construct(_mk_E_s(), _mk_D_h(alice["H_id"]), fake_sk)
    report = verify_apb(apb, registry)
    assert report.result is VerificationResult.INVALID_SIGNATURE


def test_forge_signature_with_random_bytes_fails(alice, registry):
    apb_real = APB.construct(_mk_E_s(), _mk_D_h(alice["H_id"]), alice["sk"])
    forged = APB(E_s=apb_real.E_s, D_h=apb_real.D_h, sigma_h=b"\x00" * 64)
    report = verify_apb(forged, registry)
    assert report.result is VerificationResult.INVALID_SIGNATURE


# ---------------------------------------------------------------------------
# Attack vector 3: identity swap
# ---------------------------------------------------------------------------

def test_identity_swap_breaks_attribution(alice, bob, registry):
    """Alice signs, attacker rewrites D_h.H_id to bob — verification should
    fail because bob's pk does not verify alice's signature (T8.3)."""
    apb_real = APB.construct(_mk_E_s(), _mk_D_h(alice["H_id"]), alice["sk"])
    swapped = APB(
        E_s=apb_real.E_s,
        D_h=_mk_D_h(bob["H_id"]),  # different H_id
        sigma_h=apb_real.sigma_h,
    )
    report = verify_apb(swapped, registry)
    assert report.result is VerificationResult.INVALID_SIGNATURE
    assert attribute(swapped, registry) is None


# ---------------------------------------------------------------------------
# Attack vector 4: replay
# ---------------------------------------------------------------------------

def test_replay_old_apb_rejected(alice, registry):
    old_t_e = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    apb = APB.construct(_mk_E_s(t_e=old_t_e), _mk_D_h(alice["H_id"]), alice["sk"])
    report = verify_apb(apb, registry, max_age_seconds=300.0)
    assert report.result is VerificationResult.REPLAY


def test_future_apb_rejected_clock_skew(alice, registry):
    future_t_e = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    apb = APB.construct(_mk_E_s(t_e=future_t_e), _mk_D_h(alice["H_id"]), alice["sk"])
    report = verify_apb(apb, registry, max_age_seconds=300.0)
    assert report.result is VerificationResult.REPLAY


def test_apb_within_window_accepted(alice, registry):
    apb = APB.construct(_mk_E_s(), _mk_D_h(alice["H_id"]), alice["sk"])
    report = verify_apb(apb, registry, max_age_seconds=600.0)
    assert report.is_valid


# ---------------------------------------------------------------------------
# Principal lifecycle
# ---------------------------------------------------------------------------

def test_unknown_principal_rejected(alice):
    reg = PrincipalRegistry()  # alice not registered
    apb = APB.construct(_mk_E_s(), _mk_D_h(alice["H_id"]), alice["sk"])
    report = verify_apb(apb, reg)
    assert report.result is VerificationResult.PRINCIPAL_NOT_FOUND


def test_revoked_principal_rejected(alice, registry):
    """Sign FIRST, then revoke immediately, then verify — should fail."""
    sign_t_e = _now_iso()
    time.sleep(0.01)
    registry.revoke(alice["H_id"])
    apb = APB.construct(_mk_E_s(t_e=sign_t_e), _mk_D_h(alice["H_id"]), alice["sk"])
    # Sign was AFTER revocation here is_active("H_alice", at_time=sign_t_e) —
    # but pre_revoke timestamp was BEFORE revoke. We want to test the case
    # where t_e is AFTER revocation:
    post_revoke_t_e = (datetime.now(timezone.utc) + timedelta(seconds=5)).isoformat()
    apb_post = APB.construct(
        _mk_E_s(t_e=post_revoke_t_e), _mk_D_h(alice["H_id"]), alice["sk"]
    )
    report = verify_apb(apb_post, registry, max_age_seconds=600.0)
    assert report.result is VerificationResult.PRINCIPAL_REVOKED


def test_apb_signed_before_revocation_remains_valid(alice, registry):
    """Pre-revocation APBs preserve historical validity."""
    pre_revoke_t_e = _now_iso()
    apb = APB.construct(_mk_E_s(t_e=pre_revoke_t_e), _mk_D_h(alice["H_id"]), alice["sk"])
    time.sleep(0.01)
    registry.revoke(alice["H_id"])
    report = verify_apb(apb, registry, max_age_seconds=600.0)
    assert report.is_valid
