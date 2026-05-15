# -*- coding: utf-8 -*-
"""Tests for agent/principal.py."""
from datetime import datetime, timezone

import pytest

from agent.principal import (
    Principal,
    PrincipalRegistry,
    generate_keypair,
    load_private_key,
    load_public_key,
)


# ---------------------------------------------------------------------------
# Keypair
# ---------------------------------------------------------------------------

def test_generate_keypair_sizes():
    sk, pk = generate_keypair()
    assert len(sk) == 32
    assert len(pk) == 32


def test_generate_keypair_unique():
    sk1, pk1 = generate_keypair()
    sk2, pk2 = generate_keypair()
    assert sk1 != sk2
    assert pk1 != pk2


def test_load_private_then_derive_public_matches():
    sk, pk = generate_keypair()
    sk_obj = load_private_key(sk)
    derived_pk = sk_obj.public_key().public_bytes_raw()
    assert derived_pk == pk


def test_load_public_key_roundtrip():
    sk, pk = generate_keypair()
    pk_obj = load_public_key(pk)
    assert pk_obj.public_bytes_raw() == pk


# ---------------------------------------------------------------------------
# Principal dataclass
# ---------------------------------------------------------------------------

def test_principal_creation():
    sk, pk = generate_keypair()
    p = Principal(H_id="H_alice", public_key=pk, role="auditor")
    assert p.H_id == "H_alice"
    assert p.public_key == pk
    assert p.role == "auditor"


def test_principal_invalid_pubkey_length():
    with pytest.raises(ValueError, match="32 bytes"):
        Principal(H_id="X", public_key=b"too_short")


def test_principal_is_frozen():
    sk, pk = generate_keypair()
    p = Principal(H_id="H_x", public_key=pk)
    with pytest.raises(Exception):
        p.H_id = "tampered"  # frozen dataclass should reject


# ---------------------------------------------------------------------------
# PrincipalRegistry
# ---------------------------------------------------------------------------

def _mk(H_id: str) -> Principal:
    sk, pk = generate_keypair()
    return Principal(H_id=H_id, public_key=pk)


def test_registry_add_get():
    reg = PrincipalRegistry()
    p = _mk("H_alice")
    reg.add(p)
    assert reg.get("H_alice") is p
    assert "H_alice" in reg
    assert len(reg) == 1


def test_registry_get_missing_returns_none():
    reg = PrincipalRegistry()
    assert reg.get("H_unknown") is None


def test_registry_duplicate_add_raises():
    reg = PrincipalRegistry()
    reg.add(_mk("H_alice"))
    with pytest.raises(ValueError, match="already registered"):
        reg.add(_mk("H_alice"))


def test_registry_revoke_unknown_raises():
    reg = PrincipalRegistry()
    with pytest.raises(KeyError):
        reg.revoke("H_ghost")


def test_registry_active_after_add():
    reg = PrincipalRegistry()
    reg.add(_mk("H_alice"))
    assert reg.is_active("H_alice") is True


def test_registry_inactive_after_revoke():
    reg = PrincipalRegistry()
    reg.add(_mk("H_alice"))
    reg.revoke("H_alice", reason="test")
    assert reg.is_active("H_alice") is False


def test_registry_double_revoke_raises():
    reg = PrincipalRegistry()
    reg.add(_mk("H_alice"))
    reg.revoke("H_alice")
    with pytest.raises(ValueError, match="already revoked"):
        reg.revoke("H_alice")


def test_registry_historical_validity_preserved():
    """APBs signed BEFORE revocation timestamp remain valid."""
    import time
    reg = PrincipalRegistry()
    reg.add(_mk("H_alice"))

    pre_revoke = datetime.now(timezone.utc).isoformat()
    # ensure pre_revoke is strictly before revocation timestamp
    time.sleep(0.01)
    reg.revoke("H_alice")

    # Past timestamp: principal was active then
    assert reg.is_active("H_alice", at_time=pre_revoke) is True
    # Current state: revoked
    assert reg.is_active("H_alice") is False
