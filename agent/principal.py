# -*- coding: utf-8 -*-
"""
Principal Set P — registry of identity-bound human principals (P8 §3).

P = {H_1, ..., H_n}: pre-registered set of identity-bound principals
whose re-authorization decisions are admissible at the governance layer.

DC.1 implication: P is read-only at the execution layer. Modifications
are governance events (RECALIBRATE_PRINCIPAL_SET APB).

This module models P at the P8 implementation layer:
- ed25519 keypair generation (real cryptography)
- Registry with add / get / revoke / is_active
- Revocation log preserves historical validity (APBs signed before
  revocation timestamp remain verifiable, but flagged)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Keypair generation
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate (private_key_bytes, public_key_bytes) for a new principal.

    Returns raw 32-byte ed25519 keys. The private bytes are sensitive and
    in real deployment never leave the principal's device. In our
    experimental setup we hold them in-memory for simulation.
    """
    sk = Ed25519PrivateKey.generate()
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk_bytes, pk_bytes


def load_private_key(sk_bytes: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sk_bytes)


def load_public_key(pk_bytes: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(pk_bytes)


# ---------------------------------------------------------------------------
# Principal & Registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Principal:
    """An identity-bound principal H_i with public key and metadata."""

    H_id: str
    public_key: bytes              # raw 32-byte ed25519
    role: str = ""
    registered_at: str = ""        # ISO 8601 UTC

    def __post_init__(self) -> None:
        if len(self.public_key) != 32:
            raise ValueError(
                f"public_key must be 32 bytes, got {len(self.public_key)}"
            )


@dataclass
class RevocationEntry:
    H_id: str
    revoked_at: str   # ISO 8601 UTC
    reason: str = ""


class PrincipalRegistry:
    """In-memory registry of P. Single-writer assumed for P8 experiments.

    DC.1 in real deployment: this registry is mutated only via
    RECALIBRATE_PRINCIPAL_SET APBs. Here we expose direct add/revoke
    for experimental setup.
    """

    def __init__(self) -> None:
        self._principals: dict[str, Principal] = {}
        self._revocations: dict[str, RevocationEntry] = {}

    def add(self, principal: Principal) -> None:
        if principal.H_id in self._principals:
            raise ValueError(f"principal already registered: {principal.H_id}")
        self._principals[principal.H_id] = principal

    def get(self, H_id: str) -> Optional[Principal]:
        return self._principals.get(H_id)

    def revoke(self, H_id: str, reason: str = "") -> RevocationEntry:
        if H_id not in self._principals:
            raise KeyError(f"unknown principal: {H_id}")
        if H_id in self._revocations:
            raise ValueError(f"principal already revoked: {H_id}")
        entry = RevocationEntry(
            H_id=H_id,
            revoked_at=datetime.now(timezone.utc).isoformat(),
            reason=reason,
        )
        self._revocations[H_id] = entry
        return entry

    def is_active(self, H_id: str, at_time: Optional[str] = None) -> bool:
        """Active = registered and not revoked at the given time.

        at_time is ISO 8601 UTC; defaults to now. APBs signed BEFORE
        revocation timestamp are still considered valid (caller must
        pass apb.E_s.t_e as at_time for historical validation).
        """
        if H_id not in self._principals:
            return False
        rev = self._revocations.get(H_id)
        if rev is None:
            return True
        if at_time is None:
            return False
        return at_time < rev.revoked_at

    def __len__(self) -> int:
        return len(self._principals)

    def __contains__(self, H_id: str) -> bool:
        return H_id in self._principals
