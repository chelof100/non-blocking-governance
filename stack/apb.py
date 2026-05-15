# -*- coding: utf-8 -*-
"""
Accountability Proof Block (APB) — P8 §4.

  APB = (E_s, D_h, sigma_h)

  E_s = (A_0_hash, D_hat(t_e), t_e, event_id, trace_hash, cause)
                                                           System Evidence Block
  D_h = (H_i, decision, rationale, scope)                Human Decision Block
  sigma_h = Sign_{sk_i}( canonical(E_s) || canonical(D_h) )

Construction protocol:
  1. System builds E_s (bounded fields, bounded capture time -> T8.4)
     event_id is a UUID4 generated at evidence construction time,
     guaranteeing semantic uniqueness across governance events (V5).
  2. Human inspects E_s, formulates D_h, signs with sk_i
  3. APB = (E_s, D_h, sigma_h) is immutable thereafter

Canonical serialization: RFC 8785 JSON Canonicalization Scheme (JCS).
This is a deterministic, cross-implementation-safe encoding that
specifies sort order, number representation, and unicode handling
precisely, removing any ambiguity that would undermine the
non-repudiability and tamper-detection guarantees.

Reference: RFC 8785 — https://www.rfc-editor.org/rfc/rfc8785
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import jcs  # RFC 8785 JSON Canonicalization Scheme

from agent.principal import load_private_key

# Separator between E_s and D_h in the signed message. Chosen so it cannot
# appear in canonical-JSON output (which never contains raw '||' between
# top-level objects), preventing length-extension ambiguity.
_SEP = b"||"


# ---------------------------------------------------------------------------
# Decision enum — also used by the governance layer
# ---------------------------------------------------------------------------

class GovernanceDecision(str, Enum):
    RESUME = "RESUME"
    DENY = "DENY"
    RECALIBRATE = "RECALIBRATE"


# ---------------------------------------------------------------------------
# Canonical helpers — RFC 8785 JSON Canonicalization Scheme
# ---------------------------------------------------------------------------

def _canonical(d: dict[str, Any]) -> bytes:
    """Return the RFC 8785 JCS canonical byte representation of a dict.

    RFC 8785 specifies: keys sorted by Unicode codepoint, IEEE 754 number
    representation, no insignificant whitespace, UTF-8 encoding.  This is
    strictly stronger than ad-hoc sort_keys=True JSON in that it is
    cross-implementation portable and cryptographically unambiguous.
    """
    return jcs.canonicalize(d)


def hash_object(obj: Any) -> str:
    """SHA-256 hex of a JSON-serializable object (canonical encoding)."""
    if hasattr(obj, "to_dict"):
        payload = _canonical(obj.to_dict())
    elif isinstance(obj, (dict, list)):
        payload = _canonical(obj) if isinstance(obj, dict) else json.dumps(
            obj, separators=(",", ":")
        ).encode("utf-8")
    else:
        payload = str(obj).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# System Evidence Block (E_s)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SystemEvidenceBlock:
    """Constructed by the execution layer at t_e from certified runtime state.

    Six bounded fields (Lemma 4.1: bounded field count).
    Each field is a small hash or scalar (Lemma 4.2: bounded capture time).

    event_id is a UUID4 generated once at evidence construction time.
    It provides semantic uniqueness across governance events, enabling the
    verifier's V5 (Event Uniqueness) predicate to detect duplicate
    submissions independently of the timestamp-based V4 replay window.
    Two governance events at the same t_e are distinguishable by event_id;
    a replayed APB is rejected by V5 regardless of clock state.
    """

    A_0_hash: str       # SHA-256 hex of canonical A_0 snapshot
    D_hat: float        # drift estimator at t_e
    t_e: str            # ISO 8601 UTC timestamp
    trace_hash: str     # SHA-256 hex of trace up to t_e
    cause: str          # e.g. "persistent_drift", "ram_unresolvable"
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
                        # UUID4; unique per governance event (V5)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_canonical_bytes(self) -> bytes:
        return _canonical(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SystemEvidenceBlock":
        return cls(**d)


# ---------------------------------------------------------------------------
# Human Decision Block (D_h)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HumanDecisionBlock:
    """Added by the acting principal H_i. The principal does not restate
    E_s; they declare authority over it (P7 §12)."""

    H_id: str
    decision: str       # one of GovernanceDecision values
    rationale: str
    scope: str          # described scope of authority granted

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_canonical_bytes(self) -> bytes:
        return _canonical(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HumanDecisionBlock":
        return cls(**d)


# ---------------------------------------------------------------------------
# APB
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class APB:
    """Accountability Proof Block — immutable after construction."""

    E_s: SystemEvidenceBlock
    D_h: HumanDecisionBlock
    sigma_h: bytes      # raw 64-byte ed25519 signature

    def __post_init__(self) -> None:
        if len(self.sigma_h) != 64:
            raise ValueError(
                f"sigma_h must be 64 bytes (ed25519), got {len(self.sigma_h)}"
            )

    # --- Construction --------------------------------------------------

    @classmethod
    def construct(
        cls,
        E_s: SystemEvidenceBlock,
        D_h: HumanDecisionBlock,
        private_key_bytes: bytes,
    ) -> "APB":
        """Build a signed APB. Used by the governance layer.

        The system layer prepares E_s (T8.4 termination guaranteed by
        bounded fields). The principal supplies D_h and signs locally.
        Both inputs are concatenated canonically and signed with sk_i.
        """
        message = E_s.to_canonical_bytes() + _SEP + D_h.to_canonical_bytes()
        sk = load_private_key(private_key_bytes)
        sigma_h = sk.sign(message)
        return cls(E_s=E_s, D_h=D_h, sigma_h=sigma_h)

    # --- Canonical message reconstruction (for verification) -----------

    def message_to_sign(self) -> bytes:
        """Re-derive the bytes that were signed. Used by the verifier."""
        return self.E_s.to_canonical_bytes() + _SEP + self.D_h.to_canonical_bytes()

    # --- Serialization -------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "E_s": self.E_s.to_dict(),
            "D_h": self.D_h.to_dict(),
            "sigma_h": self.sigma_h.hex(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "APB":
        return cls(
            E_s=SystemEvidenceBlock.from_dict(d["E_s"]),
            D_h=HumanDecisionBlock.from_dict(d["D_h"]),
            sigma_h=bytes.fromhex(d["sigma_h"]),
        )

    @classmethod
    def from_json(cls, s: str) -> "APB":
        return cls.from_dict(json.loads(s))


# ---------------------------------------------------------------------------
# Evidence construction helper (T8.4 bounded termination)
# ---------------------------------------------------------------------------

def construct_evidence(
    A_0: Any,
    D_hat: float,
    trace: Any,
    cause: str,
    t_e: str | None = None,
    event_id: str | None = None,
) -> SystemEvidenceBlock:
    """Build E_s from runtime state. Construction is O(|A_0| + |trace|).

    Lemma 4.1: 6 fields, fixed at compile time.
    Lemma 4.2: each field's capture time is bounded by canonical
    serialization length, which is finite for in-memory state.

    event_id defaults to a fresh UUID4.  Callers may supply a specific
    value only in deterministic replay scenarios (e.g. test fixtures);
    in production always rely on the default.

    A_0 and trace must expose `to_dict()` or be JSON-serializable.
    """
    return SystemEvidenceBlock(
        A_0_hash=hash_object(A_0),
        D_hat=float(D_hat),
        t_e=t_e or datetime.now(timezone.utc).isoformat(),
        trace_hash=hash_object(trace),
        cause=cause,
        event_id=event_id or str(uuid.uuid4()),
    )
