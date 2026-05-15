# -*- coding: utf-8 -*-
"""
APB Verifier — signature, attribution, replay, and uniqueness checks (P8 §5).

A valid APB must satisfy five predicates:
  V1. Signature verifies against the public key of the named principal.
  V2. The named principal exists in the registry.
  V3. The named principal was active at t_e (not revoked before signing).
  V4. t_e is within the acceptable window relative to the verification
      time (temporal freshness / replay defense).
  V5. event_id has not been seen before in this verification session
      (semantic uniqueness / duplicate-submission defense).

V4 and V5 are complementary defenses:
  V4 rejects APBs that are too old or from the future (clock-based).
  V5 rejects exact replays of a previously-accepted APB regardless of
     clock state — including valid replays submitted within the V4 window.

The verifier returns a VerificationResult that distinguishes failure
modes — Exp B uses the per-mode counts to validate T8.2 and T8.3.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Set

from cryptography.exceptions import InvalidSignature

from agent.principal import PrincipalRegistry, load_public_key
from stack.apb import APB


class VerificationResult(str, Enum):
    VALID = "VALID"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    PRINCIPAL_NOT_FOUND = "PRINCIPAL_NOT_FOUND"
    PRINCIPAL_REVOKED = "PRINCIPAL_REVOKED"
    REPLAY = "REPLAY"              # V4: temporal freshness violation
    DUPLICATE_EVENT_ID = "DUPLICATE_EVENT_ID"  # V5: semantic uniqueness violation
    MALFORMED = "MALFORMED"


@dataclass
class VerificationReport:
    result: VerificationResult
    apb: APB
    detail: str = ""

    @property
    def is_valid(self) -> bool:
        return self.result is VerificationResult.VALID


# ---------------------------------------------------------------------------
# Low-level signature check
# ---------------------------------------------------------------------------

def verify_signature(apb: APB, public_key_bytes: bytes) -> bool:
    """Return True iff sigma_h is a valid ed25519 signature over the
    canonical (E_s || D_h) message under the given public key.
    """
    try:
        pk_obj = load_public_key(public_key_bytes)
        pk_obj.verify(apb.sigma_h, apb.message_to_sign())
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# Full verification with registry + replay window
# ---------------------------------------------------------------------------

def verify_apb(
    apb: APB,
    registry: PrincipalRegistry,
    now: Optional[str] = None,
    max_age_seconds: float = 300.0,
    seen_event_ids: Optional[Set[str]] = None,
) -> VerificationReport:
    """Run V1-V5. Returns the FIRST failing predicate, or VALID.

    `now`: ISO 8601 UTC; defaults to current wall clock.
    `max_age_seconds`: how recent t_e must be relative to `now` (V4).
    `seen_event_ids`: mutable set of already-accepted event IDs (V5).
        If provided, the function adds accepted event_ids to this set
        so the caller maintains the nonce store across multiple calls.
        If None, V5 is skipped (useful for single-APB validation).
    """
    H_id = apb.D_h.H_id
    principal = registry.get(H_id)
    if principal is None:
        return VerificationReport(
            result=VerificationResult.PRINCIPAL_NOT_FOUND,
            apb=apb,
            detail=f"H_id={H_id!r} not in registry",
        )

    # V3: was the principal active at signing time?
    if not registry.is_active(H_id, at_time=apb.E_s.t_e):
        return VerificationReport(
            result=VerificationResult.PRINCIPAL_REVOKED,
            apb=apb,
            detail=f"H_id={H_id!r} not active at t_e={apb.E_s.t_e}",
        )

    # V1: signature
    if not verify_signature(apb, principal.public_key):
        return VerificationReport(
            result=VerificationResult.INVALID_SIGNATURE,
            apb=apb,
            detail="ed25519 verification failed",
        )

    # V4: temporal replay window (clock-based freshness)
    now_iso = now or datetime.now(timezone.utc).isoformat()
    age = _age_seconds(apb.E_s.t_e, now_iso)
    if age is None:
        return VerificationReport(
            result=VerificationResult.MALFORMED,
            apb=apb,
            detail=f"unparseable t_e: {apb.E_s.t_e!r}",
        )
    if age > max_age_seconds:
        return VerificationReport(
            result=VerificationResult.REPLAY,
            apb=apb,
            detail=f"t_e is {age:.1f}s old (max={max_age_seconds:.1f}s)",
        )
    if age < -max_age_seconds:
        return VerificationReport(
            result=VerificationResult.REPLAY,
            apb=apb,
            detail=f"t_e is {-age:.1f}s in the future (clock skew)",
        )

    # V5: semantic uniqueness — event_id must not have been seen before.
    # This defends against valid-window replays that V4 cannot catch:
    # a legitimately fresh APB submitted twice within the acceptance window
    # is rejected by V5 independently of clock state.
    if seen_event_ids is not None:
        eid = apb.E_s.event_id
        if eid in seen_event_ids:
            return VerificationReport(
                result=VerificationResult.DUPLICATE_EVENT_ID,
                apb=apb,
                detail=f"event_id {eid!r} already accepted (duplicate submission)",
            )
        seen_event_ids.add(eid)

    return VerificationReport(result=VerificationResult.VALID, apb=apb)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _age_seconds(t_e_iso: str, now_iso: str) -> Optional[float]:
    try:
        t_e = datetime.fromisoformat(t_e_iso)
        now = datetime.fromisoformat(now_iso)
    except ValueError:
        return None
    return (now - t_e).total_seconds()


def attribute(apb: APB, registry: PrincipalRegistry) -> Optional[str]:
    """Return H_id if the APB is signature-valid against a registered
    principal, else None. Used by Exp B's identity-swap test."""
    p = registry.get(apb.D_h.H_id)
    if p is None:
        return None
    return apb.D_h.H_id if verify_signature(apb, p.public_key) else None
