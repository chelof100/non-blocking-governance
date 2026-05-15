# -*- coding: utf-8 -*-
"""
Authority Resolution Function G — governance-layer analog of RAM's F (P8 §3).

  G : P x S x E -> {RESUME, DENY, RECALIBRATE}

Per P7 §12: G constructs authority from human attestation over a defined
evidence set (E_s), not from sensor state. RECALIBRATE is the only
authorized path to modify A_0 post-initialization.

Triggered by: persistent HALT events (DC.2) where the Recovery Loop
returned HALT (stuck) or ESCALATE. The GovernanceLayer packages the
evidence, routes to a principal, obtains a signed decision, and returns
the APB.

In real deployment, the human signs locally on their own device and the
private key never leaves it. For P8 experiments we simulate this with
an in-memory key store; the cryptographic guarantees (T8.2, T8.3) hold
identically as long as the verifier never sees the private keys.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from agent.principal import Principal, PrincipalRegistry
from stack.apb import (
    APB,
    GovernanceDecision,
    HumanDecisionBlock,
    SystemEvidenceBlock,
    construct_evidence,
)


# Decision policy: callable that simulates a human's response.
# Real deployment replaces this with an interactive UI / human approval flow.
DecisionPolicy = Callable[[Principal, SystemEvidenceBlock], dict[str, str]]


class GovernanceError(RuntimeError):
    pass


class GovernanceLayer:
    """Implements G. One instance per governed system.

    The key store maps H_id -> private_key_bytes. In real deployment this
    would be an external HSM / user device — never co-located with the
    execution layer. Here we colocate for experimental tractability.
    """

    def __init__(
        self,
        registry: PrincipalRegistry,
        key_store: dict[str, bytes],
    ) -> None:
        self.registry = registry
        self._key_store = dict(key_store)

    # --- High-level resolve --------------------------------------------

    def resolve(
        self,
        H_id: str,
        E_s: SystemEvidenceBlock,
        policy: DecisionPolicy,
    ) -> APB:
        """Run G with a specified principal acting via `policy`.

        Raises GovernanceError if the principal is unknown, revoked, or
        the policy returns an invalid decision.
        """
        principal = self.registry.get(H_id)
        if principal is None:
            raise GovernanceError(f"unknown principal: {H_id!r}")
        if not self.registry.is_active(H_id, at_time=E_s.t_e):
            raise GovernanceError(f"principal not active at t_e: {H_id!r}")
        if H_id not in self._key_store:
            raise GovernanceError(f"no private key for principal: {H_id!r}")

        decision = policy(principal, E_s)
        self._validate_decision(decision)

        D_h = HumanDecisionBlock(
            H_id=H_id,
            decision=decision["decision"],
            rationale=decision["rationale"],
            scope=decision["scope"],
        )
        return APB.construct(E_s, D_h, self._key_store[H_id])

    # --- Convenience: resolve from runtime state -----------------------

    def resolve_halt(
        self,
        H_id: str,
        A_0: Any,
        D_hat: float,
        trace: Any,
        cause: str,
        policy: DecisionPolicy,
        t_e: Optional[str] = None,
    ) -> APB:
        """Build E_s from runtime state, then resolve."""
        E_s = construct_evidence(A_0, D_hat, trace, cause, t_e=t_e)
        return self.resolve(H_id, E_s, policy)

    # --- Internal ------------------------------------------------------

    @staticmethod
    def _validate_decision(decision: dict[str, str]) -> None:
        for k in ("decision", "rationale", "scope"):
            if k not in decision:
                raise GovernanceError(f"policy missing key: {k!r}")
        if decision["decision"] not in {d.value for d in GovernanceDecision}:
            raise GovernanceError(
                f"invalid decision: {decision['decision']!r}; "
                f"expected one of {[d.value for d in GovernanceDecision]}"
            )


# ---------------------------------------------------------------------------
# Built-in policies (useful for experiments and tests)
# ---------------------------------------------------------------------------

def always_resume(rationale: str = "default RESUME") -> DecisionPolicy:
    def _policy(principal: Principal, E_s: SystemEvidenceBlock) -> dict[str, str]:
        return {
            "decision": GovernanceDecision.RESUME.value,
            "rationale": rationale,
            "scope": "single resumption",
        }
    return _policy


def always_deny(rationale: str = "default DENY") -> DecisionPolicy:
    def _policy(principal: Principal, E_s: SystemEvidenceBlock) -> dict[str, str]:
        return {
            "decision": GovernanceDecision.DENY.value,
            "rationale": rationale,
            "scope": "permanent denial",
        }
    return _policy


def threshold_policy(
    deny_above: float = 0.5,
    recalibrate_above: float = 0.8,
) -> DecisionPolicy:
    """Decide based on D_hat. Above `recalibrate_above` -> RECALIBRATE,
    above `deny_above` -> DENY, else RESUME."""
    def _policy(principal: Principal, E_s: SystemEvidenceBlock) -> dict[str, str]:
        if E_s.D_hat >= recalibrate_above:
            return {
                "decision": GovernanceDecision.RECALIBRATE.value,
                "rationale": f"D_hat={E_s.D_hat:.3f} above recalibrate threshold",
                "scope": "full A_0 recalibration",
            }
        if E_s.D_hat >= deny_above:
            return {
                "decision": GovernanceDecision.DENY.value,
                "rationale": f"D_hat={E_s.D_hat:.3f} above deny threshold",
                "scope": "permanent denial",
            }
        return {
            "decision": GovernanceDecision.RESUME.value,
            "rationale": f"D_hat={E_s.D_hat:.3f} within tolerance",
            "scope": "single resumption",
        }
    return _policy
