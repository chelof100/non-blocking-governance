"""
Smoke test for P10 Non-Blocking Governance baseline.
Verifies that the frozen P9 stack (61 core + 31 proxy tests) still runs
correctly as the foundation for P10 escrow extensions.

Sprint 0 gate: this test must PASS before Sprint 1 begins.
"""
import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from datetime import datetime, timezone

from agent.principal import PrincipalRegistry, generate_keypair, Principal
from stack.apb import APB, GovernanceDecision, SystemEvidenceBlock, HumanDecisionBlock
from stack.apb_verifier import verify_apb
from stack.governance_layer import GovernanceLayer, always_resume, always_deny


def _mk_evidence(D_hat: float = 0.20) -> SystemEvidenceBlock:
    return SystemEvidenceBlock(
        A_0_hash="a" * 64,
        D_hat=D_hat,
        t_e=datetime.now(timezone.utc).isoformat(),
        trace_hash="b" * 64,
        cause="persistent_drift",
    )


def test_baseline_stack() -> bool:
    """Verify P9 frozen baseline APB + GovernanceLayer intact."""
    sk, pk = generate_keypair()
    registry = PrincipalRegistry()
    registry.add(Principal(H_id="H-smoke", public_key=pk))
    key_store = {"H-smoke": sk}

    gov = GovernanceLayer(registry, key_store)

    # ADMIT path
    E_s = _mk_evidence(D_hat=0.20)
    apb_resume = gov.resolve("H-smoke", E_s, always_resume())
    assert apb_resume.D_h.decision == GovernanceDecision.RESUME.value
    report = verify_apb(apb_resume, registry, max_age_seconds=600.0)
    assert report.is_valid, f"APB verification failed: {report}"
    print(f"[SMOKE] RESUME path: APB valid OK  D_hat={E_s.D_hat}")

    # DENY path
    E_s2 = _mk_evidence(D_hat=0.80)
    apb_deny = gov.resolve("H-smoke", E_s2, always_deny())
    assert apb_deny.D_h.decision == GovernanceDecision.DENY.value
    print(f"[SMOKE] DENY   path: APB decision=DENY OK  D_hat={E_s2.D_hat}")

    print("[SMOKE] P9 frozen baseline: PASSED")
    return True


if __name__ == "__main__":
    ok = test_baseline_stack()
    sys.exit(0 if ok else 1)
