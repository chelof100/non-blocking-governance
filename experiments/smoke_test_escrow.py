"""
Smoke test for P10 Non-Blocking Governance baseline.
Verifies that the frozen P9 stack still runs correctly
as the foundation for P10 escrow extensions.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from agent.principal import PrincipalRegistry, generate_keypair, Principal
from stack.apb import build_apb, EvidenceBlock
from stack.apb_verifier import APBVerifier
from stack.iml_monitor_windowed import WindowedIMLMonitor
from stack.ram_gate import RAMGate
from stack.recovery_loop import RecoveryLoop
from stack.governance_layer import GovernanceLayer

def test_baseline_stack():
    """Verify P9 frozen baseline still intact."""
    sk, pk = generate_keypair()
    registry = PrincipalRegistry()
    registry.add(Principal("H-smoke", pk))

    monitor  = WindowedIMLMonitor(window=100)
    ram      = RAMGate(threshold=0.35)
    recovery = RecoveryLoop()
    gov      = GovernanceLayer(registry=registry, H_id="H-smoke")

    # Simulate low-risk tool call
    for _ in range(10):
        monitor.update("read_file", 0.10)

    d_hat    = monitor.deviation_score()
    decision = ram.check(d_hat)
    assert decision == "ADMIT", f"Expected ADMIT, got {decision}"

    print(f"[SMOKE] WindowedIML D̂={d_hat:.4f} → RAMGate → {decision}")
    print("[SMOKE] P9 frozen baseline: PASSED ✓")
    return True

if __name__ == "__main__":
    ok = test_baseline_stack()
    sys.exit(0 if ok else 1)
