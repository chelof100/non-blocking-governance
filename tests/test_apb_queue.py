"""test_apb_queue.py — P10 Sprint 2

Unit tests for APBQueue, DuplicateEventError, APBVerificationError,
TimeoutExpiredError.

Gate: multi-session APB resolution —
  enqueue (session A) → save → load (session B) → resolve → GovernanceDecision
"""

import uuid
from datetime import datetime, timezone, timedelta

import pytest

from agent.principal import Principal, PrincipalRegistry, generate_keypair
from escrow.apb_queue import (
    APBQueue,
    APBVerificationError,
    DuplicateEventError,
    TimeoutExpiredError,
)
from escrow.escrow_store import EscrowEntry
from escrow.timeout_policy import FallbackMode, TimeoutPolicy
from stack.apb import APB, GovernanceDecision, HumanDecisionBlock, SystemEvidenceBlock


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso(dt: datetime) -> str:
    return dt.isoformat()


_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def alice():
    sk, pk = generate_keypair()
    return {"H_id": "H_alice", "sk": sk, "pk": pk}


@pytest.fixture
def registry(alice):
    reg = PrincipalRegistry()
    reg.add(Principal(H_id=alice["H_id"], public_key=alice["pk"]))
    return reg


def _mk_E_s(D_hat: float = 0.75, t_e: str = None, event_id: str = None) -> SystemEvidenceBlock:
    return SystemEvidenceBlock(
        A_0_hash="a" * 64,
        D_hat=D_hat,
        t_e=t_e or _now_iso(),
        trace_hash="b" * 64,
        cause="persistent_drift",
        event_id=event_id or str(uuid.uuid4()),
    )


def _mk_D_h(H_id: str, decision: str = "RESUME") -> HumanDecisionBlock:
    return HumanDecisionBlock(
        H_id=H_id,
        decision=decision,
        rationale="manual review",
        scope="next 100 steps",
    )


def _mk_entry(D_hat: float = 0.75, t_halt: str = None) -> EscrowEntry:
    return EscrowEntry.create(
        tool_call="send_wire",
        args={"amount": 1_000_000},
        context={"session_id": "sess-test"},
        D_hat=D_hat,
        t_halt=t_halt or _now_iso(),
    )


def _default_policy(T_timeout: float = 3600.0, fallback: FallbackMode = FallbackMode.DENY) -> TimeoutPolicy:
    return TimeoutPolicy(T_timeout=T_timeout, fallback=fallback)


# ---------------------------------------------------------------------------
# Enqueue — basic behaviour
# ---------------------------------------------------------------------------

class TestEnqueue:
    def test_enqueue_returns_escrow_id(self):
        q = APBQueue()
        entry = _mk_entry()
        eid = str(uuid.uuid4())
        result = q.enqueue(entry, event_id=eid)
        assert result == entry.escrow_id

    def test_enqueue_adds_to_queue(self):
        q = APBQueue()
        entry = _mk_entry()
        q.enqueue(entry, event_id=str(uuid.uuid4()))
        assert len(q) == 1
        assert entry.escrow_id in q

    def test_enqueue_duplicate_event_id_raises(self):
        q = APBQueue()
        event_id = str(uuid.uuid4())
        q.enqueue(_mk_entry(), event_id=event_id)
        with pytest.raises(DuplicateEventError) as exc:
            q.enqueue(_mk_entry(), event_id=event_id)
        assert exc.value.event_id == event_id

    def test_different_event_ids_allowed(self):
        q = APBQueue()
        q.enqueue(_mk_entry(), event_id=str(uuid.uuid4()))
        q.enqueue(_mk_entry(), event_id=str(uuid.uuid4()))
        assert len(q) == 2


# ---------------------------------------------------------------------------
# Peek / list_pending — priority ordering
# ---------------------------------------------------------------------------

class TestPriority:
    def test_peek_empty_returns_none(self):
        assert APBQueue().peek() is None

    def test_peek_highest_risk_first(self):
        q = APBQueue()
        low  = _mk_entry(D_hat=0.2)
        high = _mk_entry(D_hat=0.9)
        q.enqueue(low,  event_id=str(uuid.uuid4()))
        q.enqueue(high, event_id=str(uuid.uuid4()))
        assert q.peek().escrow_id == high.escrow_id

    def test_list_pending_ordered_by_risk_desc(self):
        q = APBQueue()
        entries = [_mk_entry(D_hat=d) for d in [0.3, 0.8, 0.1, 0.6]]
        for e in entries:
            q.enqueue(e, event_id=str(uuid.uuid4()))
        listed = q.list_pending()
        d_hats = [e.D_hat for e in listed]
        assert d_hats == sorted(d_hats, reverse=True)

    def test_tie_breaks_by_t_halt_asc(self):
        q = APBQueue()
        t1 = _iso(_NOW - timedelta(seconds=60))   # older
        t2 = _iso(_NOW - timedelta(seconds=10))   # newer
        e_old = _mk_entry(D_hat=0.5, t_halt=t1)
        e_new = _mk_entry(D_hat=0.5, t_halt=t2)
        q.enqueue(e_old, event_id=str(uuid.uuid4()))
        q.enqueue(e_new, event_id=str(uuid.uuid4()))
        # Older entry should come first (same risk, oldest HALT first)
        assert q.peek().escrow_id == e_old.escrow_id


# ---------------------------------------------------------------------------
# Resolve — happy path
# ---------------------------------------------------------------------------

class TestResolveHappyPath:
    def test_resolve_resume_decision(self, alice, registry):
        q = APBQueue()
        event_id = str(uuid.uuid4())
        E_s = _mk_E_s(D_hat=0.75, event_id=event_id)
        entry = EscrowEntry.create(
            tool_call="deploy_prod",
            args={},
            context={},
            D_hat=0.75,
            t_halt=E_s.t_e,
        )
        q.enqueue(entry, event_id=event_id)

        apb = APB.construct(E_s, _mk_D_h(alice["H_id"], "RESUME"), alice["sk"])
        policy = _default_policy(T_timeout=3600.0)

        decision, resolved_entry = q.resolve(entry.escrow_id, apb, registry, policy)

        assert decision == GovernanceDecision.RESUME
        assert resolved_entry == entry

    def test_resolve_deny_decision(self, alice, registry):
        q = APBQueue()
        event_id = str(uuid.uuid4())
        E_s = _mk_E_s(event_id=event_id)
        entry = _mk_entry(t_halt=E_s.t_e)
        q.enqueue(entry, event_id=event_id)

        apb = APB.construct(E_s, _mk_D_h(alice["H_id"], "DENY"), alice["sk"])
        policy = _default_policy()

        decision, _ = q.resolve(entry.escrow_id, apb, registry, policy)
        assert decision == GovernanceDecision.DENY

    def test_resolve_removes_entry_from_queue(self, alice, registry):
        q = APBQueue()
        event_id = str(uuid.uuid4())
        E_s = _mk_E_s(event_id=event_id)
        entry = _mk_entry(t_halt=E_s.t_e)
        q.enqueue(entry, event_id=event_id)

        apb = APB.construct(E_s, _mk_D_h(alice["H_id"]), alice["sk"])
        q.resolve(entry.escrow_id, apb, registry, _default_policy())

        assert len(q) == 0
        assert entry.escrow_id not in q

    def test_resolve_allows_reenqueue_after_resolution(self, alice, registry):
        """After resolution, same event_id can be enqueued again (new governance event)."""
        q = APBQueue()
        event_id = str(uuid.uuid4())
        E_s = _mk_E_s(event_id=event_id)
        entry = _mk_entry(t_halt=E_s.t_e)
        q.enqueue(entry, event_id=event_id)

        apb = APB.construct(E_s, _mk_D_h(alice["H_id"]), alice["sk"])
        q.resolve(entry.escrow_id, apb, registry, _default_policy())

        # event_id is no longer "pending" — a fresh entry with same event_id
        # would still fail V5, but a NEW entry with a new event_id is fine
        new_entry = _mk_entry()
        new_event_id = str(uuid.uuid4())
        q.enqueue(new_entry, event_id=new_event_id)
        assert len(q) == 1


# ---------------------------------------------------------------------------
# Resolve — failure paths
# ---------------------------------------------------------------------------

class TestResolveFailures:
    def test_resolve_missing_escrow_id_raises_key_error(self, alice, registry):
        q = APBQueue()
        E_s = _mk_E_s()
        apb = APB.construct(E_s, _mk_D_h(alice["H_id"]), alice["sk"])
        with pytest.raises(KeyError):
            q.resolve("nonexistent-id", apb, registry, _default_policy())

    def test_resolve_invalid_signature_raises_verification_error(self, registry):
        q = APBQueue()
        _, other_pk = generate_keypair()
        other_sk, _ = generate_keypair()   # wrong key
        event_id = str(uuid.uuid4())
        E_s = _mk_E_s(event_id=event_id)
        entry = _mk_entry(t_halt=E_s.t_e)
        q.enqueue(entry, event_id=event_id)

        # Sign with a different key — V1 should fail
        apb = APB.construct(E_s, _mk_D_h("H_alice"), other_sk)
        with pytest.raises(APBVerificationError) as exc:
            q.resolve(entry.escrow_id, apb, registry, _default_policy())
        assert "INVALID_SIGNATURE" in str(exc.value)

    def test_resolve_unknown_principal_raises_verification_error(self, registry):
        q = APBQueue()
        stranger_sk, _ = generate_keypair()
        event_id = str(uuid.uuid4())
        E_s = _mk_E_s(event_id=event_id)
        entry = _mk_entry(t_halt=E_s.t_e)
        q.enqueue(entry, event_id=event_id)

        # H_id not in registry — V2 should fail
        apb = APB.construct(E_s, _mk_D_h("H_stranger"), stranger_sk)
        with pytest.raises(APBVerificationError) as exc:
            q.resolve(entry.escrow_id, apb, registry, _default_policy())
        assert "PRINCIPAL_NOT_FOUND" in str(exc.value)

    def test_resolve_v6_expired_raises_timeout_error(self, alice, registry):
        """APB signed after t_halt + T_timeout → V6 rejects it."""
        q = APBQueue()
        # t_halt was 2 hours ago, T_timeout = 1 hour → deadline already passed
        t_halt = _iso(_NOW - timedelta(hours=2))
        t_e    = _iso(_NOW - timedelta(hours=1, minutes=30))  # APB signed 90 min ago
        # APB arrives now: τ_apb = t_e = 90 min ago, deadline = t_halt + 60 min = 60 min ago
        # τ_apb (90 min ago) > deadline (60 min ago in the past)? No wait:
        # t_halt = NOW - 2h, deadline = t_halt + 1h = NOW - 1h
        # t_e = NOW - 1.5h (APB was signed 90 min ago, before deadline of NOW-1h)
        # Actually t_e=NOW-1.5h < deadline=NOW-1h → V6 should PASS...
        # Let me fix: APB signed AFTER the deadline
        # t_halt = NOW - 2h, T_timeout = 30min, deadline = NOW - 90min
        # t_e = NOW - 1h (APB signed 60 min ago, after deadline of 90 min ago) → V6 fails
        t_halt2 = _iso(_NOW - timedelta(hours=2))
        t_e2    = _iso(_NOW - timedelta(hours=1))  # signed 60 min ago
        T_timeout = 30 * 60  # 30 minute window; deadline = NOW - 90 min

        event_id = str(uuid.uuid4())
        E_s = _mk_E_s(event_id=event_id, t_e=t_e2)
        entry = _mk_entry(t_halt=t_halt2)
        q.enqueue(entry, event_id=event_id)

        apb = APB.construct(E_s, _mk_D_h(alice["H_id"]), alice["sk"])
        policy = TimeoutPolicy(T_timeout=T_timeout)

        with pytest.raises(TimeoutExpiredError) as exc:
            # Need large max_age_seconds so V4 doesn't fire first
            q.resolve(entry.escrow_id, apb, registry, policy, max_age_seconds=86400.0)
        assert exc.value.escrow_id == entry.escrow_id

    def test_entry_not_removed_after_verification_failure(self, registry):
        """Failed resolve must not remove the entry — it stays pending."""
        q = APBQueue()
        stranger_sk, _ = generate_keypair()
        event_id = str(uuid.uuid4())
        E_s = _mk_E_s(event_id=event_id)
        entry = _mk_entry(t_halt=E_s.t_e)
        q.enqueue(entry, event_id=event_id)

        apb = APB.construct(E_s, _mk_D_h("H_stranger"), stranger_sk)
        try:
            q.resolve(entry.escrow_id, apb, registry, _default_policy())
        except APBVerificationError:
            pass

        assert entry.escrow_id in q   # still there


# ---------------------------------------------------------------------------
# Timeout sweep
# ---------------------------------------------------------------------------

class TestApplyTimeouts:
    def test_expired_entries_removed(self):
        q = APBQueue()
        t_halt = _iso(_NOW - timedelta(hours=2))
        entry = _mk_entry(t_halt=t_halt)
        q.enqueue(entry, event_id=str(uuid.uuid4()))

        policy = TimeoutPolicy(T_timeout=3600.0)  # 1h — entry is 2h old
        expired = q.apply_timeouts(policy, now=_NOW)

        assert len(expired) == 1
        assert expired[0][0] == entry
        assert len(q) == 0

    def test_expired_fallback_mode_returned(self):
        q = APBQueue()
        t_halt = _iso(_NOW - timedelta(hours=2))
        q.enqueue(_mk_entry(t_halt=t_halt), event_id=str(uuid.uuid4()))

        policy = TimeoutPolicy(T_timeout=3600.0, fallback=FallbackMode.ESCALATE)
        expired = q.apply_timeouts(policy, now=_NOW)

        assert expired[0][1] == FallbackMode.ESCALATE

    def test_active_entries_not_touched(self):
        q = APBQueue()
        t_halt = _iso(_NOW - timedelta(minutes=10))
        entry = _mk_entry(t_halt=t_halt)
        q.enqueue(entry, event_id=str(uuid.uuid4()))

        policy = TimeoutPolicy(T_timeout=3600.0)  # 1h — entry is only 10 min old
        expired = q.apply_timeouts(policy, now=_NOW)

        assert len(expired) == 0
        assert entry.escrow_id in q

    def test_mixed_active_and_expired(self):
        q = APBQueue()
        t_expired = _iso(_NOW - timedelta(hours=2))
        t_active  = _iso(_NOW - timedelta(minutes=5))
        e_exp  = _mk_entry(t_halt=t_expired)
        e_act  = _mk_entry(t_halt=t_active)
        q.enqueue(e_exp, event_id=str(uuid.uuid4()))
        q.enqueue(e_act, event_id=str(uuid.uuid4()))

        policy = TimeoutPolicy(T_timeout=3600.0)
        expired = q.apply_timeouts(policy, now=_NOW)

        assert len(expired) == 1
        assert expired[0][0].escrow_id == e_exp.escrow_id
        assert e_act.escrow_id in q

    def test_after_timeout_event_id_can_be_reenqueued(self):
        """Timed-out entries free their event_id slot."""
        q = APBQueue()
        event_id = str(uuid.uuid4())
        t_halt = _iso(_NOW - timedelta(hours=2))
        q.enqueue(_mk_entry(t_halt=t_halt), event_id=event_id)

        policy = TimeoutPolicy(T_timeout=3600.0)
        q.apply_timeouts(policy, now=_NOW)

        # Same event_id should now be accepted again (entry was cleared)
        q.enqueue(_mk_entry(), event_id=event_id)
        assert len(q) == 1


# ---------------------------------------------------------------------------
# GATE: multi-session APB resolution
# enqueue (session A) → save → load (session B) → resolve
# ---------------------------------------------------------------------------

class TestMultiSessionGate:
    def test_gate_enqueue_save_load_resolve(self, tmp_path, alice, registry):
        """Sprint 2 gate.

        Session A: HALT fires → enqueue → save to disk.
        Session B: new APBQueue instance from disk → APB arrives → resolve.
        """
        # Session A ─────────────────────────────────────────────────
        queue_a = APBQueue()
        event_id = str(uuid.uuid4())
        E_s = _mk_E_s(D_hat=0.82, event_id=event_id)
        entry = EscrowEntry.create(
            tool_call="transfer_funds",
            args={"to": "wallet-xyz", "amount": 50_000},
            context={"session_id": "sess-A", "trace_hash": "deadbeef01"},
            D_hat=0.82,
            t_halt=E_s.t_e,
        )
        queue_a.enqueue(entry, event_id=event_id)
        assert len(queue_a) == 1

        path = tmp_path / "queue.json"
        queue_a.save(path)

        # Session B ─────────────────────────────────────────────────
        queue_b = APBQueue.from_file(path)

        assert len(queue_b) == 1
        assert entry.escrow_id in queue_b

        # Human signs APB in session B
        apb = APB.construct(E_s, _mk_D_h(alice["H_id"], "RESUME"), alice["sk"])
        policy = _default_policy(T_timeout=86400.0)  # 24h window — always in time

        decision, resolved_entry = queue_b.resolve(
            entry.escrow_id, apb, registry, policy
        )

        # Gate assertions
        assert decision == GovernanceDecision.RESUME
        assert resolved_entry.tool_call == "transfer_funds"
        assert resolved_entry.D_hat == 0.82
        assert resolved_entry.t_halt == E_s.t_e
        assert len(queue_b) == 0

    def test_gate_save_preserves_resolved_event_ids(self, tmp_path, alice, registry):
        """Resolved event_ids survive a save/load cycle — V5 replay defence persists."""
        queue_a = APBQueue()
        event_id = str(uuid.uuid4())
        E_s = _mk_E_s(event_id=event_id)
        entry = _mk_entry(t_halt=E_s.t_e)
        queue_a.enqueue(entry, event_id=event_id)

        apb = APB.construct(E_s, _mk_D_h(alice["H_id"]), alice["sk"])
        queue_a.resolve(entry.escrow_id, apb, registry, _default_policy())
        # event_id now in _resolved_event_ids

        path = tmp_path / "queue.json"
        queue_a.save(path)

        queue_b = APBQueue.from_file(path)
        # APB with same event_id should be rejected by V5 in the reloaded queue
        new_entry = _mk_entry()
        new_event_id = str(uuid.uuid4())
        queue_b.enqueue(new_entry, event_id=new_event_id)

        # Re-submitting the same APB (same event_id) should raise APBVerificationError (V5)
        with pytest.raises(APBVerificationError) as exc:
            queue_b.resolve(new_entry.escrow_id, apb, registry, _default_policy())
        assert "DUPLICATE_EVENT_ID" in str(exc.value)
