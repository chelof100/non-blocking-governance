"""test_timeout_policy.py — P10 Sprint 1

Unit tests for FallbackMode, TimeoutPolicy, and v6_check().
"""

from datetime import datetime, timezone, timedelta

import pytest

from escrow.escrow_store import EscrowEntry
from escrow.timeout_policy import FallbackMode, TimeoutPolicy, v6_check


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _make_entry(t_halt: datetime) -> EscrowEntry:
    return EscrowEntry.create(
        tool_call="deploy_infra",
        args={"env": "prod"},
        context={},
        D_hat=0.65,
        t_halt=_iso(t_halt),
    )


_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# TimeoutPolicy — expiry
# ---------------------------------------------------------------------------

class TestTimeoutPolicyExpiry:
    def test_not_expired_within_ttl(self):
        t_halt = _NOW - timedelta(seconds=30)
        policy = TimeoutPolicy(T_timeout=60.0)
        entry = _make_entry(t_halt)
        assert policy.is_expired(entry, now=_NOW) is False

    def test_expired_past_ttl(self):
        t_halt = _NOW - timedelta(seconds=90)
        policy = TimeoutPolicy(T_timeout=60.0)
        entry = _make_entry(t_halt)
        assert policy.is_expired(entry, now=_NOW) is True

    def test_exactly_at_deadline_not_expired(self):
        # deadline = t_halt + T_timeout; now == deadline → not expired (boundary: >)
        t_halt = _NOW - timedelta(seconds=60)
        policy = TimeoutPolicy(T_timeout=60.0)
        entry = _make_entry(t_halt)
        assert policy.is_expired(entry, now=_NOW) is False

    def test_one_second_past_deadline_expired(self):
        t_halt = _NOW - timedelta(seconds=61)
        policy = TimeoutPolicy(T_timeout=60.0)
        entry = _make_entry(t_halt)
        assert policy.is_expired(entry, now=_NOW) is True

    def test_uses_utc_now_when_not_provided(self):
        # Entry created far in the past → always expired regardless of local clock
        t_halt = _NOW - timedelta(days=365)
        policy = TimeoutPolicy(T_timeout=60.0)
        entry = _make_entry(t_halt)
        assert policy.is_expired(entry) is True  # no `now` arg

    def test_zero_timeout_expires_immediately(self):
        # T_timeout=0 → any entry with t_halt < now is expired
        t_halt = _NOW - timedelta(seconds=1)
        policy = TimeoutPolicy(T_timeout=0.0)
        entry = _make_entry(t_halt)
        assert policy.is_expired(entry, now=_NOW) is True


# ---------------------------------------------------------------------------
# TimeoutPolicy — fallback modes
# ---------------------------------------------------------------------------

class TestTimeoutPolicyFallback:
    def test_default_fallback_is_deny(self):
        policy = TimeoutPolicy(T_timeout=60.0)
        assert policy.fallback == FallbackMode.DENY

    def test_apply_fallback_deny(self):
        policy = TimeoutPolicy(T_timeout=60.0, fallback=FallbackMode.DENY)
        entry = _make_entry(_NOW)
        assert policy.apply_fallback(entry) == FallbackMode.DENY

    def test_apply_fallback_admit(self):
        policy = TimeoutPolicy(T_timeout=60.0, fallback=FallbackMode.ADMIT)
        entry = _make_entry(_NOW)
        assert policy.apply_fallback(entry) == FallbackMode.ADMIT

    def test_apply_fallback_escalate(self):
        policy = TimeoutPolicy(T_timeout=60.0, fallback=FallbackMode.ESCALATE)
        entry = _make_entry(_NOW)
        assert policy.apply_fallback(entry) == FallbackMode.ESCALATE

    def test_fallback_mode_values(self):
        assert FallbackMode.DENY.value     == "DENY"
        assert FallbackMode.ADMIT.value    == "ADMIT"
        assert FallbackMode.ESCALATE.value == "ESCALATE"


# ---------------------------------------------------------------------------
# v6_check — V6 predicate
# ---------------------------------------------------------------------------

class TestV6Check:
    def _make_timestamps(self, apb_offset_s: float, T_timeout: float):
        t_halt  = _iso(_NOW)
        apb_t_e = _iso(_NOW + timedelta(seconds=apb_offset_s))
        return apb_t_e, t_halt, T_timeout

    def test_v6_valid_within_window(self):
        apb_t_e, t_halt, T = self._make_timestamps(apb_offset_s=30.0, T_timeout=60.0)
        assert v6_check(apb_t_e, t_halt, T) is True

    def test_v6_expired_outside_window(self):
        apb_t_e, t_halt, T = self._make_timestamps(apb_offset_s=90.0, T_timeout=60.0)
        assert v6_check(apb_t_e, t_halt, T) is False

    def test_v6_exact_boundary_valid(self):
        # τ_apb = t_halt + T_timeout → exactly on the boundary → True (≤)
        apb_t_e, t_halt, T = self._make_timestamps(apb_offset_s=60.0, T_timeout=60.0)
        assert v6_check(apb_t_e, t_halt, T) is True

    def test_v6_one_second_past_boundary_invalid(self):
        apb_t_e, t_halt, T = self._make_timestamps(apb_offset_s=61.0, T_timeout=60.0)
        assert v6_check(apb_t_e, t_halt, T) is False

    def test_v6_apb_before_halt(self):
        # APB signed before t_halt (extreme case) — still within window
        apb_t_e, t_halt, T = self._make_timestamps(apb_offset_s=-10.0, T_timeout=60.0)
        assert v6_check(apb_t_e, t_halt, T) is True

    def test_v6_zero_timeout(self):
        # T_timeout=0 → only APBs with τ_apb ≤ t_halt are valid
        apb_t_e, t_halt, T = self._make_timestamps(apb_offset_s=0.0, T_timeout=0.0)
        assert v6_check(apb_t_e, t_halt, T) is True   # τ_apb == t_halt

        apb_t_e2, _, _ = self._make_timestamps(apb_offset_s=1.0, T_timeout=0.0)
        assert v6_check(apb_t_e2, t_halt, T) is False  # τ_apb > t_halt

    def test_v6_accepts_z_suffix_timestamps(self):
        t_halt  = "2026-05-15T12:00:00Z"
        apb_t_e = "2026-05-15T12:00:30Z"
        assert v6_check(apb_t_e, t_halt, 60.0) is True

    def test_v6_rejects_z_suffix_past_deadline(self):
        t_halt  = "2026-05-15T12:00:00Z"
        apb_t_e = "2026-05-15T12:01:30Z"   # 90s after t_halt
        assert v6_check(apb_t_e, t_halt, 60.0) is False
