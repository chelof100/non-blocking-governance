"""test_escrow_store.py — P10 Sprint 1

Unit tests for EscrowEntry + EscrowStore.

Gate: HALT → escrow_store.save() → reload() → state preserved (test_gate_halt_save_reload)
"""

import json
import tempfile
import time
from pathlib import Path

import pytest

from escrow.escrow_store import EscrowEntry, EscrowStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_T_HALT = "2026-05-15T12:00:00+00:00"


def _make_entry(
    tool_call: str = "delete_file",
    D_hat: float = 0.75,
    escrow_id: str | None = None,
) -> EscrowEntry:
    return EscrowEntry.create(
        tool_call=tool_call,
        args={"path": "/tmp/secret.txt"},
        context={"session_id": "s-abc123", "trace_hash": "deadbeef"},
        D_hat=D_hat,
        t_halt=_T_HALT,
        escrow_id=escrow_id,
    )


# ---------------------------------------------------------------------------
# EscrowEntry — serialization
# ---------------------------------------------------------------------------

class TestEscrowEntrySerialization:
    def test_to_dict_roundtrip(self):
        entry = _make_entry()
        restored = EscrowEntry.from_dict(entry.to_dict())
        assert restored == entry

    def test_to_json_roundtrip(self):
        entry = _make_entry()
        restored = EscrowEntry.from_json(entry.to_json())
        assert restored == entry

    def test_to_dict_fields(self):
        entry = _make_entry(tool_call="exec_sql", D_hat=0.3, escrow_id="abc123")
        d = entry.to_dict()
        assert d["tool_call"] == "exec_sql"
        assert d["D_hat"] == 0.3
        assert d["escrow_id"] == "abc123"
        assert d["t_halt"] == _T_HALT

    def test_from_dict_coerces_D_hat(self):
        entry = _make_entry()
        d = entry.to_dict()
        d["D_hat"] = "0.5"           # string instead of float
        restored = EscrowEntry.from_dict(d)
        assert restored.D_hat == 0.5

    def test_create_generates_escrow_id(self):
        e1 = _make_entry()
        e2 = _make_entry()
        assert e1.escrow_id != e2.escrow_id
        assert len(e1.escrow_id) == 16


# ---------------------------------------------------------------------------
# EscrowStore — CRUD
# ---------------------------------------------------------------------------

class TestEscrowStoreCRUD:
    def test_put_get(self):
        store = EscrowStore()
        entry = _make_entry()
        store.put(entry)
        assert store.get(entry.escrow_id) == entry

    def test_get_missing_raises(self):
        store = EscrowStore()
        with pytest.raises(KeyError):
            store.get("nonexistent")

    def test_remove(self):
        store = EscrowStore()
        entry = _make_entry()
        store.put(entry)
        removed = store.remove(entry.escrow_id)
        assert removed == entry
        with pytest.raises(KeyError):
            store.get(entry.escrow_id)

    def test_remove_missing_raises(self):
        store = EscrowStore()
        with pytest.raises(KeyError):
            store.remove("nonexistent")

    def test_list_entries(self):
        store = EscrowStore()
        entries = [_make_entry(tool_call=f"tool_{i}") for i in range(5)]
        for e in entries:
            store.put(e)
        listed = store.list_entries()
        assert len(listed) == 5
        assert set(e.escrow_id for e in listed) == set(e.escrow_id for e in entries)

    def test_len(self):
        store = EscrowStore()
        assert len(store) == 0
        store.put(_make_entry())
        assert len(store) == 1

    def test_contains(self):
        store = EscrowStore()
        entry = _make_entry()
        assert entry.escrow_id not in store
        store.put(entry)
        assert entry.escrow_id in store

    def test_put_overwrites(self):
        store = EscrowStore()
        entry1 = EscrowEntry.create(
            tool_call="tool_a", args={}, context={}, D_hat=0.1, t_halt=_T_HALT,
            escrow_id="fixed-id-001"
        )
        entry2 = EscrowEntry.create(
            tool_call="tool_b", args={}, context={}, D_hat=0.9, t_halt=_T_HALT,
            escrow_id="fixed-id-001"
        )
        store.put(entry1)
        store.put(entry2)
        assert len(store) == 1
        assert store.get("fixed-id-001").tool_call == "tool_b"


# ---------------------------------------------------------------------------
# EscrowStore — persistence
# ---------------------------------------------------------------------------

class TestEscrowStorePersistence:
    def test_save_creates_file(self, tmp_path):
        store = EscrowStore()
        store.put(_make_entry())
        path = tmp_path / "escrow.json"
        store.save(path)
        assert path.exists()

    def test_save_valid_json(self, tmp_path):
        store = EscrowStore()
        store.put(_make_entry())
        path = tmp_path / "escrow.json"
        store.save(path)
        data = json.loads(path.read_text())
        assert isinstance(data, list)
        assert len(data) == 1

    def test_save_load_roundtrip(self, tmp_path):
        store = EscrowStore()
        entries = [_make_entry(tool_call=f"tool_{i}") for i in range(3)]
        for e in entries:
            store.put(e)
        path = tmp_path / "escrow.json"
        store.save(path)

        store2 = EscrowStore()
        store2.load(path)
        assert len(store2) == 3
        for e in entries:
            assert store2.get(e.escrow_id) == e

    def test_from_file_classmethod(self, tmp_path):
        store = EscrowStore()
        entry = _make_entry()
        store.put(entry)
        path = tmp_path / "escrow.json"
        store.save(path)

        store2 = EscrowStore.from_file(path)
        assert store2.get(entry.escrow_id) == entry

    def test_load_replaces_state(self, tmp_path):
        path = tmp_path / "escrow.json"

        store1 = EscrowStore()
        store1.put(_make_entry(tool_call="old_tool"))
        store1.save(path)

        store2 = EscrowStore()
        store2.put(_make_entry(tool_call="new_tool"))
        store2.load(path)   # should replace new_tool with old_tool

        entries = store2.list_entries()
        assert len(entries) == 1
        assert entries[0].tool_call == "old_tool"

    def test_save_empty_store(self, tmp_path):
        store = EscrowStore()
        path = tmp_path / "empty.json"
        store.save(path)
        store2 = EscrowStore.from_file(path)
        assert len(store2) == 0

    # ----------------------------------------------------------------
    # GATE: HALT → save() → reload() → state preserved
    # ----------------------------------------------------------------

    def test_gate_halt_save_reload(self, tmp_path):
        """Sprint 1 gate.

        Simulates a HALT event: the interceptor captures a tool call and
        puts it in escrow. The store is saved (e.g. process checkpoint).
        On reload, state is byte-for-byte identical.
        """
        # 1. HALT — capture tool call into escrow
        store = EscrowStore()
        halt_entry = EscrowEntry.create(
            tool_call="send_email",
            args={"to": "cfo@example.com", "subject": "Transfer $1M"},
            context={
                "session_id": "sess-halt-42",
                "trace_hash": "cafebabe",
                "A_0_hash": "0123456789abcdef",
            },
            D_hat=0.81,
            t_halt="2026-05-15T14:30:00+00:00",
        )
        store.put(halt_entry)
        assert halt_entry.escrow_id in store

        # 2. save() — persist to disk
        path = tmp_path / "halt_escrow.json"
        store.save(path)
        assert path.exists()

        # 3. reload() — new store instance from file
        store_reloaded = EscrowStore.from_file(path)

        # 4. state preserved — exact field-by-field match
        assert halt_entry.escrow_id in store_reloaded
        restored = store_reloaded.get(halt_entry.escrow_id)

        assert restored.escrow_id == halt_entry.escrow_id
        assert restored.tool_call == halt_entry.tool_call
        assert restored.args      == halt_entry.args
        assert restored.context   == halt_entry.context
        assert restored.D_hat     == halt_entry.D_hat
        assert restored.t_halt    == halt_entry.t_halt
        assert restored            == halt_entry          # full equality


# ---------------------------------------------------------------------------
# P95 latency benchmark (non-blocking gate: P95 < 1 ms)
# ---------------------------------------------------------------------------

class TestP95Latency:
    def test_p95_serialize_deserialize(self):
        N = 1000
        entry = _make_entry()
        latencies = []

        for _ in range(N):
            t0 = time.perf_counter()
            s = entry.to_json()
            EscrowEntry.from_json(s)
            latencies.append(time.perf_counter() - t0)

        latencies.sort()
        p95_ms = latencies[int(0.95 * N)] * 1000
        assert p95_ms < 1.0, f"P95 serialize/deserialize = {p95_ms:.3f} ms (must be < 1 ms)"
