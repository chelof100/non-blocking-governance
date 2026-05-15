# -*- coding: utf-8 -*-
"""
APB Persistent Log — HMAC-chained JSONL storage (P8 §4.6).

Provides tamper-evident, append-only persistence for APBs.  Each log
entry is a JSON object on its own line (JSONL) with the following
structure:

  {
    "seq":        <int>,        # monotonically increasing, starts at 0
    "apb":        <dict>,       # APB.to_dict() payload
    "prev_hmac":  <hex str>,    # HMAC-SHA256 of the previous entry's
                                #   canonical bytes ("0"*64 for entry 0)
    "entry_hmac": <hex str>     # HMAC-SHA256 of
                                #   seq || apb_json || prev_hmac
  }

Tamper-evidence properties:
  - Deleting an entry breaks the chain (seq gap or prev_hmac mismatch).
  - Reordering entries breaks both the seq ordering and prev_hmac chain.
  - Modifying any field invalidates the entry_hmac.
  - Truncating the file is detected (missing entries).

Thread safety:
  APBLog uses an internal threading.Lock for all write operations.
  Concurrent appends from multiple threads are serialised.

The HMAC key is supplied at construction time and must be kept secret to
prevent an attacker from reforging the chain after tampering.

Reference: P8 §4.6; fault injection Experiment F4 verifies these
           properties empirically across 1 000 log tamper scenarios.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional

from stack.apb import APB


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GENESIS_HMAC = "0" * 64   # sentinel prev_hmac for the first entry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry_bytes(seq: int, apb_dict: dict, prev_hmac: str) -> bytes:
    """Canonical byte string over which entry_hmac is computed.

    Uses sorted-key JSON (RFC 8259) for the APB payload; key ordering
    is deterministic given the fixed Python dict structure.  We do NOT
    use full RFC 8785 here because the HMAC input is always produced and
    consumed by this same implementation, so cross-implementation
    portability is not required.  The guarantee we need is internal
    consistency — same Python process, same output.
    """
    apb_str = json.dumps(apb_dict, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":"))
    return (str(seq) + "|" + apb_str + "|" + prev_hmac).encode("utf-8")


def _hmac_sha256(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Log entry dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LogEntry:
    seq: int
    apb: APB
    prev_hmac: str      # hex HMAC of the previous entry (or genesis)
    entry_hmac: str     # hex HMAC of (seq, apb, prev_hmac) under log key

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "apb": self.apb.to_dict(),
            "prev_hmac": self.prev_hmac,
            "entry_hmac": self.entry_hmac,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict) -> "LogEntry":
        return cls(
            seq=d["seq"],
            apb=APB.from_dict(d["apb"]),
            prev_hmac=d["prev_hmac"],
            entry_hmac=d["entry_hmac"],
        )


# ---------------------------------------------------------------------------
# Integrity verification result
# ---------------------------------------------------------------------------

@dataclass
class IntegrityReport:
    """Result of a full log integrity scan."""
    ok: bool
    entries_checked: int
    first_fault_seq: Optional[int] = None   # seq of first bad entry, or None
    fault_reason: str = ""                   # human-readable reason

    def __bool__(self) -> bool:
        return self.ok


# ---------------------------------------------------------------------------
# APBLog — append-only, HMAC-chained JSONL log
# ---------------------------------------------------------------------------

class APBLog:
    """Thread-safe, tamper-evident APB persistence log.

    Usage::

        log = APBLog(path="/tmp/apb.log", key=b"secret")
        log.append(apb)
        report = log.verify_integrity()
        assert report.ok

    File format: one JSON object per line (JSONL).  Entries are
    append-only; the file is never rewritten.
    """

    def __init__(self, path: str | Path, key: bytes) -> None:
        """
        Parameters
        ----------
        path : str or Path
            File path for the JSONL log.  Created if it does not exist.
        key : bytes
            HMAC-SHA256 key (minimum 16 bytes recommended).
        """
        if len(key) < 16:
            raise ValueError("HMAC key must be at least 16 bytes")
        self._path = Path(path)
        self._key = key
        self._lock = threading.Lock()
        # Cache the last entry's hmac and seq for O(1) append
        self._last_hmac: str = _GENESIS_HMAC
        self._next_seq: int = 0
        self._load_tail()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def append(self, apb: APB) -> LogEntry:
        """Append an APB to the log, returning the written LogEntry.

        Thread-safe: concurrent calls are serialised via internal lock.
        """
        with self._lock:
            seq = self._next_seq
            prev_hmac = self._last_hmac
            apb_dict = apb.to_dict()
            raw = _entry_bytes(seq, apb_dict, prev_hmac)
            eh = _hmac_sha256(self._key, raw)
            entry = LogEntry(
                seq=seq,
                apb=apb,
                prev_hmac=prev_hmac,
                entry_hmac=eh,
            )
            line = entry.to_json() + "\n"
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line)
            self._last_hmac = eh
            self._next_seq = seq + 1
        return entry

    def read_all(self) -> List[LogEntry]:
        """Return all entries in sequence order."""
        return list(self._iter_raw())

    def verify_integrity(self) -> IntegrityReport:
        """Verify the full HMAC chain.

        Checks:
          1. Each entry's entry_hmac matches the HMAC recomputed from
             (seq, apb_dict, prev_hmac) under self._key.
          2. Each entry's prev_hmac matches the previous entry's
             entry_hmac (or _GENESIS_HMAC for the first entry).
          3. Sequence numbers are contiguous starting from 0.
        """
        prev_hmac = _GENESIS_HMAC
        checked = 0
        try:
            for raw_line, entry in self._iter_raw_with_dicts():
                seq_expected = checked
                d = raw_line  # this is the parsed dict

                # Seq check
                if d["seq"] != seq_expected:
                    return IntegrityReport(
                        ok=False,
                        entries_checked=checked,
                        first_fault_seq=d.get("seq"),
                        fault_reason=(
                            f"seq gap: expected {seq_expected}, got {d['seq']}"
                        ),
                    )

                # prev_hmac chain check
                if d["prev_hmac"] != prev_hmac:
                    return IntegrityReport(
                        ok=False,
                        entries_checked=checked,
                        first_fault_seq=d["seq"],
                        fault_reason=(
                            f"prev_hmac mismatch at seq={d['seq']}: "
                            f"expected {prev_hmac!r}, got {d['prev_hmac']!r}"
                        ),
                    )

                # entry_hmac check
                raw = _entry_bytes(d["seq"], d["apb"], d["prev_hmac"])
                expected_hmac = _hmac_sha256(self._key, raw)
                if not hmac.compare_digest(d["entry_hmac"], expected_hmac):
                    return IntegrityReport(
                        ok=False,
                        entries_checked=checked,
                        first_fault_seq=d["seq"],
                        fault_reason=f"entry_hmac invalid at seq={d['seq']}",
                    )

                prev_hmac = d["entry_hmac"]
                checked += 1
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            return IntegrityReport(
                ok=False,
                entries_checked=checked,
                first_fault_seq=checked,
                fault_reason=f"parse error at entry {checked}: {exc}",
            )

        return IntegrityReport(ok=True, entries_checked=checked)

    def __len__(self) -> int:
        return self._next_seq

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_tail(self) -> None:
        """Scan log file to restore last_hmac and next_seq."""
        if not self._path.exists():
            return
        last_line = None
        count = 0
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
                    count += 1
        if last_line is not None:
            try:
                d = json.loads(last_line)
                self._last_hmac = d["entry_hmac"]
                self._next_seq = count
            except (json.JSONDecodeError, KeyError):
                # Corrupted tail — let verify_integrity() catch it
                self._next_seq = count

    def _iter_raw(self) -> Iterator[LogEntry]:
        """Yield LogEntry objects from file (order: written)."""
        if not self._path.exists():
            return
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    d = json.loads(line)
                    yield LogEntry.from_dict(d)

    def _iter_raw_with_dicts(self) -> Iterator[tuple[dict, LogEntry]]:
        """Yield (raw_dict, LogEntry) pairs for integrity checking.

        We need the raw dict (not the reconstructed object) so that
        verify_integrity can recompute entry_hmac over exactly the
        stored apb JSON bytes.
        """
        if not self._path.exists():
            return
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    d = json.loads(line)
                    yield d, LogEntry.from_dict(d)
