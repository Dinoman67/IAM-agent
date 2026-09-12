"""Tamper-evident evidence ledger — hash-chained audit trail.

Each entry links to the previous entry's hash (like a mini blockchain).
Anyone can verify the chain; any edit breaks every later link.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from pydantic import BaseModel, Field


def _hash(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


class LedgerEntry(BaseModel):
    index: int = 0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = "note"
    data: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = "GENESIS"
    entry_hash: str = ""


def append_entry(chain: List[LedgerEntry], event_type: str, data: Dict[str, Any]) -> LedgerEntry:
    prev = chain[-1].entry_hash if chain else "GENESIS"
    entry = LedgerEntry(index=len(chain), event_type=event_type, data=data, prev_hash=prev)
    entry.entry_hash = _hash({"index": entry.index, "ts": entry.timestamp, "type": event_type, "data": data, "prev": prev})
    chain.append(entry)
    return entry


def verify_chain(chain: List[LedgerEntry]) -> Dict[str, Any]:
    prev = "GENESIS"
    for i, e in enumerate(chain):
        if e.index != i or e.prev_hash != prev:
            return {"valid": False, "broken_at": i, "reason": "index/prev-hash mismatch"}
        recomputed = _hash({"index": e.index, "ts": e.timestamp, "type": e.event_type, "data": e.data, "prev": e.prev_hash})
        if recomputed != e.entry_hash:
            return {"valid": False, "broken_at": i, "reason": "entry hash mismatch (tampered content)"}
        prev = e.entry_hash
    return {"valid": True, "entries": len(chain), "tip": prev}


def chain_from_events(events: List[Dict[str, Any]]) -> List[LedgerEntry]:
    chain: List[LedgerEntry] = []
    for ev in events:
        append_entry(chain, ev.get("event_type", "event"), {"summary": ev.get("summary", ""), "id": ev.get("event_id", "")})
    return chain


__all__ = ["LedgerEntry", "append_entry", "verify_chain", "chain_from_events"]
