"""RFC 8785-style canonicalization, SHA-256 chaining, Merkle batching, and anti-truncation checkpoints."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


GENESIS_HASH = "0" * 64


def canonical_json(obj: Any) -> str:
    """Deterministic JSON serialization (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class SealedEvent:
    seq: int
    payload: dict[str, Any]
    prev_hash: str
    event_hash: str


@dataclass(frozen=True)
class HeadCheckpoint:
    """Monotonic external witness commitment binding sequence length to head hash."""
    seq: int
    head_hash: str
    merkle_root: str


def merkle_root_rfc6962(leaves: list[str]) -> str:
    """Compute an RFC 6962-style binary Merkle tree root over hex leaf hashes."""
    if not leaves:
        return sha256_hex(b"")
    nodes = [sha256_hex(b"\x00" + bytes.fromhex(h)) for h in leaves]
    while len(nodes) > 1:
        next_level: list[str] = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                combined = b"\x01" + bytes.fromhex(nodes[i]) + bytes.fromhex(nodes[i + 1])
                next_level.append(sha256_hex(combined))
            else:
                next_level.append(nodes[i])
        nodes = next_level
    return nodes[0]


class WitnessChain:
    """Append-only split-plane execution log with monotonic anti-truncation checkpoints."""

    def __init__(self) -> None:
        self.events: list[SealedEvent] = []
        self.checkpoints: list[HeadCheckpoint] = []

    def append(self, payload: dict[str, Any]) -> SealedEvent:
        seq = len(self.events)
        prev_hash = self.events[-1].event_hash if self.events else GENESIS_HASH
        body = canonical_json({"seq": seq, "prev_hash": prev_hash, "payload": payload}).encode("utf-8")
        event_hash = sha256_hex(body)
        sealed = SealedEvent(seq=seq, payload=payload, prev_hash=prev_hash, event_hash=event_hash)
        self.events.append(sealed)
        return sealed

    def emit_checkpoint(self) -> HeadCheckpoint:
        if not self.events:
            raise ValueError("Cannot emit checkpoint for empty chain")
        leaves = [e.event_hash for e in self.events]
        cp = HeadCheckpoint(
            seq=self.events[-1].seq,
            head_hash=self.events[-1].event_hash,
            merkle_root=merkle_root_rfc6962(leaves),
        )
        self.checkpoints.append(cp)
        return cp


def verify_chain(
    events: list[SealedEvent],
    checkpoint: HeadCheckpoint | None = None,
) -> tuple[bool, str]:
    """Verify hash-chain integrity and optionally detect tail-truncation/equivocation via checkpoint."""
    prev = GENESIS_HASH
    for idx, ev in enumerate(events):
        if ev.seq != idx:
            return False, f"sequence gap at index {idx} (got seq={ev.seq})"
        if ev.prev_hash != prev:
            return False, f"prev_hash mismatch at seq={idx}"
        expected = sha256_hex(
            canonical_json({"seq": ev.seq, "prev_hash": ev.prev_hash, "payload": ev.payload}).encode("utf-8")
        )
        if ev.event_hash != expected:
            return False, f"payload/hash tampering detected at seq={idx}"
        prev = ev.event_hash

    if checkpoint is not None:
        if len(events) - 1 < checkpoint.seq:
            return False, f"tail truncation detected: expected seq>={checkpoint.seq}, got {len(events) - 1}"
        if events[checkpoint.seq].event_hash != checkpoint.head_hash:
            return False, f"split-view equivocation detected at seq={checkpoint.seq}"
        prefix_root = merkle_root_rfc6962([e.event_hash for e in events[: checkpoint.seq + 1]])
        if prefix_root != checkpoint.merkle_root:
            return False, "merkle root mismatch against checkpoint"

    return True, "ok"
