import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from witness_research import SealedEvent, WitnessChain, verify_chain


def test_valid_chain_and_checkpoint() -> None:
    chain = WitnessChain()
    for i in range(10):
        chain.append({"tool": "read_file", "step": i})
    cp = chain.emit_checkpoint()
    ok, msg = verify_chain(chain.events, cp)
    assert ok, msg


def test_detects_interior_bitflip() -> None:
    chain = WitnessChain()
    for i in range(6):
        chain.append({"tool": "sql_query", "step": i})
    cp = chain.emit_checkpoint()
    tampered = list(chain.events)
    ev = tampered[3]
    tampered[3] = SealedEvent(
        seq=ev.seq,
        payload={"tool": "drop_table", "step": 3},
        prev_hash=ev.prev_hash,
        event_hash=ev.event_hash,
    )
    ok, msg = verify_chain(tampered, cp)
    assert not ok
    assert "tampering" in msg


def test_detects_tail_truncation_via_checkpoint() -> None:
    chain = WitnessChain()
    for i in range(8):
        chain.append({"tool": "bash", "step": i})
    cp = chain.emit_checkpoint()
    # Attacker drops last 2 events to hide exfiltration
    truncated = chain.events[:-2]
    ok, msg = verify_chain(truncated, cp)
    assert not ok
    assert "tail truncation" in msg


def test_detects_split_view_equivocation() -> None:
    chain_a = WitnessChain()
    chain_b = WitnessChain()
    for i in range(4):
        chain_a.append({"tool": "search", "step": i})
        chain_b.append({"tool": "search", "step": i})
    chain_a.append({"tool": "benign_write"})
    chain_b.append({"tool": "exfiltrate_env"})
    cp_a = chain_a.emit_checkpoint()

    ok, msg = verify_chain(chain_b.events, cp_a)
    assert not ok
    assert "equivocation" in msg
