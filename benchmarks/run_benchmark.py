import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from witness_research import WitnessChain, verify_chain


def main() -> None:
    n = 1000
    chain = WitnessChain()
    t0 = time.perf_counter()
    for i in range(n):
        chain.append({"tool": "agent_step", "i": i, "args": {"query": f"item-{i}"}})
    t_seal = (time.perf_counter() - t0) * 1000
    cp = chain.emit_checkpoint()

    t1 = time.perf_counter()
    ok, msg = verify_chain(chain.events, cp)
    t_verify = (time.perf_counter() - t1) * 1000

    assert ok, msg
    print(f"Events: {n}")
    print(f"Mean local sealing overhead: {t_seal / n:.4f} ms/event")
    print(f"Full chain + Merkle verification: {t_verify:.2f} ms")


if __name__ == "__main__":
    main()
