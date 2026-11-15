# PegBit Witness Research: Anti-Truncation & Split-Plane Auditability

[![CI](https://github.com/PegBitStudio/pegbit-witness-research/actions/workflows/ci.yml/badge.svg)](https://github.com/PegBitStudio/pegbit-witness-research/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **PegBit Studio · Applied AI Systems Research** (`PegBit Technologies Ltd`)  
> Research Inquiry: [pegbitstudio.com/research#witness](https://www.pegbitstudio.com/research#witness) · Open Science Policy: [pegbitstudio.com/research/policy](https://www.pegbitstudio.com/research/policy)

## Research Problem & Falsifiable Hypothesis

Standard append-only SHA-256 hash chains detect **interior tampering** (modifying or deleting an earlier record), but fail against two realistic threats in autonomous AI agent execution:

1. **Tail-Truncation Attacks:** A compromised agent runtime drops the last $k$ malicious tool calls before the next external timestamp anchor.
2. **Split-View (Equivocation) Attacks:** A host presents two different hash histories to two different verifiers between anchor windows.

**Hypothesis:** By pairing RFC 8785 canonical JSON SHA-256 chaining and RFC 6962 Merkle batching with **monotonic external head-hash checkpoints** at tool-execution boundaries, a split-plane runtime can detect **100% of tail-truncation and equivocation faults** while keeping local per-event sealing overhead **< 5 ms** and keeping raw prompts/PII strictly off-plane.

## Quickstart

```bash
python -m pytest -v
python benchmarks/run_benchmark.py
```

## Structure

- `src/witness_research/sealer.py` — Canonical JSON (RFC 8785 subset), SHA-256 hash-chain sealing, RFC 6962 Merkle root synthesis, and monotonic head-checkpoint verification.
- `tests/test_anti_truncation.py` — Fault-injection suite testing bit-flips, interior deletion, tail truncation, and split-view equivocation.
- `benchmarks/run_benchmark.py` — Reproducible local sealing & verification latency benchmark.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
