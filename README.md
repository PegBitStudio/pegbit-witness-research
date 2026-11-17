# PegBit Witness Research: Anti-Truncation & Split-Plane Auditability

[![CI](https://github.com/PegBitStudio/pegbit-witness-research/actions/workflows/ci.yml/badge.svg)](https://github.com/PegBitStudio/pegbit-witness-research/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **PegBit Studio · Flagship Research Pillar 01** (`PegBit Technologies Ltd`, Nigeria)  
> Research Programme: [pegbitstudio.com/research#verifiable-ai](https://www.pegbitstudio.com/research#verifiable-ai) · Publications: [pegbitstudio.com/research/publications](https://www.pegbitstudio.com/research/publications)

---

## Preliminary Local Benchmark Results
*(Single-run local baseline; not yet independent external cryptographic audit.)*

| Metric | Observed Result | Notes |
| :--- | :--- | :--- |
| **Anti-Truncation & Equivocation Tests (`pytest`)** | **4 / 4 passed** (`0.08s`) | Valid chain, interior bitflip, post-checkpoint tail truncation, split-view fork |
| **Mean Local Sealing Overhead (`1,000` events)** | **0.0099 ms / event** | Local SHA-256 + canonical JSON sealing |
| **Full Chain + Merkle Verification (`1,000` events)** | **8.84 ms** | Offline verification latency |
| **Production Context** | **Live deployment** | Global Prayer Altar (Canada), from a private codebase; this repository is a smaller reference version |

---

## Research Problem & Threat-Model Qualification

Standard append-only SHA-256 hash chains detect **interior tampering**, but fail against **tail-truncation** and **split-view equivocation** when a compromised host controls both logs and local checkpoints.

**Thesis (research goal, not all built yet):** Pairing canonical JSON SHA-256 chaining and Merkle batching with **externally witnessed Signed Tree Head (STH) checkpoints** enables offline detection of interior tampering, anchored-prefix truncation, and split-view forks (when auditors compare/gossip receipts) without exposing private prompt payloads.

**Built today vs planned:**

- **Built in this repository:** sorted-key canonical JSON (RFC 8785-style, not fully compliant), SHA-256 hash chaining, RFC 6962-style Merkle roots, head checkpoints, and offline verification that detects interior edits, tail truncation and split-view forks against a saved checkpoint.
- **Not built yet:** signed checkpoints (e.g. Ed25519), external witnesses or k-of-n quorum, RFC 3161 trusted timestamps, Merkle consistency proofs, and prompt-private verification. Checkpoints here are unsigned and held locally.

**Mandatory Qualification:** Cryptographic chaining + external checkpoints prove **post-capture immutability and sequence consistency** for captured events; they do *not* independently prove that original inputs were truthful or detect uncaptured side-channel actions outside the instrumented boundary.

## Quickstart

```bash
PYTHONPATH=src python -m pytest -v
PYTHONPATH=src python benchmarks/run_benchmark.py
```

## Structure

- `src/witness_research/sealer.py` — Sorted-key canonical JSON (RFC 8785-style), SHA-256 hash-chain sealing, RFC 6962 Merkle root synthesis, and monotonic head-checkpoint verification.
- `tests/test_anti_truncation.py` — Fault-injection suite testing bit-flips, interior deletion, tail truncation, and split-view equivocation.
- `benchmarks/run_benchmark.py` — Reproducible local sealing & verification latency benchmark.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
