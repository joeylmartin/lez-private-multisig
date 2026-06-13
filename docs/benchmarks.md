# Benchmarks

Machine: MacBook (Apple Silicon, arm64), r0vm 3.0.5 local prover,
`RISC0_DEV_MODE=0` (real proofs). Reproduce with:

```bash
cargo build --release -p pms_sdk --example bench_prove
RISC0_DEV_MODE=0 ./target/release/examples/bench_prove
```

## Private approval (the laptop-proving criterion)

One `Approve` as a private execution: program guest proof + the platform's
privacy-preserving circuit proof (succinct receipt, program receipt composed
via `env::verify`), over a 2-of-3 multisig with one open proposal and a fresh
shielded member account.

| Metric | Value |
|---|---|
| Program guest cycles | **296,557** (1 segment, 38 ms unproven execution) |
| Full proving wall-clock | **101.1 s** |
| Proof size (succinct receipt) | 226,835 bytes |
| Proof verification | 10.1 ms |

The official LEZ docs state a private *transfer* takes "a few minutes" to
prove on a user machine; a private approval lands at ~1.7 minutes on this
hardware — the same ballpark, comfortably practical for a voting flow.
Dev-mode (`RISC0_DEV_MODE=1`) round-trips in ~100 ms for development.

## Compute-unit context (public-mode instructions)

The public execution budget at the pinned platform version is a fixed
32 M-cycle session limit per transaction
(`MAX_NUM_CYCLES_PUBLIC_EXECUTION`). The approval instruction's ~0.30 M
cycles uses **under 1 %** of that budget; Create/Propose/Execute are of the
same order (dominated by borsh + SHA256 over small account data). Per-member
cost of the membership scan is one 96-byte SHA256 per member (N ≤ 16).
