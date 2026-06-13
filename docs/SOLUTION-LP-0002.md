# Solution: LP-0002 — Private M-of-N Multisig

> Drop this into the λPrize repo as `solutions/LP-0002.md` and open a PR titled
> `Solution: LP-0002 — Private M-of-N Multisig`. It is kept in the
> implementation repo so it versions alongside the code.

## Summary

A private M-of-N multisig primitive for the Logos Execution Zone. Members hold
**shielded LEZ accounts**; membership is a set of salted commitments; approvals
are submitted as **privacy-preserving transactions** that record an unlinkable
per-proposal nullifier. On-chain state shows only that a threshold was met —
never which members approved, and never a member account ID or signature.

The design needs **no custom ZK circuit**: an approval is a *private execution*
of the multisig program (plain Rust) inside the platform's own
privacy-preserving circuit, which already hides instruction data and the
member's account while attesting control via the account's nullifier secret
key. The membership constraint that blocks the public PoC — claiming
fresh zero-nonce accounts — never arises, because member accounts are never
presented to the program.

## Repositories

- **Program + SDK + CLI + tests + demo + docs:** `lez-private-multisig`
- **Basecamp GUI app:** `logos-private-multisig-ui`

Both dual-licensed MIT / Apache-2.0.

## Approach

- **Membership:** `member_cm = SHA256(DST ‖ salt ‖ member_account_id)`, stored
  as a flat list in the MultisigState PDA. No accounts claimed.
- **Approval:** a private execution with the member's shielded account as an
  authorized pre-state and the salt in (hidden) instruction data. The program
  verifies the salt commits to the authorized account and is in the member set,
  then records `vote_nullifier = SHA256(DST ‖ salt ‖ multisig_id ‖ index ‖
  action_hash)`. Deterministic per (member, proposal) → double votes collide;
  domain/instance/action binding → no cross-proposal or cross-instance replay.
- **Execution:** permissionless and unsigned; emits the stored ChainedCall.
- **Two nullifier namespaces** (platform state-versioning vs. our app-level
  vote nullifiers) are domain-separated and explained in the write-up.

Full design, threat model, the nonce/`program_owner` answer, limitations, and
alternatives (FROST, Semaphore-classic, platform vote-tickets — and why each
was rejected) are in [docs/design.md](design.md).

## Evidence against success criteria

### Functionality
- Anonymous approval, threshold without revealing voters, double-vote
  prevention, unlinkable execution, laptop-side proving — all demonstrated by
  `e2e_tests/tests/e2e_private_approve.rs` (asserts zero signatures, no member
  ID / salt in the tx bytes, local `PMS_E012` on double vote) and the
  `RISC0_DEV_MODE=0` run in [docs/evidence/](evidence/).
- Reference integration: a treasury-style vault→recipient token transfer gated
  by 2-of-3 approval (`scripts/demo.sh`, `e2e_lifecycle`).
- Testnet instance: a 2-of-3 multisig on `https://testnet.lez.logos.co`
  driven through the **full lifecycle** — two real private approvals
  (proofs 98 s / 95 s) → execute → 100 tokens moved vault→recipient,
  proposal `Executed`. On-chain IDs, the two approval tx hashes, and a decode
  proving they are unsigned/leak-free are in
  [docs/evidence/testnet.md](evidence/testnet.md) (program id
  `4034ba058ee8b799fe0f5cf449b503a7a0d2acb1554144f81bf9cd942a171c2b`).

### Usability
- **SDK:** `pms_sdk` (`MemberIdentity`, `MultisigClient`).
- **Basecamp GUI:** `logos-private-multisig-ui` — builds with `nix build`,
  loads into the standalone host, smoke-tested.
- **SPEL IDL:** `idl/private_multisig_idl.json` (6 instructions), generated
  from the `#[lez_program]` source by `idl-gen`.

### Reliability
- Proof-generation failures surface as typed `SdkError::Proving` (carrying the
  `PMS_Exxx` code) before any submission; pre-state races as `NotIncluded`.
- Partial approvals are durable on-chain; `has_voted` recomputes from chain
  state (no client bookkeeping), so they resume across restarts.
- Deterministic, documented error codes: `pms_core/src/error.rs`.

### Performance
- CU/cycle + proving benchmarks: [docs/benchmarks.md](benchmarks.md)
  (guest 296,557 cycles ≈ <1% of the 32M public budget; full approval proof
  ~101 s; verification ~10 ms).

### Supportability
- Deployed/tested on local standalone sequencer and testnet.
- `e2e` suites run against a standalone sequencer in CI
  (`.github/workflows/ci.yml`); the `check` job gates the default branch.
- README documents deployment + CLI + Basecamp usage and program addresses.
- `scripts/demo.sh` is the reproducible `RISC0_DEV_MODE=0` end-to-end demo.
- Narrated video: recorded separately for the submission PR.

## How to reproduce the demo

```bash
# Build the pms CLI and the reproducible guest binary (needs Docker + rzup)
cargo build --release -p pms-cli
cargo risczero build --manifest-path methods/guest/Cargo.toml

# Run the full lifecycle with REAL proofs against a fresh local sequencer
LEZ_DIR=<path-to-logos-execution-zone-v0.1.2> ./scripts/demo.sh
```

## Known limitations

- Fixed membership in v1 (no rotation); member set ≤ 16 (flat scan).
- Repeat voting from the *same* account uses the account-update path; the SDK
  exposes the hook but the demo/tests exercise the fresh-account path.
- Anti-collusion / receipt-freeness is explicitly out of scope (see write-up).
