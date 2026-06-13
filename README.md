# Private M-of-N Multisig for LEZ (LP-0002)

A multisig program for the Logos Execution Zone where **approvals reveal
nothing about who voted** — not to observers, not to other members. On-chain
state shows only that the M-of-N threshold was reached.

## How it works

- **Membership = salted commitments.** At creation, each member submits
  `member_cm = SHA256(DST ‖ salt ‖ account_id)` where `salt` is a 32-byte
  secret held in the member's wallet and `account_id` is their (shielded)
  account. The on-chain member list is opaque — even members cannot identify
  each other's entries. **No accounts are claimed by the program**, so
  shielded accounts (fixed `program_owner`, evolving nonce) can be members —
  the constraint that breaks the public multisig PoC simply does not arise.
- **Approval = anonymous nullifier.** A vote is an execution of this program
  carrying the member's `salt` in instruction data, with the member's account
  as an authorized pre-state. The program checks the salt commits to the
  authorized account and that the commitment is in the member set, then
  records `vote_nullifier = SHA256(DST ‖ salt ‖ multisig_id ‖ proposal_index ‖
  action_hash)`. Submitted as a **LEZ private execution**, the transaction
  reveals neither the instruction data (salt) nor the member account — only
  the proposal diff: one opaque nullifier, count + 1.
- **Double votes collide.** The nullifier is deterministic per
  (member, proposal), so voting twice produces a duplicate the program
  rejects — while nullifiers across proposals are unlinkable.
- **Execution is permissionless and unlinkable.** Once
  `vote_nullifiers.len() ≥ M`, anyone can submit Execute (no signature
  required); the program emits the stored ChainedCall to the target program.
  No member account is ever involved.

The same guest binary runs in both LEZ execution modes; the protocol — not
the program — decides public vs. private. The e2e test drives the full
lifecycle in public mode (identical logic, visible transport); the private
transport for Approve is the SDK's job (in progress).

## Layout

| Crate | Purpose |
|---|---|
| `pms_core` | Shared types: state, instructions, domain-separated hashing (commitments + nullifiers), SPEL-compatible PDA derivation, documented error codes |
| `multisig_program` | Program logic + SPEL `#[lez_program]` surface (IDL source of truth) |
| `methods` / `methods/guest` | Risc0 guest build (`private_multisig.bin`, program ID = image ID) |
| `idl-gen` | Generates `idl/private_multisig_idl.json` from the program source |
| `e2e_tests` | Full lifecycle against a real local sequencer |

Pinned platform: `logos-execution-zone` tag **v0.1.2** (`nssa`-era naming —
matches SPEL's pin and the current testnet generation), `spel` rev `73fc462`,
`risc0-zkvm` 3.0.5.

## Build

```bash
# Unit tests (program logic, hashing, PDA math)
cargo test -p pms_core -p multisig_program

# Guest binary — reproducible Docker build (requires Docker)
cargo risczero build --manifest-path methods/guest/Cargo.toml
# → target/riscv32im-risc0-zkvm-elf/docker/private_multisig.bin (+ ImageID)

# IDL
cargo run -p private-multisig-idl-gen > idl/private_multisig_idl.json
```

## E2E test

Requires a local standalone sequencer from logos-execution-zone @ v0.1.2:

```bash
# In logos-execution-zone @ v0.1.2:
RUST_LOG=info RISC0_DEV_MODE=1 cargo run --features standalone -p sequencer_service \
    sequencer/service/configs/debug/sequencer_config.json

# In this repo:
# Public-mode lifecycle (program logic, visible transport):
TOKEN_PROGRAM=<lez>/artifacts/program_methods/token.bin \
PMS_PROGRAM=$(pwd)/target/riscv32im-risc0-zkvm-elf/docker/private_multisig.bin \
cargo test -p private-multisig-e2e --test e2e_lifecycle -- --nocapture

# PRIVATE approvals via the SDK (privacy-preserving transactions):
RISC0_DEV_MODE=1 \
TOKEN_PROGRAM=<lez>/artifacts/program_methods/token.bin \
PMS_PROGRAM=$(pwd)/target/riscv32im-risc0-zkvm-elf/docker/private_multisig.bin \
cargo test -p private-multisig-e2e --test e2e_private_approve -- --nocapture
```

`e2e_lifecycle` drives the full flow with public transactions (deploy, token,
multisig, vault, propose, approve ×2, double-vote rejected **on-chain**,
permissionless execute, balance checks). `e2e_private_approve` repeats the
flow with approvals submitted as **privacy-preserving transactions** via the
SDK and asserts the privacy properties against the actual chain bytes: zero
signatures, no member account ID, no salt; double votes fail **locally during
proving** with PMS_E012 before anything is submitted; `has_voted` is
recomputed purely from chain state (resumability).

## SDK

`pms_sdk` is the host-side library the CLI/GUI build on:

- `MemberIdentity` — shielded-account keypair (nullifier + viewing keys,
  platform wallet derivation) + membership salt; exports the on-chain
  commitment.
- `MultisigClient` — reads (state/proposal/`has_voted`), public-mode ops
  (create/propose/init_vault/execute, all unsigned), and
  **`approve_private` / `reject_private`**: local execution + privacy-circuit
  proof + unsigned transaction submission. Program-rule violations surface as
  typed errors carrying the `PMS_Exxx` code before submission; inclusion
  conflicts (another vote landed first) surface as `NotIncluded` with
  refresh-and-re-prove guidance.

## Benchmarks

Real proving (`RISC0_DEV_MODE=0`) on an Apple Silicon laptop: program guest
**296,557 cycles**; full private-approval proof (program receipt + succinct
privacy-circuit receipt) **101 s** wall-clock; proof 227 KB; verification
10 ms. Details in [docs/benchmarks.md](docs/benchmarks.md).

## Error codes

All program failures use stable, documented `PMS_Exxx` panic strings — see
[`pms_core/src/error.rs`](pms_core/src/error.rs).

## Status / roadmap

- [x] Program: create / propose / approve / reject / execute with anonymous
      membership + per-proposal nullifiers (29 unit tests)
- [x] Reproducible guest build (Docker image ID)
- [x] SPEL IDL
- [x] E2E lifecycle vs. real sequencer (public mode)
- [x] SDK: private-execution transport for Approve/Reject (privacy circuit
      proving, zero-signature submission, typed error surface)
- [x] Private-mode e2e with on-chain privacy assertions
- [x] `RISC0_DEV_MODE=0` laptop benchmark (101 s / approval; docs/benchmarks.md)
- [ ] Member-account update path UX (sync-private equivalent for repeat voters)
- [ ] CLI + Basecamp GUI module
- [ ] Testnet deployment evidence, demo.sh, write-up, video
