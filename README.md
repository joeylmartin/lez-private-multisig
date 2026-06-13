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
TOKEN_PROGRAM=<lez>/artifacts/program_methods/token.bin \
PMS_PROGRAM=$(pwd)/target/riscv32im-risc0-zkvm-elf/docker/private_multisig.bin \
cargo test -p private-multisig-e2e --test e2e_lifecycle -- --nocapture
```

The test deploys both programs, creates a token + 2-of-3 multisig, funds the
vault, proposes a vault→recipient transfer, approves with two members,
**verifies a double-vote is rejected**, executes permissionlessly via
ChainedCall, and checks the resulting balances.

## Error codes

All program failures use stable, documented `PMS_Exxx` panic strings — see
[`pms_core/src/error.rs`](pms_core/src/error.rs).

## Status / roadmap

- [x] Program: create / propose / approve / reject / execute with anonymous
      membership + per-proposal nullifiers (29 unit tests)
- [x] Reproducible guest build (Docker image ID)
- [x] SPEL IDL
- [x] E2E lifecycle vs. real sequencer (public mode)
- [ ] SDK: private-execution transport for Approve (privacy circuit proving,
      `RISC0_DEV_MODE=0` benchmarks)
- [ ] CLI + Basecamp GUI module
- [ ] Testnet deployment evidence, demo.sh, write-up, video
