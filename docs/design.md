# Private M-of-N Multisig for LEZ — Design Write-up

*LP-0002 submission. Companion docs: [benchmarks.md](benchmarks.md),
[../README.md](../README.md) (build/run), [../idl/](../idl/) (SPEL IDL).*

## 1. The problem

The public lez-multisig PoC cannot admit shielded accounts as members, for a
structural reason: it authenticates members by **claiming their accounts**
(`program_owner = multisig`) and by checking signed writes against a public
member list. A shielded account can never satisfy this:

1. **Claiming requires an uninitialized account.** A shielded account in use
   is already claimed by the privacy protocol's programs, its nonce evolves
   on every use, and `program_owner` is immutable — the claim precondition
   can never be met, and ownership can never be transferred.
2. **The member list is public state** — a watchlist by itself.
3. **Votes are signed public writes** — voting patterns fully exposed.

## 2. The scheme

### 2.1 Membership: salted commitments, no claimed accounts

A member is represented on-chain by

```
member_cm = SHA256("/PMS/v0.1/MemberCommitment/" ‖ salt ‖ member_account_id)
```

where `salt` is a random 32-byte secret in the member's wallet and
`member_account_id` is their shielded account's ID (derived from the
account's nullifier public key, exactly as the platform derives it).
`CreateMultisig` stores the flat list of commitments plus the threshold M.

**This is the direct answer to the nonce/`program_owner` question: the
constraints evaporate because member accounts are never presented to the
multisig for claiming at all.** No account is claimed; nothing about a
member's account state matters at creation time. Even members cannot
identify each other's entries in the list (each knows only their own salt).

### 2.2 Approval: a private execution recording an unlinkable nullifier

LEZ programs are Risc0 guests, and the platform natively supports running a
program *privately*: the user executes it locally inside the platform's
generic privacy-preserving circuit and submits a proof; validators verify
the proof against the chain's current public state. Crucially, for such a
transaction the chain sees **neither the program's instruction data nor
which private accounts were touched** — only: the touched *public* accounts'
pre/post states, fresh commitments/nullifiers for private accounts, and
ciphertexts addressed to their owners.

An approval is a private execution of the multisig program with:

- **Public pre-states:** the MultisigState PDA (read) and the Proposal PDA
  (mutated).
- **Private pre-state:** the member's shielded account, *authorized* — the
  privacy circuit proves knowledge of the account's nullifier secret key
  (nsk), which is the platform's own definition of controlling a shielded
  account. The program never sees the nsk; it sees the runtime-attested
  `is_authorized` flag.
- **Instruction data (hidden):** the member's `salt`.

The program then enforces, in plain Rust:

1. the supplied salt commits to the **authorized** account's ID and that
   commitment is in the member set (membership, bound to the shielded
   account);
2. computes the **vote nullifier**

   ```
   vote_nullifier = SHA256("/PMS/v0.1/VoteNullifier/" ‖ salt ‖
                           multisig_state_account_id ‖ proposal_index_le ‖
                           action_hash)
   ```

   and rejects if it is already recorded (`PMS_E012`);
3. appends the nullifier to the Proposal PDA.

What this yields, criterion by criterion:

- **Anonymity, including from other members.** The transaction is *unsigned*
  (verified live: the sequencer accepts zero-signature privacy-preserving
  transactions, so there is not even a fee-payer to correlate). Its bytes
  contain no member account ID and no salt — asserted programmatically in
  `e2e_tests/tests/e2e_private_approve.rs` against the serialized
  transaction. The member's account appears only as a fresh commitment and
  a platform nullifier, both unlinkable without the member's keys.
- **Double-vote prevention.** The nullifier is deterministic per
  (member, proposal): voting twice produces a byte-identical nullifier and
  the program rejects it. Honest clients fail *locally during proving* —
  nothing is submitted.
- **Unlinkability across proposals.** `proposal_index` and `action_hash`
  are inside the hash; nullifiers for different proposals are independent
  SHA256 outputs.
- **Replay protection.** The nullifier binds to the multisig state
  *account ID* (which itself commits to the program ID and `create_key`) and
  to the `action_hash` — an approval cannot be replayed against another
  instance, another program, or a modified action.

### 2.3 Two nullifier namespaces (terminology guard)

LEZ already uses "nullifier" at the platform level: each private-account
*state update* reveals a platform nullifier that marks the previous account
commitment spent. Those cannot provide double-vote prevention — an account's
commitment chain evolves on every use, so nothing platform-level stops the
same member approving twice from two account versions. Our `vote_nullifier`
is an **application-level** nullifier (one per member per proposal), kept in
the Proposal PDA and domain-separated (`/PMS/...` vs `/LEE/...` tags).

We considered and rejected riding the platform's deterministic
*account-initialization* nullifier via per-(member, proposal) private PDAs:
elegant, but anyone learning a member's npk (shared with every transfer
counterparty) could pre-initialize the ticket account and burn the member's
vote. The salt-based application nullifier has no such griefing surface.

### 2.4 Propose and Execute: deliberately permissionless

Proposal content is public (in scope per the prize). Anyone may propose;
proposals carry no authority — approvals do. This removes the proposer
identity leak the PoC has (proposer field + auto-approval).

`Execute` is unsigned and permissionless: once
`vote_nullifiers.len() ≥ M` anyone can crank it; the program emits the
stored ChainedCall (same mechanism as the public PoC — e.g. a token transfer
authorized via the vault PDA seed). Execution is unlinkable to members
because no member account, signature, or identity is involved — there is
nothing to link.

### 2.5 Why no custom ZK circuit

The handoff analysis considered three options: (A) a dedicated approval
guest composed into the program via `env::verify`; (B) riding the platform's
private execution; (C) a hand-written Groth16 circuit. Reading the LEE
source settled it: the privacy circuit already (a) passes public accounts
through (the program can read the member set and write the proposal),
(b) hides instruction data (the salt has a private channel), and (c) attests
shielded-account control via nsk. Option B therefore needs **zero
additional cryptography** — the multisig is ~600 lines of plain Rust, and
its privacy reduces entirely to the audited platform circuit. A is the
documented fallback (composition is supported — the platform itself uses
`env::verify`); C is strictly worse on LEZ (nothing verifies Groth16;
everything is Risc0 + accelerated SHA256).

## 3. Trust assumptions & threat model

- **The platform's privacy circuit** is the cryptographic root of trust
  (exactly as for private transfers): its image ID is pinned in the
  sequencer, and our proofs are receipts of it.
- **The program's image ID is the program ID.** Members should verify the
  published ID against the reproducible Docker build
  (`cargo risczero build`) before trusting a deployment.
- **Salt secrecy = vote privacy + vote integrity** for that member. A leaked
  salt lets the holder (a) link that member's commitments/nullifiers and
  (b) vote in their stead **only if** they also control the member's
  shielded account (the circuit still demands nsk knowledge for the
  authorized pre-state). Losing the salt (but keeping the account) means the
  member can no longer vote — store both together; both derive from wallet
  storage in the SDK.
- **The sequencer sees timing and source IPs.** Network-level anonymity
  (e.g. submitting through a mixnet — the Logos stack's Blend network is the
  natural fit) is out of scope but composes cleanly since transactions are
  unsigned.
- **Liveness:** an approval proof binds to the proposal's exact pre-state;
  concurrent approvals serialize, and a losing prover must re-prove
  (~2 minutes). With small N this is benign; the SDK surfaces it as a typed
  `NotIncluded` error with refresh-and-retry guidance.
- **Collusion / receipt-freeness is out of scope** (not in the success
  criteria): a member *can* prove how they voted by revealing their salt.
  MACI-style coercion resistance is future work.

## 4. Known limitations

1. **Fixed membership (v1).** Member rotation requires re-creating the
   multisig (as did the PoC originally). A `ProposeConfig` flow over the
   commitment list is straightforward future work.
2. **Member set size ≤ 16** (`MAX_MEMBERS`): the membership check is a flat
   scan (one 96-byte SHA256 per member). Larger sets want a Merkle root —
   the program is ~30 lines away from it; not needed at prize scale.
3. **Repeat voting from the same account** uses the account *update* path
   (synced state + on-chain membership proof via `getProofForCommitment`).
   The SDK exposes it (`member_account: Some(state)`), but the demo and
   tests exercise the fresh-account *init* path; a wallet-grade
   `sync-private` equivalent is future work.
4. **Anonymity-set note:** a fresh member account's first vote emits an
   *initialization* nullifier; an observer can tell *some* fresh private
   account was initialized (not whose). Members who also use their account
   for transfers blend into the global commitment set.
5. **Vote switching is observable as an event** ("one rejection retracted,
   one approval added in the same transaction") though not attributable.

## 5. Integration guide (for module authors)

Use `pms_sdk`:

```rust
let client = MultisigClient::new(sequencer_url, program_bytes)?;

// One-time, per member (keep both secrets in wallet storage):
let member = MemberIdentity::from_seed(seed, salt);
// share member.commitment() with the multisig creator

client.create_multisig(create_key, m, commitments).await?;
client.propose(create_key, 1, target_prog, instr, n, seeds, auth).await?;

// The private vote (run off the UI thread; minutes under RISC0_DEV_MODE=0):
client.approve_private(create_key, 1, &member, None).await?;

// Resumability — no local bookkeeping needed:
let voted = client.has_voted(&create_key, 1, &member).await?;

client.execute(create_key, 1, vec![vault, recipient]).await?;
```

Error handling: program rules surface as `SdkError::Proving` carrying the
documented `PMS_Exxx` string (deterministic; do not retry); transient prover
failures are retryable; `SdkError::NotIncluded` means the proposal changed
under you — refresh and re-prove. All error codes:
[`pms_core/src/error.rs`](../pms_core/src/error.rs).

The CLI (`pms`) wraps the same SDK 1:1 and is what `scripts/demo.sh` drives;
the Basecamp module wraps the CLI. The SPEL IDL
(`idl/private_multisig_idl.json`) describes all six instructions and PDA
derivations for any other tooling.

## 6. Alternatives considered

- **FROST / threshold signatures:** rejected — a threshold signature proves
  "M of N signed" but provides no per-proposal double-vote accounting
  without extra machinery, requires interactive DKG (poor UX for this
  setting), and verifying exotic signatures in-guest costs more than the
  entire approval program. Nullifier-based anonymous signalling
  (Semaphore-style, here implemented on the platform's own privacy rails)
  matches the criteria exactly.
- **Semaphore-classic (Groth16 + Poseidon):** wrong fit for LEZ — see §2.5.
- **Platform-level vote tickets (private PDAs):** see §2.3 griefing analysis.
