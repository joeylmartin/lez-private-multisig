//! pms_core — shared types for the **private** M-of-N multisig program (LP-0002).
//!
//! Unlike the public lez-multisig PoC, membership is a set of salted
//! commitments rather than a list of account IDs, and votes are recorded as
//! unlinkable per-proposal nullifiers rather than signed member writes:
//!
//! * `member_cm = SHA256(DST_MEMBER ‖ salt ‖ member_account_id)` — only someone
//!   knowing `salt` can prove membership; the on-chain member list reveals
//!   nothing, not even to other members.
//! * `vote_nullifier = SHA256(DST_VOTE ‖ salt ‖ multisig_account_id ‖
//!   proposal_index ‖ action_hash)` — deterministic per (member, proposal), so
//!   a double vote is a duplicate nullifier, while distinct proposals yield
//!   unlinkable values.
//!
//! No member accounts are ever claimed by the program. The nonce /
//! `program_owner` constraints that block shielded accounts from the public
//! PoC do not apply: a member's account only appears as a pass-through
//! pre-state whose control is attested by the runtime (`is_authorized`),
//! which in a private execution is proven by the privacy circuit via the
//! account's nullifier secret key.

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::account::AccountId;
use nssa_core::program::{PdaSeed, ProgramId};
use serde::{Deserialize, Serialize};

pub mod error;

/// Maximum number of members (N). Keeps the nullifier scan and state size
/// trivially within account-data and cycle budgets.
pub const MAX_MEMBERS: usize = 16;

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

/// Instructions for the private M-of-N multisig program.
///
/// Flow:
/// 1. `CreateMultisig` — anyone; stores member commitments + threshold
/// 2. `Propose` — anyone (proposal content is public by design)
/// 3. `Approve { member_salt }` — submitted as a *private execution*; the salt
///    travels in instruction data, which a privacy-preserving transaction
///    never reveals on-chain
/// 4. `Execute` — anyone, once `threshold` approvals are recorded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Instruction {
    /// Create a new multisig with M-of-N threshold over member commitments.
    ///
    /// Accounts: `[multisig_state (uninitialized PDA)]`
    CreateMultisig {
        /// Unique key for PDA derivation — allows multiple multisigs per program
        create_key: [u8; 32],
        /// Required approvals for execution (M)
        threshold: u8,
        /// Salted member commitments (see [`member_commitment`])
        member_cms: Vec<[u8; 32]>,
    },

    /// Create a new proposal. Proposing is permissionless: proposal content is
    /// public and approvals are what carry authority.
    ///
    /// Accounts: `[multisig_state (mut), proposal (uninitialized PDA)]`
    ///
    /// The action fields are flattened (rather than nesting [`ProposalAction`])
    /// so the SPEL IDL describes them as plain instruction arguments.
    Propose {
        create_key: [u8; 32],
        /// Must equal `MultisigState::transaction_index + 1`
        proposal_index: u64,
        target_program_id: ProgramId,
        target_instruction_data: Vec<u32>,
        target_account_count: u8,
        pda_seeds: Vec<[u8; 32]>,
        authorized_indices: Vec<u8>,
    },

    /// Approve a proposal anonymously.
    ///
    /// Accounts: `[multisig_state, proposal (mut), member_account (authorized)]`
    ///
    /// `member_salt` is the member's secret. In a private execution it is
    /// never revealed; the chain records only the resulting nullifier.
    Approve {
        create_key: [u8; 32],
        proposal_index: u64,
        member_salt: [u8; 32],
    },

    /// Reject a proposal anonymously (same mechanics as `Approve`).
    /// When more than N − M members reject, the proposal can never reach the
    /// threshold and is marked `Rejected`.
    Reject {
        create_key: [u8; 32],
        proposal_index: u64,
        member_salt: [u8; 32],
    },

    /// Execute a fully-approved proposal by emitting a ChainedCall.
    /// Execution is permissionless — no member account is involved, which
    /// keeps execution unlinkable to any member.
    ///
    /// Accounts: `[multisig_state, proposal (mut), target_accounts...]`
    Execute {
        create_key: [u8; 32],
        proposal_index: u64,
    },

    /// Initialize the multisig's token vault: chain-calls the token program's
    /// `InitializeAccount` with the vault PDA authorized via this program's
    /// `pda_seeds`. Permissionless — anyone may set up the vault so it can
    /// then receive plain token transfers.
    ///
    /// Accounts: `[token_definition, vault (uninitialized PDA)]`
    InitVault {
        create_key: [u8; 32],
        token_program_id: ProgramId,
    },
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct MultisigState {
    /// Unique key used to derive this multisig's PDAs
    pub create_key: [u8; 32],
    /// Required approvals (M)
    pub threshold: u8,
    /// Salted member commitments. Fixed at creation (member rotation is out
    /// of scope for v1); `member_cms.len()` is N.
    pub member_cms: Vec<[u8; 32]>,
    /// Proposal counter, incremented on each Propose
    pub transaction_index: u64,
}

impl MultisigState {
    pub fn new(create_key: [u8; 32], threshold: u8, member_cms: Vec<[u8; 32]>) -> Self {
        Self {
            create_key,
            threshold,
            member_cms,
            transaction_index: 0,
        }
    }

    pub fn member_count(&self) -> usize {
        self.member_cms.len()
    }

    pub fn is_member_cm(&self, cm: &[u8; 32]) -> bool {
        self.member_cms.contains(cm)
    }
}

/// The ChainedCall a proposal will emit on execution.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ProposalAction {
    /// Target program to call
    pub target_program_id: ProgramId,
    /// Serialized instruction data for the target program
    pub target_instruction_data: Vec<u32>,
    /// Expected number of target accounts at execute time
    pub target_account_count: u8,
    /// PDA seeds the multisig authorizes for the callee (e.g. the vault seed)
    pub pda_seeds: Vec<[u8; 32]>,
    /// Which target account indices (0-based) get `is_authorized = true`
    pub authorized_indices: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ProposalStatus {
    /// Accepting approvals/rejections
    Active,
    /// Reached threshold and executed
    Executed,
    /// Can never reach threshold (rejections > N − M)
    Rejected,
}

/// A proposal stored in its own PDA account.
///
/// Note what is *absent* compared to the public PoC: no proposer identity and
/// no list of approver account IDs — only unlinkable nullifiers.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Proposal {
    /// Matches `MultisigState::transaction_index` at creation
    pub index: u64,
    /// The create_key of the parent multisig
    pub multisig_create_key: [u8; 32],
    /// What executing this proposal does
    pub action: ProposalAction,
    /// `SHA256(DST_ACTION ‖ borsh(action))`; approval nullifiers bind to this,
    /// so an approval cannot be detached and replayed against a different action
    pub action_hash: [u8; 32],
    /// Unlinkable per-member vote nullifiers
    pub vote_nullifiers: Vec<[u8; 32]>,
    /// Unlinkable per-member reject nullifiers
    pub reject_nullifiers: Vec<[u8; 32]>,
    pub status: ProposalStatus,
}

impl Proposal {
    pub fn new(index: u64, multisig_create_key: [u8; 32], action: ProposalAction) -> Self {
        let action_hash = action_hash(&action);
        Self {
            index,
            multisig_create_key,
            action,
            action_hash,
            vote_nullifiers: Vec::new(),
            reject_nullifiers: Vec::new(),
            status: ProposalStatus::Active,
        }
    }

    pub fn approval_count(&self) -> usize {
        self.vote_nullifiers.len()
    }

    pub fn has_threshold(&self, threshold: u8) -> bool {
        self.vote_nullifiers.len() >= threshold as usize
    }

    /// True when enough members rejected that the threshold is unreachable.
    pub fn is_dead(&self, threshold: u8, member_count: usize) -> bool {
        member_count - self.reject_nullifiers.len() < threshold as usize
    }
}

// ---------------------------------------------------------------------------
// Hashing — domain-separated SHA256, accelerated inside Risc0 guests
// ---------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use risc0_zkvm::sha::{Impl, Sha256 as _};
    Impl::hash_bytes(bytes)
        .as_bytes()
        .try_into()
        .expect("SHA256 output is 32 bytes")
}

/// Zero-pad an ASCII domain tag to 32 bytes (mirrors the LEE prefix style).
fn dst(tag: &str) -> [u8; 32] {
    let src = tag.as_bytes();
    assert!(src.len() <= 32, "domain tag exceeds 32 bytes");
    let mut out = [0u8; 32];
    out[..src.len()].copy_from_slice(src);
    out
}

/// `member_cm = SHA256(DST_MEMBER ‖ salt ‖ member_account_id)`
///
/// `member_account_id` is the member's (shielded) account ID; `salt` is a
/// random 32-byte secret held in the member's wallet. The commitment hides
/// both the account and the membership relation.
pub fn member_commitment(salt: &[u8; 32], member_account_id: &AccountId) -> [u8; 32] {
    let mut bytes = [0u8; 96];
    bytes[..32].copy_from_slice(&dst("/PMS/v0.1/MemberCommitment/"));
    bytes[32..64].copy_from_slice(salt);
    bytes[64..96].copy_from_slice(member_account_id.value());
    sha256(&bytes)
}

/// `vote_nullifier = SHA256(DST_VOTE ‖ salt ‖ multisig_account_id ‖ index ‖ action_hash)`
///
/// Binding to the multisig **state account ID** (which already commits to the
/// program ID and create_key) prevents cross-instance and cross-program
/// replay; binding to `action_hash` prevents re-targeting an approval.
pub fn vote_nullifier(
    salt: &[u8; 32],
    multisig_account_id: &AccountId,
    proposal_index: u64,
    action_hash: &[u8; 32],
) -> [u8; 32] {
    nullifier_with_dst(
        "/PMS/v0.1/VoteNullifier/",
        salt,
        multisig_account_id,
        proposal_index,
        action_hash,
    )
}

/// Same construction as [`vote_nullifier`] under a distinct domain tag.
pub fn reject_nullifier(
    salt: &[u8; 32],
    multisig_account_id: &AccountId,
    proposal_index: u64,
    action_hash: &[u8; 32],
) -> [u8; 32] {
    nullifier_with_dst(
        "/PMS/v0.1/RejectNullifier/",
        salt,
        multisig_account_id,
        proposal_index,
        action_hash,
    )
}

fn nullifier_with_dst(
    tag: &str,
    salt: &[u8; 32],
    multisig_account_id: &AccountId,
    proposal_index: u64,
    action_hash: &[u8; 32],
) -> [u8; 32] {
    let mut bytes = [0u8; 136];
    bytes[..32].copy_from_slice(&dst(tag));
    bytes[32..64].copy_from_slice(salt);
    bytes[64..96].copy_from_slice(multisig_account_id.value());
    bytes[96..104].copy_from_slice(&proposal_index.to_le_bytes());
    bytes[104..136].copy_from_slice(action_hash);
    sha256(&bytes)
}

/// `action_hash = SHA256(DST_ACTION ‖ borsh(action))`
pub fn action_hash(action: &ProposalAction) -> [u8; 32] {
    let mut bytes = dst("/PMS/v0.1/ActionHash/").to_vec();
    bytes.extend_from_slice(&borsh::to_vec(action).expect("action serialization is infallible"));
    sha256(&bytes)
}

// ---------------------------------------------------------------------------
// PDA derivation — byte-compatible with SPEL's `compute_pda` / `ToSeed`
// (string literals zero-padded to 32, u64 little-endian zero-padded to 32,
//  multiple seeds combined via SHA256(seed1 ‖ seed2 ‖ ...))
// ---------------------------------------------------------------------------

pub const STATE_PDA_TAG: &str = "pms_state";
pub const PROPOSAL_PDA_TAG: &str = "pms_proposal";
pub const VAULT_PDA_TAG: &str = "pms_vault";

fn seed_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&value.to_le_bytes());
    out
}

fn combine_seeds(seeds: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.finalize().into()
}

pub fn multisig_state_pda_seed(create_key: &[u8; 32]) -> PdaSeed {
    PdaSeed::new(combine_seeds(&[dst(STATE_PDA_TAG), *create_key]))
}

pub fn proposal_pda_seed(create_key: &[u8; 32], proposal_index: u64) -> PdaSeed {
    PdaSeed::new(combine_seeds(&[
        dst(PROPOSAL_PDA_TAG),
        *create_key,
        seed_u64(proposal_index),
    ]))
}

pub fn vault_pda_seed(create_key: &[u8; 32]) -> PdaSeed {
    PdaSeed::new(combine_seeds(&[dst(VAULT_PDA_TAG), *create_key]))
}

/// Raw seed bytes of the vault PDA (for storage in `ProposalAction::pda_seeds`).
pub fn vault_pda_seed_bytes(create_key: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[dst(VAULT_PDA_TAG), *create_key])
}

pub fn compute_multisig_state_pda(program_id: &ProgramId, create_key: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(program_id, &multisig_state_pda_seed(create_key))
}

pub fn compute_proposal_pda(
    program_id: &ProgramId,
    create_key: &[u8; 32],
    proposal_index: u64,
) -> AccountId {
    AccountId::for_public_pda(program_id, &proposal_pda_seed(create_key, proposal_index))
}

pub fn compute_vault_pda(program_id: &ProgramId, create_key: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(program_id, &vault_pda_seed(create_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_id(byte: u8) -> AccountId {
        AccountId::new([byte; 32])
    }

    #[test]
    fn member_commitment_is_deterministic_and_salt_sensitive() {
        let id = account_id(7);
        let cm1 = member_commitment(&[1u8; 32], &id);
        let cm2 = member_commitment(&[1u8; 32], &id);
        let cm3 = member_commitment(&[2u8; 32], &id);
        assert_eq!(cm1, cm2);
        assert_ne!(cm1, cm3);
        assert_ne!(cm1, member_commitment(&[1u8; 32], &account_id(8)));
    }

    #[test]
    fn vote_nullifier_unlinkable_across_proposals_but_stable_within() {
        let salt = [3u8; 32];
        let msig = account_id(9);
        let ah = [4u8; 32];
        let n1 = vote_nullifier(&salt, &msig, 1, &ah);
        let n1_again = vote_nullifier(&salt, &msig, 1, &ah);
        let n2 = vote_nullifier(&salt, &msig, 2, &ah);
        assert_eq!(n1, n1_again, "same member + proposal must collide (double-vote detection)");
        assert_ne!(n1, n2, "different proposals must produce unlinkable nullifiers");
    }

    #[test]
    fn vote_and_reject_nullifiers_are_domain_separated() {
        let salt = [3u8; 32];
        let msig = account_id(9);
        let ah = [4u8; 32];
        assert_ne!(
            vote_nullifier(&salt, &msig, 1, &ah),
            reject_nullifier(&salt, &msig, 1, &ah)
        );
    }

    #[test]
    fn nullifier_binds_to_instance_and_action() {
        let salt = [3u8; 32];
        let ah = [4u8; 32];
        assert_ne!(
            vote_nullifier(&salt, &account_id(1), 1, &ah),
            vote_nullifier(&salt, &account_id(2), 1, &ah),
            "must not be replayable across multisig instances"
        );
        assert_ne!(
            vote_nullifier(&salt, &account_id(1), 1, &[4u8; 32]),
            vote_nullifier(&salt, &account_id(1), 1, &[5u8; 32]),
            "must not be replayable across different actions"
        );
    }

    #[test]
    fn action_hash_changes_with_content() {
        let mut action = ProposalAction {
            target_program_id: [1u32; 8],
            target_instruction_data: vec![1, 2, 3],
            target_account_count: 2,
            pda_seeds: vec![[0u8; 32]],
            authorized_indices: vec![0],
        };
        let h1 = action_hash(&action);
        action.target_instruction_data = vec![1, 2, 4];
        assert_ne!(h1, action_hash(&action));
    }

    #[test]
    fn pdas_are_distinct_per_kind_and_instance() {
        let program_id = [7u32; 8];
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let state_a = compute_multisig_state_pda(&program_id, &key_a);
        assert_ne!(state_a, compute_multisig_state_pda(&program_id, &key_b));
        assert_ne!(state_a, compute_vault_pda(&program_id, &key_a));
        assert_ne!(
            compute_proposal_pda(&program_id, &key_a, 1),
            compute_proposal_pda(&program_id, &key_a, 2)
        );
    }

    /// pms_core's PDA math must agree with SPEL's `compute_pda_multi`, since
    /// the IDL declares the same seed specs.
    #[test]
    fn pda_matches_spel_formula() {
        use sha2::{Digest, Sha256};
        let program_id = [7u32; 8];
        let create_key = [9u8; 32];

        // Recompute by hand following spel's ToSeed + compute_pda rules.
        let mut tag = [0u8; 32];
        tag[..STATE_PDA_TAG.len()].copy_from_slice(STATE_PDA_TAG.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(create_key);
        let combined: [u8; 32] = hasher.finalize().into();
        let expected = AccountId::for_public_pda(&program_id, &PdaSeed::new(combined));

        assert_eq!(compute_multisig_state_pda(&program_id, &create_key), expected);
    }
}
