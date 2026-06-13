//! Deterministic program error strings (FURPS: documented error codes).
//!
//! LEZ programs fail by panicking inside the guest; the panic message is what
//! a client sees in the proving/execution error. Every assert in the program
//! uses one of these constants, so failures are stable and documented.

/// CreateMultisig: the state PDA already holds data.
pub const ERR_ALREADY_INITIALIZED: &str = "PMS_E001: multisig state account is already initialized";
/// CreateMultisig: threshold must satisfy 1 <= M <= N <= MAX_MEMBERS.
pub const ERR_BAD_THRESHOLD: &str = "PMS_E002: invalid threshold for member count";
/// CreateMultisig: duplicate member commitments supplied.
pub const ERR_DUPLICATE_MEMBER: &str = "PMS_E003: duplicate member commitment";
/// Account 0 does not contain a multisig state for the given create_key.
pub const ERR_STATE_MISMATCH: &str = "PMS_E004: multisig state does not match create_key";
/// Propose: the proposal PDA already holds data.
pub const ERR_PROPOSAL_EXISTS: &str = "PMS_E005: proposal account is already initialized";
/// Propose: proposal_index must be transaction_index + 1.
pub const ERR_BAD_PROPOSAL_INDEX: &str = "PMS_E006: proposal index is not the next index";
/// Propose: authorized_indices out of range of target_account_count.
pub const ERR_BAD_AUTHORIZED_INDEX: &str = "PMS_E007: authorized index out of range";
/// The proposal account does not belong to this multisig / index.
pub const ERR_PROPOSAL_MISMATCH: &str = "PMS_E008: proposal does not match multisig or index";
/// Approve/Reject/Execute: proposal is not Active.
pub const ERR_PROPOSAL_NOT_ACTIVE: &str = "PMS_E009: proposal is not active";
/// Approve/Reject: the member account pre-state is not authorized
/// (signature missing in public mode; nsk proof missing in private mode).
pub const ERR_MEMBER_NOT_AUTHORIZED: &str = "PMS_E010: member account is not authorized";
/// Approve/Reject: commitment of (salt, account) is not in the member set.
pub const ERR_NOT_A_MEMBER: &str = "PMS_E011: not a member of this multisig";
/// Approve: this member already approved this proposal (duplicate nullifier).
pub const ERR_DUPLICATE_VOTE: &str = "PMS_E012: duplicate vote nullifier (already approved)";
/// Reject: this member already rejected this proposal (duplicate nullifier).
pub const ERR_DUPLICATE_REJECT: &str = "PMS_E013: duplicate reject nullifier (already rejected)";
/// Execute: fewer than `threshold` approvals recorded.
pub const ERR_THRESHOLD_NOT_MET: &str = "PMS_E014: approval threshold not met";
/// Execute: wrong number of target accounts supplied.
pub const ERR_BAD_TARGET_COUNT: &str = "PMS_E015: target account count mismatch";
/// Wrong number of accounts passed to the instruction.
pub const ERR_BAD_ACCOUNT_COUNT: &str = "PMS_E016: unexpected number of accounts";
