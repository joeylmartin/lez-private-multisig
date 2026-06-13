//! Approve handler — the anonymous vote.
//!
//! Accounts:
//! - accounts[0]: multisig_state PDA (read-only)
//! - accounts[1]: proposal PDA (mut)
//! - accounts[2]: member account (must be `is_authorized`; passed through
//!   unchanged)
//!
//! The instruction carries the member's secret `salt`. Submitted as a LEZ
//! *private execution*, instruction data is never revealed on-chain — the
//! transaction publishes only the proposal diff (one new opaque nullifier,
//! count + 1) and the member account's unlinkable platform commitment.
//!
//! Authorization chain:
//! 1. The runtime attests `accounts[2].is_authorized` — in a private
//!    execution the privacy circuit proves knowledge of the account's
//!    nullifier secret key; in public mode it means the tx is signed by the
//!    account's key. Either way: the submitter controls this account.
//! 2. `member_commitment(salt, account_id)` must be in the member set —
//!    the controlled account is a member, and the prover knows its salt.
//! 3. `vote_nullifier(salt, multisig_id, index, action_hash)` is appended —
//!    deterministic per (member, proposal), so double votes collide, but
//!    unlinkable across proposals and to the member.

use nssa_core::account::AccountWithMetadata;
use nssa_core::program::{AccountPostState, ChainedCall};
use pms_core::error::*;
use pms_core::{
    member_commitment, reject_nullifier, vote_nullifier, MultisigState, Proposal, ProposalStatus,
};

pub fn handle(
    accounts: &[AccountWithMetadata],
    create_key: &[u8; 32],
    proposal_index: u64,
    member_salt: &[u8; 32],
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    let (state_account, proposal_account, member_account, state, mut proposal) =
        common_vote_checks(accounts, create_key, proposal_index, member_salt);

    let nullifier = vote_nullifier(
        member_salt,
        &state_account.account_id,
        proposal_index,
        &proposal.action_hash,
    );
    assert!(
        !proposal.vote_nullifiers.contains(&nullifier),
        "{}",
        ERR_DUPLICATE_VOTE
    );

    // Vote switching (mirrors the public PoC's reject→approve flip): if this
    // member previously rejected, retract that rejection. Observers see "one
    // rejection retracted, one approval added" — but not by whom.
    let this_members_rejection = reject_nullifier(
        member_salt,
        &state_account.account_id,
        proposal_index,
        &proposal.action_hash,
    );
    proposal.reject_nullifiers.retain(|n| n != &this_members_rejection);

    proposal.vote_nullifiers.push(nullifier);

    finalize_vote(state_account, proposal_account, member_account, &state, &proposal)
}

/// Shared validation for Approve and Reject: account shape, authorization,
/// state/proposal consistency, and the **membership proof** — the supplied
/// salt must commit to the authorized member account's ID.
pub(crate) fn common_vote_checks<'a>(
    accounts: &'a [AccountWithMetadata],
    create_key: &[u8; 32],
    proposal_index: u64,
    member_salt: &[u8; 32],
) -> (
    &'a AccountWithMetadata,
    &'a AccountWithMetadata,
    &'a AccountWithMetadata,
    MultisigState,
    Proposal,
) {
    assert!(accounts.len() == 3, "{}", ERR_BAD_ACCOUNT_COUNT);
    let state_account = &accounts[0];
    let proposal_account = &accounts[1];
    let member_account = &accounts[2];

    assert!(member_account.is_authorized, "{}", ERR_MEMBER_NOT_AUTHORIZED);

    let state: MultisigState =
        borsh::from_slice(&state_account.account.data).expect(ERR_STATE_MISMATCH);
    assert!(state.create_key == *create_key, "{}", ERR_STATE_MISMATCH);

    let cm = member_commitment(member_salt, &member_account.account_id);
    assert!(state.is_member_cm(&cm), "{}", ERR_NOT_A_MEMBER);

    let proposal: Proposal =
        borsh::from_slice(&proposal_account.account.data).expect(ERR_PROPOSAL_MISMATCH);
    assert!(
        proposal.multisig_create_key == state.create_key && proposal.index == proposal_index,
        "{}",
        ERR_PROPOSAL_MISMATCH
    );
    assert!(
        proposal.status == ProposalStatus::Active,
        "{}",
        ERR_PROPOSAL_NOT_ACTIVE
    );

    (state_account, proposal_account, member_account, state, proposal)
}

/// Membership check + post-state assembly shared by Approve and Reject.
pub(crate) fn finalize_vote(
    state_account: &AccountWithMetadata,
    proposal_account: &AccountWithMetadata,
    member_account: &AccountWithMetadata,
    state: &MultisigState,
    proposal: &Proposal,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    let _ = state;
    let mut proposal_post = proposal_account.account.clone();
    proposal_post.data = borsh::to_vec(proposal)
        .expect("proposal serialization is infallible")
        .try_into()
        .expect("proposal fits in account data");

    (
        vec![
            // State and member accounts pass through unchanged. The member's
            // nonce evolution (private mode) is handled by the privacy
            // circuit after validation — programs must not touch nonces.
            AccountPostState::new(state_account.account.clone()),
            AccountPostState::new(proposal_post),
            AccountPostState::new(member_account.account.clone()),
        ],
        vec![],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use pms_core::action_hash;

    #[test]
    fn member_can_approve_anonymously() {
        let fx = VoteFixture::new(2, 3);
        let accounts = fx.vote_accounts(0);
        let (posts, chained) = crate::process(
            &accounts,
            &pms_core::Instruction::Approve {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
        assert!(chained.is_empty());
        let proposal: Proposal =
            borsh::from_slice(&Vec::from(posts[1].account().data.clone())).unwrap();
        assert_eq!(proposal.vote_nullifiers.len(), 1);
        // The recorded nullifier must not be derivable from public data alone:
        // check it matches the salt-derived value (and nothing else we store).
        let expected = vote_nullifier(
            &fx.salts[0],
            &accounts[0].account_id,
            1,
            &action_hash(&fx.action),
        );
        assert_eq!(proposal.vote_nullifiers[0], expected);
    }

    #[test]
    #[should_panic(expected = "PMS_E012")]
    fn double_vote_is_rejected() {
        let fx = VoteFixture::new(2, 3);
        let accounts = fx.vote_accounts(0);
        let (posts, _) = crate::process(
            &accounts,
            &pms_core::Instruction::Approve {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
        // Re-vote against the updated proposal state.
        let accounts2 = fx.with_updated_proposal(&posts[1]);
        crate::process(
            &accounts2,
            &pms_core::Instruction::Approve {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
    }

    #[test]
    #[should_panic(expected = "PMS_E011")]
    fn non_member_salt_is_rejected() {
        let fx = VoteFixture::new(2, 3);
        crate::process(
            &fx.vote_accounts(0),
            &pms_core::Instruction::Approve {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: [0xEE; 32], // not a member salt
            },
        );
    }

    #[test]
    #[should_panic(expected = "PMS_E011")]
    fn right_salt_wrong_account_is_rejected() {
        let fx = VoteFixture::new(2, 3);
        let mut accounts = fx.vote_accounts(0);
        // Authorized account that is not the one committed with this salt.
        accounts[2] = make_account(0x55, vec![], true);
        crate::process(
            &accounts,
            &pms_core::Instruction::Approve {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
    }

    #[test]
    #[should_panic(expected = "PMS_E010")]
    fn unauthorized_member_account_is_rejected() {
        let fx = VoteFixture::new(2, 3);
        let mut accounts = fx.vote_accounts(0);
        accounts[2].is_authorized = false;
        crate::process(
            &accounts,
            &pms_core::Instruction::Approve {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
    }

    #[test]
    fn two_members_reach_threshold() {
        let fx = VoteFixture::new(2, 3);
        let (posts, _) = crate::process(
            &fx.vote_accounts(0),
            &pms_core::Instruction::Approve {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
        let mut accounts = fx.with_updated_proposal(&posts[1]);
        accounts[2] = fx.member_account(1);
        let (posts, _) = crate::process(
            &accounts,
            &pms_core::Instruction::Approve {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[1],
            },
        );
        let proposal: Proposal =
            borsh::from_slice(&Vec::from(posts[1].account().data.clone())).unwrap();
        assert_eq!(proposal.vote_nullifiers.len(), 2);
        assert!(proposal.has_threshold(2));
        // Unlinkability sanity: the two nullifiers share no obvious structure.
        assert_ne!(proposal.vote_nullifiers[0], proposal.vote_nullifiers[1]);
    }
}
