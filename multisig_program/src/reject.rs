//! Reject handler — anonymous rejection, symmetric to Approve.
//!
//! When the remaining non-rejecting members can no longer reach the
//! threshold (`N − rejections < M`), the proposal flips to `Rejected`.

use nssa_core::account::AccountWithMetadata;
use nssa_core::program::{AccountPostState, ChainedCall};
use pms_core::error::*;
use pms_core::{reject_nullifier, vote_nullifier, ProposalStatus};

use crate::approve::{common_vote_checks, finalize_vote};

pub fn handle(
    accounts: &[AccountWithMetadata],
    create_key: &[u8; 32],
    proposal_index: u64,
    member_salt: &[u8; 32],
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    let (state_account, proposal_account, member_account, state, mut proposal) =
        common_vote_checks(accounts, create_key, proposal_index, member_salt);

    let nullifier = reject_nullifier(
        member_salt,
        &state_account.account_id,
        proposal_index,
        &proposal.action_hash,
    );
    assert!(
        !proposal.reject_nullifiers.contains(&nullifier),
        "{}",
        ERR_DUPLICATE_REJECT
    );

    // Vote switching: retract this member's earlier approval, if any.
    let this_members_vote = vote_nullifier(
        member_salt,
        &state_account.account_id,
        proposal_index,
        &proposal.action_hash,
    );
    proposal.vote_nullifiers.retain(|n| n != &this_members_vote);

    proposal.reject_nullifiers.push(nullifier);

    if proposal.is_dead(state.threshold, state.member_count()) {
        proposal.status = ProposalStatus::Rejected;
    }

    finalize_vote(state_account, proposal_account, member_account, &state, &proposal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use pms_core::Proposal;

    #[test]
    fn rejections_kill_unreachable_proposal() {
        // 2-of-3: two rejections leave only 1 possible approver < threshold 2.
        let fx = VoteFixture::new(2, 3);
        let (posts, _) = crate::process(
            &fx.vote_accounts(0),
            &pms_core::Instruction::Reject {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
        let proposal: Proposal =
            borsh::from_slice(&Vec::from(posts[1].account().data.clone())).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Active);

        let mut accounts = fx.with_updated_proposal(&posts[1]);
        accounts[2] = fx.member_account(1);
        let (posts, _) = crate::process(
            &accounts,
            &pms_core::Instruction::Reject {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[1],
            },
        );
        let proposal: Proposal =
            borsh::from_slice(&Vec::from(posts[1].account().data.clone())).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected);
    }

    #[test]
    #[should_panic(expected = "PMS_E013")]
    fn double_reject_is_rejected() {
        let fx = VoteFixture::new(2, 3);
        let (posts, _) = crate::process(
            &fx.vote_accounts(0),
            &pms_core::Instruction::Reject {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
        let accounts = fx.with_updated_proposal(&posts[1]);
        crate::process(
            &accounts,
            &pms_core::Instruction::Reject {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
    }

    #[test]
    fn reject_then_approve_switches_vote() {
        let fx = VoteFixture::new(2, 3);
        let (posts, _) = crate::process(
            &fx.vote_accounts(0),
            &pms_core::Instruction::Reject {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
        let accounts = fx.with_updated_proposal(&posts[1]);
        let (posts, _) = crate::process(
            &accounts,
            &pms_core::Instruction::Approve {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
        let proposal: Proposal =
            borsh::from_slice(&Vec::from(posts[1].account().data.clone())).unwrap();
        assert_eq!(proposal.reject_nullifiers.len(), 0, "rejection retracted");
        assert_eq!(proposal.vote_nullifiers.len(), 1, "approval recorded");
    }
}
