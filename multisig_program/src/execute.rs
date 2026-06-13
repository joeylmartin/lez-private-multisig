//! Execute handler — emits the stored ChainedCall once the threshold is met.
//!
//! Accounts:
//! - accounts[0]: multisig_state PDA (read-only)
//! - accounts[1]: proposal PDA (mut — status flips to Executed)
//! - accounts[2..]: target accounts forwarded to the ChainedCall
//!
//! Execution is **permissionless** (the public PoC required a member to
//! sign; here that would be a pointless linkage surface — the approvals
//! already carry all authority). Anyone can submit Execute once
//! `vote_nullifiers.len() >= threshold`.

use nssa_core::account::AccountWithMetadata;
use nssa_core::program::{AccountPostState, ChainedCall, PdaSeed};
use pms_core::error::*;
use pms_core::{MultisigState, Proposal, ProposalStatus};

pub fn handle(
    accounts: &[AccountWithMetadata],
    create_key: &[u8; 32],
    proposal_index: u64,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    assert!(accounts.len() >= 2, "{}", ERR_BAD_ACCOUNT_COUNT);
    let state_account = &accounts[0];
    let proposal_account = &accounts[1];
    let target_accounts = &accounts[2..];

    let state: MultisigState =
        borsh::from_slice(&state_account.account.data).expect(ERR_STATE_MISMATCH);
    assert!(state.create_key == *create_key, "{}", ERR_STATE_MISMATCH);

    let mut proposal: Proposal =
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
    assert!(
        proposal.has_threshold(state.threshold),
        "{}",
        ERR_THRESHOLD_NOT_MET
    );
    assert!(
        target_accounts.len() == proposal.action.target_account_count as usize,
        "{}",
        ERR_BAD_TARGET_COUNT
    );

    proposal.status = ProposalStatus::Executed;

    let chained_pre_states: Vec<AccountWithMetadata> = target_accounts
        .iter()
        .enumerate()
        .map(|(i, acc)| {
            let mut acc = acc.clone();
            if proposal.action.authorized_indices.contains(&(i as u8)) {
                acc.is_authorized = true;
            }
            acc
        })
        .collect();

    let chained_call = ChainedCall {
        program_id: proposal.action.target_program_id,
        instruction_data: proposal.action.target_instruction_data.clone(),
        pre_states: chained_pre_states,
        pda_seeds: proposal
            .action
            .pda_seeds
            .iter()
            .map(|s| PdaSeed::new(*s))
            .collect(),
    };

    let mut proposal_post = proposal_account.account.clone();
    proposal_post.data = borsh::to_vec(&proposal)
        .expect("proposal serialization is infallible")
        .try_into()
        .expect("proposal fits in account data");

    let mut post_states = vec![
        AccountPostState::new(state_account.account.clone()),
        AccountPostState::new(proposal_post),
    ];
    for target in target_accounts {
        post_states.push(AccountPostState::new(target.account.clone()));
    }

    (post_states, vec![chained_call])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    fn approved_fixture() -> (VoteFixture, Vec<AccountWithMetadata>) {
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
        let accounts = fx.with_updated_proposal(&posts[1]);
        (fx, accounts)
    }

    #[test]
    fn execute_emits_chained_call_without_any_member_account() {
        let (fx, accounts) = approved_fixture();
        // [state, proposal, target0, target1] — no executor, no member.
        let exec_accounts = vec![
            accounts[0].clone(),
            accounts[1].clone(),
            make_account(0x30, vec![], false),
            make_account(0x31, vec![], false),
        ];
        let (posts, chained) = crate::process(
            &exec_accounts,
            &pms_core::Instruction::Execute {
                create_key: fx.create_key,
                proposal_index: 1,
            },
        );
        assert_eq!(chained.len(), 1);
        assert_eq!(chained[0].program_id, fx.action.target_program_id);
        assert!(chained[0].pre_states[0].is_authorized, "index 0 authorized");
        assert!(!chained[0].pre_states[1].is_authorized);

        let proposal: pms_core::Proposal =
            borsh::from_slice(&Vec::from(posts[1].account().data.clone())).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Executed);
    }

    #[test]
    #[should_panic(expected = "PMS_E014")]
    fn execute_below_threshold_fails() {
        let fx = VoteFixture::new(2, 3);
        let (posts, _) = crate::process(
            &fx.vote_accounts(0),
            &pms_core::Instruction::Approve {
                create_key: fx.create_key,
                proposal_index: 1,
                member_salt: fx.salts[0],
            },
        );
        let accounts = fx.with_updated_proposal(&posts[1]);
        let exec_accounts = vec![
            accounts[0].clone(),
            accounts[1].clone(),
            make_account(0x30, vec![], false),
            make_account(0x31, vec![], false),
        ];
        crate::process(
            &exec_accounts,
            &pms_core::Instruction::Execute {
                create_key: fx.create_key,
                proposal_index: 1,
            },
        );
    }

    #[test]
    #[should_panic(expected = "PMS_E009")]
    fn execute_twice_fails() {
        let (fx, accounts) = approved_fixture();
        let exec_accounts = vec![
            accounts[0].clone(),
            accounts[1].clone(),
            make_account(0x30, vec![], false),
            make_account(0x31, vec![], false),
        ];
        let (posts, _) = crate::process(
            &exec_accounts,
            &pms_core::Instruction::Execute {
                create_key: fx.create_key,
                proposal_index: 1,
            },
        );
        let mut again = exec_accounts.clone();
        again[1].account = posts[1].account().clone();
        crate::process(
            &again,
            &pms_core::Instruction::Execute {
                create_key: fx.create_key,
                proposal_index: 1,
            },
        );
    }

    #[test]
    #[should_panic(expected = "PMS_E015")]
    fn execute_with_wrong_target_count_fails() {
        let (fx, accounts) = approved_fixture();
        let exec_accounts = vec![
            accounts[0].clone(),
            accounts[1].clone(),
            make_account(0x30, vec![], false),
        ];
        crate::process(
            &exec_accounts,
            &pms_core::Instruction::Execute {
                create_key: fx.create_key,
                proposal_index: 1,
            },
        );
    }
}
