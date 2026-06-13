//! Propose handler.
//!
//! Accounts:
//! - accounts[0]: multisig_state PDA (mut — counter increments)
//! - accounts[1]: proposal PDA (uninitialized; claimed via `Claim::Pda`)
//!
//! Proposing is **permissionless**: proposal content is public by design and
//! carries no authority — only approvals do. This avoids leaking any member
//! identity at propose time (the public PoC's proposer field and
//! auto-approval are deliberately absent).

use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::{AccountPostState, ChainedCall, Claim};
use pms_core::error::*;
use pms_core::{proposal_pda_seed, MultisigState, Proposal, ProposalAction};

pub fn handle(
    accounts: &[AccountWithMetadata],
    create_key: &[u8; 32],
    proposal_index: u64,
    action: &ProposalAction,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    assert!(accounts.len() == 2, "{}", ERR_BAD_ACCOUNT_COUNT);
    let state_account = &accounts[0];
    let proposal_account = &accounts[1];

    let mut state: MultisigState =
        borsh::from_slice(&state_account.account.data).expect(ERR_STATE_MISMATCH);
    assert!(state.create_key == *create_key, "{}", ERR_STATE_MISMATCH);

    assert!(
        proposal_account.account == Account::default(),
        "{}",
        ERR_PROPOSAL_EXISTS
    );
    assert!(
        proposal_index == state.transaction_index + 1,
        "{}",
        ERR_BAD_PROPOSAL_INDEX
    );
    for idx in &action.authorized_indices {
        assert!(*idx < action.target_account_count, "{}", ERR_BAD_AUTHORIZED_INDEX);
    }

    state.transaction_index = proposal_index;
    let proposal = Proposal::new(proposal_index, *create_key, action.clone());

    let mut state_post = state_account.account.clone();
    state_post.data = borsh::to_vec(&state)
        .expect("state serialization is infallible")
        .try_into()
        .expect("state fits in account data");

    let mut proposal_post = proposal_account.account.clone();
    proposal_post.data = borsh::to_vec(&proposal)
        .expect("proposal serialization is infallible")
        .try_into()
        .expect("proposal fits in account data");

    (
        vec![
            AccountPostState::new(state_post),
            AccountPostState::new_claimed(
                proposal_post,
                Claim::Pda(proposal_pda_seed(create_key, proposal_index)),
            ),
        ],
        vec![],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nssa_core::account::AccountId;

    pub fn make_account(id_byte: u8, data: Vec<u8>, authorized: bool) -> AccountWithMetadata {
        let mut account = Account::default();
        account.data = data.try_into().unwrap();
        AccountWithMetadata {
            account_id: AccountId::new([id_byte; 32]),
            account,
            is_authorized: authorized,
        }
    }

    pub fn state_data(create_key: [u8; 32], threshold: u8, member_cms: Vec<[u8; 32]>) -> Vec<u8> {
        borsh::to_vec(&MultisigState::new(create_key, threshold, member_cms)).unwrap()
    }

    pub fn test_action() -> ProposalAction {
        ProposalAction {
            target_program_id: [42u32; 8],
            target_instruction_data: vec![1, 2, 3],
            target_account_count: 2,
            pda_seeds: vec![[5u8; 32]],
            authorized_indices: vec![0],
        }
    }

    #[test]
    fn creates_proposal_and_increments_counter() {
        let create_key = [7u8; 32];
        let accounts = vec![
            make_account(1, state_data(create_key, 2, vec![[10u8; 32]; 1]), false),
            make_account(2, vec![], false),
        ];
        let (posts, chained) = handle(&accounts, &create_key, 1, &test_action());
        assert!(chained.is_empty());

        let state: MultisigState =
            borsh::from_slice(&Vec::from(posts[0].account().data.clone())).unwrap();
        assert_eq!(state.transaction_index, 1);

        let proposal: Proposal =
            borsh::from_slice(&Vec::from(posts[1].account().data.clone())).unwrap();
        assert_eq!(proposal.index, 1);
        assert_eq!(proposal.action_hash, pms_core::action_hash(&test_action()));
        assert!(proposal.vote_nullifiers.is_empty(), "no auto-approval");
    }

    #[test]
    #[should_panic(expected = "PMS_E006")]
    fn rejects_wrong_index() {
        let create_key = [7u8; 32];
        let accounts = vec![
            make_account(1, state_data(create_key, 2, vec![[10u8; 32]; 1]), false),
            make_account(2, vec![], false),
        ];
        handle(&accounts, &create_key, 2, &test_action());
    }

    #[test]
    #[should_panic(expected = "PMS_E004")]
    fn rejects_create_key_mismatch() {
        let accounts = vec![
            make_account(1, state_data([7u8; 32], 2, vec![[10u8; 32]; 1]), false),
            make_account(2, vec![], false),
        ];
        handle(&accounts, &[8u8; 32], 1, &test_action());
    }

    #[test]
    #[should_panic(expected = "PMS_E007")]
    fn rejects_out_of_range_authorized_index() {
        let create_key = [7u8; 32];
        let mut action = test_action();
        action.authorized_indices = vec![5];
        let accounts = vec![
            make_account(1, state_data(create_key, 2, vec![[10u8; 32]; 1]), false),
            make_account(2, vec![], false),
        ];
        handle(&accounts, &create_key, 1, &action);
    }
}
