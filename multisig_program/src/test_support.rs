//! Shared fixtures for handler unit tests.

use nssa_core::account::{Account, AccountId, AccountWithMetadata};
use nssa_core::program::AccountPostState;
use pms_core::{member_commitment, MultisigState, Proposal, ProposalAction};

pub fn make_account(id_byte: u8, data: Vec<u8>, authorized: bool) -> AccountWithMetadata {
    let mut account = Account::default();
    account.data = data.try_into().unwrap();
    AccountWithMetadata {
        account_id: AccountId::new([id_byte; 32]),
        account,
        is_authorized: authorized,
    }
}

/// A multisig with one open proposal (index 1), ready for voting.
pub struct VoteFixture {
    pub create_key: [u8; 32],
    pub salts: Vec<[u8; 32]>,
    pub action: ProposalAction,
    state_data: Vec<u8>,
    proposal_data: Vec<u8>,
}

impl VoteFixture {
    pub fn new(threshold: u8, n: usize) -> Self {
        let create_key = [7u8; 32];
        let salts: Vec<[u8; 32]> = (0..n).map(|i| [(i as u8) + 1; 32]).collect();
        let member_cms: Vec<[u8; 32]> = salts
            .iter()
            .enumerate()
            .map(|(i, salt)| member_commitment(salt, &Self::member_id(i)))
            .collect();

        let mut state = MultisigState::new(create_key, threshold, member_cms);
        state.transaction_index = 1; // post-Propose

        let action = ProposalAction {
            target_program_id: [42u32; 8],
            target_instruction_data: vec![1, 2, 3],
            target_account_count: 2,
            pda_seeds: vec![[5u8; 32]],
            authorized_indices: vec![0],
        };
        let proposal = Proposal::new(1, create_key, action.clone());

        Self {
            create_key,
            salts,
            action,
            state_data: borsh::to_vec(&state).unwrap(),
            proposal_data: borsh::to_vec(&proposal).unwrap(),
        }
    }

    fn member_id(i: usize) -> AccountId {
        AccountId::new([0x10 + (i as u8); 32])
    }

    /// The member's account: just an authorized pass-through pre-state. Its
    /// contents are arbitrary — the program never inspects them.
    pub fn member_account(&self, i: usize) -> AccountWithMetadata {
        AccountWithMetadata {
            account_id: Self::member_id(i),
            account: Account::default(),
            is_authorized: true,
        }
    }

    /// `[multisig_state, proposal, member_i]`
    pub fn vote_accounts(&self, member: usize) -> Vec<AccountWithMetadata> {
        vec![
            make_account(0x01, self.state_data.clone(), false),
            make_account(0x02, self.proposal_data.clone(), false),
            self.member_account(member),
        ]
    }

    /// Same as [`Self::vote_accounts`] (member 0) but with the proposal
    /// account replaced by an updated post-state from a previous vote.
    pub fn with_updated_proposal(&self, proposal_post: &AccountPostState) -> Vec<AccountWithMetadata> {
        let mut accounts = self.vote_accounts(0);
        accounts[1].account = proposal_post.account().clone();
        accounts
    }
}
