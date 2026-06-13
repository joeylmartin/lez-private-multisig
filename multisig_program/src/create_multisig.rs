//! CreateMultisig handler.
//!
//! Accounts:
//! - accounts[0]: multisig_state PDA (uninitialized; claimed via `Claim::Pda`)
//!
//! Unlike the public PoC, **no member accounts are passed and none are
//! claimed**. Members exist only as salted commitments inside the state, so
//! shielded accounts (whose nonce evolves and whose `program_owner` is fixed
//! by the privacy protocol) can be members.

use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::{AccountPostState, ChainedCall, Claim};
use pms_core::error::*;
use pms_core::{multisig_state_pda_seed, MultisigState, MAX_MEMBERS};

pub fn handle(
    accounts: &[AccountWithMetadata],
    create_key: &[u8; 32],
    threshold: u8,
    member_cms: &[[u8; 32]],
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    assert!(accounts.len() == 1, "{}", ERR_BAD_ACCOUNT_COUNT);
    let state_account = &accounts[0];

    assert!(
        state_account.account == Account::default(),
        "{}",
        ERR_ALREADY_INITIALIZED
    );

    let n = member_cms.len();
    assert!(
        threshold >= 1 && (threshold as usize) <= n && n <= MAX_MEMBERS,
        "{}",
        ERR_BAD_THRESHOLD
    );
    for (i, cm) in member_cms.iter().enumerate() {
        assert!(
            !member_cms[..i].contains(cm),
            "{}",
            ERR_DUPLICATE_MEMBER
        );
    }

    let state = MultisigState::new(*create_key, threshold, member_cms.to_vec());
    let mut state_post = state_account.account.clone();
    state_post.data = borsh::to_vec(&state)
        .expect("state serialization is infallible")
        .try_into()
        .expect("state fits in account data");

    // Claim::Pda makes the runtime verify accounts[0] is exactly the PDA for
    // this (program, create_key) — no separate account-id check needed here.
    let post = AccountPostState::new_claimed(
        state_post,
        Claim::Pda(multisig_state_pda_seed(create_key)),
    );

    (vec![post], vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use nssa_core::account::AccountId;

    fn uninitialized(id_byte: u8) -> AccountWithMetadata {
        AccountWithMetadata {
            account_id: AccountId::new([id_byte; 32]),
            account: Account::default(),
            is_authorized: false,
        }
    }

    #[test]
    fn creates_state_with_commitments() {
        let cms = vec![[10u8; 32], [11u8; 32], [12u8; 32]];
        let (posts, chained) = handle(&[uninitialized(1)], &[7u8; 32], 2, &cms);
        assert!(chained.is_empty());
        assert_eq!(posts.len(), 1);
        let state: MultisigState =
            borsh::from_slice(&Vec::from(posts[0].account().data.clone())).unwrap();
        assert_eq!(state.threshold, 2);
        assert_eq!(state.member_cms, cms);
        assert_eq!(state.transaction_index, 0);
    }

    #[test]
    #[should_panic(expected = "PMS_E002")]
    fn rejects_threshold_above_member_count() {
        handle(&[uninitialized(1)], &[7u8; 32], 4, &[[1u8; 32], [2u8; 32]]);
    }

    #[test]
    #[should_panic(expected = "PMS_E002")]
    fn rejects_zero_threshold() {
        handle(&[uninitialized(1)], &[7u8; 32], 0, &[[1u8; 32]]);
    }

    #[test]
    #[should_panic(expected = "PMS_E003")]
    fn rejects_duplicate_member_cms() {
        handle(&[uninitialized(1)], &[7u8; 32], 1, &[[1u8; 32], [1u8; 32]]);
    }

    #[test]
    #[should_panic(expected = "PMS_E001")]
    fn rejects_initialized_state_account() {
        let mut acc = uninitialized(1);
        acc.account.balance = 5;
        handle(&[acc], &[7u8; 32], 1, &[[1u8; 32]]);
    }
}
