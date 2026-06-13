//! InitVault handler — sets up the multisig's token vault.
//!
//! Accounts:
//! - accounts[0]: token definition account (pass-through)
//! - accounts[1]: vault PDA (uninitialized; initialized by the token program)
//!
//! The token program requires the holding account to be *authorized* when
//! initializing it. A PDA cannot sign, so this program authorizes its own
//! vault by emitting the ChainedCall with `pda_seeds = [vault_seed]` — the
//! runtime verifies the seed derives the vault's account ID under this
//! program and grants the callee the authorization.

use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::{AccountPostState, ChainedCall, PdaSeed, ProgramId};
use pms_core::error::*;
use pms_core::vault_pda_seed;

pub fn handle(
    accounts: &[AccountWithMetadata],
    create_key: &[u8; 32],
    token_program_id: &ProgramId,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    assert!(accounts.len() == 2, "{}", ERR_BAD_ACCOUNT_COUNT);
    let definition_account = &accounts[0];
    let vault_account = &accounts[1];

    assert!(
        vault_account.account == Account::default(),
        "{}",
        ERR_PROPOSAL_EXISTS
    );

    let vault_seed = vault_pda_seed(create_key);

    let mut authorized_vault = vault_account.clone();
    authorized_vault.is_authorized = true;

    let chained_call = ChainedCall {
        program_id: *token_program_id,
        instruction_data: risc0_zkvm::serde::to_vec(&token_initialize_account_instruction())
            .expect("instruction serialization is infallible"),
        pre_states: vec![definition_account.clone(), authorized_vault],
        pda_seeds: vec![vault_seed],
    };

    (
        vec![
            AccountPostState::new(definition_account.account.clone()),
            AccountPostState::new(vault_account.account.clone()),
        ],
        vec![chained_call],
    )
}

/// The token program's `InitializeAccount` instruction. Encoded structurally
/// (unit variant index 3) to avoid depending on token_core inside the guest.
fn token_initialize_account_instruction() -> TokenInitializeAccount {
    TokenInitializeAccount::InitializeAccount
}

/// Mirror of the token program's instruction enum, reduced to the variant we
/// emit. Variant indices must match `token_core::Instruction` (risc0 serde
/// encodes the variant tag by index): Transfer=0, NewFungibleDefinition=1,
/// NewDefinitionWithMetadata=2, InitializeAccount=3.
#[derive(serde::Serialize)]
enum TokenInitializeAccount {
    #[allow(dead_code)]
    Transfer { amount_to_transfer: u128 },
    #[allow(dead_code)]
    NewFungibleDefinition { name: String, total_supply: u128 },
    #[allow(dead_code)]
    NewDefinitionWithMetadata { unused: u8 },
    InitializeAccount,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_account;

    #[test]
    fn init_vault_emits_authorized_chained_call() {
        let accounts = vec![
            make_account(0x40, vec![1, 2, 3], false), // definition
            make_account(0x41, vec![], false),        // vault (uninitialized)
        ];
        let (posts, chained) = handle(&accounts, &[7u8; 32], &[9u32; 8]);
        assert_eq!(posts.len(), 2);
        assert_eq!(chained.len(), 1);
        assert_eq!(chained[0].program_id, [9u32; 8]);
        assert_eq!(chained[0].pda_seeds.len(), 1);
        assert!(
            chained[0].pre_states[1].is_authorized,
            "vault must be authorized for the token program via pda_seeds"
        );
        // Variant tag must be 3 (InitializeAccount) in risc0 serde encoding.
        assert_eq!(chained[0].instruction_data[0], 3);
    }

    #[test]
    #[should_panic(expected = "PMS_E005")]
    fn init_vault_rejects_initialized_vault() {
        let accounts = vec![
            make_account(0x40, vec![1, 2, 3], false),
            make_account(0x41, vec![9, 9], false),
        ];
        handle(&accounts, &[7u8; 32], &[9u32; 8]);
    }
}
