//! Private M-of-N multisig program for LEZ (LP-0002).
//!
//! Members are salted commitments; approvals are unlinkable nullifiers
//! recorded by a (normally private) execution of this program. See pms_core
//! for the cryptographic constructions and docs/ for the full write-up.

pub mod approve;
pub mod create_multisig;
pub mod execute;
pub mod init_vault;
pub mod propose;
pub mod reject;

#[cfg(test)]
pub mod test_support;

use nssa_core::program::ProgramId;
use pms_core::ProposalAction;
use spel_framework::prelude::*;

/// SPEL program surface. Dispatch maps `pms_core::Instruction` variants onto
/// these handlers; the IDL (idl/private_multisig_idl.json) is generated from
/// this file by `methods/guest/src/bin/generate_idl.rs`.
///
/// Handlers follow the SPEL idiom: run the logic from the handler modules,
/// write the resulting account states back into the account params, and
/// return them via `SpelOutput::execute` — the macro applies the PDA claims
/// declared in the `#[account(init, pda = ...)]` attributes.
#[lez_program(instruction = "pms_core::Instruction")]
mod private_multisig_program {
    use super::*;

    /// Create a new M-of-N multisig over salted member commitments.
    /// No member accounts are passed or claimed — shielded accounts can be
    /// members because they never appear on-chain at all.
    #[instruction]
    pub fn create_multisig(
        #[account(init, pda = [literal("pms_state"), arg("create_key")])]
        multisig_state: AccountWithMetadata,
        create_key: [u8; 32],
        threshold: u8,
        member_cms: Vec<[u8; 32]>,
    ) -> SpelResult {
        let mut multisig_state = multisig_state;
        let accounts = vec![multisig_state.clone()];
        let (post_states, chained_calls) =
            crate::create_multisig::handle(&accounts, &create_key, threshold, &member_cms);
        multisig_state.account = post_states[0].account().clone();
        Ok(SpelOutput::execute(vec![multisig_state], chained_calls))
    }

    /// Create a proposal (permissionless; content is public by design).
    #[instruction]
    pub fn propose(
        #[account(mut)]
        multisig_state: AccountWithMetadata,
        #[account(init, pda = [literal("pms_proposal"), arg("create_key"), arg("proposal_index")])]
        proposal: AccountWithMetadata,
        create_key: [u8; 32],
        proposal_index: u64,
        target_program_id: ProgramId,
        target_instruction_data: Vec<u32>,
        target_account_count: u8,
        pda_seeds: Vec<[u8; 32]>,
        authorized_indices: Vec<u8>,
    ) -> SpelResult {
        let mut multisig_state = multisig_state;
        let mut proposal = proposal;
        let accounts = vec![multisig_state.clone(), proposal.clone()];
        let action = ProposalAction {
            target_program_id,
            target_instruction_data,
            target_account_count,
            pda_seeds,
            authorized_indices,
        };
        let (post_states, chained_calls) =
            crate::propose::handle(&accounts, &create_key, proposal_index, &action);
        multisig_state.account = post_states[0].account().clone();
        proposal.account = post_states[1].account().clone();
        Ok(SpelOutput::execute(vec![multisig_state, proposal], chained_calls))
    }

    /// Approve anonymously. Submit as a **private execution**: `member_salt`
    /// rides in instruction data, which a privacy-preserving transaction
    /// never reveals; the chain records only an unlinkable nullifier.
    #[instruction]
    pub fn approve(
        multisig_state: AccountWithMetadata,
        #[account(mut, pda = [literal("pms_proposal"), arg("create_key"), arg("proposal_index")])]
        proposal: AccountWithMetadata,
        #[account(signer)]
        member_account: AccountWithMetadata,
        create_key: [u8; 32],
        proposal_index: u64,
        member_salt: [u8; 32],
    ) -> SpelResult {
        let mut proposal = proposal;
        let accounts = vec![multisig_state.clone(), proposal.clone(), member_account.clone()];
        let (post_states, chained_calls) =
            crate::approve::handle(&accounts, &create_key, proposal_index, &member_salt);
        proposal.account = post_states[1].account().clone();
        Ok(SpelOutput::execute(
            vec![multisig_state, proposal, member_account],
            chained_calls,
        ))
    }

    /// Reject anonymously (same privacy mechanics as approve).
    #[instruction]
    pub fn reject(
        multisig_state: AccountWithMetadata,
        #[account(mut, pda = [literal("pms_proposal"), arg("create_key"), arg("proposal_index")])]
        proposal: AccountWithMetadata,
        #[account(signer)]
        member_account: AccountWithMetadata,
        create_key: [u8; 32],
        proposal_index: u64,
        member_salt: [u8; 32],
    ) -> SpelResult {
        let mut proposal = proposal;
        let accounts = vec![multisig_state.clone(), proposal.clone(), member_account.clone()];
        let (post_states, chained_calls) =
            crate::reject::handle(&accounts, &create_key, proposal_index, &member_salt);
        proposal.account = post_states[1].account().clone();
        Ok(SpelOutput::execute(
            vec![multisig_state, proposal, member_account],
            chained_calls,
        ))
    }

    /// Execute a fully-approved proposal (permissionless — anyone can crank;
    /// no member account is involved, keeping execution unlinkable).
    #[instruction]
    pub fn execute(
        multisig_state: AccountWithMetadata,
        #[account(mut, pda = [literal("pms_proposal"), arg("create_key"), arg("proposal_index")])]
        proposal: AccountWithMetadata,
        target_accounts: Vec<AccountWithMetadata>,
        create_key: [u8; 32],
        proposal_index: u64,
    ) -> SpelResult {
        let mut accounts = vec![multisig_state, proposal];
        accounts.extend(target_accounts);
        let (post_states, chained_calls) =
            crate::execute::handle(&accounts, &create_key, proposal_index);
        for (acc, post) in accounts.iter_mut().zip(&post_states) {
            acc.account = post.account().clone();
        }
        Ok(SpelOutput::execute(accounts, chained_calls))
    }

    /// Initialize the multisig's token vault (permissionless). Chain-calls
    /// the token program with the vault authorized via this program's PDA
    /// seed, so the vault can then receive ordinary token transfers.
    #[instruction]
    pub fn init_vault(
        token_definition: AccountWithMetadata,
        #[account(mut, pda = [literal("pms_vault"), arg("create_key")])]
        vault: AccountWithMetadata,
        create_key: [u8; 32],
        token_program_id: ProgramId,
    ) -> SpelResult {
        let accounts = vec![token_definition.clone(), vault.clone()];
        let (_post_states, chained_calls) =
            crate::init_vault::handle(&accounts, &create_key, &token_program_id);
        Ok(SpelOutput::execute(
            vec![token_definition, vault],
            chained_calls,
        ))
    }
}

/// Instruction dispatch used by the guest binary
/// (methods/guest/src/bin/private_multisig.rs).
pub fn process(
    accounts: &[nssa_core::account::AccountWithMetadata],
    instruction: &pms_core::Instruction,
) -> (
    Vec<nssa_core::program::AccountPostState>,
    Vec<nssa_core::program::ChainedCall>,
) {
    use pms_core::Instruction;
    match instruction {
        Instruction::CreateMultisig {
            create_key,
            threshold,
            member_cms,
        } => create_multisig::handle(accounts, create_key, *threshold, member_cms),
        Instruction::Propose {
            create_key,
            proposal_index,
            target_program_id,
            target_instruction_data,
            target_account_count,
            pda_seeds,
            authorized_indices,
        } => {
            let action = ProposalAction {
                target_program_id: *target_program_id,
                target_instruction_data: target_instruction_data.clone(),
                target_account_count: *target_account_count,
                pda_seeds: pda_seeds.clone(),
                authorized_indices: authorized_indices.clone(),
            };
            propose::handle(accounts, create_key, *proposal_index, &action)
        }
        Instruction::Approve {
            create_key,
            proposal_index,
            member_salt,
        } => approve::handle(accounts, create_key, *proposal_index, member_salt),
        Instruction::Reject {
            create_key,
            proposal_index,
            member_salt,
        } => reject::handle(accounts, create_key, *proposal_index, member_salt),
        Instruction::Execute {
            create_key,
            proposal_index,
        } => execute::handle(accounts, create_key, *proposal_index),
        Instruction::InitVault {
            create_key,
            token_program_id,
        } => init_vault::handle(accounts, create_key, token_program_id),
    }
}
