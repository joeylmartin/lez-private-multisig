//! Risc0 guest entry point for the private multisig program.
//!
//! The same binary serves both execution modes — the protocol, not the
//! program, decides whether a transaction is public (re-executed by
//! validators) or private (proven locally inside the platform's
//! privacy-preserving circuit, which verifies this guest's receipt via
//! composition and hides instruction data + private accounts).

#![no_main]

use nssa_core::program::{read_nssa_inputs, ProgramInput, ProgramOutput};
use pms_core::Instruction;

risc0_zkvm::guest::entry!(main);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let (post_states, chained_calls) = multisig_program::process(&pre_states, &instruction);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}
