//! Benchmark: real proving time for one private approval on this machine.
//!
//! Runs the exact pipeline `MultisigClient::approve_private` uses — program
//! guest execution + proof, then the privacy-preserving circuit proof
//! (succinct) with the program receipt as a composition assumption — against
//! synthetic in-memory accounts, so no sequencer is needed.
//!
//! Usage:
//!   RISC0_DEV_MODE=0 cargo run --release -p pms_sdk --example bench_prove \
//!       [path/to/private_multisig.bin]
//!
//! Prints program-guest cycle count, total wall-clock, and proof size.

use std::time::Instant;

use nssa::privacy_preserving_transaction::circuit::{self, ProgramWithDependencies};
use nssa::program::Program;
use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::InstructionData;
use pms_core::{member_commitment, Instruction, MultisigState, Proposal, ProposalAction};
use pms_sdk::MemberIdentity;

fn main() {
    let bin_path = std::env::args().nth(1).unwrap_or_else(|| {
        format!(
            "{}/../target/riscv32im-risc0-zkvm-elf/docker/private_multisig.bin",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let bytecode = std::fs::read(&bin_path)
        .unwrap_or_else(|_| panic!("cannot read program binary at '{bin_path}'"));
    let program = Program::new(bytecode).expect("valid program");
    let program_id = program.id();
    println!("program id (image id): {program_id:?}");
    println!(
        "RISC0_DEV_MODE = {}",
        std::env::var("RISC0_DEV_MODE").unwrap_or_else(|_| "<unset>".into())
    );

    // ── Synthetic 2-of-3 multisig with one open proposal ─────────────────
    let create_key = [7u8; 32];
    let members: Vec<MemberIdentity> = (0..3).map(|_| MemberIdentity::random()).collect();
    let member_cms: Vec<[u8; 32]> = members
        .iter()
        .map(|m| member_commitment(&m.salt, &m.account_id()))
        .collect();
    let mut state = MultisigState::new(create_key, 2, member_cms);
    state.transaction_index = 1;

    let action = ProposalAction {
        target_program_id: [42u32; 8],
        target_instruction_data: vec![1, 2, 3],
        target_account_count: 2,
        pda_seeds: vec![[5u8; 32]],
        authorized_indices: vec![0],
    };
    let proposal = Proposal::new(1, create_key, action);

    let state_id = pms_core::compute_multisig_state_pda(&program_id, &create_key);
    let proposal_id = pms_core::compute_proposal_pda(&program_id, &create_key, 1);

    let mut state_account = Account::default();
    state_account.data = borsh::to_vec(&state).unwrap().try_into().unwrap();
    state_account.program_owner = program_id;
    let mut proposal_account = Account::default();
    proposal_account.data = borsh::to_vec(&proposal).unwrap().try_into().unwrap();
    proposal_account.program_owner = program_id;

    let member = &members[0];
    let pre_states = vec![
        AccountWithMetadata::new(state_account, false, state_id),
        AccountWithMetadata::new(proposal_account, false, proposal_id),
        AccountWithMetadata::new(Account::default(), true, member.account_id()),
    ];

    let instruction_data: InstructionData =
        Program::serialize_instruction(Instruction::Approve {
            create_key,
            proposal_index: 1,
            member_salt: member.salt,
        })
        .unwrap();

    // ── Cycle count of the program guest alone (executor, no proving) ────
    {
        use risc0_zkvm::{default_executor, ExecutorEnv};
        let mut env_builder = ExecutorEnv::builder();
        env_builder.write(&program_id).unwrap();
        env_builder.write(&None::<nssa_core::program::ProgramId>).unwrap();
        env_builder.write(&pre_states).unwrap();
        env_builder.write(&instruction_data).unwrap();
        let env = env_builder.build().unwrap();
        let t = Instant::now();
        let session = default_executor().execute(env, program.elf()).unwrap();
        println!(
            "program guest execution: {} cycles ({} segments), {:?}",
            session.cycles(),
            session.segments.len(),
            t.elapsed()
        );
    }

    // ── Full pipeline: program proof + privacy circuit proof ─────────────
    let npk = member.npk();
    let vpk = member.vpk();
    let eph =
        key_protocol::key_management::ephemeral_key_holder::EphemeralKeyHolder::new(&npk);
    let ssk = eph.calculate_shared_secret_sender(&vpk);

    println!("proving full private approval (program receipt + privacy circuit, succinct)...");
    let t = Instant::now();
    let (output, proof) = circuit::execute_and_prove(
        pre_states,
        instruction_data,
        vec![0, 0, 1],
        vec![(npk, ssk)],
        vec![member.nsk()],
        vec![None],
        &ProgramWithDependencies::from(program),
    )
    .expect("proving failed");
    let elapsed = t.elapsed();

    let proof_bytes = proof.clone().into_inner();
    println!("──────────────────────────────────────────────");
    println!("TOTAL PROVING WALL-CLOCK: {elapsed:?}");
    println!("proof size: {} bytes", proof_bytes.len());
    println!(
        "circuit output: {} public accounts, {} commitments, {} nullifiers",
        output.public_post_states.len(),
        output.new_commitments.len(),
        output.new_nullifiers.len()
    );
    println!("verifying proof...");
    let t = Instant::now();
    let inner: risc0_zkvm::InnerReceipt =
        borsh::from_slice(&proof_bytes).expect("decodable receipt");
    let receipt = risc0_zkvm::Receipt::new(inner, output.to_bytes());
    receipt
        .verify(nssa::PRIVACY_PRESERVING_CIRCUIT_ID)
        .expect("proof must verify against circuit output");
    println!("verification: {:?}", t.elapsed());
}
