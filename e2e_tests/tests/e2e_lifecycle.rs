//! End-to-end lifecycle test for the private multisig program.
//!
//! Drives the full flow against a real local sequencer using **public-mode**
//! transactions: the program logic (membership commitments, vote nullifiers,
//! double-vote prevention, permissionless execute) is identical in private
//! mode — only the transport differs (instruction data and the member account
//! are hidden by the privacy circuit there).
//!
//! Flow:
//! 1. Deploy token program + private multisig program
//! 2. Create a fungible token (minter holds supply)
//! 3. Create a 2-of-3 multisig from salted member commitments
//! 4. Fund the multisig vault PDA and pre-initialize the recipient holding
//! 5. Propose: transfer 100 tokens vault → recipient (unsigned tx — permissionless)
//! 6. Approve as member 1 (vote nullifier #1)
//! 7. Replay member 1's approval — must be REJECTED (duplicate nullifier)
//! 8. Approve as member 2 (threshold reached)
//! 9. Execute (unsigned tx — permissionless, no member involved)
//! 10. Verify the recipient received the tokens and the proposal is Executed
//!
//! Prerequisites:
//! - Sequencer at SEQUENCER_URL (default http://127.0.0.1:3040), e.g.
//!   logos-execution-zone @ v0.1.2: `cargo run --features standalone -p
//!   sequencer_service sequencer/service/configs/debug/sequencer_config.json`
//!   (run with RISC0_DEV_MODE=1 for fast public-mode blocks)
//! - PMS_PROGRAM: path to private_multisig.bin
//!   (default target/riscv32im-risc0-zkvm-elf/docker/private_multisig.bin)
//! - TOKEN_PROGRAM: path to the platform token program binary
//!   (e.g. <logos-execution-zone>/artifacts/program_methods/token.bin)

use std::time::Duration;

use common::transaction::NSSATransaction;
use nssa::program::Program;
use nssa::public_transaction::{Message, WitnessSet};
use nssa::{
    AccountId, PrivateKey, ProgramDeploymentTransaction, PublicKey, PublicTransaction,
};
use pms_core::{
    compute_multisig_state_pda, compute_proposal_pda, compute_vault_pda, member_commitment,
    vault_pda_seed_bytes, Instruction, MultisigState, Proposal, ProposalStatus,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use token_core::{Instruction as TokenInstruction, TokenHolding};

const BLOCK_WAIT_SECS: u64 = 15;

fn account_id_from_key(key: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(key))
}

fn sequencer_client() -> SequencerClient {
    let url =
        std::env::var("SEQUENCER_URL").unwrap_or_else(|_| "http://127.0.0.1:3040".to_string());
    SequencerClientBuilder::default()
        .build(url)
        .expect("failed to create sequencer client")
}

/// Submit a public transaction and wait for inclusion.
async fn submit_tx(client: &SequencerClient, tx: PublicTransaction) {
    let included = try_submit_tx(client, tx).await;
    assert!(included, "transaction was not included in a block");
}

/// Submit a public transaction; return whether it was included in a block.
async fn try_submit_tx(client: &SequencerClient, tx: PublicTransaction) -> bool {
    let tx = NSSATransaction::Public(tx);
    let tx_hash = match client.send_transaction(tx).await {
        Ok(hash) => hash,
        Err(e) => {
            println!("  tx rejected at submission: {e}");
            return false;
        }
    };
    println!("  tx_hash: {tx_hash:?}");

    let max_wait = Duration::from_secs(BLOCK_WAIT_SECS * 3);
    let poll = Duration::from_secs(2);
    let start = std::time::Instant::now();
    loop {
        tokio::time::sleep(poll).await;
        if let Ok(Some(_)) = client.get_transaction(tx_hash).await {
            println!("  ✅ included in block");
            return true;
        }
        if start.elapsed() > max_wait {
            println!("  ⛔ not included after {max_wait:?}");
            return false;
        }
    }
}

async fn get_nonce(client: &SequencerClient, id: AccountId) -> nssa_core::account::Nonce {
    client
        .get_account(id)
        .await
        .map(|a| a.nonce)
        .unwrap_or_default()
}

async fn token_balance(client: &SequencerClient, id: AccountId) -> Option<u128> {
    let account = client.get_account(id).await.ok()?;
    let data: Vec<u8> = account.data.into();
    match borsh::from_slice::<TokenHolding>(&data).ok()? {
        TokenHolding::Fungible { balance, .. } => Some(balance),
        _ => None,
    }
}

async fn fetch_state(client: &SequencerClient, id: AccountId) -> MultisigState {
    let account = client.get_account(id).await.expect("state account");
    let data: Vec<u8> = account.data.into();
    borsh::from_slice(&data).expect("deserialize MultisigState")
}

async fn fetch_proposal(client: &SequencerClient, id: AccountId) -> Proposal {
    let account = client.get_account(id).await.expect("proposal account");
    let data: Vec<u8> = account.data.into();
    borsh::from_slice(&data).expect("deserialize Proposal")
}

fn read_program(env_var: &str, default_path: &str) -> Vec<u8> {
    let path = std::env::var(env_var).unwrap_or_else(|_| {
        format!("{}/../{}", env!("CARGO_MANIFEST_DIR"), default_path)
    });
    std::fs::read(&path).unwrap_or_else(|_| panic!("cannot read {env_var} binary at '{path}'"))
}

#[tokio::test]
async fn test_private_multisig_lifecycle() {
    let client = sequencer_client();

    // ── Deploy programs ──────────────────────────────────────────────────
    println!("📦 Deploying programs...");
    let token_bytecode = read_program("TOKEN_PROGRAM", "../lez-v012/artifacts/program_methods/token.bin");
    let pms_bytecode = read_program(
        "PMS_PROGRAM",
        "target/riscv32im-risc0-zkvm-elf/docker/private_multisig.bin",
    );

    let token_program_id = Program::new(token_bytecode.clone()).expect("valid token program").id();
    let pms_program_id = Program::new(pms_bytecode.clone()).expect("valid pms program").id();
    println!("  token program id: {token_program_id:?}");
    println!("  private multisig program id: {pms_program_id:?}");

    for (name, bytecode) in [("token", token_bytecode), ("private_multisig", pms_bytecode)] {
        let msg = nssa::program_deployment_transaction::Message::new(bytecode);
        let tx = NSSATransaction::ProgramDeployment(ProgramDeploymentTransaction::new(msg));
        match client.send_transaction(tx).await {
            Ok(hash) => {
                println!("  {name} deployment submitted: {hash:?}");
                tokio::time::sleep(Duration::from_secs(BLOCK_WAIT_SECS)).await;
            }
            Err(e) => println!("  {name} deployment skipped (already deployed?): {e}"),
        }
    }

    // ── Step 1: create token, supply to minter ───────────────────────────
    println!("\n═══ STEP 1: Create fungible token ═══");
    let def_key = PrivateKey::new_os_random();
    let def_id = account_id_from_key(&def_key);
    let minter_key = PrivateKey::new_os_random();
    let minter_id = account_id_from_key(&minter_key);

    let msg = Message::try_new(
        token_program_id,
        vec![def_id, minter_id],
        vec![get_nonce(&client, def_id).await, get_nonce(&client, minter_id).await],
        TokenInstruction::NewFungibleDefinition {
            name: "PrivTestToken".to_string(),
            total_supply: 1_000_000,
        },
    )
    .unwrap();
    let ws = WitnessSet::for_message(&msg, &[&def_key, &minter_key]);
    submit_tx(&client, PublicTransaction::new(msg, ws)).await;
    assert_eq!(token_balance(&client, minter_id).await, Some(1_000_000));
    println!("  ✅ minter holds 1,000,000 tokens");

    // ── Step 2: create 2-of-3 multisig from salted commitments ───────────
    println!("\n═══ STEP 2: Create 2-of-3 private multisig ═══");
    // Each member: an account keypair (stands in for a shielded account in
    // public mode) + a secret salt. Only H(salt ‖ account_id) goes on-chain.
    let member_keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new_os_random()).collect();
    let member_ids: Vec<AccountId> = member_keys.iter().map(account_id_from_key).collect();
    let member_salts: Vec<[u8; 32]> = (0..3)
        .map(|_| *account_id_from_key(&PrivateKey::new_os_random()).value())
        .collect();
    let member_cms: Vec<[u8; 32]> = member_ids
        .iter()
        .zip(&member_salts)
        .map(|(id, salt)| member_commitment(salt, id))
        .collect();

    let create_key = *account_id_from_key(&PrivateKey::new_os_random()).value();
    let state_id = compute_multisig_state_pda(&pms_program_id, &create_key);
    let vault_id = compute_vault_pda(&pms_program_id, &create_key);
    println!("  multisig state PDA: {state_id}");
    println!("  vault PDA: {vault_id}");

    // Unsigned transaction: creating a multisig needs no authority beyond
    // the PDA claim, and reveals no member identities.
    let msg = Message::try_new(
        pms_program_id,
        vec![state_id],
        vec![],
        Instruction::CreateMultisig {
            create_key,
            threshold: 2,
            member_cms: member_cms.clone(),
        },
    )
    .unwrap();
    let ws = WitnessSet::for_message(&msg, &[] as &[&PrivateKey]);
    submit_tx(&client, PublicTransaction::new(msg, ws)).await;

    let state = fetch_state(&client, state_id).await;
    assert_eq!(state.threshold, 2);
    assert_eq!(state.member_cms, member_cms);
    println!("  ✅ multisig created — on-chain member list is 3 opaque commitments");

    // ── Step 3: init + fund the vault, pre-initialize recipient ──────────
    println!("\n═══ STEP 3: Init vault, fund it (500), init recipient holding ═══");
    let recipient_key = PrivateKey::new_os_random();
    let recipient_id = account_id_from_key(&recipient_key);

    // InitVault: our program authorizes its vault PDA toward the token
    // program via pda_seeds (a PDA cannot sign). Unsigned tx.
    let msg = Message::try_new(
        pms_program_id,
        vec![def_id, vault_id],
        vec![],
        Instruction::InitVault {
            create_key,
            token_program_id,
        },
    )
    .unwrap();
    let ws = WitnessSet::for_message(&msg, &[] as &[&PrivateKey]);
    submit_tx(&client, PublicTransaction::new(msg, ws)).await;
    assert_eq!(token_balance(&client, vault_id).await, Some(0));
    println!("  ✅ vault token holding initialized via ChainedCall");

    let msg = Message::try_new(
        token_program_id,
        vec![minter_id, vault_id],
        vec![get_nonce(&client, minter_id).await],
        TokenInstruction::Transfer {
            amount_to_transfer: 500,
        },
    )
    .unwrap();
    let ws = WitnessSet::for_message(&msg, &[&minter_key]);
    submit_tx(&client, PublicTransaction::new(msg, ws)).await;
    assert_eq!(token_balance(&client, vault_id).await, Some(500));

    let msg = Message::try_new(
        token_program_id,
        vec![minter_id, recipient_id],
        vec![
            get_nonce(&client, minter_id).await,
            get_nonce(&client, recipient_id).await,
        ],
        TokenInstruction::Transfer {
            amount_to_transfer: 1,
        },
    )
    .unwrap();
    let ws = WitnessSet::for_message(&msg, &[&minter_key, &recipient_key]);
    submit_tx(&client, PublicTransaction::new(msg, ws)).await;
    println!("  ✅ vault funded with 500; recipient holding initialized with 1");

    // ── Step 4: propose vault → recipient transfer (permissionless) ──────
    println!("\n═══ STEP 4: Propose transfer of 100 vault → recipient ═══");
    let proposal_index = 1u64;
    let proposal_id = compute_proposal_pda(&pms_program_id, &create_key, proposal_index);

    let target_instruction_data = Program::serialize_instruction(TokenInstruction::Transfer {
        amount_to_transfer: 100,
    })
    .unwrap();

    let msg = Message::try_new(
        pms_program_id,
        vec![state_id, proposal_id],
        vec![],
        Instruction::Propose {
            create_key,
            proposal_index,
            target_program_id: token_program_id,
            target_instruction_data,
            target_account_count: 2,
            pda_seeds: vec![vault_pda_seed_bytes(&create_key)],
            authorized_indices: vec![0],
        },
    )
    .unwrap();
    let ws = WitnessSet::for_message(&msg, &[] as &[&PrivateKey]);
    submit_tx(&client, PublicTransaction::new(msg, ws)).await;

    let proposal = fetch_proposal(&client, proposal_id).await;
    assert_eq!(proposal.status, ProposalStatus::Active);
    assert_eq!(proposal.vote_nullifiers.len(), 0, "no auto-approval");
    println!("  ✅ proposal #1 created (anonymous — no proposer recorded)");

    // ── Step 5: member 1 approves ─────────────────────────────────────────
    println!("\n═══ STEP 5: Member 1 approves ═══");
    let approve_as = |member: usize, nonce: nssa_core::account::Nonce| {
        let msg = Message::try_new(
            pms_program_id,
            vec![state_id, proposal_id, member_ids[member]],
            vec![nonce],
            Instruction::Approve {
                create_key,
                proposal_index,
                member_salt: member_salts[member],
            },
        )
        .unwrap();
        let ws = WitnessSet::for_message(&msg, &[&member_keys[member]]);
        PublicTransaction::new(msg, ws)
    };

    let nonce = get_nonce(&client, member_ids[0]).await;
    submit_tx(&client, approve_as(0, nonce)).await;
    let proposal = fetch_proposal(&client, proposal_id).await;
    assert_eq!(proposal.vote_nullifiers.len(), 1);
    println!("  ✅ approval recorded as opaque nullifier #1");

    // ── Step 6: member 1 tries to approve AGAIN — must be rejected ───────
    println!("\n═══ STEP 6: Member 1 double-votes — must be rejected ═══");
    let nonce = get_nonce(&client, member_ids[0]).await;
    let included = try_submit_tx(&client, approve_as(0, nonce)).await;
    assert!(!included, "double vote must not be included");
    let proposal = fetch_proposal(&client, proposal_id).await;
    assert_eq!(
        proposal.vote_nullifiers.len(),
        1,
        "duplicate nullifier must not be recorded"
    );
    println!("  ✅ double vote rejected (duplicate nullifier)");

    // ── Step 7: member 2 approves — threshold reached ─────────────────────
    println!("\n═══ STEP 7: Member 2 approves (reaches 2-of-3) ═══");
    let nonce = get_nonce(&client, member_ids[1]).await;
    submit_tx(&client, approve_as(1, nonce)).await;
    let proposal = fetch_proposal(&client, proposal_id).await;
    assert_eq!(proposal.vote_nullifiers.len(), 2);
    println!("  ✅ threshold reached — chain shows 2 unlinkable nullifiers");

    // ── Step 8: execute (permissionless, unsigned) ────────────────────────
    println!("\n═══ STEP 8: Execute proposal (unsigned tx, no member) ═══");
    let msg = Message::try_new(
        pms_program_id,
        vec![state_id, proposal_id, vault_id, recipient_id],
        vec![],
        Instruction::Execute {
            create_key,
            proposal_index,
        },
    )
    .unwrap();
    let ws = WitnessSet::for_message(&msg, &[] as &[&PrivateKey]);
    submit_tx(&client, PublicTransaction::new(msg, ws)).await;

    // ── Step 9: verify ────────────────────────────────────────────────────
    println!("\n═══ STEP 9: Verify outcome ═══");
    let proposal = fetch_proposal(&client, proposal_id).await;
    assert_eq!(proposal.status, ProposalStatus::Executed);
    assert_eq!(token_balance(&client, vault_id).await, Some(400));
    assert_eq!(token_balance(&client, recipient_id).await, Some(101));
    println!("  ✅ vault 500→400, recipient 1→101, proposal Executed");
    println!("\n🎉 full private-multisig lifecycle passed");
}
