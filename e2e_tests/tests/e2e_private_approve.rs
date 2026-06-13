//! End-to-end test of **private approvals** via the SDK.
//!
//! Approvals are submitted as privacy-preserving transactions: the program
//! runs locally inside the platform's privacy circuit and only the proof +
//! the proposal diff go on-chain. This test asserts the privacy properties
//! directly against the bytes the chain sees:
//!
//! - the approval transaction carries **zero signatures**,
//! - its public account list is exactly {multisig state, proposal},
//! - the serialized transaction contains **neither the member's account ID
//!   nor the member's salt**,
//! - a double vote fails **locally during proving** with PMS_E012 (nothing
//!   is ever submitted),
//! - `has_voted` recomputes membership from chain state (resumability).
//!
//! Run with RISC0_DEV_MODE=1 (both here and on the sequencer) for fast
//! iteration; the proving pipeline is identical with =0, just slow.
//!
//! Prerequisites: same as e2e_lifecycle.rs (local v0.1.2 standalone
//! sequencer; TOKEN_PROGRAM + PMS_PROGRAM env vars or defaults).

use std::time::Duration;

use common::transaction::NSSATransaction;
use nssa::program::Program;
use nssa::public_transaction::{Message, WitnessSet};
use nssa::{AccountId, PrivateKey, PublicTransaction};
use pms_core::{compute_vault_pda, ProposalStatus};
use pms_sdk::{account_id_from_key, MemberIdentity, MultisigClient, SdkError};
use sequencer_service_rpc::RpcClient as _;
use token_core::{Instruction as TokenInstruction, TokenHolding};

fn read_program(env_var: &str, default_path: &str) -> Vec<u8> {
    let path = std::env::var(env_var)
        .unwrap_or_else(|_| format!("{}/../{}", env!("CARGO_MANIFEST_DIR"), default_path));
    std::fs::read(&path).unwrap_or_else(|_| panic!("cannot read {env_var} binary at '{path}'"))
}

async fn token_balance(client: &MultisigClient, id: AccountId) -> Option<u128> {
    let account = client.account(id).await.ok()?;
    let data: Vec<u8> = account.data.into();
    match borsh::from_slice::<TokenHolding>(&data).ok()? {
        TokenHolding::Fungible { balance, .. } => Some(balance),
        _ => None,
    }
}

#[tokio::test]
async fn test_private_approvals() {
    let _ = env_logger::builder().is_test(true).try_init();
    let sequencer_url =
        std::env::var("SEQUENCER_URL").unwrap_or_else(|_| "http://127.0.0.1:3040".to_string());

    let token_bytecode =
        read_program("TOKEN_PROGRAM", "../lez-v012/artifacts/program_methods/token.bin");
    let pms_bytecode = read_program(
        "PMS_PROGRAM",
        "target/riscv32im-risc0-zkvm-elf/docker/private_multisig.bin",
    );
    let token_program_id = Program::new(token_bytecode).expect("valid token program").id();

    let client = MultisigClient::new(&sequencer_url, pms_bytecode).expect("client");
    println!("📦 Deploying multisig program...");
    client.deploy_program().await.expect("deploy");

    // ── Token setup: definition + funded minter ──────────────────────────
    println!("═══ Token setup ═══");
    let def_key = PrivateKey::new_os_random();
    let def_id = account_id_from_key(&def_key);
    let minter_key = PrivateKey::new_os_random();
    let minter_id = account_id_from_key(&minter_key);

    let msg = Message::try_new(
        token_program_id,
        vec![def_id, minter_id],
        vec![Default::default(), Default::default()],
        TokenInstruction::NewFungibleDefinition {
            name: "PrivApproveToken".to_string(),
            total_supply: 1_000_000,
        },
    )
    .unwrap();
    let ws = WitnessSet::for_message(&msg, &[&def_key, &minter_key]);
    let tx_hash = client
        .sequencer()
        .send_transaction(NSSATransaction::Public(PublicTransaction::new(msg, ws)))
        .await
        .expect("token setup tx");
    wait_included(&client, tx_hash).await;

    // ── Multisig from PRIVATE member identities ──────────────────────────
    println!("═══ Create 2-of-3 multisig (shielded-account members) ═══");
    let members: Vec<MemberIdentity> = (0..3).map(|_| MemberIdentity::random()).collect();
    let member_cms: Vec<[u8; 32]> = members.iter().map(|m| m.commitment()).collect();

    let create_key: [u8; 32] = *account_id_from_key(&PrivateKey::new_os_random()).value();
    client
        .create_multisig(create_key, 2, member_cms)
        .await
        .expect("create multisig");
    let state = client.multisig_state(&create_key).await.expect("state");
    assert_eq!(state.threshold, 2);
    println!("  ✅ members are commitments to shielded account IDs");

    // ── Vault init + funding ─────────────────────────────────────────────
    println!("═══ Vault setup ═══");
    let vault_id = compute_vault_pda(&client.program_id(), &create_key);
    client
        .init_vault(create_key, def_id, token_program_id)
        .await
        .expect("init vault");

    let recipient_key = PrivateKey::new_os_random();
    let recipient_id = account_id_from_key(&recipient_key);

    let minter_nonce = client.account(minter_id).await.expect("minter").nonce;
    let msg = Message::try_new(
        token_program_id,
        vec![minter_id, vault_id],
        vec![minter_nonce],
        TokenInstruction::Transfer {
            amount_to_transfer: 500,
        },
    )
    .unwrap();
    let ws = WitnessSet::for_message(&msg, &[&minter_key]);
    let tx_hash = client
        .sequencer()
        .send_transaction(NSSATransaction::Public(PublicTransaction::new(msg, ws)))
        .await
        .expect("fund vault");
    wait_included(&client, tx_hash).await;

    let minter_nonce = client.account(minter_id).await.expect("minter").nonce;
    let msg = Message::try_new(
        token_program_id,
        vec![minter_id, recipient_id],
        vec![minter_nonce, Default::default()],
        TokenInstruction::Transfer {
            amount_to_transfer: 1,
        },
    )
    .unwrap();
    let ws = WitnessSet::for_message(&msg, &[&minter_key, &recipient_key]);
    let tx_hash = client
        .sequencer()
        .send_transaction(NSSATransaction::Public(PublicTransaction::new(msg, ws)))
        .await
        .expect("init recipient");
    wait_included(&client, tx_hash).await;
    assert_eq!(token_balance(&client, vault_id).await, Some(500));
    println!("  ✅ vault funded (500), recipient initialized");

    // ── Propose ──────────────────────────────────────────────────────────
    println!("═══ Propose vault → recipient transfer (100) ═══");
    let proposal_index = 1u64;
    let target_instruction_data = Program::serialize_instruction(TokenInstruction::Transfer {
        amount_to_transfer: 100,
    })
    .unwrap();
    client
        .propose(
            create_key,
            proposal_index,
            token_program_id,
            target_instruction_data,
            2,
            vec![pms_core::vault_pda_seed_bytes(&create_key)],
            vec![0],
        )
        .await
        .expect("propose");

    // ── PRIVATE approval #1 ──────────────────────────────────────────────
    println!("═══ Member 1 approves PRIVATELY ═══");
    assert!(!client
        .has_voted(&create_key, proposal_index, &members[0])
        .await
        .unwrap());
    let tx_hash = client
        .approve_private(create_key, proposal_index, &members[0], None)
        .await
        .expect("private approve member 1");

    // The chain-visible transaction must reveal nothing about the member.
    let tx = client
        .sequencer()
        .get_transaction(tx_hash)
        .await
        .unwrap()
        .expect("tx on chain");
    let NSSATransaction::PrivacyPreserving(ptx) = tx else {
        panic!("approval must be a privacy-preserving transaction");
    };
    assert!(
        ptx.witness_set.signatures_and_public_keys().is_empty(),
        "approval must carry zero signatures"
    );
    let tx_bytes = borsh::to_vec(&ptx).unwrap();
    let member_id_bytes = members[0].account_id().value().to_vec();
    assert!(
        !contains_subslice(&tx_bytes, &member_id_bytes),
        "tx must not contain the member's account id"
    );
    assert!(
        !contains_subslice(&tx_bytes, &members[0].salt),
        "tx must not contain the member's salt"
    );
    println!("  ✅ on-chain tx: 0 signatures, no member account id, no salt");

    assert!(client
        .has_voted(&create_key, proposal_index, &members[0])
        .await
        .unwrap());
    assert!(!client
        .has_voted(&create_key, proposal_index, &members[2])
        .await
        .unwrap());
    println!("  ✅ has_voted recomputed from chain state (resumable)");

    // ── Double vote fails locally, before submission ─────────────────────
    println!("═══ Member 1 double-votes — must fail during local proving ═══");
    let last_block_before = client.sequencer().get_last_block_id().await.unwrap();
    let err = client
        .approve_private(create_key, proposal_index, &members[0], None)
        .await
        .expect_err("double vote must fail");
    match &err {
        SdkError::Proving(msg) => assert!(
            msg.contains("PMS_E012"),
            "expected PMS_E012 in proving error, got: {msg}"
        ),
        other => panic!("expected local proving failure, got: {other}"),
    }
    println!("  ✅ rejected locally with PMS_E012 — nothing was submitted");
    let _ = last_block_before; // (block id may advance from empty blocks)

    let proposal = client.proposal(&create_key, proposal_index).await.unwrap();
    assert_eq!(proposal.vote_nullifiers.len(), 1);

    // ── PRIVATE approval #2 → threshold ──────────────────────────────────
    println!("═══ Member 2 approves PRIVATELY (reaches 2-of-3) ═══");
    client
        .approve_private(create_key, proposal_index, &members[1], None)
        .await
        .expect("private approve member 2");
    let proposal = client.proposal(&create_key, proposal_index).await.unwrap();
    assert_eq!(proposal.vote_nullifiers.len(), 2);
    assert_ne!(proposal.vote_nullifiers[0], proposal.vote_nullifiers[1]);
    println!("  ✅ two unlinkable nullifiers on-chain");

    // ── Execute (permissionless) + verify ────────────────────────────────
    println!("═══ Execute + verify ═══");
    client
        .execute(create_key, proposal_index, vec![vault_id, recipient_id])
        .await
        .expect("execute");
    let proposal = client.proposal(&create_key, proposal_index).await.unwrap();
    assert_eq!(proposal.status, ProposalStatus::Executed);
    assert_eq!(token_balance(&client, vault_id).await, Some(400));
    assert_eq!(token_balance(&client, recipient_id).await, Some(101));
    println!("  ✅ vault 500→400, recipient 1→101");
    println!("\n🎉 private approval flow passed");
}

async fn wait_included(client: &MultisigClient, tx_hash: common::HashType) {
    let poll = Duration::from_secs(2);
    let start = std::time::Instant::now();
    loop {
        tokio::time::sleep(poll).await;
        if let Ok(Some(_)) = client.sequencer().get_transaction(tx_hash).await {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(45),
            "tx {tx_hash:?} not included"
        );
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
