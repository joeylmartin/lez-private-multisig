//! Host-side SDK for the LEZ private multisig.
//!
//! The centerpiece is [`MultisigClient::approve_private`]: it runs the
//! multisig program locally inside the platform's privacy-preserving circuit
//! and submits the resulting proof. On-chain, the transaction reveals only
//! the proposal account's diff (one opaque nullifier, count + 1) plus an
//! unlinkable commitment for the member's shielded account — **not** the
//! instruction data (the member's salt), **not** the member's account ID,
//! and **not** any signature tying the transaction to the member.
//!
//! Proving runs client-side and can take minutes with `RISC0_DEV_MODE=0`;
//! callers should run [`MultisigClient::approve_private`] off the UI thread.
//! All failures surface as typed [`SdkError`]s; program-rule violations
//! (e.g. a double vote) fail **locally during proving** with the program's
//! documented `PMS_Exxx` message before anything is submitted.

use std::time::Duration;

use common::transaction::NSSATransaction;
use common::HashType;
use key_protocol::key_management::ephemeral_key_holder::EphemeralKeyHolder;
use key_protocol::key_management::secret_holders::{PrivateKeyHolder, SecretSpendingKey};
use nssa::privacy_preserving_transaction::circuit::{self, ProgramWithDependencies};
use nssa::privacy_preserving_transaction::message::Message as PrivacyMessage;
use nssa::privacy_preserving_transaction::witness_set::WitnessSet as PrivacyWitnessSet;
use nssa::program::Program;
use nssa::public_transaction::{Message as PublicMessage, WitnessSet as PublicWitnessSet};
use nssa::{
    AccountId, PrivacyPreservingTransaction, PrivateKey, ProgramDeploymentTransaction, PublicKey,
    PublicTransaction,
};
use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::encryption::ViewingPublicKey;
use nssa_core::program::{InstructionData, ProgramId};
use nssa_core::NullifierPublicKey;
use pms_core::{
    compute_multisig_state_pda, compute_proposal_pda, member_commitment, Instruction,
    MultisigState, Proposal,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};

pub use pms_core;

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("sequencer error: {0}")]
    Sequencer(String),
    #[error("account {0} not found or not yet initialized")]
    AccountNotFound(AccountId),
    #[error("failed to decode on-chain state: {0}")]
    Decode(String),
    /// Local execution/proving failed. If the message contains a `PMS_Exxx`
    /// code, the *program* rejected the action (e.g. PMS_E012 = double vote)
    /// — retrying without changing inputs will fail again. Other causes
    /// (OOM, interrupted prover) are safe to retry.
    #[error("local execution/proving failed: {0}")]
    Proving(String),
    #[error("transaction {0:?} was not included after {1:?} (public pre-state may have changed — refresh and re-prove)")]
    NotIncluded(HashType, Duration),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

type Result<T> = std::result::Result<T, SdkError>;

// ---------------------------------------------------------------------------
// Member identity
// ---------------------------------------------------------------------------

/// A multisig member's secrets: the shielded-account keypair (nullifier +
/// viewing keys, exactly the platform's private-account key model) plus the
/// membership `salt`. Everything needed to vote; nothing here ever appears
/// on-chain.
pub struct MemberIdentity {
    keys: PrivateKeyHolder,
    pub salt: [u8; 32],
}

impl MemberIdentity {
    /// Derive deterministically from a 32-byte seed (BIP32-style derivation,
    /// same scheme as the platform wallet) plus an independent salt.
    pub fn from_seed(seed: [u8; 32], salt: [u8; 32]) -> Self {
        let ssk = SecretSpendingKey(seed);
        Self {
            keys: ssk.produce_private_key_holder(None),
            salt,
        }
    }

    /// Fresh random identity (demo / testing convenience).
    pub fn random() -> Self {
        use rand::RngCore as _;
        let mut seed = [0u8; 32];
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        rand::rngs::OsRng.fill_bytes(&mut salt);
        Self::from_seed(seed, salt)
    }

    pub fn npk(&self) -> NullifierPublicKey {
        self.keys.generate_nullifier_public_key()
    }

    pub fn vpk(&self) -> ViewingPublicKey {
        self.keys.generate_viewing_public_key()
    }

    /// The member's shielded account ID (derived from the nullifier public
    /// key, exactly as the platform derives private-account IDs).
    pub fn account_id(&self) -> AccountId {
        AccountId::from(&self.npk())
    }

    /// The salted commitment that represents this member on-chain.
    pub fn commitment(&self) -> [u8; 32] {
        member_commitment(&self.salt, &self.account_id())
    }

    /// The nullifier secret key (needed when driving the proving pipeline
    /// directly, e.g. benchmarks).
    pub fn nsk(&self) -> nssa_core::NullifierSecretKey {
        self.keys.nullifier_secret_key
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct MultisigClient {
    client: SequencerClient,
    program: Program,
    program_id: ProgramId,
    /// How long to wait for a submitted tx to appear in a block.
    pub inclusion_timeout: Duration,
}

impl MultisigClient {
    pub fn new(sequencer_url: &str, program_bytecode: Vec<u8>) -> Result<Self> {
        let client = SequencerClientBuilder::default()
            .build(sequencer_url)
            .map_err(|e| SdkError::Sequencer(e.to_string()))?;
        let program = Program::new(program_bytecode)
            .map_err(|e| SdkError::InvalidInput(format!("invalid program bytecode: {e:?}")))?;
        let program_id = program.id();
        Ok(Self {
            client,
            program,
            program_id,
            inclusion_timeout: Duration::from_secs(45),
        })
    }

    pub fn program_id(&self) -> ProgramId {
        self.program_id
    }

    pub fn sequencer(&self) -> &SequencerClient {
        &self.client
    }

    // ── On-chain reads ────────────────────────────────────────────────────

    pub async fn account(&self, id: AccountId) -> Result<Account> {
        self.client
            .get_account(id)
            .await
            .map_err(|e| SdkError::Sequencer(e.to_string()))
    }

    pub async fn multisig_state(&self, create_key: &[u8; 32]) -> Result<MultisigState> {
        let id = compute_multisig_state_pda(&self.program_id, create_key);
        let account = self.account(id).await?;
        if account == Account::default() {
            return Err(SdkError::AccountNotFound(id));
        }
        borsh::from_slice(&account.data).map_err(|e| SdkError::Decode(e.to_string()))
    }

    pub async fn proposal(&self, create_key: &[u8; 32], index: u64) -> Result<Proposal> {
        let id = compute_proposal_pda(&self.program_id, create_key, index);
        let account = self.account(id).await?;
        if account == Account::default() {
            return Err(SdkError::AccountNotFound(id));
        }
        borsh::from_slice(&account.data).map_err(|e| SdkError::Decode(e.to_string()))
    }

    /// Has this member already approved the given proposal? Recomputed
    /// locally from the member's secrets + public proposal state — this is
    /// the resumability story: no client-side bookkeeping is needed.
    pub async fn has_voted(
        &self,
        create_key: &[u8; 32],
        index: u64,
        member: &MemberIdentity,
    ) -> Result<bool> {
        let state_id = compute_multisig_state_pda(&self.program_id, create_key);
        let proposal = self.proposal(create_key, index).await?;
        let nullifier =
            pms_core::vote_nullifier(&member.salt, &state_id, index, &proposal.action_hash);
        Ok(proposal.vote_nullifiers.contains(&nullifier))
    }

    // ── Public-mode operations (no privacy needed) ────────────────────────

    /// Deploy the multisig program (idempotent — already-deployed is OK).
    pub async fn deploy_program(&self) -> Result<()> {
        let msg = nssa::program_deployment_transaction::Message::new(
            self.program.elf().to_vec(),
        );
        let tx = NSSATransaction::ProgramDeployment(ProgramDeploymentTransaction::new(msg));
        match self.client.send_transaction(tx).await {
            Ok(_) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(())
            }
            // Already deployed is fine.
            Err(e) if e.to_string().contains("ProgramAlreadyExists") => Ok(()),
            Err(e) => Err(SdkError::Sequencer(e.to_string())),
        }
    }

    pub async fn create_multisig(
        &self,
        create_key: [u8; 32],
        threshold: u8,
        member_cms: Vec<[u8; 32]>,
    ) -> Result<HashType> {
        let state_id = compute_multisig_state_pda(&self.program_id, &create_key);
        self.submit_public_unsigned(
            vec![state_id],
            Instruction::CreateMultisig {
                create_key,
                threshold,
                member_cms,
            },
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn propose(
        &self,
        create_key: [u8; 32],
        proposal_index: u64,
        target_program_id: ProgramId,
        target_instruction_data: Vec<u32>,
        target_account_count: u8,
        pda_seeds: Vec<[u8; 32]>,
        authorized_indices: Vec<u8>,
    ) -> Result<HashType> {
        let state_id = compute_multisig_state_pda(&self.program_id, &create_key);
        let proposal_id = compute_proposal_pda(&self.program_id, &create_key, proposal_index);
        self.submit_public_unsigned(
            vec![state_id, proposal_id],
            Instruction::Propose {
                create_key,
                proposal_index,
                target_program_id,
                target_instruction_data,
                target_account_count,
                pda_seeds,
                authorized_indices,
            },
        )
        .await
    }

    /// Initialize the multisig's token vault (see program docs).
    pub async fn init_vault(
        &self,
        create_key: [u8; 32],
        token_definition_id: AccountId,
        token_program_id: ProgramId,
    ) -> Result<HashType> {
        let vault_id = pms_core::compute_vault_pda(&self.program_id, &create_key);
        self.submit_public_unsigned(
            vec![token_definition_id, vault_id],
            Instruction::InitVault {
                create_key,
                token_program_id,
            },
        )
        .await
    }

    /// Execute a fully-approved proposal. Permissionless and unsigned —
    /// deliberately involves no member identity.
    pub async fn execute(
        &self,
        create_key: [u8; 32],
        proposal_index: u64,
        target_account_ids: Vec<AccountId>,
    ) -> Result<HashType> {
        let state_id = compute_multisig_state_pda(&self.program_id, &create_key);
        let proposal_id = compute_proposal_pda(&self.program_id, &create_key, proposal_index);
        let mut ids = vec![state_id, proposal_id];
        ids.extend(target_account_ids);
        self.submit_public_unsigned(
            ids,
            Instruction::Execute {
                create_key,
                proposal_index,
            },
        )
        .await
    }

    // ── The private approval ──────────────────────────────────────────────

    /// Approve a proposal as a **private execution**.
    ///
    /// Runs the multisig program locally over the current on-chain state of
    /// the multisig + proposal accounts together with the member's shielded
    /// account, proves the execution inside the platform's privacy circuit
    /// (this is the minutes-long step under `RISC0_DEV_MODE=0`), and submits
    /// the proof. The transaction carries **no signatures** and reveals no
    /// member data.
    ///
    /// `member_account` is the current state of the member's shielded
    /// account: `None` for a fresh (never-used) account — the common demo
    /// path — or `Some(account)` with the synced state for an account that
    /// has been used before (requires its commitment to be on-chain; the
    /// membership proof is fetched from the sequencer automatically).
    pub async fn approve_private(
        &self,
        create_key: [u8; 32],
        proposal_index: u64,
        member: &MemberIdentity,
        member_account: Option<Account>,
    ) -> Result<HashType> {
        self.vote_private(create_key, proposal_index, member, member_account, true)
            .await
    }

    /// Reject a proposal as a private execution (same mechanics as
    /// [`Self::approve_private`]).
    pub async fn reject_private(
        &self,
        create_key: [u8; 32],
        proposal_index: u64,
        member: &MemberIdentity,
        member_account: Option<Account>,
    ) -> Result<HashType> {
        self.vote_private(create_key, proposal_index, member, member_account, false)
            .await
    }

    async fn vote_private(
        &self,
        create_key: [u8; 32],
        proposal_index: u64,
        member: &MemberIdentity,
        member_account: Option<Account>,
        approve: bool,
    ) -> Result<HashType> {
        let state_id = compute_multisig_state_pda(&self.program_id, &create_key);
        let proposal_id = compute_proposal_pda(&self.program_id, &create_key, proposal_index);

        // 1. Current public pre-states. The proof binds to these exactly; if
        //    another vote lands first, inclusion fails and the caller must
        //    re-prove against the refreshed state (see SdkError::NotIncluded).
        let state_account = self.account(state_id).await?;
        let proposal_account = self.account(proposal_id).await?;

        // 2. The member's shielded account pre-state. Fresh accounts take the
        //    init path (no membership proof); used accounts need their synced
        //    state + a membership proof for their current commitment.
        let member_id = member.account_id();
        let (member_pre, membership_proof) = match member_account {
            None => (Account::default(), None),
            Some(account) => {
                let commitment = nssa_core::Commitment::new(&member.npk(), &account);
                let proof = self
                    .client
                    .get_proof_for_commitment(commitment)
                    .await
                    .map_err(|e| SdkError::Sequencer(e.to_string()))?
                    .ok_or_else(|| {
                        SdkError::InvalidInput(
                            "member account state has no on-chain commitment — resync".into(),
                        )
                    })?;
                (account, Some(proof))
            }
        };

        let pre_states = vec![
            AccountWithMetadata::new(state_account, false, state_id),
            AccountWithMetadata::new(proposal_account, false, proposal_id),
            AccountWithMetadata::new(member_pre, true, member_id),
        ];

        let instruction = if approve {
            Instruction::Approve {
                create_key,
                proposal_index,
                member_salt: member.salt,
            }
        } else {
            Instruction::Reject {
                create_key,
                proposal_index,
                member_salt: member.salt,
            }
        };
        let instruction_data: InstructionData = Program::serialize_instruction(instruction)
            .map_err(|e| SdkError::InvalidInput(format!("{e:?}")))?;

        // 3. Encryption keys for the member's post-state ciphertext
        //    (addressed to the member's own viewing key).
        let npk = member.npk();
        let vpk = member.vpk();
        let eph = EphemeralKeyHolder::new(&npk);
        let ssk = eph.calculate_shared_secret_sender(&vpk);
        let epk = eph.generate_ephemeral_public_key();

        // 4. Local execution + proof inside the privacy circuit. Program
        //    rule violations (double vote, non-member salt, …) panic here
        //    with their PMS_Exxx string — nothing is submitted.
        log::info!("proving private vote (this can take minutes with RISC0_DEV_MODE=0)...");
        let started = std::time::Instant::now();
        let (output, proof) = circuit::execute_and_prove(
            pre_states,
            instruction_data,
            vec![0, 0, 1],
            vec![(npk, ssk)],
            vec![member.keys.nullifier_secret_key],
            vec![membership_proof],
            &ProgramWithDependencies::from(self.program.clone()),
        )
        .map_err(|e| SdkError::Proving(format!("{e:?}")))?;
        log::info!("proof generated in {:?}", started.elapsed());

        // 5. Assemble the unsigned privacy-preserving transaction.
        let message = PrivacyMessage::try_from_circuit_output(
            vec![state_id, proposal_id],
            vec![],
            vec![(npk, vpk, epk)],
            output,
        )
        .map_err(|e| SdkError::InvalidInput(format!("{e:?}")))?;
        let witness_set = PrivacyWitnessSet::for_message(&message, proof, &[]);
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        self.submit_and_wait(NSSATransaction::PrivacyPreserving(tx))
            .await
    }

    // ── Internals ─────────────────────────────────────────────────────────

    async fn submit_public_unsigned(
        &self,
        account_ids: Vec<AccountId>,
        instruction: Instruction,
    ) -> Result<HashType> {
        let msg = PublicMessage::try_new(self.program_id, account_ids, vec![], instruction)
            .map_err(|e| SdkError::InvalidInput(format!("{e:?}")))?;
        let ws = PublicWitnessSet::for_message(&msg, &[] as &[&PrivateKey]);
        self.submit_and_wait(NSSATransaction::Public(PublicTransaction::new(msg, ws)))
            .await
    }

    async fn submit_and_wait(&self, tx: NSSATransaction) -> Result<HashType> {
        let tx_hash = self
            .client
            .send_transaction(tx)
            .await
            .map_err(|e| SdkError::Sequencer(e.to_string()))?;

        let poll = Duration::from_secs(2);
        let start = std::time::Instant::now();
        loop {
            tokio::time::sleep(poll).await;
            if let Ok(Some(_)) = self.client.get_transaction(tx_hash).await {
                return Ok(tx_hash);
            }
            if start.elapsed() > self.inclusion_timeout {
                return Err(SdkError::NotIncluded(tx_hash, self.inclusion_timeout));
            }
        }
    }
}

/// Convenience: derive a public-key account id (courier/test accounts).
pub fn account_id_from_key(key: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(key))
}
