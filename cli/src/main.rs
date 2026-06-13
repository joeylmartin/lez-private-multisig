//! `pms` — CLI for the LEZ private multisig.
//!
//! Member identities (shielded-account keys + membership salt) live in local
//! JSON files created by `pms keygen`; nothing identifying ever goes
//! on-chain. `approve`/`reject` run the program locally inside the
//! platform's privacy circuit (minutes with RISC0_DEV_MODE=0) and submit an
//! unsigned privacy-preserving transaction.
//!
//! `pms token ...` subcommands wrap the platform token program so demos can
//! be driven end-to-end from this binary alone.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use common::transaction::NSSATransaction;
use nssa::program::Program;
use nssa::public_transaction::{Message, WitnessSet};
use nssa::{AccountId, PrivateKey, PublicTransaction};
use pms_sdk::{account_id_from_key, MemberIdentity, MultisigClient};
use sequencer_service_rpc::RpcClient as _;
use token_core::{Instruction as TokenInstruction, TokenHolding};

#[derive(Parser)]
#[command(name = "pms", about = "Private M-of-N multisig for LEZ", version)]
struct Cli {
    /// Sequencer RPC URL
    #[arg(long, global = true, env = "SEQUENCER_URL", default_value = "http://127.0.0.1:3040")]
    url: String,
    /// Path to the private_multisig program binary
    #[arg(
        long,
        global = true,
        env = "PMS_PROGRAM",
        default_value = "target/riscv32im-risc0-zkvm-elf/docker/private_multisig.bin"
    )]
    program: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a member identity (shielded-account keys + salt) into a JSON file
    Keygen {
        /// Output file for the identity
        #[arg(long)]
        out: PathBuf,
    },
    /// Deploy the multisig program (idempotent)
    Deploy,
    /// Create a new M-of-N multisig from member commitments
    Create {
        /// 32-byte hex create key (random if omitted; printed)
        #[arg(long)]
        create_key: Option<String>,
        #[arg(long)]
        threshold: u8,
        /// Member commitments (hex, from `pms keygen` output); repeatable
        #[arg(long = "member-cm", required = true)]
        member_cms: Vec<String>,
    },
    /// Initialize the multisig's token vault
    InitVault {
        #[arg(long)]
        create_key: String,
        /// Token definition account (base58)
        #[arg(long)]
        definition: String,
        /// Path to the token program binary (for its program ID)
        #[arg(long, env = "TOKEN_PROGRAM")]
        token_program: PathBuf,
    },
    /// Propose a token transfer from the multisig vault
    ProposeTransfer {
        #[arg(long)]
        create_key: String,
        /// Proposal index (must be the next index)
        #[arg(long)]
        index: u64,
        #[arg(long, env = "TOKEN_PROGRAM")]
        token_program: PathBuf,
        #[arg(long)]
        amount: u128,
        /// Recipient token-holding account (base58)
        #[arg(long)]
        recipient: String,
    },
    /// Approve a proposal anonymously (private execution; proving takes
    /// minutes with RISC0_DEV_MODE=0)
    Approve {
        #[arg(long)]
        create_key: String,
        #[arg(long)]
        index: u64,
        /// Member identity file from `pms keygen`
        #[arg(long)]
        identity: PathBuf,
    },
    /// Reject a proposal anonymously (same mechanics as approve)
    Reject {
        #[arg(long)]
        create_key: String,
        #[arg(long)]
        index: u64,
        #[arg(long)]
        identity: PathBuf,
    },
    /// Execute a fully-approved proposal (permissionless)
    Execute {
        #[arg(long)]
        create_key: String,
        #[arg(long)]
        index: u64,
        /// Target accounts for the chained call (base58); repeatable
        #[arg(long = "target")]
        targets: Vec<String>,
    },
    /// Show multisig state and (optionally) a proposal
    Status {
        #[arg(long)]
        create_key: String,
        #[arg(long)]
        index: Option<u64>,
        /// With an identity: also report whether this member has voted
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Show a token-holding account's balance
    Balance {
        /// Account (base58)
        #[arg(long)]
        account: String,
    },
    /// Platform token helpers (demo plumbing)
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Create a fungible token; writes definition+minter keys to JSON files
    Create {
        #[arg(long, env = "TOKEN_PROGRAM")]
        token_program: PathBuf,
        #[arg(long)]
        supply: u128,
        /// Output file for the definition account key
        #[arg(long)]
        definition_out: PathBuf,
        /// Output file for the minter account key
        #[arg(long)]
        minter_out: PathBuf,
    },
    /// Generate a fresh keypair account file (e.g. a transfer recipient)
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Transfer tokens between holding accounts
    Transfer {
        #[arg(long, env = "TOKEN_PROGRAM")]
        token_program: PathBuf,
        /// Sender key file
        #[arg(long)]
        from: PathBuf,
        /// Recipient: base58 account id, or a key file path (signs to
        /// initialize an uninitialized holding)
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },
}

// ── Identity / key files ──────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct IdentityFile {
    seed: String,
    salt: String,
}

fn load_identity(path: &PathBuf) -> Result<MemberIdentity> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read identity file {}", path.display()))?;
    let file: IdentityFile = serde_json::from_str(&raw).context("invalid identity file")?;
    Ok(MemberIdentity::from_seed(
        parse_hex32(&file.seed).context("identity seed")?,
        parse_hex32(&file.salt).context("identity salt")?,
    ))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    private_key: String,
}

fn load_key(path: &PathBuf) -> Result<PrivateKey> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read key file {}", path.display()))?;
    let file: KeyFile = serde_json::from_str(&raw).context("invalid key file")?;
    PrivateKey::try_new(parse_hex32(&file.private_key)?)
        .map_err(|e| anyhow!("invalid private key: {e:?}"))
}

fn write_key(path: &PathBuf, key_bytes: [u8; 32]) -> Result<AccountId> {
    let key = PrivateKey::try_new(key_bytes).map_err(|e| anyhow!("{e:?}"))?;
    let id = account_id_from_key(&key);
    std::fs::write(
        path,
        serde_json::to_string_pretty(&KeyFile {
            private_key: hex::encode(key_bytes),
        })?,
    )?;
    Ok(id)
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).context("invalid hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes, got {}", bytes.len()))
}

fn parse_account(s: &str) -> Result<AccountId> {
    s.parse()
        .map_err(|e| anyhow!("invalid account id '{s}': {e:?}"))
}

fn random32() -> [u8; 32] {
    use rand::RngCore as _;
    let mut out = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

fn token_program_id(path: &PathBuf) -> Result<nssa_core::program::ProgramId> {
    let bytecode =
        std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(Program::new(bytecode)
        .map_err(|e| anyhow!("invalid token program: {e:?}"))?
        .id())
}

// ── Main ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    // keygen needs no client/program
    if let Command::Keygen { out } = &cli.command {
        let seed = random32();
        let salt = random32();
        let identity = MemberIdentity::from_seed(seed, salt);
        std::fs::write(
            out,
            serde_json::to_string_pretty(&IdentityFile {
                seed: hex::encode(seed),
                salt: hex::encode(salt),
            })?,
        )?;
        println!("identity written to {}", out.display());
        println!("shielded account id: {}", identity.account_id());
        println!("member commitment:   {}", hex::encode(identity.commitment()));
        return Ok(());
    }

    let bytecode = std::fs::read(&cli.program)
        .with_context(|| format!("cannot read program binary {}", cli.program.display()))?;
    let mut client =
        MultisigClient::new(&cli.url, bytecode).map_err(|e| anyhow!("client: {e}"))?;
    if let Ok(secs) = std::env::var("PMS_INCLUSION_TIMEOUT_SECS") {
        client.inclusion_timeout = Duration::from_secs(secs.parse().context("PMS_INCLUSION_TIMEOUT_SECS")?);
    }
    let client = client;

    match cli.command {
        Command::Keygen { .. } => unreachable!("handled above"),

        Command::Deploy => {
            client.deploy_program().await.map_err(|e| anyhow!("{e}"))?;
            println!("program deployed (or already present)");
            println!("program id: {}", hex_program_id(&client.program_id()));
        }

        Command::Create {
            create_key,
            threshold,
            member_cms,
        } => {
            let key = match create_key {
                Some(s) => parse_hex32(&s)?,
                None => random32(),
            };
            let cms = member_cms
                .iter()
                .map(|s| parse_hex32(s))
                .collect::<Result<Vec<_>>>()?;
            client
                .create_multisig(key, threshold, cms.clone())
                .await
                .map_err(|e| anyhow!("{e}"))?;
            println!("multisig created ({}-of-{})", threshold, cms.len());
            println!("create key: {}", hex::encode(key));
            println!(
                "state PDA:  {}",
                pms_core::compute_multisig_state_pda(&client.program_id(), &key)
            );
            println!(
                "vault PDA:  {}",
                pms_core::compute_vault_pda(&client.program_id(), &key)
            );
        }

        Command::InitVault {
            create_key,
            definition,
            token_program,
        } => {
            let key = parse_hex32(&create_key)?;
            let def = parse_account(&definition)?;
            let token_id = token_program_id(&token_program)?;
            client
                .init_vault(key, def, token_id)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            println!(
                "vault initialized: {}",
                pms_core::compute_vault_pda(&client.program_id(), &key)
            );
        }

        Command::ProposeTransfer {
            create_key,
            index,
            token_program,
            amount,
            recipient,
        } => {
            let key = parse_hex32(&create_key)?;
            let token_id = token_program_id(&token_program)?;
            let recipient = parse_account(&recipient)?;
            let instruction_data =
                Program::serialize_instruction(TokenInstruction::Transfer {
                    amount_to_transfer: amount,
                })
                .map_err(|e| anyhow!("{e:?}"))?;
            client
                .propose(
                    key,
                    index,
                    token_id,
                    instruction_data,
                    2,
                    vec![pms_core::vault_pda_seed_bytes(&key)],
                    vec![0],
                )
                .await
                .map_err(|e| anyhow!("{e}"))?;
            println!("proposal #{index} created: transfer {amount} from vault to {recipient}");
            println!("(execute with: --target <vault> --target {recipient})");
        }

        Command::Approve {
            create_key,
            index,
            identity,
        } => {
            vote(&client, &create_key, index, &identity, true).await?;
        }
        Command::Reject {
            create_key,
            index,
            identity,
        } => {
            vote(&client, &create_key, index, &identity, false).await?;
        }

        Command::Execute {
            create_key,
            index,
            targets,
        } => {
            let key = parse_hex32(&create_key)?;
            let target_ids = targets
                .iter()
                .map(|s| parse_account(s))
                .collect::<Result<Vec<_>>>()?;
            client
                .execute(key, index, target_ids)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            println!("✅ proposal #{index} executed");
        }

        Command::Status {
            create_key,
            index,
            identity,
        } => {
            let key = parse_hex32(&create_key)?;
            let state = client.multisig_state(&key).await.map_err(|e| anyhow!("{e}"))?;
            println!(
                "multisig {}-of-{} · proposals so far: {}",
                state.threshold,
                state.member_count(),
                state.transaction_index
            );
            for (i, cm) in state.member_cms.iter().enumerate() {
                println!("  member {}: {}", i + 1, hex::encode(cm));
            }
            if let Some(index) = index {
                let proposal = client.proposal(&key, index).await.map_err(|e| anyhow!("{e}"))?;
                println!(
                    "proposal #{index}: {:?} · approvals: {} · rejections: {}",
                    proposal.status,
                    proposal.vote_nullifiers.len(),
                    proposal.reject_nullifiers.len()
                );
                for n in &proposal.vote_nullifiers {
                    println!("  vote nullifier: {}", hex::encode(n));
                }
                if let Some(identity) = identity {
                    let member = load_identity(&identity)?;
                    let voted = client
                        .has_voted(&key, index, &member)
                        .await
                        .map_err(|e| anyhow!("{e}"))?;
                    println!(
                        "this identity {} voted on #{index}",
                        if voted { "HAS" } else { "has NOT" }
                    );
                }
            }
        }

        Command::Balance { account } => {
            let id = parse_account(&account)?;
            let acc = client.account(id).await.map_err(|e| anyhow!("{e}"))?;
            let data: Vec<u8> = acc.data.into();
            match borsh::from_slice::<TokenHolding>(&data) {
                Ok(TokenHolding::Fungible { balance, .. }) => {
                    println!("{id}: {balance} tokens");
                }
                _ => println!("{id}: not a fungible token holding"),
            }
        }

        Command::Token(cmd) => token_command(&client, cmd).await?,
    }

    Ok(())
}

fn hex_program_id(id: &nssa_core::program::ProgramId) -> String {
    let bytes: &[u8] = bytemuck_cast(id);
    hex::encode(bytes)
}

fn bytemuck_cast(id: &nssa_core::program::ProgramId) -> &[u8] {
    // ProgramId is [u32; 8]; render as little-endian bytes (matches risc0
    // image-id hex conventions used by `cargo risczero build`).
    unsafe { std::slice::from_raw_parts(id.as_ptr().cast::<u8>(), 32) }
}

// ── Token helpers ─────────────────────────────────────────────────────────

async fn token_command(client: &MultisigClient, cmd: TokenCommand) -> Result<()> {
    match cmd {
        TokenCommand::Create {
            token_program,
            supply,
            definition_out,
            minter_out,
        } => {
            let token_id = token_program_id(&token_program)?;
            let def_bytes = random32();
            let minter_bytes = random32();
            let def_id = write_key(&definition_out, def_bytes)?;
            let minter_id = write_key(&minter_out, minter_bytes)?;
            let def_key = PrivateKey::try_new(def_bytes).unwrap();
            let minter_key = PrivateKey::try_new(minter_bytes).unwrap();

            let msg = Message::try_new(
                token_id,
                vec![def_id, minter_id],
                vec![Default::default(), Default::default()],
                TokenInstruction::NewFungibleDefinition {
                    name: "PMSDemoToken".to_string(),
                    total_supply: supply,
                },
            )
            .map_err(|e| anyhow!("{e:?}"))?;
            let ws = WitnessSet::for_message(&msg, &[&def_key, &minter_key]);
            submit_public(client, PublicTransaction::new(msg, ws)).await?;
            println!("token created · definition {def_id} · minter {minter_id} ({supply} tokens)");
        }

        TokenCommand::Keygen { out } => {
            let id = write_key(&out, random32())?;
            println!("key written to {} · account {id}", out.display());
        }

        TokenCommand::Transfer {
            token_program,
            from,
            to,
            amount,
        } => {
            let token_id = token_program_id(&token_program)?;
            let from_key = load_key(&from)?;
            let from_id = account_id_from_key(&from_key);

            // Recipient: account id (initialized holding) or key file
            // (signs to initialize its own holding on first receive).
            let (to_id, to_key) = match std::fs::metadata(&to) {
                Ok(_) => {
                    let key = load_key(&PathBuf::from(&to))?;
                    (account_id_from_key(&key), Some(key))
                }
                Err(_) => (parse_account(&to)?, None),
            };

            let from_nonce = client.account(from_id).await.map_err(|e| anyhow!("{e}"))?.nonce;
            let mut nonces = vec![from_nonce];
            if let Some(_) = &to_key {
                let to_nonce = client.account(to_id).await.map_err(|e| anyhow!("{e}"))?.nonce;
                nonces.push(to_nonce);
            }
            let msg = Message::try_new(
                token_id,
                vec![from_id, to_id],
                nonces,
                TokenInstruction::Transfer {
                    amount_to_transfer: amount,
                },
            )
            .map_err(|e| anyhow!("{e:?}"))?;
            let ws = match &to_key {
                Some(to_key) => WitnessSet::for_message(&msg, &[&from_key, to_key]),
                None => WitnessSet::for_message(&msg, &[&from_key]),
            };
            submit_public(client, PublicTransaction::new(msg, ws)).await?;
            println!("transferred {amount} from {from_id} to {to_id}");
        }
    }
    Ok(())
}


async fn vote(
    client: &MultisigClient,
    create_key: &str,
    index: u64,
    identity: &PathBuf,
    approve: bool,
) -> Result<()> {
    let key = parse_hex32(create_key)?;
    let member = load_identity(identity)?;
    println!(
        "{} proposal #{index} privately as an anonymous member...",
        if approve { "approving" } else { "rejecting" }
    );
    println!("(proving locally — takes ~2 minutes with RISC0_DEV_MODE=0)");
    let result = if approve {
        client.approve_private(key, index, &member, None).await
    } else {
        client.reject_private(key, index, &member, None).await
    };
    match result {
        Ok(hash) => {
            println!("✅ vote recorded — tx {hash:?}");
            println!("   the transaction carries no signature, no account id, no salt");
            Ok(())
        }
        Err(e) => bail!("vote failed: {e}"),
    }
}

async fn submit_public(client: &MultisigClient, tx: PublicTransaction) -> Result<()> {
    let hash = client
        .sequencer()
        .send_transaction(NSSATransaction::Public(tx))
        .await
        .map_err(|e| anyhow!("submit: {e}"))?;
    let start = std::time::Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Ok(Some(_)) = client.sequencer().get_transaction(hash).await {
            return Ok(());
        }
        if start.elapsed() > client.inclusion_timeout {
            bail!("tx {hash:?} not included after {:?}", client.inclusion_timeout);
        }
    }
}
