//! Decode the two on-chain testnet approval transactions with the real
//! NSSATransaction types and assert the privacy properties: each is a
//! PrivacyPreserving tx carrying ZERO signatures.
use common::transaction::NSSATransaction;
use sequencer_service_rpc::{RpcClient as _, SequencerClientBuilder};

#[tokio::main]
async fn main() {
    let url = "https://testnet.lez.logos.co".to_string();
    let client = SequencerClientBuilder::default().build(url).unwrap();
    let hashes = [
        ("member1 approval", "d23c3c2320a4afc2c6dc937bceb6bcc89c0d2ca1cd6d786256a9278af78dd80a"),
        ("member2 approval", "71fb9598c5a182a41d42afa6ced4bdb838de29271cbbefc5731baa72fab3c512"),
    ];
    for (label, h) in hashes {
        let bytes = hex::decode(h).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let tx = client.get_transaction(common::HashType(arr)).await.unwrap().unwrap();
        match tx {
            NSSATransaction::PrivacyPreserving(ptx) => {
                let nsigs = ptx.witness_set().signatures_and_public_keys().len();
                let npub = ptx.message().public_account_ids.len();
                println!("{label}: PrivacyPreserving | signatures={nsigs} | public_accounts={npub} | commitments={} | nullifiers={}",
                    ptx.message().new_commitments.len(), ptx.message().new_nullifiers.len());
                assert_eq!(nsigs, 0, "PRIVACY VIOLATION: tx carries signatures");
            }
            other => panic!("{label}: expected PrivacyPreserving, got {other:?}"),
        }
    }
    println!("\nPASS: both approvals are unsigned PrivacyPreserving transactions on testnet");
}
