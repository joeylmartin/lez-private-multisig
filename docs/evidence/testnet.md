# Testnet lifecycle evidence

A full 2-of-3 private multisig lifecycle executed on the **public LEZ testnet**
(`https://testnet.lez.logos.co`, explorer `https://explorer.testnet.lez.logos.co/`)
on 2026-06-13, with **real proofs** (`RISC0_DEV_MODE=0`). Raw run output:
[`testnet-lifecycle.log`](testnet-lifecycle.log).

## Program & instance

| | |
|---|---|
| Program ID (Risc0 image ID) | `4034ba058ee8b799fe0f5cf449b503a7a0d2acb1554144f81bf9cd942a171c2b` |
| Multisig create key | `0aa9bd1576e7572bd3c74fe09aa91335c04a259d0c590bb0c1ce00805e9bc8d7` |
| Multisig state PDA | `FSrcLG5gyyGDjzjDBzHnag3TPmF7yCpR162W5HKEQU3Q` |
| Vault PDA | `BSbNCQcJLBRiargLw9rud5xZZcHdpisVsvjdYoRsTob4` |
| Recipient | `AxqhyMyBxGLg4MEaCrgaABLD8vCFnm1H6nRS3tRJXArA` |
| Threshold | 2-of-3 |

The on-chain member list is three opaque salted commitments
(`b1d7a10c…`, `093a7e57…`, `da6a4ecb…`) — no member account IDs.

## The lifecycle

1. **Member 1 approves** — privacy-preserving tx
   `d23c3c2320a4afc2c6dc937bceb6bcc89c0d2ca1cd6d786256a9278af78dd80a`
   (real proof generated in **98.3 s**).
2. **Member 2 approves** — privacy-preserving tx
   `71fb9598c5a182a41d42afa6ced4bdb838de29271cbbefc5731baa72fab3c512`
   (real proof generated in **94.6 s**). Threshold reached.
3. **Execute** — proposal `#1` → `Executed`; the stored ChainedCall moved
   100 tokens from the vault to the recipient.

Final on-chain state: proposal **Executed**, two unlinkable vote nullifiers
(`b7093b4c…`, `1243e487…`), **vault 500 → 400**, **recipient 1 → 101**.

## Privacy verified against the on-chain bytes

Decoding the two approval transactions fetched back from the testnet with the
real `NSSATransaction` types (`cargo run -p private-multisig-e2e --example
verify_testnet_tx`):

```
member1 approval: PrivacyPreserving | signatures=0 | public_accounts=2 | commitments=1 | nullifiers=1
member2 approval: PrivacyPreserving | signatures=0 | public_accounts=2 | commitments=1 | nullifiers=1
PASS: both approvals are unsigned PrivacyPreserving transactions on testnet
```

A byte-scan of the raw 227 KB member-1 transaction confirms it contains
**neither the member's salt nor the member's shielded account ID**
(`8xMfZ2jK42b67MCCReihJLkgcWVLVjD7ogGkuYg2VV5v`). The only things the chain
records for an approval are the two public account IDs (multisig state +
proposal), one platform commitment, and one opaque vote nullifier — nothing
that links to a member.

## Reproduce the verification

```bash
# Re-decode the on-chain approval transactions and re-assert the properties:
cargo run -p private-multisig-e2e --example verify_testnet_tx

# Re-query the executed proposal + balances:
SEQUENCER_URL=https://testnet.lez.logos.co \
  pms status  --create-key 0aa9bd1576e7572bd3c74fe09aa91335c04a259d0c590bb0c1ce00805e9bc8d7 --index 1
SEQUENCER_URL=https://testnet.lez.logos.co \
  pms balance --account BSbNCQcJLBRiargLw9rud5xZZcHdpisVsvjdYoRsTob4
```
