# Evidence

## Local end-to-end demo with real proofs (`RISC0_DEV_MODE=0`)

`local-demo-run.log` is the full output of `scripts/demo.sh` run against a
fresh local LEZ standalone sequencer (logos-execution-zone @ v0.1.2), with
**real proofs on both sides** — the client proves each approval and the
sequencer verifies the real receipt (it too runs `RISC0_DEV_MODE=0`).

What the run demonstrates, end to end:

1. The private multisig program deploys (program id =
   `4034ba058ee8b799fe0f5cf449b503a7a0d2acb1554144f81bf9cd942a171c2b`, the
   reproducible Docker image id).
2. A 2-of-3 multisig is created from **salted member commitments** — the
   chain stores three opaque 32-byte hashes, no member account ids.
3. The vault is initialized (via an authorized ChainedCall to the token
   program) and funded with 500 tokens.
4. A transfer proposal is created permissionlessly (unsigned tx).
5. **Two members approve anonymously**, each as a privacy-preserving
   transaction. Measured proving wall-clock on this laptop (Apple Silicon):

   | Approval | Proof generation | Total `pms approve` wall-clock |
   |----------|------------------|--------------------------------|
   | Member 1 | 99.30 s          | 1m47s                          |
   | Member 2 | 94.04 s          | 1m44s                          |

6. **A double-vote attempt is rejected locally** during proving (`PMS_E012`)
   — nothing is submitted.
7. The proposal is executed permissionlessly (unsigned tx, no member
   involved); the ChainedCall moves 100 tokens vault → recipient.
8. Final state: vault 500 → 400, recipient 1 → 101, proposal `Executed`,
   with **two unlinkable vote nullifiers** and **zero member signatures**
   recorded on chain.

Reproduce:

```bash
LEZ_DIR=<path-to-logos-execution-zone-v0.1.2> ./scripts/demo.sh
```

## Testnet

The program and a 2-of-3 instance were also deployed to the public testnet
(`https://testnet.lez.logos.co`) and driven through `propose`; completing the
private approvals there is in progress (each approval is a ~2-minute proof and
testnet inclusion latency required a raised `PMS_INCLUSION_TIMEOUT_SECS`).
The local run above is the authoritative real-proof evidence; the testnet run
is supplementary.

- program id: `4034ba058ee8b799fe0f5cf449b503a7a0d2acb1554144f81bf9cd942a171c2b`
- explorer: https://explorer.testnet.lez.logos.co/
