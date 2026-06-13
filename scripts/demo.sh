#!/usr/bin/env bash
# ============================================================================
# Private M-of-N Multisig — end-to-end demo with REAL proofs (RISC0_DEV_MODE=0)
#
# Runs the full lifecycle against a real local LEZ standalone sequencer:
#   deploy → token setup → 2-of-3 multisig from salted member commitments →
#   vault init+funding → proposal → two ANONYMOUS approvals (each proven
#   locally inside the privacy circuit, ~2 min on a laptop) → a double-vote
#   attempt that fails locally → permissionless execute → balance checks.
#
# Prerequisites:
#   - Rust toolchain + rzup (r0vm 3.0.5)
#   - Docker (for the reproducible guest build, first run only)
#   - logos-execution-zone checked out at tag v0.1.2 (LEZ_DIR below)
#
# Usage:
#   LEZ_DIR=~/Desktop/lez-v012 ./scripts/demo.sh
# ============================================================================
set -euo pipefail

LEZ_DIR="${LEZ_DIR:?Set LEZ_DIR to a logos-execution-zone checkout at v0.1.2}"
SEQ_PORT=3040
export SEQUENCER_URL="http://127.0.0.1:${SEQ_PORT}"
export RISC0_DEV_MODE="${RISC0_DEV_MODE:-0}"   # real proofs unless overridden

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
export PMS_PROGRAM="$REPO_ROOT/target/riscv32im-risc0-zkvm-elf/docker/private_multisig.bin"
export TOKEN_PROGRAM="$LEZ_DIR/artifacts/program_methods/token.bin"
RUN_DIR="$REPO_ROOT/demo-run"
PMS="$REPO_ROOT/target/release/pms"

bold()  { printf "\033[1m%s\033[0m\n" "$*"; }
step()  { printf "\n\033[1;34m═══ %s ═══\033[0m\n" "$*"; }

step "Preflight"
[ -f "$TOKEN_PROGRAM" ] || { echo "token program not found at $TOKEN_PROGRAM"; exit 1; }
if [ ! -f "$PMS_PROGRAM" ]; then
  bold "Guest binary missing — building reproducibly in Docker (one-time)..."
  cargo risczero build --manifest-path methods/guest/Cargo.toml
fi
if [ ! -x "$PMS" ]; then
  bold "Building the pms CLI..."
  cargo build --release -p pms-cli
fi
echo "RISC0_DEV_MODE=$RISC0_DEV_MODE (0 = real proofs)"

step "Starting a fresh standalone sequencer"
pkill -f "sequencer_service" 2>/dev/null || true
sleep 1
SEQ_HOME="$(mktemp -d /tmp/pms-demo-seq.XXXXXX)"
( cd "$SEQ_HOME" && RUST_LOG=info RISC0_DEV_MODE="$RISC0_DEV_MODE" \
    "$LEZ_DIR/target/debug/sequencer_service" \
    "$LEZ_DIR/sequencer/service/configs/debug/sequencer_config.json" \
    > "$SEQ_HOME/seq.log" 2>&1 ) &
SEQ_PID=$!
trap 'kill $SEQ_PID 2>/dev/null || true' EXIT
for i in $(seq 1 30); do
  if curl -s -m 2 -X POST "$SEQUENCER_URL" -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","id":1,"method":"checkHealth","params":[]}' 2>/dev/null | grep -q result; then
    echo "sequencer healthy (pid $SEQ_PID, home $SEQ_HOME)"; break
  fi
  [ "$i" = 30 ] && { echo "sequencer did not come up"; exit 1; }
  sleep 2
done

rm -rf "$RUN_DIR"; mkdir -p "$RUN_DIR"

step "Deploying the private multisig program"
"$PMS" deploy

step "Token setup (definition + 1,000,000 to the minter)"
"$PMS" token create --supply 1000000 \
    --definition-out "$RUN_DIR/def.json" --minter-out "$RUN_DIR/minter.json" | tee "$RUN_DIR/token.out"
DEF_ID=$(grep -o 'definition [^ ]*' "$RUN_DIR/token.out" | awk '{print $2}')

step "Three members generate identities LOCALLY (nothing goes on-chain)"
for i in 1 2 3; do
  "$PMS" keygen --out "$RUN_DIR/member$i.json" | tee "$RUN_DIR/member$i.out"
done
CM1=$(grep 'member commitment' "$RUN_DIR/member1.out" | awk '{print $3}')
CM2=$(grep 'member commitment' "$RUN_DIR/member2.out" | awk '{print $3}')
CM3=$(grep 'member commitment' "$RUN_DIR/member3.out" | awk '{print $3}')

step "Create the 2-of-3 multisig — the chain sees only 3 opaque commitments"
CREATE_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
"$PMS" create --create-key "$CREATE_KEY" --threshold 2 \
    --member-cm "$CM1" --member-cm "$CM2" --member-cm "$CM3" | tee "$RUN_DIR/create.out"
VAULT=$(grep 'vault PDA' "$RUN_DIR/create.out" | awk '{print $3}')

step "Initialize + fund the vault (500 tokens)"
"$PMS" init-vault --create-key "$CREATE_KEY" --definition "$DEF_ID"
"$PMS" token transfer --from "$RUN_DIR/minter.json" --to "$VAULT" --amount 500
"$PMS" balance --account "$VAULT"

step "Create the payout recipient"
"$PMS" token keygen --out "$RUN_DIR/recipient.json" | tee "$RUN_DIR/recipient.out"
RECIPIENT=$(grep -o 'account [^ ]*' "$RUN_DIR/recipient.out" | awk '{print $2}')
"$PMS" token transfer --from "$RUN_DIR/minter.json" --to "$RUN_DIR/recipient.json" --amount 1

step "Propose: pay 100 tokens from the vault to $RECIPIENT (permissionless, unsigned)"
"$PMS" propose-transfer --create-key "$CREATE_KEY" --index 1 \
    --amount 100 --recipient "$RECIPIENT"
"$PMS" status --create-key "$CREATE_KEY" --index 1

step "Member 1 approves ANONYMOUSLY (real proof — this is the ~2 minute step)"
time "$PMS" approve --create-key "$CREATE_KEY" --index 1 --identity "$RUN_DIR/member1.json"
"$PMS" status --create-key "$CREATE_KEY" --index 1 --identity "$RUN_DIR/member1.json"

step "Member 1 tries to vote AGAIN — rejected locally, nothing submitted"
if "$PMS" approve --create-key "$CREATE_KEY" --index 1 --identity "$RUN_DIR/member1.json"; then
  echo "ERROR: double vote should have failed"; exit 1
else
  bold "double vote rejected (PMS_E012: duplicate vote nullifier)"
fi

step "Member 2 approves ANONYMOUSLY (reaches 2-of-3)"
time "$PMS" approve --create-key "$CREATE_KEY" --index 1 --identity "$RUN_DIR/member2.json"
"$PMS" status --create-key "$CREATE_KEY" --index 1

step "Execute (permissionless, unsigned — involves no member at all)"
"$PMS" execute --create-key "$CREATE_KEY" --index 1 \
    --target "$VAULT" --target "$RECIPIENT"

step "Final balances"
"$PMS" balance --account "$VAULT"
"$PMS" balance --account "$RECIPIENT"
"$PMS" status --create-key "$CREATE_KEY" --index 1

bold ""
bold "🎉 Demo complete: 2-of-3 threshold reached and executed."
bold "   On-chain: 3 opaque member commitments, 2 unlinkable vote nullifiers,"
bold "   zero member signatures, zero member account IDs."
echo "sequencer log: $SEQ_HOME/seq.log · artifacts: $RUN_DIR/"
