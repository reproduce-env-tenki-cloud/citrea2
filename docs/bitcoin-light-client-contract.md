# Bitcoin Light Client Contract (`BitcoinLightClient.sol`)

This document provides an overview of the `BitcoinLightClient.sol` smart contract, a core component of the Citrea protocol. It functions as an on-chain light client for the Bitcoin network, enabling other smart contracts on Citrea to verify Bitcoin transactions.

## Overview

`BitcoinLightClient.sol` is a system contract deployed on Citrea. Its primary responsibility is to maintain a record of Bitcoin block headers and provide functions to verify the inclusion of transactions within those blocks. This is crucial for the security and functionality of the Citrea-Bitcoin bridge, as it allows the bridge contract to confirm that deposits have been finalized on the Bitcoin network.

The Bitcoin Light Client contract's `setBlockInfo` function is called by the system caller (or system signer as described in [eth-mainnet-evm-differences.md](./eth-mainnet-evm-differences.md)). Even though these system transactions are put into L2 blocks by the sequencer, all Citrea actors verify the updates:
- Citrea full nodes verify that the updates to the system contract is valid by cross-checking the provided hashes, WTXID merkle roots and the coinbase transaction depth with their Bitcoin full nodes. 
- The batch proof circuit verifies the updates to the Bitcoin Light Client contract by providing "short header proofs" as inputs. Short header proofs are proofs that attest to a certain Bitcoin block height, hash, and coinbase transaction. This is used to verify that the update to the contract is correct.
- The Light Client Proof circuit, for any given batch proof, checks that the last L1 hash on the Bitcoin Light Client contract belongs to the Bitcoin header chain that is known by the circuit.

Due to these verifications, incorrect updates to the Bitcoin Light Client contract is rejected both on the L2 and on the L1. For further information on this topic, please see [batch-proof-circuit.md](./batch-proof-circuit.md#short-header-proof-verification) and [light-client-circuit.md](./light-client-circuit.md#processing-complete-proofs), `crates/short-header-proof-provider` and `crates/bitcoin-da/src/spec/short_proof.rs`

## Core Concepts

### Block Header Storage

The contract stores essential information for each Bitcoin block relayed to it:
-   **Block Hash**: The unique identifier of a Bitcoin block.
-   **Witness Root**: The root of the wtxids for a block.
-   **Coinbase Depth**: The depth of the coinbase transaction in the block's Merkle tree, which is necessary to avoid the attack explained in [this blog](https://bitslog.com/2018/06/09/leaf-node-weakness-in-bitcoin-merkle-tree-design/#:~:text=Another%20way%20to,equal%20tree%20depths).

### Roles

-   **System Caller**: A special, hardcoded address (`0xdeaD...`) authorized to add new Bitcoin block information to the contract via the `setBlockInfo` function.

## Key Functions

### State Updates

-   **`initializeBlockNumber(uint256 _blockNumber)`**: A one-time function called at genesis to set the starting Bitcoin block number.
-   **`setBlockInfo(bytes32 _blockHash, bytes32 _witnessRoot, uint256 _coinbaseDepth)`**: Called by the `SYSTEM_CALLER` to add data for a new Bitcoin block. 

### Verification

-   **`verifyInclusion(bytes32 _blockHash, bytes32 _wtxId, ...)`**: Verifies that a SegWit transaction (identified by its `wtxId`) is included in a specific block's witness Merkle tree. This is the primary function used by the bridge to confirm deposits.
-   **`verifyInclusionByTxId(uint256 _blockNumber, bytes32 _txId, ...)`**: Verifies the inclusion of a transaction in a block's transaction Merkle tree.
