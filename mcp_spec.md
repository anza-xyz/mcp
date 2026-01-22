# MCP (Multiple Concurrent Proposers) Protocol Specification

**Version:** 1.0-draft
**Status:** Draft (structures defined, integration incomplete)

## Table of Contents

1. [Overview](#1-overview)
2. [Protocol Constants](#2-protocol-constants)
3. [Roles and Schedules](#3-roles-and-schedules)
4. [Data Structures](#4-data-structures)
5. [Shred Format](#5-shred-format)
6. [Transaction Format](#6-transaction-format)
7. [Proposer Operations](#7-proposer-operations)
8. [Relay Operations](#8-relay-operations)
9. [Consensus Leader Operations](#9-consensus-leader-operations)
10. [Validator Operations](#10-validator-operations)
11. [Replay Operations](#11-replay-operations)
12. [Fee Mechanics](#12-fee-mechanics)
13. [Wire Formats](#13-wire-formats)
14. [Storage Schema](#14-storage-schema)
15. [Security Considerations](#15-security-considerations)

---

## 1. Overview

MCP (Multiple Concurrent Proposers) enables parallel transaction submission by multiple proposers within a single slot. The protocol separates transaction ordering from execution, with proposers generating shreds containing transaction batches that are verified by relays, aggregated by a consensus leader, and executed deterministically during replay.

### 1.1 Protocol Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────┐     ┌────────────┐
│  Proposers  │────▶│   Relays    │────▶│ Consensus Leader│────▶│ Validators │
│   (0-15)    │     │  (0-199)    │     │                 │     │            │
└─────────────┘     └─────────────┘     └─────────────────┘     └────────────┘
      │                   │                      │                     │
      │ Distribute        │ Verify &            │ Aggregate           │ Validate,
      │ Shreds            │ Attest              │ & Broadcast         │ Vote, Replay
      ▼                   ▼                      ▼                     ▼
```

### 1.2 Key Properties

- **Parallel Submission:** 16 proposers submit transaction batches concurrently
- **Data Availability:** 200 relays verify and attest to shred availability
- **Deterministic Ordering:** Transactions ordered by (proposer_id, position_in_batch)
- **Fee Separation:** Inclusion fees charged regardless of execution outcome
- **Bankless Leaders:** Proposers record without executing; execution deferred to replay

---

## 2. Protocol Constants

All constants are derived from genesis configuration and MUST be identical across all nodes.

### 2.1 Core Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `NUM_PROPOSERS` | 16 | Number of proposers per slot |
| `NUM_RELAYS` | 200 | Number of relays per slot |
| `ATTESTATION_THRESHOLD` | 60% | Stake required for valid attestation |
| `INCLUSION_THRESHOLD` | 40% | Stake required for proposer inclusion |
| `RECONSTRUCTION_THRESHOLD` | 20% | Stake required for batch reconstruction |
| `CONSENSUS_PAYLOAD_PROPOSER_ID` | 0xFF | Reserved ID for consensus shreds |

### 2.2 FEC (Forward Error Correction) Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MCP_DATA_SHREDS_PER_FEC_BLOCK` | 40 | Data shreds per FEC block |
| `MCP_CODING_SHREDS_PER_FEC_BLOCK` | 160 | Coding shreds per FEC block |
| `MCP_SHREDS_PER_FEC_BLOCK` | 200 | Total shreds per FEC block |

The FEC rate (40:160) provides 4:1 redundancy, allowing reconstruction from any 40 of 200 shreds (20%).

### 2.3 Merkle Proof Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `SIZE_OF_MERKLE_ROOT` | 32 bytes | Hash size |
| `SIZE_OF_MERKLE_PROOF_ENTRY` | 20 bytes | Truncated hash for proofs |
| `PROOF_ENTRIES_FOR_MCP_BATCH` | 8 | ceil(log2(200)) |

---

## 3. Roles and Schedules

### 3.1 Role Definitions

**Proposer:** Stake-weighted validator that creates transaction batches and distributes shreds to relays. Valid `proposer_id` range: [0, 15].

**Relay:** Stake-weighted validator that receives shreds from proposers, verifies commitments, and submits attestations to the consensus leader. Valid `relay_id` range: [0, 199].

**Consensus Leader:** The slot leader who aggregates relay attestations and broadcasts the consensus block.

### 3.2 Schedule Generation

Schedules are deterministically generated per epoch using stake-weighted selection **without replacement** to ensure unique validators per slot:

```
seed = hash(epoch_number || role_magic)
rng = ChaCha20Rng::from_seed(seed)
schedule = stake_weighted_sample_without_replacement(validators, stakes, rng, pool_size)
```

**Proposer Schedule:** 16 unique validators selected stake-weighted, rotating one position per slot.

**Relay Schedule:** 200 unique validators selected stake-weighted, rotating one position per slot.

**Note:** The selection algorithm MUST ensure no duplicate validators within a single slot's proposer or relay set.

**Leader Schedule:** Unchanged from standard Solana; uses `NUM_CONSECUTIVE_LEADER_SLOTS` repetition.

### 3.3 Schedule Lookup

```rust
fn get_proposers_for_slot(slot: u64, epoch_stakes: &EpochStakes) -> [Pubkey; 16]
fn get_relays_for_slot(slot: u64, epoch_stakes: &EpochStakes) -> [Pubkey; 200]
fn get_leader_for_slot(slot: u64, epoch_stakes: &EpochStakes) -> Pubkey
```

---

## 4. Data Structures

### 4.1 McpConfig

Runtime configuration for MCP parameters:

```rust
struct McpConfig {
    num_proposers: u8,           // 16
    num_relays: u16,             // 200
    attestation_threshold: Fraction,    // 60%
    inclusion_threshold: Fraction,      // 40%
    reconstruction_threshold: Fraction, // 20%
}
```

### 4.2 AttestationEntry

Single entry in a relay attestation:

```rust
struct AttestationEntry {
    proposer_id: u8,      // 1 byte
    merkle_root: Hash,    // 32 bytes
}
```

### 4.3 RelayAttestation

Complete relay attestation for a slot:

```rust
struct RelayAttestation {
    version: u8,                    // 1 byte
    slot: u64,                      // 8 bytes
    relay_id: u16,                  // 2 bytes
    entries: Vec<AttestationEntry>, // Variable (sorted by proposer_id)
    relay_signature: Signature,     // 64 bytes
}
```

### 4.4 AggregateAttestation

Consensus leader's aggregated attestations:

```rust
struct AggregateAttestation {
    slot: u64,
    entries: Vec<AggregatedProposerEntry>,
    block_id: Hash,  // hash(canonical_aggregate)
}

struct AggregatedProposerEntry {
    proposer_id: u8,
    merkle_root: Hash,
    relay_ids: Vec<u16>,
    attesting_stake: u64,
}
```

### 4.5 ConsensusPayload

Consensus block payload:

```rust
struct ConsensusPayload {
    version: u8,                    // 1 byte
    slot: u64,                      // 8 bytes
    leader_id: Pubkey,              // 32 bytes
    aggregate: SlotAggregate,       // Variable
    consensus_meta: ConsensusMeta,  // Variable
    delayed_bankhash: Hash,         // 32 bytes
    leader_signature: Signature,    // 64 bytes
}
```

---

## 5. Shred Format

### 5.1 Common Header (MCP Extended)

Total size: **84 bytes** (legacy: 83 bytes without proposer_id)

```
┌──────────────────┬───────────────────────────────────────────────┐
│ Offset (bytes)   │ Field                                         │
├──────────────────┼───────────────────────────────────────────────┤
│ 0-63             │ signature (64 bytes)                          │
│ 64               │ shred_variant (1 byte)                        │
│ 65-72            │ slot (8 bytes, little-endian)                 │
│ 73-76            │ index (4 bytes, little-endian)                │
│ 77-78            │ version (2 bytes, little-endian)              │
│ 79               │ proposer_id (1 byte) ◀── NEW IN MCP           │
│ 80-83            │ fec_set_index (4 bytes, little-endian)        │
└──────────────────┴───────────────────────────────────────────────┘
```

### 5.2 Proposer ID Values

| Value | Meaning |
|-------|---------|
| 0x00 - 0x0F | Standard proposers (0-15) |
| 0x10 - 0xFE | Reserved (invalid) |
| 0xFF | Consensus payload shreds |

### 5.3 Merkle Tree

- Leaf hash: `SHA256(0x00 || "SOLANA_MERKLE_SHREDS_LEAF" || shred_data)`
- Node hash: `SHA256(0x01 || "SOLANA_MERKLE_SHREDS_NODE" || left[0:20] || right[0:20])`
- Proof entries are 20-byte truncated hashes
- MCP batches use 8 proof entries (for 200 shreds)

---

## 6. Transaction Format

### 6.1 MCP Transaction Config

Extended transaction configuration with MCP-specific fees. Fields are serialized in mask order (variable-length encoding).

```
┌──────────────────┬───────────────────────────────────────────────┐
│ Field            │ Size (if present)                             │
├──────────────────┼───────────────────────────────────────────────┤
│ config_mask      │ 1 byte (always present)                       │
│ inclusion_fee    │ 8 bytes, little-endian (if bit 0x01 set)      │
│ ordering_fee     │ 8 bytes, little-endian (if bit 0x02 set)      │
│ target_proposer  │ 32 bytes, pubkey (if bit 0x04 set)            │
└──────────────────┴───────────────────────────────────────────────┘
```

**Note:** Offsets are variable depending on which bits are set. Only present fields are serialized, in the order shown.

### 6.2 Config Mask Bits

| Bit | Field |
|-----|-------|
| 0x01 | inclusion_fee present |
| 0x02 | ordering_fee present |
| 0x04 | target_proposer present |

### 6.3 Fee Types

All fees are charged upfront in the fee phase before execution. This ensures proposers are compensated even if execution fails.

| Fee Type | Description | Recipient |
|----------|-------------|-----------|
| signature_fee | Standard signature verification | Validator |
| prioritization_fee | Execution priority | Validator |
| inclusion_fee | Data availability compensation | Proposer |
| ordering_fee | Priority within proposer batch | Proposer |

---

## 7. Proposer Operations

### 7.1 Batch Creation (Bankless)

Proposers create transaction batches without executing:

1. Receive transactions from mempool
2. Validate signatures (no state execution)
3. Order by ordering_fee descending, then by transaction hash (for determinism)
4. Serialize batch:
   ```
   | slot (8) | proposer_id (1) | tx_count (4) | [tx_len (4) | tx_data]... |
   ```

### 7.2 Shred Encoding

1. Serialize batch to bytes
2. Apply Reed-Solomon encoding (40 data + 160 coding)
3. Build Merkle tree over all 200 shreds
4. Sign commitment: `sign(slot || proposer_id || merkle_root)`

### 7.3 Distribution to Relays

**Relay Assignment:** Each relay receives one shred per FEC block. The mapping is:

```
relay_id = shred_index % NUM_RELAYS
```

Where `shred_index` is in range [0, 199] for MCP FEC blocks.

**Message Format:** Send to each relay via unicast:

```
┌──────────────────────────────────────────────────────────────────┐
│ ProposerShredMessage                                             │
├──────────────────┬───────────────────────────────────────────────┤
│ slot             │ 8 bytes, little-endian                        │
│ proposer_id      │ 1 byte                                        │
│ commitment       │ 32 bytes (merkle root)                        │
│ shred_data_len   │ 4 bytes, little-endian                        │
│ shred_data       │ Variable                                      │
│ witness_len      │ 2 bytes, little-endian                        │
│ witness          │ Variable (merkle proof, max 8 entries)        │
│ proposer_sig     │ 64 bytes                                      │
└──────────────────┴───────────────────────────────────────────────┘
```

---

## 8. Relay Operations

### 8.1 Shred Verification

For each received shred message:

1. Validate `proposer_id` in range [0, 15]
2. Verify proposer signature: `verify(proposer_pubkey, slot || proposer_id || commitment, sig)`
3. Compute leaf hash: `SHA256(MERKLE_HASH_PREFIX_LEAF || shred_data)`
4. Verify merkle proof against commitment
5. Check for duplicates

### 8.2 Shred Storage

Store verified shreds by composite key: `(slot, proposer_id, shred_index)`

### 8.3 Attestation Generation

At relay deadline (slot end):

1. Collect verified (proposer_id, merkle_root) pairs
2. Sort entries by proposer_id ascending
3. Serialize attestation (see Wire Formats)
4. Sign: `sign(version || slot || relay_id || entries_len || entries)`
5. Submit to consensus leader

---

## 9. Consensus Leader Operations

### 9.1 Attestation Aggregation

For each slot:

1. Collect relay attestations
2. Verify each relay signature
3. Detect equivocations (same relay, same proposer, different merkle_root)
4. Drop equivocating relays
5. For each proposer, select merkle_root with highest attesting stake
6. Include proposer if `attesting_stake >= ATTESTATION_THRESHOLD * total_stake`

### 9.2 Block ID Computation

```rust
block_id = SHA256(canonical_aggregate_bytes)
```

**Canonical Aggregate Serialization:**

```
| version (1) | slot (8) | leader_id (32) | aggregate | consensus_meta | delayed_bankhash (32) |
```

Where `aggregate` is serialized as:
```
| num_proposers (1) | [proposer_id (1) | merkle_root (32) | relay_count (2) | stake (8)]... | total_stake (8) |
```

And `consensus_meta` is:
```
| timestamp (8) | parent_block_id (32) | epoch (8) |
```

All multi-byte integers are little-endian. The signature is NOT included in block_id computation.

### 9.3 Consensus Payload Broadcast

1. Construct ConsensusPayload
2. Sign payload
3. Encode as shreds with `proposer_id = 0xFF`
4. Broadcast via turbine

---

## 10. Validator Operations

### 10.1 Block Validation

Before voting, validators MUST verify:

1. **Leader Signature:** Consensus payload signed by expected slot leader
2. **Delayed Bankhash:** Matches expected value from previous slot
3. **Availability Threshold:** For each proposer in aggregate:
   - `received_shreds >= RECONSTRUCTION_THRESHOLD * NUM_RELAYS`
   - (40 of 200 shreds minimum)

### 10.2 Voting

If validation passes:

1. Extract `block_id` from consensus payload
2. Create vote: `(slot, block_id, voter_pubkey)`
3. Sign and broadcast vote

If validation fails or pending:

- Do NOT vote
- Continue collecting shreds
- Re-evaluate when threshold met

---

## 11. Replay Operations

### 11.1 Message Reconstruction

For each proposer in the aggregate:

1. Wait for `K = RECONSTRUCTION_THRESHOLD * NUM_RELAYS` shreds (40)
2. Apply Reed-Solomon decoding to recover data shreds
3. Re-encode and verify merkle root matches commitment
4. If mismatch: drop proposer entirely

### 11.2 Transaction Ordering

Deterministic ordering across all proposers:

```
for proposer_id in 0..NUM_PROPOSERS:
    for tx in proposer_batch[proposer_id]:
        ordered_output.append(tx)
```

All validators MUST produce identical ordered output.

### 11.3 Two-Phase Execution

**Phase 1: Fee Deduction**
- Load fee payer accounts
- Deduct ALL fees (signature + prioritization + inclusion + ordering)
- Fees charged even if execution will fail

**Phase 2: State Transitions**
- Execute transactions in order
- Do NOT re-charge fees
- Record success/failure status

### 11.4 Empty Slots

When consensus produces null result (⊥):

1. Output empty execution for slot
2. Store in execution output column family
3. Finalize slot

---

## 12. Fee Mechanics

### 12.1 Fee Payer Requirements

To prevent DA fee payer attacks, fee payers MUST have sufficient balance for worst-case inclusion across all proposers:

| Account Type | Required Balance |
|--------------|-----------------|
| System Account | `NUM_PROPOSERS * total_fee` |
| Nonce Account | `NUM_PROPOSERS * total_fee + rent_minimum` |

Where `total_fee = signature_fee + prioritization_fee + inclusion_fee + ordering_fee`

**Rationale:** A transaction may be included by multiple proposers (up to all 16) in the same slot. The fee payer must be able to cover fees in all cases to prevent griefing attacks where users submit to multiple proposers with insufficient funds.

### 12.2 Fee Charging and Distribution

**Charging:** All fees are deducted from the fee payer in the fee phase, before execution. This happens regardless of whether execution succeeds or fails.

**Distribution:**

| Fee Type | Recipient | Notes |
|----------|-----------|-------|
| signature_fee | Validator rewards pool | Distributed on slot finalization |
| prioritization_fee | Validator rewards pool | Distributed on slot finalization |
| inclusion_fee | Proposer who included tx | Distributed on slot finalization |
| ordering_fee | Proposer who included tx | Distributed on slot finalization |

### 12.3 Per-Slot Tracking

Track cumulative commitments per fee payer per slot to prevent over-commitment when multiple proposers include the same transaction.

---

## 13. Wire Formats

### 13.1 Relay Attestation (v1)

```
┌─────────────────────────────────────────────────────────────────┐
│ Field              │ Size     │ Description                     │
├────────────────────┼──────────┼─────────────────────────────────┤
│ version            │ 1 byte   │ 0x01                            │
│ slot               │ 8 bytes  │ Little-endian u64               │
│ relay_id           │ 2 bytes  │ Little-endian u16               │
│ entries_len        │ 2 bytes  │ Little-endian u16, max 16       │
│ entries            │ 33*N     │ N entries, each 33 bytes        │
│ relay_signature    │ 64 bytes │ Ed25519 signature               │
└────────────────────┴──────────┴─────────────────────────────────┘

Entry format:
│ proposer_id        │ 1 byte   │                                 │
│ merkle_root        │ 32 bytes │                                 │
```

**Signature covers:** `version || slot || relay_id || entries_len || entries`

**Entries MUST be sorted by proposer_id ascending.**

### 13.2 Consensus Payload

```
┌─────────────────────────────────────────────────────────────────┐
│ Field              │ Size     │ Description                     │
├────────────────────┼──────────┼─────────────────────────────────┤
│ version            │ 1 byte   │ 0x01                            │
│ slot               │ 8 bytes  │ Little-endian u64               │
│ leader_id          │ 32 bytes │ Leader pubkey                   │
│ aggregate          │ Variable │ Serialized aggregate            │
│ consensus_meta     │ Variable │ Timestamp, parent_id, epoch     │
│ delayed_bankhash   │ 32 bytes │ Previous slot bankhash          │
│ leader_signature   │ 64 bytes │ Ed25519 signature               │
└────────────────────┴──────────┴─────────────────────────────────┘
```

### 13.3 MCP Transaction Config

```
┌─────────────────────────────────────────────────────────────────┐
│ Bit Mask           │ 1 byte   │ Indicates present fields        │
├────────────────────┼──────────┼─────────────────────────────────┤
│ 0x01 set?          │ 8 bytes  │ inclusion_fee (little-endian)   │
│ 0x02 set?          │ 8 bytes  │ ordering_fee (little-endian)    │
│ 0x04 set?          │ 32 bytes │ target_proposer (pubkey)        │
└────────────────────┴──────────┴─────────────────────────────────┘
```

---

## 14. Storage Schema

### 14.1 Blockstore Column Families

| Column Family | Key Format | Value |
|---------------|------------|-------|
| `McpShredData` | `(slot, proposer_id, shred_index)` | Shred bytes |
| `McpShredCode` | `(slot, proposer_id, shred_index)` | Shred bytes |
| `McpSlotMeta` | `(slot, proposer_id)` | Slot metadata |
| `McpErasureMeta` | `(slot, proposer_id, fec_set_index)` | Erasure metadata |
| `McpMerkleRootMeta` | `(slot, proposer_id, fec_set_index)` | Merkle root |
| `McpIndex` | `(slot, proposer_id)` | Shred index bitmap |
| `McpConsensusPayload` | `(slot, block_id)` | Consensus payload |
| `McpExecutionOutput` | `(slot, block_id)` | Execution result |

### 14.2 Key Encoding

Composite keys are encoded as:
- Slot: 8 bytes big-endian (for lexicographic ordering)
- Proposer ID: 1 byte
- Shred Index: 8 bytes big-endian
- Block ID: 32 bytes

---

## 15. Security Considerations

### 15.1 Equivocation Detection

Relays that submit conflicting attestations (different merkle_root for same proposer_id in same slot) are detected and dropped. Their attestations are excluded from aggregation.

### 15.2 Merkle Proof Security

Second preimage attack prevention using domain separation:
- Leaf prefix: `0x00 || "SOLANA_MERKLE_SHREDS_LEAF"`
- Node prefix: `0x01 || "SOLANA_MERKLE_SHREDS_NODE"`

### 15.3 DA Fee Payer Attack Prevention

Fee payers must have balance for `NUM_PROPOSERS * fee` to prevent:
- Submitting to multiple proposers with insufficient funds
- Griefing proposers with failed fee collection

### 15.4 Reconstruction Threshold

The 20% threshold (40 of 200 shreds) ensures:
- Reconstruction possible with minority of relays
- Matches FEC data shred count exactly
- Balances availability with network efficiency

### 15.5 Proposer Commitment Verification

After reconstruction, the merkle root is re-computed and verified against the proposer's signed commitment. Mismatches result in proposer exclusion.

---

## Appendix A: Implementation Files

| Component | File |
|-----------|------|
| Protocol Constants | `ledger/src/mcp.rs` |
| Schedules | `ledger/src/mcp_schedule.rs` |
| Schedule Cache | `ledger/src/mcp_schedule_cache.rs` |
| Attestation Format | `ledger/src/mcp_attestation.rs` |
| Blockstore Columns | `ledger/src/blockstore/column.rs` |
| Fee Payer Validation | `svm/src/mcp_fee_payer.rs` |
| Fee-Only Replay | `svm/src/mcp_fee_replay.rs` |
| Relay Processing | `turbine/src/mcp_relay.rs` |
| Proposer Distribution | `turbine/src/mcp_proposer.rs` |
| Attestation Service | `core/src/mcp_attestation_service.rs` |
| Replay Components | `core/src/mcp_replay.rs` |
| Consensus Broadcast | `core/src/mcp_consensus_broadcast.rs` |
| Block Voting | `core/src/mcp_voting.rs` |
| Bankless Leader | `core/src/mcp_bankless.rs` |

---

## Appendix B: Determinism Requirements

The following MUST produce identical results across all implementations:

1. Schedule generation from epoch stakes
2. Merkle tree construction and proof generation
3. Attestation serialization (entries sorted by proposer_id)
4. Aggregate computation and block_id derivation
5. Transaction ordering (by proposer_id, then position)
6. Fee calculation and deduction
7. Execution output for each slot

---

## Appendix C: Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0-draft | 2026-01-22 | Initial specification (draft) |
| 1.0-draft | 2026-01-22 | Corrected fee charging, block_id serialization, relay distribution |
