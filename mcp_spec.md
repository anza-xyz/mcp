# MCP (Multiple Concurrent Proposers) Protocol Specification

**Version:** 1.0-draft
**Status:** Draft (structures defined, integration incomplete)

## Table of Contents

1. [Overview](#1-overview)
2. [Protocol Constants](#2-protocol-constants)
3. [Roles and Schedules](#3-roles-and-schedules)
4. [Data Structures](#4-data-structures)
5. [Cryptographic Primitives](#5-cryptographic-primitives)
6. [Shred Format](#6-shred-format)
7. [Transaction Format](#7-transaction-format)
8. [Proposer Operations](#8-proposer-operations)
9. [Relay Operations](#9-relay-operations)
10. [Consensus Leader Operations](#10-consensus-leader-operations)
11. [Validator Operations](#11-validator-operations)
12. [Replay Operations](#12-replay-operations)
13. [Fee Mechanics](#13-fee-mechanics)
14. [Wire Formats](#14-wire-formats)
15. [Storage Schema](#15-storage-schema)
16. [Security Considerations](#16-security-considerations)
17. [Determinism Requirements](#17-determinism-requirements)
18. [Forward-Compatible Extensions](#18-forward-compatible-extensions)

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
| `ATTESTATION_THRESHOLD` | 60% | Minimum fraction of relays in block |
| `INCLUSION_THRESHOLD` | 40% | Minimum fraction of relays per proposer |
| `RECONSTRUCTION_THRESHOLD` | 20% | Minimum fraction for reconstruction |
| `BANKHASH_DELAY_SLOTS` | 4 | Bank hash delay for validation |
| `CONSENSUS_PAYLOAD_PROPOSER_ID` | 0xFF | Reserved ID for consensus shreds |

**Derived Integer Thresholds (ceil):**

| Constant | Formula | Value | Description |
|----------|---------|-------|-------------|
| `MIN_RELAYS_IN_BLOCK` | ceil(0.60 × 200) | 120 | Minimum relay attestations for valid block |
| `MIN_RELAYS_PER_PROPOSER` | ceil(0.40 × 200) | 80 | Minimum relays for proposer inclusion |
| `K_DATA_SHREDS` | ceil(0.20 × 200) | 40 | Minimum shreds for reconstruction |

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

### 2.4 Packet Sizing Constants

MCP shreds are sized to fit within Solana's UDP packet budget.

| Constant | Value | Description |
|----------|-------|-------------|
| `MCP_SHRED_TOTAL_BYTES` | 1,225 | Total shred message size |
| `MCP_SHRED_PAYLOAD_BYTES` | 952 | Shred data payload capacity |
| `MERKLE_PROOF_BYTES` | 160 | 8 entries × 20 bytes |
| `SIGNATURE_BYTES` | 64 | Ed25519 signature |

**Shred Message Breakdown:**
```
1225 = 8(slot) + 1(proposer_id) + 4(shred_index) + 32(commitment)
     + 952(shred_data) + 1(witness_len) + 160(witness) + 64(signature)
```

### 2.5 Batch Size Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PROPOSER_PAYLOAD_BYTES` | 38,080 | K_DATA_SHREDS × MCP_SHRED_PAYLOAD_BYTES |
| `MAX_TRANSACTIONS_PER_BATCH` | 65,536 | Maximum transactions per proposer batch |
| `MAX_TX_SIZE` | 4,096 | Maximum serialized transaction size |
| `MAX_WITNESS_ENTRIES` | 8 | Maximum merkle proof entries |

**Enforcement:** Batches exceeding these limits MUST be rejected. Validators MUST NOT process oversized batches during replay. Shreds with `witness_len > 8` MUST be silently dropped.

---

## 3. Roles and Schedules

### 3.1 Role Definitions

**Proposer (q):** Stake-weighted validator that creates transaction batches and distributes shreds to relays. Valid `proposer_id` range: [0, NUM_PROPOSERS-1].

**Relay (r):** Stake-weighted validator that receives shreds from proposers, verifies commitments, and submits attestations to the consensus leader. Valid `relay_id` range: [0, NUM_RELAYS-1].

**Consensus Leader (L):** The slot leader who aggregates relay attestations and broadcasts the consensus block. Leader schedule unchanged from standard Solana.

**Validator:** Any validator participating in consensus and replay.

### 3.2 Canonical Validator Registry

At epoch `E`, define `ValidatorRegistry_E` as the list of active validator vote pubkeys in **ascending lexicographic order of pubkey bytes**. All indices used by MCP reference this registry deterministically.

- `validator_index` in votes refers to an index into `ValidatorRegistry_E`
- Committee selection outputs ordered lists of `validator_index` values, which map to pubkeys

### 3.3 Schedule Generation

Schedules are deterministically generated per epoch using stake-weighted selection **without replacement**:

```
seed_role = SHA256("mcp:committee:" || role || LE64(epoch_number))
rng = ChaCha20Rng::from_seed(seed_role)
pool = stake_weighted_sample_without_replacement(validators, stakes, rng, ROLE_COUNT)
```

**Pool Size:** The pool size MUST equal the role count exactly:
- Proposer pool: 16 validators
- Relay pool: 200 validators

**Stake-Weighted Sampling Without Replacement:**

```
candidates = all validators in registry order
for k in 0..ROLE_COUNT-1:
    W_C = sum of stakes for remaining candidates
    r = rng.next_u64() mod W_C
    pick = smallest index i such that cumulative_stake[i] > r
    pool[k] = pick
    remove pick from candidates
```

**Slot Assignment via Modular Indexing:** For slot `s` within the epoch:
```
slot_index = s - epoch_start_slot
for i in 0..ROLE_COUNT:
    role_validators[i] = pool[(slot_index + i) % ROLE_COUNT]
```

This rotates the pool by one position per slot while mathematically guaranteeing uniqueness within each slot (consecutive indices in a circular pool are always distinct).

**Leader Schedule:** Unchanged from standard Solana; uses `NUM_CONSECUTIVE_LEADER_SLOTS` repetition.

### 3.4 Schedule Lookup

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

### 4.6 McpPayloadV1

Proposer payload format (the byte string `M` that proposers encode with RS):

```rust
struct McpPayloadV1 {
    payload_version: u8,      // = 1
    slot: u64,                // 8 bytes, little-endian
    proposer_id: u8,          // [0, NUM_PROPOSERS-1]
    payload_len: u32,         // 4 bytes, length of payload body
    tx_count: u16,            // 2 bytes, number of transactions
    txs: Vec<TxEntry>,        // concatenated transactions
}

struct TxEntry {
    tx_len: u16,              // length in bytes of serialized transaction
    tx_bytes: Vec<u8>,        // tx_len bytes
}
```

**Constraints:**
- `payload_len` MUST equal bytes from `tx_count` to end of payload
- Each `tx_len` MUST be > 0 and ≤ `MAX_TX_SIZE` (4096)
- Total serialized payload ≤ `MAX_PROPOSER_PAYLOAD_BYTES` (38,080)

### 4.7 McpVoteV1

Compact vote format (117 bytes):

```rust
struct McpVoteV1 {
    slot: u64,                // 8 bytes
    validator_index: u32,     // 4 bytes (index into ValidatorRegistry)
    block_hash: Hash,         // 32 bytes
    vote_type: u8,            // 1 byte
    timestamp: i64,           // 8 bytes
    signature: Signature,     // 64 bytes
}
```

**Signature:** `Ed25519Sign(SK, "mcp:vote:v1" || serialize_without_signature(vote))`

---

## 5. Cryptographic Primitives

### 5.1 Hash Function

`Hash(x)` is SHA-256, returning 32 bytes, used as Solana `Hash` type.

### 5.2 Signatures

All signatures are Ed25519 over the exact byte strings defined in this specification.

### 5.3 Merkle Tree Commitment

MCP uses a fixed-depth Merkle tree with 20-byte truncated proof entries to fit shreds within UDP packet budget.

#### 5.3.1 Domain Separation

All hashes use domain separation to prevent second-preimage attacks:

- `LEAF_PREFIX = 0x00`
- `NODE_PREFIX = 0x01`
- `LEAF_DOMAIN = "SOLANA_MERKLE_SHREDS_LEAF"`
- `NODE_DOMAIN = "SOLANA_MERKLE_SHREDS_NODE"`

#### 5.3.2 Leaf Hash

Given shred payload bytes (exactly `MCP_SHRED_PAYLOAD_BYTES` = 952 bytes):

```
leaf_hash = SHA256(LEAF_PREFIX || LEAF_DOMAIN || shred_payload)   // 32 bytes
leaf_trunc = leaf_hash[0..20]                                      // 20 bytes
```

#### 5.3.3 Node Hash

Given two children as 20-byte truncations:

```
node_hash = SHA256(NODE_PREFIX || NODE_DOMAIN || left20 || right20)  // 32 bytes
node_trunc = node_hash[0..20]                                         // 20 bytes
```

#### 5.3.4 Tree Structure (256 Leaves)

For each proposer payload in slot `s`:

- Tree has 256 leaves (complete binary tree, depth 8)
- Leaves `L[i]` for `i = 0..255`:
  - For `i < NUM_RELAYS` (200): `L[i]` is `leaf_trunc` of shred payload at `shred_index=i`
  - For `i >= 200`: `L[i]` is `leaf_trunc` of **all zeros** (952 zero bytes)
- **Commitment** is the full 32-byte `node_hash` at the root (not truncated)

#### 5.3.5 Merkle Proof (Witness)

A witness for `shred_index i` is the concatenation of 8 sibling truncations (20 bytes each) along the path from leaf `i` to root:

```
witness = sibling0_20 || sibling1_20 || ... || sibling7_20   // 160 bytes
witness_len = 8                                               // u8
```

Verification recomputes upward hashes using §5.3.3 and checks the resulting root equals the commitment.

### 5.4 Erasure Coding (Reed-Solomon)

MCP uses systematic Reed-Solomon with:

- `N = NUM_RELAYS = 200` total shreds
- `K = K_DATA_SHREDS = 40` data shreds
- `N-K = 160` coding shreds

**Encoding:** Given payload `M` of length ≤ `MAX_PROPOSER_PAYLOAD_BYTES`:

1. Pad `M` with trailing zeros to length `K × MCP_SHRED_PAYLOAD_BYTES`
2. Split into `K` chunks of `MCP_SHRED_PAYLOAD_BYTES` each
3. Apply systematic RS encoding to produce `N` chunks (each 952 bytes)

**Decoding:** Given any `K` distinct shard indices, decode deterministically to recover original `K` data shards and thus the padded message.

**Determinism:** All implementations MUST produce identical output bytes given the same input shards.

---

## 6. Shred Format

### 6.1 Common Header (MCP Extended)

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

## 7. Transaction Format

### 7.1 MCP Transaction Config

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

### 7.2 Config Mask Bits

| Bit | Field |
|-----|-------|
| 0x01 | inclusion_fee present |
| 0x02 | ordering_fee present |
| 0x04 | target_proposer present |

### 7.3 Fee Types

All fees are charged upfront in the fee phase before execution. This ensures proposers are compensated even if execution fails.

| Fee Type | Description | Recipient |
|----------|-------------|-----------|
| signature_fee | Standard signature verification | Validator |
| prioritization_fee | Execution priority | Validator |
| inclusion_fee | Data availability compensation | Proposer |
| ordering_fee | Priority within proposer batch | Proposer |

---

## 8. Proposer Operations

### 8.1 Batch Creation (Bankless)

Proposers create transaction batches without executing:

1. Receive transactions from mempool
2. Validate signatures (no state execution)
3. Order by ordering_fee descending, then by SHA256(serialized_transaction) ascending (for determinism)
   - The hash is computed over the full serialized transaction bytes
   - Ties in ordering_fee are broken deterministically by transaction hash
4. Serialize batch:
   ```
   | slot (8) | proposer_id (1) | tx_count (4) | [tx_len (4) | tx_data]... |
   ```

### 8.2 Shred Encoding

1. Serialize batch to bytes
2. Apply Reed-Solomon encoding (40 data + 160 coding)
3. Build Merkle tree over all 200 shreds
4. For each shred, sign: `sign(slot || proposer_id || shred_index || merkle_root)`
   - `shred_index` is 4 bytes little-endian (range [0, 199])
   - Binding shred_index prevents cross-shred signature replay attacks

### 8.3 Distribution to Relays

**Relay Assignment:** Each relay receives one shred per FEC block. The mapping is:

```
relay_id = shred_index % NUM_RELAYS
```

Where `shred_index` is in range [0, 199] for MCP FEC blocks.

**Stake-Weighted Relay Positions:** The `relay_id` maps to a stake-weighted position in the relay schedule, NOT directly to a validator. The schedule generation (Section 3.2) assigns validators to positions [0, 199] based on stake weight. Higher-stake validators are more likely to be assigned positions, but the `shred_index % NUM_RELAYS` formula distributes shreds uniformly across all scheduled relay positions for that slot.

**Message Format:** Send to each relay via unicast:

```
┌──────────────────────────────────────────────────────────────────┐
│ ProposerShredMessage                                             │
├──────────────────┬───────────────────────────────────────────────┤
│ slot             │ 8 bytes, little-endian                        │
│ proposer_id      │ 1 byte                                        │
│ shred_index      │ 4 bytes, little-endian (range [0, 199])       │
│ commitment       │ 32 bytes (merkle root)                        │
│ shred_data_len   │ 4 bytes, little-endian                        │
│ shred_data       │ Variable                                      │
│ witness_len      │ 2 bytes, little-endian                        │
│ witness          │ Variable (merkle proof, max 8 entries)        │
│ proposer_sig     │ 64 bytes                                      │
└──────────────────┴───────────────────────────────────────────────┘
```

**Witness Size Enforcement:** If `witness_len > 8`, the message MUST be rejected as malformed.
Relays MUST NOT process messages with invalid witness lengths.

---

## 9. Relay Operations

### 9.1 Shred Verification

For each received shred message:

1. Validate `proposer_id` in range [0, 15]
2. Validate `shred_index` in range [0, 199]
3. Validate `witness_len <= 8` (reject if exceeded)
4. Verify proposer signature: `verify(proposer_pubkey, slot || proposer_id || shred_index || commitment, sig)`
   - Signature data is 45 bytes: slot (8) + proposer_id (1) + shred_index (4) + commitment (32)
5. Compute leaf hash: `SHA256(MERKLE_HASH_PREFIX_LEAF || shred_data)`
6. Verify merkle proof against commitment
7. Check for duplicates (same slot, proposer_id, shred_index)

**Verification Failure Handling:**
- Invalid proposer_id: silently drop message
- Invalid shred_index: silently drop message
- Invalid witness_len: silently drop message
- Signature verification failed: silently drop message
- Merkle proof failed: silently drop message
- Duplicate shred: silently drop message (keep first received)

### 9.2 Shred Storage

Store verified shreds by composite key: `(slot, proposer_id, shred_index)`

### 9.3 Attestation Generation

At relay deadline (slot end):

1. Collect verified (proposer_id, merkle_root) pairs
2. Sort entries by proposer_id ascending
3. Serialize attestation (see Wire Formats)
4. Sign: `sign(version || slot || relay_id || entries_len || entries)`
5. Submit to consensus leader

---

## 10. Consensus Leader Operations

### 10.1 Attestation Aggregation

For each slot:

1. Collect relay attestations
2. Verify each relay signature
3. Detect equivocations (same relay, same proposer, different merkle_root)
4. Drop equivocating relays
5. For each proposer, select merkle_root with highest attesting stake
6. Include proposer if `attesting_stake >= ATTESTATION_THRESHOLD * total_stake`

### 10.2 Block ID Computation

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

### 10.3 Consensus Payload Broadcast

1. Construct ConsensusPayload
2. Sign payload
3. Encode as shreds with `proposer_id = 0xFF`
4. Broadcast via turbine

---

## 11. Validator Operations

### 11.1 Block Validation

Before voting, validators MUST verify:

1. **Leader Identity:** `leader_id` matches expected slot leader
2. **Leader Signature:** Consensus payload signed correctly
3. **Delayed Bankhash:** Matches `BankHash(slot - BANKHASH_DELAY_SLOTS)` from local finalized fork
4. **Relay Count:** `num_relays >= MIN_RELAYS_IN_BLOCK` (120)
5. **Relay Entries:** Sorted by ascending `relay_id`, all unique
6. **Relay Signatures:** Each relay signature is valid

If any verification fails, the validator MUST treat the block as invalid and MUST NOT vote.

### 11.2 Compute Implied Proposer Commitments

Given a valid block, validators compute which proposer commitments are "implied":

For each `proposer_id` q:

1. Gather all `(commitment, proposer_signature)` pairs for proposer q from relay entries
2. **Proposer Equivocation Rule:** If two different commitments `C1 != C2` both have valid proposer signatures for slot s, proposer q is **equivocating** and MUST be excluded entirely
3. Count relay support: `count(C)` = number of distinct relays attesting to commitment C
4. Select `C*` as the commitment with maximum `count(C)`. Break ties by lexicographically smallest commitment bytes
5. If `count(C*) >= MIN_RELAYS_PER_PROPOSER` (80), include `(q, C*)` in `ImpliedCommitments`

### 11.3 Availability Check

For each `(proposer_id, commitment)` in `ImpliedCommitments`:

1. Count distinct `shred_index` values with valid Merkle proofs matching this commitment
2. If count < `K_DATA_SHREDS` (40), validator MUST NOT vote yet

### 11.4 Voting

If all checks pass:

1. Extract `block_id` from consensus payload
2. Create vote: `(slot, block_id, voter_pubkey, timestamp)`
3. Sign: `Ed25519Sign(SK, "mcp:vote:v1" || vote_data)`
4. Broadcast vote

If validation fails or pending:

- Do NOT vote
- Continue collecting shreds
- Re-evaluate when availability threshold met

---

## 12. Replay Operations

Replay begins once the block is finalized in consensus.

### 12.1 Deterministic Reconstruction

For each `(proposer_id, commitment)` in `ImpliedCommitments`:

1. Collect all locally stored shreds matching `(slot, proposer_id, commitment)` that pass Merkle verification
2. If fewer than `K_DATA_SHREDS` (40) distinct indices exist, output `⊥` for this proposer
3. Let `I` be the sorted list of available indices; take the first `K_DATA_SHREDS` indices
4. Apply Reed-Solomon decoding using shards at those indices to recover `M_padded`
5. Re-encode `M_padded` and re-compute Merkle commitment root:
   - If it does not equal `commitment`, output `⊥` for this proposer
6. Parse `M_padded` as `McpPayloadV1`:
   - Use `payload_len`, `tx_count`, and `tx_len` to recover exact transactions
   - Reject malformed payloads by outputting `⊥`

### 12.2 Global Transaction Ordering

Let `TxList[q]` be the list of parsed transactions for proposer q, in the order encoded by the proposer.

The global ordered transaction stream:

```
Ordered = concat(TxList[0], TxList[1], ..., TxList[NUM_PROPOSERS-1])
```

Transactions from excluded or failed proposers (`⊥`) contribute nothing. All validators MUST produce identical ordered output.

### 12.3 Transaction De-duplication

To prevent multiple charging/execution of identical transactions, validators MUST deterministically de-duplicate:

1. Define `txid = SHA256(serialized_tx_bytes)`
2. When scanning `Ordered`, keep the **first** occurrence of each `txid`
3. Drop subsequent duplicates

The first occurrence determines which proposer receives MCP fees.

### 12.4 Two-Phase Execution

**Phase A — Fee Deduction (pre-execution):**

For each tx in de-duplicated order:

1. Perform standard prechecks (signature, lifetime_specifier, etc.)
2. Compute standard fees (signature_fee, prioritization_fee) per runtime rules
3. Compute MCP fees (inclusion_fee, ordering_fee) from tx config
4. Attempt to deduct all fees from fee payer
   - If fee payer cannot cover total fees, mark tx failed and skip execution
5. Distribute MCP fees to the **including proposer** (proposer whose list contributed first occurrence)

**Phase B — Execution (state transitions):**

Execute only transactions that passed Phase A fee deduction:

- No additional fee charging
- Record success/failure outcomes per standard Solana semantics
- Fees charged in Phase A are **not refunded** if execution fails

### 12.5 Empty Slots

When consensus produces null result (⊥):

1. Output empty execution for slot
2. Store in execution output column family
3. Finalize slot

---

## 13. Fee Mechanics

### 13.1 Fee Payer Requirements

To prevent DA fee payer attacks, fee payers MUST have sufficient balance for worst-case inclusion across all proposers:

| Account Type | Required Balance |
|--------------|-----------------|
| System Account | `NUM_PROPOSERS * total_fee` |
| Nonce Account | `NUM_PROPOSERS * total_fee + rent_minimum` |

Where `total_fee = signature_fee + prioritization_fee + inclusion_fee + ordering_fee`

**Rationale:** A transaction may be included by multiple proposers (up to all 16) in the same slot. The fee payer must be able to cover fees in all cases to prevent griefing attacks where users submit to multiple proposers with insufficient funds.

### 13.2 Fee Charging and Distribution

**Charging:** All fees are deducted from the fee payer in the fee phase, before execution. This happens regardless of whether execution succeeds or fails.

**Distribution:**

| Fee Type | Recipient | Notes |
|----------|-----------|-------|
| signature_fee | Validator rewards pool | Distributed on slot finalization |
| prioritization_fee | Validator rewards pool | Distributed on slot finalization |
| inclusion_fee | Proposer who included tx | Distributed on slot finalization |
| ordering_fee | Proposer who included tx | Distributed on slot finalization |

### 13.3 Per-Slot Tracking

Track cumulative commitments per fee payer per slot to prevent over-commitment when multiple proposers include the same transaction.

---

## 14. Wire Formats

### 14.1 Relay Attestation (v1)

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

### 14.2 Consensus Payload

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

### 14.3 MCP Transaction Config

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

## 15. Storage Schema

### 16.1 Blockstore Column Families

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

### 16.2 Key Encoding

Composite keys are encoded as:
- Slot: 8 bytes big-endian (for lexicographic ordering)
- Proposer ID: 1 byte
- Shred Index: 8 bytes big-endian
- Block ID: 32 bytes

---

## 16. Security Considerations

### 16.1 Equivocation Detection

Relays that submit conflicting attestations (different merkle_root for same proposer_id in same slot) are detected and dropped. Their attestations are excluded from aggregation.

### 16.2 Merkle Proof Security

Second preimage attack prevention using domain separation:
- Leaf prefix: `0x00 || "SOLANA_MERKLE_SHREDS_LEAF"`
- Node prefix: `0x01 || "SOLANA_MERKLE_SHREDS_NODE"`

### 16.3 DA Fee Payer Attack Prevention

Fee payers must have balance for `NUM_PROPOSERS * fee` to prevent:
- Submitting to multiple proposers with insufficient funds
- Griefing proposers with failed fee collection

### 16.4 Reconstruction Threshold

The 20% threshold (40 of 200 shreds) ensures:
- Reconstruction possible with minority of relays
- Matches FEC data shred count exactly
- Balances availability with network efficiency

### 16.5 Proposer Commitment Verification

After reconstruction, the merkle root is re-computed and verified against the proposer's signed commitment. Mismatches result in proposer exclusion.

---

## 17. Determinism Requirements

All nodes MUST agree exactly on the following to maintain consensus:

### 17.1 Schedule Generation
- `ValidatorRegistry_E` ordering (lexicographic by pubkey bytes)
- Committee selection for proposers/relays for every slot
- Pool generation using stake-weighted sampling without replacement

### 17.2 Cryptographic Operations
- Merkle tree construction and commitment computation
- Merkle proof verification
- Reed-Solomon encoding/decoding output bytes
- SHA256 hash outputs for transaction ordering

### 17.3 Block Processing
- `computeImpliedCommitments` tie-break rules (lexicographic commitment)
- Deterministic reconstruction index selection (lowest K indices)
- Attestation serialization (entries sorted by proposer_id)
- Aggregate computation and block_id derivation

### 17.4 Transaction Processing
- Transaction ordering: by proposer_id ascending, then position in batch
- Transaction de-duplication: first occurrence wins
- Fee calculation and deduction
- Execution output for each slot

---

## 18. Forward-Compatible Extensions

The following are explicitly deferred to future versions:

### 18.1 Threshold Encryption / Hiding
Future versions may add threshold encryption to hide transaction content until after ordering is committed. This version uses plaintext transactions.

### 18.2 Multi-FEC Streaming
Future versions may allow proposers to submit multiple FEC batches per slot (streaming). This version limits each proposer to one batch per slot.

### 18.3 Relay Replay Watermarks
Future versions may add lag-based replay budget control to prevent slow relays from causing consensus delays.

### 18.4 MEV Protection
This version defines ordering and availability only. MEV protection mechanisms are out of scope.

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

## Appendix B: Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0-draft | 2026-01-22 | Initial specification (draft) |
| 1.0-draft | 2026-01-22 | Corrected fee charging, block_id serialization, relay distribution |
| 1.0-draft | 2026-01-22 | Added shred_index to signature binding, batch limits, verification failure handling, clarified schedule generation |
| 1.0-draft | 2026-01-22 | Major update: added cryptographic primitives (§5), McpPayloadV1/McpVoteV1 structures, proposer equivocation rule, de-duplication, 256-leaf Merkle tree, derived thresholds, forward-compatible extensions |
