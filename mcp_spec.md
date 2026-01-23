# MCP (Multiple Concurrent Proposers) Protocol Specification (Plaintext / No Encryption)

**Spec ID:** MCP-001  
**Version:** 1.0.0-draft3 (Plaintext)  
**Date:** 2026-01-22  
**Status:** Draft (implementable; wire formats stable for v1 messages)

This document defines the **source-of-truth** protocol behavior and wire formats for the **Solana‑Alpenglow MCP** fork **without transaction encryption** (no hiding / threshold encryption in this version). It is intended to match the public MCP “Part 1” structure while resolving underspecification and internal inconsistencies so that independent implementations interoperate.

> **Editorial note (interoperability):** The public MCP diagram currently shows a 160‑byte Merkle witness and also fixes `NUM_RELAYS=200`. A standard Merkle path over 200 leaves would not fit in 160 bytes using 32‑byte hashes. This spec resolves that tension by defining a **256‑leaf padded Merkle tree** with **8 proof entries** of **20‑byte truncations** (total 160 bytes). This is normative for MCP‑001.

---

## Table of Contents

1. [Overview](#1-overview)  
2. [Protocol Constants](#2-protocol-constants)  
3. [Roles, Committees, and Scheduling](#3-roles-committees-and-scheduling)  
4. [Cryptographic and Coding Primitives](#4-cryptographic-and-coding-primitives)  
5. [Canonical Payload Structures](#5-canonical-payload-structures)  
6. [Wire Formats](#6-wire-formats)  
7. [Transaction Format](#7-transaction-format)  
8. [Proposer Operations](#8-proposer-operations)  
9. [Relay Operations](#9-relay-operations)  
10. [Consensus Leader Operations](#10-consensus-leader-operations)  
11. [Validator Operations](#11-validator-operations)  
12. [Replay Operations](#12-replay-operations)  
13. [Fee Mechanics](#13-fee-mechanics)  
14. [Storage Schema](#14-storage-schema)  
15. [Security Considerations](#15-security-considerations)  
16. [Determinism Requirements](#16-determinism-requirements)  
17. [Forward-Compatible Extensions](#17-forward-compatible-extensions)  
18. [References](#18-references)  

---

## 1. Overview

MCP (Multiple Concurrent Proposers) allows **multiple proposers** to submit transaction payloads for the **same slot** in parallel. A **relay committee** acts as a data-availability and fanout layer. The **slot leader** aggregates relay attestations into a consensus block. Execution occurs later during deterministic replay.

### 1.1 Goals

- **Parallel submission:** multiple proposers per slot.
- **Data availability signaling:** relays attest to receiving a proposer’s payload in time.
- **Deterministic replay:** all validators reconstruct identical proposer payloads and execute transactions in a deterministic order.
- **Consensus safety preserved:** MCP is a gadget over the underlying Alpenglow consensus. It adds **new block validity checks** but does not redefine fork choice.

### 1.2 Non-goals (this version)

- **No encryption / hiding.** Transactions are plaintext.
- **No MEV protection.** MCP only defines ordering and availability.
- **No multi-FEC streaming.** Each proposer contributes **at most one** erasure-coded payload per slot.

### 1.3 Slot phases (logical)

For slot `s`:

1. **Proposal phase:** each proposer constructs a payload `M_{s,q}`, erasure-encodes it into `NUM_RELAYS` shreds, commits to the shred vector, and sends **one shred** to each relay.
2. **Relay phase:** each relay verifies its received shreds and broadcasts verified shreds to validators; relays send attestations to the leader.
3. **Consensus phase (leader):** leader aggregates relay attestations and proposes an Alpenglow block containing the MCP payload.
4. **Consensus voting:** validators verify the block and verify they can reconstruct enough shreds for each included proposer; then vote.
5. **Replay:** validators reconstruct proposer payloads from shreds, parse transactions, order deterministically, execute, and produce the slot output.

---

## 2. Protocol Constants

All constants are derived from genesis configuration / feature activation and MUST be identical across all nodes that have MCP enabled.

### 2.1 Core constants

| Constant | Value | Meaning |
|---|---:|---|
| `NUM_PROPOSERS` | 16 | Number of proposers per slot |
| `NUM_RELAYS` | 200 | Number of relays per slot |
| `ATTESTATION_THRESHOLD` | 0.60 | **Block-level** minimum fraction of relays whose attestations must be included for the block to be valid |
| `INCLUSION_THRESHOLD` | 0.40 | **Per-proposer** minimum fraction of relays that must attest to a proposer commitment for that proposer to be included |
| `RECONSTRUCTION_THRESHOLD` | 0.20 | Minimum fraction of distinct relay shreds required to reconstruct a proposer payload |
| `BANKHASH_DELAY_SLOTS` | 4 | Bank hash delay used by “bankless leader” validation (§11.1) |

**Derived integer thresholds (ceil):**

```
MIN_RELAYS_IN_BLOCK      = ceil(ATTESTATION_THRESHOLD * NUM_RELAYS)      = 120
MIN_RELAYS_PER_PROPOSER  = ceil(INCLUSION_THRESHOLD   * NUM_RELAYS)      =  80
K_DATA_SHREDS            = ceil(RECONSTRUCTION_THRESHOLD * NUM_RELAYS)   =  40
```

### 2.2 Packet sizing constants

MCP shreds are sized to fit within Solana’s UDP packet budget.

| Constant | Value |
|---|---:|
| `MCP_SHRED_TOTAL_BYTES` | 1225 |
| `MCP_SHRED_PAYLOAD_BYTES` | 952 |
| `MERKLE_ROOT_BYTES` | 32 |
| `MERKLE_PROOF_ENTRY_BYTES` | 20 |
| `MERKLE_PROOF_ENTRIES` | 8 |
| `MERKLE_PROOF_BYTES` | 160 |
| `SIGNATURE_BYTES` | 64 |

These satisfy:

```
1225 = 8(slot) + 4(proposer_index) + 4(shred_index) + 32(commitment)
     + 952(shred_data) + 1(witness_len) + 160(witness) + 64(signature)
```

### 2.3 Payload size limits

Each proposer payload is encoded into `NUM_RELAYS` shreds of `MCP_SHRED_PAYLOAD_BYTES`, with `K_DATA_SHREDS` data capacity.

| Limit | Value |
|---|---:|
| `MAX_PROPOSER_PAYLOAD_BYTES` | `K_DATA_SHREDS * MCP_SHRED_PAYLOAD_BYTES` = `40 * 952` = **38,080 bytes** |

A proposer MUST NOT produce a payload exceeding this limit. Oversized payloads are invalid and MUST be rejected.

---

## 3. Roles, Committees, and Scheduling

### 3.1 Roles

**Proposer (q):** A validator selected into the proposer committee for slot `s`, indexed by `proposer_index ∈ [0, NUM_PROPOSERS-1]`. Produces one MCP payload for slot `s`.

**Relay (r):** A validator selected into the relay committee for slot `s`, indexed by `relay_index ∈ [0, NUM_RELAYS-1]`. Receives one shred from each proposer and attests to commitments it verified.

**Consensus Leader (L):** The underlying Alpenglow slot leader for slot `s` (leader schedule unchanged by MCP).

**Validator:** Any validator participating in consensus and replay.

### 3.2 Canonical validator registry

At epoch `E`, define `ValidatorRegistry_E` as the list of active validator vote pubkeys in **ascending lexicographic order of pubkey bytes**.

All indices used by MCP reference this registry deterministically:

- Any `*_index` field in MCP wire messages refers to an index into `ValidatorRegistry_E`.
- Committee selection outputs ordered lists of `validator_index` values (which map to vote pubkeys).

### 3.3 Committee selection (stake-weighted rotation)

This spec uses **deterministic stake-weighted rotation** per slot:

- Each role maintains an ordered committee for slot `s`.
- The committee for slot `s+1` is derived by rotating the committee for slot `s` by 1 position and sampling 1 new validator by stake weight to fill the vacated position.

#### 3.3.1 RNG

For role `role ∈ {proposer, relay}`:

```
seed_role = SHA256("mcp:committee:" || role || LE64(epoch_number))
rng_role  = ChaCha20(seed_role)      // 32-byte seed
```

For slot `s` within epoch:

```
slot_index = s - epoch_start_slot(epoch)
seed_slot  = SHA256(seed_role || LE64(slot_index))
rng_slot   = ChaCha20(seed_slot)
```

#### 3.3.2 Weighted sample (deterministic)

Given candidate set `C` (validator indices in registry order):

1. Let `W_C = sum_{i ∈ C} stake[i]`.
2. Draw `r = rng_slot.next_u64() mod W_C` (deterministic; mod bias is acceptable).
3. Return the smallest `i ∈ C` such that cumulative stake over `C` first exceeds `r`.

#### 3.3.3 Rotation update rule

Let `ROLE_COUNT` be 16 (proposers) or 200 (relays). Let `Committee_role[s]` be an **ordered** list of length `ROLE_COUNT`.

**Epoch initialization (slot `s0`):** fill the committee by repeated weighted sampling **without replacement** using `rng_slot` at `slot_index=0`.

**Next slot (`s+1`):**

1. Rotate left by 1:
   ```
   committee' = committee[1..] || [committee[0]]
   ```
2. Replace the last element with a new sample:
   - Candidate set `C = all validators \ committee'` (avoid duplicates within the committee).
   - If `C` is empty (too few validators), set `C = all validators`.
   - Sample `pick = weighted_sample(C)` and set `committee'[-1] = pick`.

The resulting `committee'` is `Committee_role[s+1]`.

---

## 4. Cryptographic and Coding Primitives

### 4.1 Hash

`Hash(x)` is SHA-256, returning 32 bytes.

### 4.2 Signatures

All signatures are Ed25519 over the exact byte strings defined below.

**ASCII strings** are byte-for-byte ASCII with **no trailing NUL**, concatenated exactly as written.

### 4.3 Erasure coding (Reed–Solomon)

MCP uses a systematic Reed–Solomon erasure code with parameters:

- `N = NUM_RELAYS = 200` total shreds
- `K = K_DATA_SHREDS = 40` data shreds
- `N-K = 160` coding shreds

**Normative requirement:** All implementations MUST use the *same* RS codec and produce identical shard bytes given the same input. In the Solana‑Alpenglow fork, the RS implementation MUST match the one used for Solana FEC shreds (systematic RS over GF(2^8)) with parameters `(data_shards=40, parity_shards=160)`.

#### 4.3.1 Encoding

Given payload bytes `M` with `|M| ≤ MAX_PROPOSER_PAYLOAD_BYTES`:

1. Pad `M` with trailing zero bytes to length exactly `K * MCP_SHRED_PAYLOAD_BYTES`.
2. Split into `K` equal-size chunks of length `MCP_SHRED_PAYLOAD_BYTES`.
3. Apply systematic RS encoding to produce `N` chunks (each 952 bytes).

Output is `shreds[0..N-1]`, each exactly 952 bytes.

#### 4.3.2 Decoding

Given any set of `K` distinct shard indices `{(i, shreds[i])}`, decode deterministically to recover the original padded `M_padded`.

Nodes MUST reject shards with invalid Merkle proofs before attempting decoding.

### 4.4 Vector commitment: fixed-depth Merkle with 20-byte proof entries

This section defines a Merkle commitment scheme that yields:

- Commitment/root: 32 bytes.
- Proof entries: 20 bytes each.
- Proof length: 8 entries (for a 256-leaf padded tree).
- Total witness bytes: 160.

#### 4.4.1 Domain separation

All hashes use domain separation:

- `LEAF_PREFIX = 0x00`
- `NODE_PREFIX = 0x01`
- `LEAF_DOMAIN = ASCII("SOLANA_MERKLE_SHREDS_LEAF")`
- `NODE_DOMAIN = ASCII("SOLANA_MERKLE_SHREDS_NODE")`

#### 4.4.2 Leaf hash

For leaf payload bytes `leaf_bytes` (exactly 952 bytes):

```
leaf_hash  = SHA256(LEAF_PREFIX || LEAF_DOMAIN || leaf_bytes)   // 32 bytes
leaf_trunc = leaf_hash[0..20]                                   // 20 bytes
```

#### 4.4.3 Node hash

Given two children as 20-byte truncations:

```
node_hash  = SHA256(NODE_PREFIX || NODE_DOMAIN || left20 || right20)  // 32 bytes
node_trunc = node_hash[0..20]                                          // 20 bytes
```

#### 4.4.4 Tree shape and commitment

For slot `s` and proposer `q`, define a complete binary tree over **256 leaves**:

- For `i in [0..NUM_RELAYS-1]` (0..199): leaf `i` is the RS shard bytes `shreds[i]`.
- For `i in [NUM_RELAYS..255]` (200..255): leaf bytes are 952 zero bytes.

The tree is built bottom-up using `leaf_trunc` and `node_trunc` as the carried values. The **commitment** is the full 32-byte `node_hash` at the root (not truncated).

#### 4.4.5 Witness format and verification

A witness for leaf index `i` is the concatenation of the **8 sibling truncations** along the path from leaf `i` to the root, from lowest level upward:

```
witness = sib0_20 || sib1_20 || ... || sib7_20   // 160 bytes
```

To verify:

```
cur20 = leaf_trunc(leaf_bytes)
for level = 0..7:
    sib20 = witness_entry(level)          // 20 bytes
    if ((i >> level) & 1) == 0:
        left20  = cur20
        right20 = sib20
    else:
        left20  = sib20
        right20 = cur20
    node_hash = SHA256(NODE_PREFIX || NODE_DOMAIN || left20 || right20)   // 32 bytes
    if level == 7:
        root32 = node_hash
    cur20 = node_hash[0..20]
accept iff root32 == commitment32
```

Implementations MAY compute the root32 by tracking the last full `node_hash` at the root level; the result MUST equal the commitment exactly.

---

## 5. Canonical Payload Structures

All integers are little-endian unless stated otherwise.

### 5.1 Proposer payload format: `McpPayloadV1`

This is the byte string `M` that proposers RS‑encode (§4.3).

```
struct McpPayloadV1 {
  u8   payload_version;        // = 1
  u64  slot;                   // slot number
  u32  proposer_index;         // [0..NUM_PROPOSERS-1]
  u32  payload_len;            // number of bytes following this field (payload body length)
  u16  tx_count;               // number of transactions
  TxEntry txs[tx_count];       // concatenated
  u8   reserved[payload_len - (2 + sum(tx_entry_bytes))]; // MUST be zero for v1
}

struct TxEntry {
  u16  tx_len;                 // length in bytes of serialized transaction
  u8   tx_bytes[tx_len];
}
```

**Constraints:**

- `payload_version` MUST equal `1`.
- `slot` and `proposer_index` MUST match the `(s,q)` being reconstructed; otherwise the payload is malformed.
- `payload_len` MUST equal the number of bytes from `tx_count` to the end of the payload body.
- Each `tx_len` MUST be `> 0` and MUST be ≤ 4096.
- Total serialized payload length (`1+8+4+4 + payload_len`) MUST be ≤ `MAX_PROPOSER_PAYLOAD_BYTES` (38,080).
- Any `reserved[...]` bytes in v1 MUST be **all zeros** (forward-compatibility padding).

### 5.2 Proposer commitment signature

The proposer signs the **commitment only** (the commitment already binds to slot/proposer because the payload header is inside the committed RS shards).

```
proposer_sig_msg = ASCII("mcp:commitment:v1") || commitment32
proposer_signature = Ed25519Sign(SK_proposer, proposer_sig_msg)
```

---

## 6. Wire Formats

This section defines the on-wire messages. Implementations MAY transport these over UDP/Turbine/gossip, but the **byte layouts and signature messages are normative**.

Unless otherwise stated, all multi-byte integers are little-endian.

### 6.1 Shred message: `McpShredV1` (1225 bytes)

| Offset | Field | Type | Bytes |
|---:|---|---|---:|
| 0 | slot | u64 | 8 |
| 8 | proposer_index | u32 | 4 |
| 12 | shred_index | u32 | 4 |
| 16 | commitment | [u8; 32] | 32 |
| 48 | shred_data | [u8; 952] | 952 |
| 1000 | witness_len | u8 | 1 |
| 1001 | witness | [u8; 160] | 160 |
| 1161 | proposer_signature | [u8; 64] | 64 |

**Semantics / validity:**

- `proposer_index` MUST be in `[0, NUM_PROPOSERS-1]`.
- `shred_index` MUST be in `[0, NUM_RELAYS-1]`.
- For a relay at index `r`, the only acceptable shred for that relay is `shred_index == r`.
- `witness_len` MUST equal `MERKLE_PROOF_ENTRIES (=8)`.
- `proposer_signature` MUST verify against the scheduled proposer pubkey for `(slot, proposer_index)` over `proposer_sig_msg` (§5.2).
- `witness` MUST open `commitment` at leaf `shred_index` for `shred_data` (§4.4).

If any check fails, receivers MUST drop the message.

### 6.2 Relay attestation: `RelayAttestationV1` (variable)

| Field | Type |
|---|---|
| slot | u64 |
| relay_index | u32 |
| num_attestations | u8 |
| entries | `num_attestations` × `AttestationEntryV1` |
| relay_signature | [u8; 64] |

```
struct AttestationEntryV1 {
  u32 proposer_index;
  [u8;32] commitment;
  [u8;64] proposer_signature;
}
```

**Relay signature:**

```
relay_sig_msg = ASCII("mcp:relay-attestation:v1") || serialize_without_relay_signature(attestation)
relay_signature = Ed25519Sign(SK_relay, relay_sig_msg)
```

**Constraints:**

- `relay_index` MUST be in `[0, NUM_RELAYS-1]` and MUST match the relay’s scheduled position.
- `num_attestations` MUST be ≤ `NUM_PROPOSERS` (16).
- Entries MUST be sorted by ascending `proposer_index`.
- At most one entry per `proposer_index`.
- For each entry, `proposer_signature` MUST verify over `commitment` with the scheduled proposer pubkey.

### 6.3 Consensus block MCP payload: `AggregateAttestationV1` (variable)

This is the MCP payload carried inside an Alpenglow block for slot `s`.

| Field | Type |
|---|---|
| slot | u64 |
| leader_index | u32 |
| delayed_bankhash | [u8; 32] |
| num_relays | u16 |
| relay_entries | `num_relays` × `RelayEntryV1` |
| leader_signature | [u8; 64] |

```
struct RelayEntryV1 {
  u32 relay_index;
  u8  num_attestations;
  AttestationEntryV1 entries[num_attestations];
  [u8;64] relay_signature;
}
```

**Block hash and leader signature:**

Define:

```
block_body = serialize_without_leader_signature(AggregateAttestationV1)
block_hash = SHA256(ASCII("mcp:block-hash:v1") || block_body)
leader_signature = Ed25519Sign(SK_leader, ASCII("mcp:block-sig:v1") || block_hash)
```

Validators vote on `block_hash` (carried in vote messages).

**Constraints:**

- `num_relays` MUST be ≥ `MIN_RELAYS_IN_BLOCK` (=120) for the block to be valid.
- `relay_entries` MUST be sorted by ascending `relay_index`.
- `relay_index` values MUST be distinct.
- Each embedded `relay_signature` MUST verify over the embedded relay attestation body (`RelayAttestationV1` without its signature).
- `delayed_bankhash` MUST equal the validator’s local `BankHash(slot - BANKHASH_DELAY_SLOTS)` on its finalized fork.

### 6.4 Vote message: `McpVoteV1` (117 bytes)

| Offset | Field | Type | Bytes |
|---:|---|---|---:|
| 0 | slot | u64 | 8 |
| 8 | validator_index | u32 | 4 |
| 12 | block_hash | [u8; 32] | 32 |
| 44 | vote_type | u8 | 1 |
| 45 | timestamp | i64 | 8 |
| 53 | signature | [u8; 64] | 64 |

`signature = Ed25519Sign(SK_validator, ASCII("mcp:vote:v1") || serialize_without_signature(vote))`.

**vote_type:** This field is interpreted by underlying Alpenglow voting semantics (e.g., notarize/finalize). MCP does not redefine it; it is included to keep the vote message self-contained.

---

## 7. Transaction Format

MCP uses a transaction format that matches Solana transaction semantics with an additional `transaction_config_mask` and optional config values.

This section is normative for MCP-specific fields; all other transaction semantics follow the Solana runtime.

### 7.1 Transaction V1 layout (summary)

```
offset  size  field
0       1     version_byte
1       3     legacy_header (3x u8)
4       4     transaction_config_mask (u32)
8       32    lifetime_specifier ([u8;32])   // recent blockhash or durable nonce hash
40      1     num_instructions (u8)
41      1     num_addresses (u8)
42      var   addresses ([u8;32] * num_addresses)
...     var   config values in bit order
...     var   instruction headers
...     var   instruction payloads
...     var   signatures
```

### 7.2 Config mask bits (u32)

| Bit index | Name | Type | Meaning |
|---:|---|---|---|
| 0 | `inclusion_fee` | u32 | Lamports paid to proposer for including this tx |
| 1 | `ordering_fee` | u32 | Lamports paid to proposer for higher intra-proposer ordering |
| 2 | `compute_unit_limit` | u32 | Requested CU limit |
| 3 | `accounts_data_size_limit` | u32 | Requested accounts data size |
| 4 | `heap_size` | u32 | Requested heap size |
| 5 | `target_proposer` | u32 | If present, only proposer with this proposer_index may include |

Fields are serialized in ascending bit index order, omitting fields whose bits are not set.

### 7.3 Limits

- Max serialized tx size: **4096 bytes**.
- Max signature count: **42**.
- Max accounts: **96**.
- Max instructions: **255**.

---

## 8. Proposer Operations

For slot `s`, proposer `q`:

### 8.1 Transaction intake and filtering

1. Collect pending transactions from the network/mempool.
2. Perform **stateless validation**:
   - Transaction parses correctly.
   - Signatures verify.
   - Serialized size ≤ 4096 bytes.
3. Apply target filtering:
   - If tx has `target_proposer` and it is not equal to `q`, discard the tx.

### 8.2 Ordering and packing

Proposer ordering is deterministic:

1. Define `ordering_fee(tx)` = tx.config.ordering_fee if present else 0.
2. Define `tx_hash = SHA256(serialized_tx_bytes)`.
3. Sort transactions by:
   1. `ordering_fee` descending
   2. `tx_hash` ascending

Pack transactions in that order into `McpPayloadV1` until adding the next tx would exceed `MAX_PROPOSER_PAYLOAD_BYTES`.

### 8.3 Encoding and shred distribution

1. Serialize `McpPayloadV1` to bytes `M`.
2. RS-encode `M` into `NUM_RELAYS` shards of 952 bytes (§4.3).
3. Compute Merkle commitment root over the shard vector (§4.4).
4. Compute `proposer_signature` over the commitment (§5.2).
5. For each `relay_index r`:
   - Compute Merkle witness for leaf `r`.
   - Construct `McpShredV1` with `shred_index = r` and send to relay `r` (unicast).

---

## 9. Relay Operations

Relay `r` for slot `s`:

### 9.1 Shred verification (per received `McpShredV1`)

For each received `McpShredV1`:

1. Verify `slot == s` and `shred_index == relay_index(r)`.
2. Verify `proposer_index ∈ [0, NUM_PROPOSERS-1]`.
3. Verify `witness_len == 8`.
4. Verify `proposer_signature` against the scheduled proposer pubkey:
   - `PK_q = Proposers[s][proposer_index]`
   - Verify `Ed25519Verify(PK_q, proposer_sig_msg, proposer_signature)`
5. Verify the Merkle witness opens `commitment` at index `shred_index` for `shred_data`.

If any check fails, the shred MUST be dropped.

Relays SHOULD treat duplicate `(slot, proposer_index, shred_index)` shreds as follows:
- Keep the first valid shred.
- Drop later duplicates (even if valid), to bound DoS amplification.

### 9.2 Storage and retransmission

For each verified shred, the relay:

- Stores it under key `(slot, proposer_index, shred_index)`, and
- Broadcasts the verified shred bytes (`McpShredV1`) to the validator network (gossip / turbine).

Relays MUST NOT retransmit invalid shreds.

### 9.3 Relay attestation construction

At the attestation deadline for slot `s`:

1. For each proposer `q`, if the relay has a verified shred for `q`, include an `AttestationEntryV1`:
   - `(proposer_index=q, commitment, proposer_signature)`
2. Sort entries by ascending proposer_index.
3. Sign as in §6.2 and send `RelayAttestationV1` to the slot leader.

---

## 10. Consensus Leader Operations

For slot `s`, leader `L`:

1. Collect `RelayAttestationV1` messages until the leader proposal deadline.
2. For each received relay attestation:
   - Verify the relay is a member of `Relays[s]` at the claimed `relay_index`.
   - Verify the relay signature.
   - Verify each `AttestationEntryV1`:
     - proposer_index is in range
     - proposer is in `Proposers[s]`
     - proposer_signature is valid for the commitment
3. Build `AggregateAttestationV1`:
   - Include at least `MIN_RELAYS_IN_BLOCK` distinct relay entries (120).
   - Set `delayed_bankhash = BankHash(s - BANKHASH_DELAY_SLOTS)` from the leader’s local finalized fork view.
4. Compute `block_hash` and `leader_signature` (§6.3).
5. Broadcast the Alpenglow block containing this MCP payload.

---

## 11. Validator Operations

### 11.1 Block validation (before voting)

Upon receiving an Alpenglow block for slot `s` containing `AggregateAttestationV1`:

1. Verify `leader_index` matches the expected Alpenglow leader for slot `s`.
2. Verify `leader_signature` against `block_hash` (§6.3).
3. Verify `delayed_bankhash == BankHash(s - BANKHASH_DELAY_SLOTS)` on the validator’s locally finalized fork.
4. Verify `num_relays ≥ MIN_RELAYS_IN_BLOCK` and relay entries are sorted and unique.
5. Verify each relay entry:
   - Relay is scheduled for slot `s` at `relay_index`.
   - Relay signature is valid.
   - Entries are sorted and unique per proposer_index.
   - Each proposer_signature is valid for the given commitment.

If any check fails, the validator MUST treat the block as invalid and MUST NOT vote for it.

### 11.2 Compute implied proposer commitments (`computeImpliedBlocks`)

Given a valid `AggregateAttestationV1`, compute the set `ImpliedBlocks`:

For each proposer_index `q`:

1. Gather all commitments `C` attested for proposer `q` by distinct relays in the block.
2. **Proposer equivocation rule:**  
   If there exist **two different commitments** `C1 != C2` for proposer `q` such that both have valid proposer signatures, then proposer `q` is **equivocating** and MUST be excluded.
3. Otherwise, compute support:
   - `count(C)` = number of distinct relays in the block that attest to commitment `C` for proposer `q`.
4. Choose `C*` with maximum `count(C)`; break ties by lexicographically smallest `C` bytes.
5. If `count(C*) ≥ MIN_RELAYS_PER_PROPOSER` (=80), include `(q, C*)` in `ImpliedBlocks`. Otherwise exclude proposer `q`.

### 11.3 Availability check before voting

For each `(q, commitment)` in `ImpliedBlocks`:

1. Count the number of **distinct shred_index** values for which the validator has a shred that:
   - matches `(slot s, proposer_index q, commitment)`, and
   - has a valid Merkle proof
2. If this count is `< K_DATA_SHREDS` (=40), the validator MUST NOT vote yet.

If all implied proposer commitments meet the local availability threshold, the validator MAY vote (subject to underlying Alpenglow rules).

---

## 12. Replay Operations

Replay begins once the block is finalized in Alpenglow.

### 12.1 Deterministic reconstruction: `DeterministicECCDecode`

For each `(q, commitment)` in `ImpliedBlocks`:

1. Collect all locally stored shreds `(i, shred_data[i])` for this `(slot, proposer_index=q, commitment)` that pass Merkle verification.
2. If fewer than `K_DATA_SHREDS` distinct indices exist, output `⊥` for this proposer.
3. Let `I` be the sorted list of available indices; take the first `K_DATA_SHREDS` indices `I0`.
4. Decode RS using shards at indices `I0` to recover `M_padded` (length exactly 38,080 bytes).
5. Re-encode `M_padded` and re-compute the Merkle commitment root:
   - If it does not equal `commitment`, output `⊥`.
6. Parse `M_padded` as `McpPayloadV1`:
   - Enforce all constraints in §5.1, including matching `(slot, proposer_index)` and zero reserved bytes.
   - Reject malformed payloads by outputting `⊥`.

### 12.2 Global ordering

Let `TxList[q]` be the list of parsed transactions for proposer `q`, in the order encoded by the proposer.

The global ordered transaction stream is:

```
Ordered = concat(TxList[0], TxList[1], ..., TxList[NUM_PROPOSERS-1])
```

Transactions from excluded or failed proposers (`⊥`) contribute nothing.

### 12.3 De-duplication

To prevent multiple charging/execution of identical transactions, validators MUST deterministically de-duplicate:

- Define `txid = SHA256(serialized_tx_bytes)`.
- When scanning `Ordered`, keep the **first** occurrence of each `txid` and drop subsequent duplicates.

The first occurrence determines which proposer receives MCP fees (§13.2).

### 12.4 Two-phase processing

Replay is executed in two phases to separate fee collection from state transition outcomes.

**Phase A — Fee deduction (pre-execution):**

For each tx in de-duplicated order:

1. Perform Solana’s standard prechecks (signature, lifetime_specifier, etc.).
2. Compute standard fees (signature fee, prioritization fee) per runtime rules.
3. Compute MCP fees:
   - inclusion_fee (u32 lamports, default 0)
   - ordering_fee (u32 lamports, default 0)
4. Attempt to deduct all fees from the fee payer.
   - If fee payer cannot cover total fees, mark tx failed and do not execute.
5. Distribute MCP fees to the **including proposer**.

**Phase B — Execution (state transitions):**

Execute only transactions that passed Phase A fee deduction.

- No additional fee charging is performed.
- Record success/failure outcomes per standard Solana semantics.

### 12.5 Empty / skipped slots

If the underlying consensus output for slot `s` is `⊥`, MCP replay output is the empty list `∅`.

---

## 13. Fee Mechanics

### 13.1 Fee types

| Fee | Source | Recipient | Charged when |
|---|---|---|---|
| signature fee | runtime | validator rewards | Phase A |
| prioritization fee | runtime | validator rewards | Phase A |
| inclusion_fee | tx config | including proposer | Phase A |
| ordering_fee | tx config | including proposer | Phase A |

### 13.2 Including proposer

The including proposer for a transaction is the proposer_index that contributed the tx’s **first occurrence** in the global ordered list (after ordering but before de-dup).

### 13.3 Execution failure

Fees charged in Phase A are **not refunded** if Phase B execution fails.

---

## 14. Storage Schema

Suggested Blockstore column families (names are informative; exact implementation may vary):

| Column Family | Key | Value |
|---|---|---|
| `McpShred` | `(slot, proposer_index, shred_index)` | full `McpShredV1` bytes |
| `McpRelayAttestation` | `(slot, relay_index)` | `RelayAttestationV1` bytes |
| `McpAggregateAttestation` | `(slot, block_hash)` | `AggregateAttestationV1` bytes |
| `McpReconstructedPayload` | `(slot, block_hash, proposer_index)` | `McpPayloadV1` bytes or `⊥` |
| `McpExecutionOutput` | `(slot, block_hash)` | execution result |

Key encoding for on-disk ordering should use big-endian for `slot` if lexicographic ordering is desired; on-wire encoding is little-endian.

---

## 15. Security Considerations

### 15.1 Proposer equivocation

A proposer that signs two different commitments for the same `(slot, proposer_index)` is excluded entirely (§11.2).

### 15.2 Relay equivocation

If a relay sends conflicting relay attestations for the same slot (different signed bodies), leaders and validators SHOULD ignore that relay’s entries. Implementations SHOULD log and, if available, penalize the relay via policy.

### 15.3 Data availability

Requiring both:

- `MIN_RELAYS_IN_BLOCK` relay attestations in the block (≥120), and
- per-proposer inclusion threshold (≥80 relays),

combined with validator local availability checks (≥40 shreds) prevents leaders from including proposer commitments that the network cannot reconstruct.

### 15.4 Truncated Merkle proofs

This spec uses 20-byte truncated proof entries and feeds only 20-byte truncations into parent hashing (§4.4). This is a tradeoff to keep fixed UDP packet sizes; it reduces Merkle collision resistance vs full 32-byte paths.

### 15.5 DoS considerations

Relays and validators MUST enforce:

- maximum tx size,
- maximum proposer payload bytes,
- strict parsing and bounds checks,
- fixed witness length and proof verification before RS decoding.

---

## 16. Determinism Requirements

All nodes MUST agree on:

1. `ValidatorRegistry_E` ordering.
2. Committee selection for proposers/relays for every slot.
3. RS encoding/decoding output bytes.
4. Merkle commitment and witness verification.
5. `computeImpliedBlocks` tie-break rules.
6. Deterministic reconstruction index selection (lowest K indices).
7. Transaction ordering, de-duplication, fee charging, and execution outputs.

---

## 17. Forward-Compatible Extensions

The following are explicitly deferred to future versions and MUST NOT be assumed in MCP‑001:

- **Threshold encryption / hiding.**
- **Multi-FEC / streaming proposer payloads** (multiple commitments per proposer per slot).
- **Replay lag control / SIMD-0322 integration:** the public MCP materials describe adding replay watermarks to relay attestations and applying a deterministic serial execution (DTAA) budget controller. If implemented, this will require a new message version or a new attestation type so wire formats remain unambiguous.

---

## 18. References

- Public MCP interactive spec (Part 1): https://mcpspec.vercel.app/  
- “Supernova: Fast Multiple Concurrent Proposers via Threshold Encryption”, Nov 23 2025 (background for committee/threshold intuition; encryption sections are out-of-scope for this plaintext spec).


