---
title: MCP Protocol Specification
---

MULTIPLE CONCURRENT PROPOSERS (MCP) PROTOCOL
Part 1 Specification

1. Introduction

This document specifies the Multiple Concurrent Proposers (MCP) protocol for a
slot-based ledger that already has a leader-based consensus protocol. MCP
allows several proposers to build transaction batches for the same slot, uses
relays to attest to batch availability, and commits a leader-signed aggregate
to consensus. The protocol defines scheduling, message formats, and the rules
that validators MUST follow to accept, vote, reconstruct, and replay batches.
The consensus protocol itself is out of scope except for the inputs and
outputs defined here.

1.1 Motivation and Goals

This section states the properties MCP is designed to provide.

Safety means honest validators do not diverge or rewrite history. Once a
transaction appears in a slot of an honest output log, all honest validators
eventually record the same transaction at the same slot and never replace it.

Liveness means the protocol continues to make progress. After the network
stabilizes, honest validators keep producing new log entries and a valid slot
does not remain undecided forever.

Selective-censorship resistance means that after stabilization an honest
proposer cannot be singled out for censorship by the relay and leader pipeline.
Transactions submitted in time to an honest proposer are either included in the
output log for the slot or the slot is declared empty.

We also want to achieve these properties without sacrificing latency or
bandwidth. We refer to these two goals as IBRL, meaning increase bandwidth and
reduce latency.

1.2 Protocol Overview

The setup phase fixes the system parameters and deterministically derives the
proposer, relay, and leader schedules so every validator agrees on roles for a
slot.

The proposal phase has each proposer collect transactions, encode a batch into
shreds, commit to those shreds, and send one shred with a witness to each relay.

The retransmit or relay phase has relays verify their assigned shreds,
forward them to validators, and attest to which proposers they served.

The consensus leader phase aggregates relay attestations into a canonical
payload and signs the consensus block that refers to it, then broadcasts the
block to the rest of the validator set.

The consensus voting phase has validators verify the leader block, check that
each implied proposer batch is available locally, and vote only when
reconstruction is feasible.

The reconstruct and replay phase rebuilds proposer batches from shreds,
verifies commitments, orders batches deterministically, and executes the
resulting transaction log for the slot.

Stages MAY be pipelined across slots, so a validator can execute different
stages for different slots at the same time without changing the per-slot
rules.

Baseline (single-leader, non-MCP)
```text
+-----------+    Txs    +--------+   Shreds  +-------+   Shreds   +---------------+
| Client(s) | --------> | Leader | --------> | Relay | ---------> | Validator(s)  |<---+
+-----------+           +--------+           +-------+            +---------------+    |
                                                                             |         |
                                                                             |         |
                                                                             +---------+
                                                                               Alpenglow
                                                                               Consensus
```


MCP (Constellation)
```text
+-----------+    Txs    +----------+   Shreds  +-------+   Shreds   +--------------+
| Client(s) | --------> | Proposer | --------> | Relay | ---------> | Validator(s) |<---+
+-----------+           +----------+           +-------+            +--------------+    |
                                       Attestation|                          ^|         |
                                                  v                          ||         |
                                               +--------+AggregateAttestation|+---------+
                                               | Leader |--------------------+ Alpenglow
                                               +--------+                      Consensus
```


2. Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

A slot is a discrete unit of time in the ledger. An epoch is a contiguous range
of slots over which validator stakes are stable. A validator is a node that
participates in consensus and executes the protocol. A proposer is a validator
selected for a slot to build a transaction batch. A relay is a validator
selected for a slot to store and attest to a shred. The leader is the validator
selected by the consensus protocol to aggregate relay attestations for a slot.
A shred is a fixed-length erasure-coded fragment of a proposer batch. A
commitment is a Merkle root computed over the ordered set of shreds for a batch.
A witness is a Merkle proof that binds a shred to its commitment. An
attestation is a relay-signed statement that it has stored a valid shred for a
proposer. An aggregate is the leader-collected set of relay attestations for a
slot. An implied block is a proposer commitment that meets the inclusion rules
in the aggregate.

Validator identities in schedules are the validator node identity public keys.
When the consensus leader schedule is vote-keyed, stake-weighted sampling is
performed over vote account public keys and each selected vote account is mapped
to its node identity public key for all scheduling and signature checks.

SlotTime(s) denotes the start time of slot s according to the consensus time
base. SLOT_DURATION is the fixed duration of a slot. Timing offsets in this
protocol are defined as non-negative durations relative to SlotTime(s).
The genesis bank hash is the bank hash for slot 0 as defined by the genesis
configuration.
block_id refers to the bank hash for a slot and is also called block_hash in
Vote messages.

All integers are little-endian. Signed integers are encoded in two's complement
form of the given width. Unsigned integers are encoded in standard binary form.
Byte strings are encoded as raw bytes with no length prefix unless specified.
All structures are serialized by concatenating their fields in the order
defined, with no padding or alignment.

3. Protocol Operation

3.1 Setup Stage

At the start of each slot s, each validator derives Proposers[s], Relays[s], and
Leader[s] as defined in Section 5 and initializes per-slot state for collecting
shreds, attestations, and votes. The proposer batch payload is encoded as a u32
count followed by that many (u32 length, transaction bytes) pairs, where each
transaction bytes value is a Transaction message as defined in Section 7.1. Any
trailing zero bytes added for padding MUST be ignored by decoders. Decoders MUST
reject a payload if any length extends past the available bytes or if any
remaining bytes after the final transaction are non-zero.

The encoded payload is exactly DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES
bytes, including any trailing zero padding.

3.2 Proposal Stage

Each proposer collects pending transactions into a batch. If a validator
appears multiple times in Proposers[s], it MUST act independently for each
proposer_index. Global block-level constraints on compute units (CU) and loaded
account data are divided evenly
among the proposers. Let CU_LIMIT and ACCOUNTS_DATA_LIMIT be the global limits
for the slot under the underlying execution rules. Each proposer budget is
floor(CU_LIMIT / NUM_PROPOSERS) and floor(ACCOUNTS_DATA_LIMIT / NUM_PROPOSERS),
and any remainder is unused. A proposer batch MUST NOT exceed these per-proposer
limits. A proposer MUST NOT include duplicate transactions within its batch, and
transactions are duplicates if their serialized Transaction bytes are identical.
Validators MUST treat any batch that violates these limits or includes
duplicates as invalid and exclude that proposer. The proposer then encodes the
batch into exactly one erasure batch of NUM_RELAYS shreds using erasure coding
with the parameters from Section 4. Each shred has SHRED_DATA_BYTES bytes. The
serialized batch MUST NOT
exceed DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES bytes so that the encoding
yields exactly one shred per relay. The per-proposer CU and loaded account data
limits MUST be set so that a batch that respects them can satisfy this size
bound. The encoder MUST define shred indices from 0 to NUM_RELAYS-1 and MUST
output shreds in that order. The proposer computes the Merkle commitment over
all shreds, computes the witness for each shred index, and signs the commitment.
The proposer MUST include the corresponding witness in each Shred message. The
proposer MUST send exactly one Shred message to each relay in Relays[s], with
shred_index equal to the relay_index position in Relays[s], and MUST NOT send conflicting
commitments for the same slot and proposer_index.
Shreds intended for slot s MUST be sent no later than
SlotTime(s) + PROPOSAL_DEADLINE_OFFSET.

3.3 Relay and Retransmit Stage

Each relay validates each received Shred message for slot s by checking that the
proposer_index is less than NUM_PROPOSERS, that the proposer_signature verifies
against the commitment using the proposer identity
Proposers[s][proposer_index], and that the witness verifies against the
commitment for the relay's assigned relay_index. A relay processes a shred only
if shred_index equals one of its assigned relay_index positions in Relays[s]. If
a validator appears multiple times in Relays[s], it MUST act independently for
each relay_index. If any check fails, the relay MUST discard the shred. If the
checks pass, the relay
stores the shred keyed by
(slot, proposer_index, shred_index) and MUST retransmit the same Shred message
unchanged over the network's standard broadcast mechanism. The relay MUST
create at most one attestation entry per (slot, proposer_index). If a relay
receives multiple valid shreds that imply different commitments for the same
slot and proposer_index, it MUST NOT attest to any of them. At the relay
deadline for slot s, which is SlotTime(s) + RELAY_DEADLINE_OFFSET, each relay
constructs RelayAttestation v1 containing all valid proposer entries it
accepted for the slot, sorted by proposer_index, signs it, and sends it to
Leader[s]. Each relay MUST emit at most one
RelayAttestation per (slot, relay_index). If additional shreds arrive after it
has broadcast its attestation for that relay_index, it MUST NOT issue another
RelayAttestation for that (slot, relay_index). It MAY retransmit such late
shreds but MUST NOT add them to an attestation. The relay MUST include the
proposer_signature received in each entry so that other nodes can verify the
commitment without contacting the proposer.

3.4 Consensus Leader Stage

The leader collects RelayAttestation messages until its aggregation deadline at
SlotTime(s) + AGGREGATION_DEADLINE_OFFSET.
For each relay message, the leader verifies the relay_signature and then checks
each proposer_signature inside it. The leader MUST discard a relay message if
relay_index is greater than or equal to NUM_RELAYS, if the relay_signature is
invalid when verified against Relays[s][relay_index], or if any
proposer_signature inside it is invalid when verified against
Proposers[s][proposer_index]. The leader
builds an AggregateAttestation containing all valid relay entries, sorted by
relay_index. Relay entries MUST be included byte-for-byte from the received
RelayAttestation messages; the leader MUST NOT modify or filter the per-proposer
lists. The leader then constructs a ConsensusBlock with the aggregate,
consensus_meta, and delayed_bankhash, signs it, and submits it to the consensus
protocol. delayed_bankhash is the bank hash for slot s - BANKHASH_DELAY_SLOTS,
or the genesis bank hash if s < BANKHASH_DELAY_SLOTS. The relay entry count is
the number of retained relay entries with distinct relay_index values. If the
number of relay entries in the aggregate is less
than ATTESTATION_THRESHOLD * NUM_RELAYS, the leader SHOULD submit an empty
ConsensusBlock with aggregate_len=0 and aggregate_bytes empty. Validators MUST
treat any non-empty block below this threshold as invalid, and MUST treat an
empty ConsensusBlock as an empty execution result.

3.5 Consensus Voting Stage

When a validator receives a ConsensusBlock for slot s, it MUST verify the
leader_signature, check that the leader_index matches Leader[s], and verify
delayed_bankhash against the local bank hash for slot s - BANKHASH_DELAY_SLOTS,
or the genesis bank hash if s < BANKHASH_DELAY_SLOTS. If any check fails, the
validator MUST NOT vote for the block. If aggregate_len is zero, the validator
MUST treat the block as an empty result and MAY skip AggregateAttestation
verification and proceed directly to compute the empty replay result. Otherwise,
the validator MUST verify each
relay_signature in the
AggregateAttestation. If relay_index is greater than or equal to NUM_RELAYS or a
relay_signature is invalid when verified against Relays[s][relay_index], the
validator MUST discard that relay entry. If multiple relay entries share the
same relay_index, the validator MUST discard all entries for that relay_index.
The validator MUST verify each
proposer_signature inside the remaining relay entries, and if proposer_index is
greater than or equal to NUM_PROPOSERS or any proposer_signature inside a relay
entry is invalid when verified against Proposers[s][proposer_index], the
validator MUST discard that relay entry. The validator computes the implied
blocks by examining the AggregateAttestation. For each proposer_index in
Proposers[s], the validator collects all commitments attested by relays in the
aggregate. The relay attestation count for a proposer is the number of retained
relay entries with distinct relay_index values that include that proposer. If
the set of commitments contains more than one distinct value, the proposer is
treated as equivocating and MUST be excluded. If there is exactly one
commitment and the number of distinct relay attestations for it is at least
INCLUSION_THRESHOLD * NUM_RELAYS as rounded in Section 4, the proposer is
included with that commitment. For each included proposer, the validator counts
the number of locally stored shreds with distinct shred_index values that pass
witness verification for that commitment. If any included proposer has fewer
than RECONSTRUCTION_THRESHOLD * NUM_RELAYS valid shreds as rounded in Section 4,
the validator MUST NOT vote for the block. If all included proposers meet the
threshold, the validator MUST reconstruct and replay as defined in Section 3.6
to compute block_id. The validator then submits a consensus vote with
block_hash equal to block_id.

3.6 Reconstruct and Replay Stage

Validators reconstruct proposer batches for all included proposers either before
voting or after consensus output. For each proposer, reconstruction begins when
at least RECONSTRUCTION_THRESHOLD * NUM_RELAYS valid shreds are available.
The validator MUST select the set of DATA_SHREDS_PER_FEC_BLOCK shreds with the
lowest shred_index values among those that pass witness verification for the
commitment and have distinct shred_index values. If multiple different shreds
exist for the same (slot, proposer_index, shred_index), that shred_index MUST be
treated as unavailable. If decoding fails, the proposer batch is treated as
unavailable. The validator decodes the batch using the erasure code, re-encodes
it, and recomputes the commitment. If the recomputed commitment does not match
the included commitment, the proposer batch MUST be discarded. If any included
proposer batch is unavailable or discarded, the ConsensusBlock is invalid and
MUST NOT be voted on or replayed. A proposer batch that contains duplicate transactions,
where duplicates have identical serialized Transaction bytes, MUST be discarded.
After reconstruction, validators concatenate the transactions from the surviving
proposer batches ordered by proposer_index and then order them by ordering_fee
in descending order, treating missing ordering_fee as zero. If two transactions
have the same ordering_fee, their relative order MUST follow their order in the
concatenated proposer batches. The resulting ordering is equivalent to sorting
by the tuple (-ordering_fee, proposer_index, transaction_index_in_batch). The
protocol does not define cross-proposer
deduplication; replay follows the underlying transaction processing semantics
for already-processed transactions based on the transaction message hash and
recent blockhash. The resulting ordered transaction list is the execution output
for the slot. If consensus outputs an empty result for slot s, validators MUST
output an empty execution result for the slot.

4. System Parameters

The protocol uses system parameters that MUST be identical for all nodes and
MUST be set by genesis or a network-wide feature gate. These parameters include
NUM_PROPOSERS, NUM_RELAYS, ATTESTATION_THRESHOLD, INCLUSION_THRESHOLD,
RECONSTRUCTION_THRESHOLD, DATA_SHREDS_PER_FEC_BLOCK, CODING_SHREDS_PER_FEC_BLOCK,
MERKLE_PROOF_ENTRY_BYTES, WITNESS_LEN, SHRED_DATA_BYTES, SHRED_MESSAGE_BYTES,
MAX_CONSENSUS_META_BYTES, BANKHASH_DELAY_SLOTS, PROPOSAL_DEADLINE_OFFSET,
RELAY_DEADLINE_OFFSET, and AGGREGATION_DEADLINE_OFFSET. The recommended values
for this version are NUM_PROPOSERS=16, NUM_RELAYS=200,
ATTESTATION_THRESHOLD=0.6, INCLUSION_THRESHOLD=0.4,
RECONSTRUCTION_THRESHOLD=0.2, DATA_SHREDS_PER_FEC_BLOCK=40,
CODING_SHREDS_PER_FEC_BLOCK=160, MERKLE_PROOF_ENTRY_BYTES=20, WITNESS_LEN=8,
SHRED_DATA_BYTES=952, SHRED_MESSAGE_BYTES=1225, and MAX_CONSENSUS_META_BYTES=4096.
BANKHASH_DELAY_SLOTS and the deadline offsets are consensus-defined parameters
and are not assigned recommended values in this document.
The erasure coding
parameters MUST satisfy DATA_SHREDS_PER_FEC_BLOCK plus
CODING_SHREDS_PER_FEC_BLOCK equals NUM_RELAYS. The erasure coding rate is
defined as RECONSTRUCTION_THRESHOLD=DATA_SHREDS_PER_FEC_BLOCK/NUM_RELAYS.
INCLUSION_THRESHOLD SHOULD be greater than or equal to
RECONSTRUCTION_THRESHOLD so that an included proposer is reconstructable with
high probability. SHRED_MESSAGE_BYTES MUST be supported by the transport
without protocol-level fragmentation. When a threshold is applied to a relay
count, the required count is the smallest integer greater than or equal to
threshold multiplied by NUM_RELAYS. BANKHASH_DELAY_SLOTS MUST be a non-negative
integer. PROPOSAL_DEADLINE_OFFSET, RELAY_DEADLINE_OFFSET, and
AGGREGATION_DEADLINE_OFFSET are non-negative durations that MUST satisfy
PROPOSAL_DEADLINE_OFFSET <= RELAY_DEADLINE_OFFSET <= AGGREGATION_DEADLINE_OFFSET
<= SLOT_DURATION.

5. Schedules and Indices

For each epoch, every validator MUST derive deterministic, stake-weighted
schedules for proposers, relays, and consensus leaders using the same stake set
and the same leader schedule algorithm used by the consensus protocol. For the
stake-weighted schedule, validators form a keyed stake list from the epoch stake
set. When the consensus leader schedule is vote-keyed, keyed stakes are the vote
account public keys with stake greater than zero; otherwise keyed stakes are the
validator identity public keys with stake greater than zero. The keyed stakes
list is sorted by stake in descending order and then by public key in descending
order, and duplicate public keys are removed after sorting. The schedule is
constructed by sampling from a WeightedIndex distribution over the sorted stake
weights, where weights are u64 stake values, using a ChaChaRng seeded with 32
bytes. When vote-keyed stakes are used, each sampled vote account is mapped to
its node identity public key and the schedule list consists of these identity
keys. The schedule length is slots_in_epoch for the epoch. For the consensus leader
schedule, the seed is the epoch encoded as a little-endian u64 placed in the
first 8 bytes with the remaining bytes set to zero, matching Agave's leader
schedule. For proposer and relay schedules, the same algorithm is used with
domain-separated seeds computed as SHA-256("MCP-PROPOSER-SCHEDULE" ||
epoch_le_bytes) and SHA-256("MCP-RELAY-SCHEDULE" || epoch_le_bytes),
respectively, where epoch_le_bytes is the epoch encoded as a little-endian u64.
Let repeat be the consensus leader schedule repeat parameter
(NUM_CONSECUTIVE_LEADER_SLOTS in Agave). For each slot index i in
[0, slots_in_epoch - 1], if i mod repeat equals 0, sample a new key from the
distribution; otherwise reuse the previously sampled key. The resulting ordered
list of keys for the epoch is the schedule.

For each slot s, Proposers[s] is the ordered list of NUM_PROPOSERS identities
obtained by taking the next NUM_PROPOSERS entries from the proposer schedule
starting at the slot's index within the epoch, with wrap-around. Relays[s] is
defined the same way from the relay schedule. Leader[s] is the consensus leader
for slot s. A proposer index is the position of a validator in Proposers[s].
Proposers[s] and Relays[s] MAY contain duplicate identities, and a validator MAY
appear multiple times within a list or across lists. A relay index is the
position of a validator in Relays[s]. A leader index is the position of the
leader in the consensus leader schedule for the slot. A validator index is the
position of the validator identity public key in the identity-keyed list formed
by mapping the keyed stake list in order to node identities for the epoch.
These indices are
slot-scoped and MUST be used in message formats. Equivocation and uniqueness
rules in this protocol are defined per (slot, proposer_index) and per
(slot, relay_index), not per validator identity.

6. Cryptographic Primitives

Hash denotes the 32-byte output of SHA-256. Signature denotes a 64-byte
Ed25519 signature. Public keys are 32-byte Ed25519 public keys. A Merkle
commitment is computed over the ordered list of NUM_RELAYS shreds with leaf
index i equal to shred_index i. The leaf hash for shred i is
SHA-256(MERKLE_HASH_PREFIX_LEAF || slot || proposer_index || i || shred_data),
where slot is encoded as a u64, proposer_index as a u32, i as a u32, and
shred_data is SHRED_DATA_BYTES bytes. MERKLE_HASH_PREFIX_LEAF is the
byte string 0x00 || "SOLANA_MERKLE_SHREDS_LEAF" and MERKLE_HASH_PREFIX_NODE is
0x01 || "SOLANA_MERKLE_SHREDS_NODE". A Merkle proof entry is the first
MERKLE_PROOF_ENTRY_BYTES bytes of a SHA-256 hash. Internal node hashes are
computed as SHA-256(MERKLE_HASH_PREFIX_NODE || left_entry || right_entry) where
left_entry and right_entry are the truncated proof entries of the child hashes.
When a level has an odd number of nodes, the last node is paired with itself.
Parent nodes are computed in order from index 0 upward by pairing (0,1), (2,3),
and so on at each level, and the parent index for a node is floor(i/2). The
proof for a leaf uses the sibling entry at index i xor 1 (or the node itself if
it is the last unpaired node), and the direction at each level is determined by
the least significant bit of the current index.
The commitment is the full 32-byte root hash of the tree. The witness is the
ordered list of sibling proof entries from leaf to root. The witness length is
WITNESS_LEN, which equals log2(NUM_RELAYS) when NUM_RELAYS is a power of two and
otherwise equals floor(log2(NUM_RELAYS)) + 1. A witness verifies if it
recomputes the commitment for the given index and leaf using the truncated
entries at each step.

Erasure coding uses Reed-Solomon over GF(2^8) with primitive polynomial 0x11d
and parameters N=NUM_RELAYS and K=DATA_SHREDS_PER_FEC_BLOCK. The encoding is
systematic. The payload bytes are partitioned into K shards of SHRED_DATA_BYTES
each, padding with zero bytes to fill the last shard if needed, and then N-K
parity shards are produced. Shard index i in [0, K-1] is the data shard i and
shard index i in [K, N-1] is the coding shard i-K. Decoding MUST use the lowest
K shard indices available and MUST treat missing shards as erasures.

Signature preimages are domain-separated. The domain strings are the ASCII byte
sequences "MCP-PROPOSER-COMMITMENT-V1", "MCP-RELAY-ATTESTATION-V1",
"MCP-CONSENSUS-BLOCK-V1", and "MCP-VOTE-V1". Each signature is computed as
Ed25519Sign(sk, domain || message_bytes) where message_bytes are defined in the
relevant message section.

7. Message Formats

This specification defines version value 1 for all messages that include a
version field. Messages with unknown versions MUST be rejected.

7.1. Transaction

A Transaction message is serialized as a sequence of fields in this order:
VersionByte (u8), LegacyHeader (u8, u8, u8), TransactionConfigMask (u32),
LifetimeSpecifier ([u8; 32]), NumInstructions (u8), NumAddresses (u8),
Addresses ([[u8; 32]] with length NumAddresses), ConfigValues ([[u8; 4]] with
length equal to the popcount of TransactionConfigMask), InstructionHeaders
([(u8, u8, u16)] with length NumInstructions), InstructionPayloads
([InstructionPayload] with length NumInstructions), and Signatures ([[u8; 64]]
with length NumRequiredSignatures). LegacyHeader is the triple
(num_required_signatures, num_readonly_signed, num_readonly_unsigned), and
NumRequiredSignatures refers to the first value in that triple. NumAddresses
MUST be greater than or equal to NumRequiredSignatures.
LifetimeSpecifier is the recent blockhash or durable nonce value as defined by
the underlying ledger rules.
TransactionConfigMask is a u32 bitmask that controls which config values are
present. Bit 0 controls inclusion_fee, bit 1 controls ordering_fee, bit 2
controls compute_unit_limit, bit 3 controls accounts_data_size_limit, bit 4
controls heap_size, and bit 5 controls target_proposer. When a bit is set, the
corresponding 4-byte value MUST appear in ascending bit order, and each value is
encoded as a little-endian u32. Each InstructionHeader is a tuple
(ProgramAccountIndex, NumInstructionAccounts, NumInstructionDataBytes). Each
InstructionPayload is the concatenation of InstructionAccountIndexes, a u8
array of length NumInstructionAccounts, and InstructionData, a u8 array of
length NumInstructionDataBytes. This protocol does not change the signature
semantics or instruction semantics beyond the additional config fields. The
transaction message to be signed is the byte sequence from VersionByte through
the end of InstructionPayloads. The transaction message hash is
SHA-256(transaction_message_bytes). Signatures[i] MUST verify against Addresses[i]
for 0 <= i < NumRequiredSignatures. The fee payer is Addresses[0]. The config
values have the following meanings and units: inclusion_fee and ordering_fee are
u32 lamport values, compute_unit_limit is a u32 compute unit budget,
accounts_data_size_limit is a u32 byte limit, heap_size is a u32 byte limit, and
target_proposer is a u32 proposer_index within the slot's Proposers list.
Mempool admission and proposer
selection policy are local. ordering_fee is used for deterministic ordering as
defined in Section 3.6. inclusion_fee and target_proposer are advisory and MUST
NOT be enforced during replay. Fee charging and account validation follow the
underlying ledger rules as described in Section 8.


Transaction Wire Format (variable length)
```text
+---------------------------+----------------------------------------+
| Field                     | Size (bytes)                           |
+---------------------------+----------------------------------------+
| VersionByte               | 1                                      |
| LegacyHeader              | 3                                      |
| TransactionConfigMask     | 4                                      |
| LifetimeSpecifier         | 32                                     |
| NumInstructions           | 1                                      |
| NumAddresses              | 1                                      |
| Addresses                 | 32 * NumAddresses                      |
| ConfigValues              | 4 * popcount(TransactionConfigMask)    |
| InstructionHeaders        | 4 * NumInstructions                    |
| InstructionPayloads       | sum over instructions of               |
|                           | (NumInstructionAccounts                |
|                           | + NumInstructionDataBytes)             |
| Signatures                | 64 * NumRequiredSignatures             |
+---------------------------+----------------------------------------+
```

7.2. Shred

A Shred message carries a single erasure-coded shred from a proposer. It is
serialized as slot (u64), proposer_index (u32), shred_index (u32), commitment
(32 bytes), shred_data (SHRED_DATA_BYTES bytes), witness_len (u8), witness
(witness_len consecutive MERKLE_PROOF_ENTRY_BYTES entries), and
proposer_signature (64 bytes).
shred_data is the erasure shard content for shred_index.
The proposer_signature is computed as Ed25519Sign over
"MCP-PROPOSER-COMMITMENT-V1" || slot || proposer_index || commitment. The
shred_index MUST be less than NUM_RELAYS and MUST equal the relay index for the
intended relay. The witness_len
value MUST equal WITNESS_LEN as defined in Section 4. The witness MUST be a
valid Merkle proof for shred_index under the commitment. Shred v1 has no
explicit version field; versioning is by protocol parameters and message size,
and any Shred message whose serialized length is not SHRED_MESSAGE_BYTES MUST
be rejected.


Shred Wire Format (fixed length)
```text
+-----------------+------------------------------+
| Field           | Size (bytes)                 |
+-----------------+------------------------------+
| slot            | 8                            |
| proposer_index  | 4                            |
| shred_index     | 4                            |
| commitment      | 32                           |
| shred_data      | SHRED_DATA_BYTES             |
| witness_len     | 1                            |
| witness         | MERKLE_PROOF_ENTRY_BYTES *   |
|                 | witness_len                  |
| proposer_sig    | 64                           |
+-----------------+------------------------------+
```

7.3. RelayAttestation

RelayAttestation v1 is serialized as version (u8), slot (u64), relay_index
(u32), entries_len (u8), entries (entries_len repetitions of proposer_index
u32, commitment 32 bytes, proposer_signature 64 bytes), and relay_signature
(64 bytes). entries_len MUST be less than or equal to NUM_PROPOSERS and MUST
match the number of entries. Entries MUST be sorted by proposer_index in
ascending order and MUST NOT contain duplicates. relay_index MUST be less than
NUM_RELAYS. The relay_signature is computed as Ed25519Sign over
"MCP-RELAY-ATTESTATION-V1" || version || slot || relay_index || entries_len ||
entries. Each proposer_signature MUST verify as defined in Section 7.2.


RelayAttestation Wire Format (variable length)
```text
+-----------------+----------------------------------------+
| Field           | Size (bytes)                           |
+-----------------+----------------------------------------+
| version         | 1                                      |
| slot            | 8                                      |
| relay_index     | 4                                      |
| entries_len     | 1                                      |
| entries         | entries_len * (4 + 32 + 64)            |
| relay_sig       | 64                                     |
+-----------------+----------------------------------------+
```

7.4. AggregateAttestation

AggregateAttestation v1 is serialized as version (u8), slot (u64),
leader_index (u32), relays_len (u16), and relay_entries. Each relay entry is
serialized as relay_index (u32), entries_len (u8), entries (entries_len
repetitions of proposer_index u32, commitment 32 bytes, proposer_signature
64 bytes), and relay_signature (64 bytes). Relay entries MUST be sorted by
relay_index in ascending order. The entries inside each relay entry MUST be
sorted by proposer_index in ascending order. entries_len MUST be less than or
equal to NUM_PROPOSERS. relays_len MUST be less than or equal to NUM_RELAYS and
MUST match the number of relay entries. Each
relay_signature MUST verify against the RelayAttestation v1 preimage using the
"MCP-RELAY-ATTESTATION-V1" domain, version=1, the AggregateAttestation slot
value, and the relay_index, entries_len, and entries bytes as encoded in the
relay entry. AggregateAttestation does not include a leader signature. The
canonical bytes of AggregateAttestation are the exact serialization defined in
this section.


AggregateAttestation Wire Format (variable length)
```text
+-----------------+------------------------------------------------+
| Field           | Size (bytes)                                   |
+-----------------+------------------------------------------------+
| version         | 1                                              |
| slot            | 8                                              |
| leader_index    | 4                                              |
| relays_len      | 2                                              |
| relay_entries   | sum of per-relay entries, see below            |
+-----------------+------------------------------------------------+
```

Relay Entry Wire Format (variable length)
```text
+-----------------+----------------------------------------+
| Field           | Size (bytes)                           |
+-----------------+----------------------------------------+
| relay_index     | 4                                      |
| entries_len     | 1                                      |
| entries         | entries_len * (4 + 32 + 64)            |
| relay_sig       | 64                                     |
+-----------------+----------------------------------------+
```

7.5. ConsensusBlock

ConsensusBlock v1 is the leader-broadcast message submitted to consensus. It is
serialized as version (u8), slot (u64), leader_index (u32), aggregate_len
(u32), aggregate_bytes (aggregate_len bytes containing the canonical
AggregateAttestation v1), consensus_meta_len (u32), consensus_meta
(consensus_meta_len bytes), delayed_bankhash (32 bytes), and leader_signature
(64 bytes). The leader_signature is computed over all preceding bytes in the
ConsensusBlock, prefixed by the "MCP-CONSENSUS-BLOCK-V1" domain. aggregate_len
MUST match the length of aggregate_bytes and the AggregateAttestation MUST
consume all aggregate_bytes with no trailing data. aggregate_len MUST be less
than or equal to MAX_AGGREGATE_BYTES, where MAX_AGGREGATE_BYTES is
1 + 8 + 4 + 2 + NUM_RELAYS * (4 + 1 + NUM_PROPOSERS * (4 + 32 + 64) + 64). If
aggregate_len is zero, aggregate_bytes MUST be empty. consensus_meta_len MUST be
less than or equal to MAX_CONSENSUS_META_BYTES. The consensus_meta field is an
opaque payload defined by the consensus protocol and MUST be interpreted
consistently by all validators. The block_id is the bank hash for slot s
computed by the underlying ledger rules after replay and freeze of the ordered
transaction log derived from aggregate_bytes. In Agave this is Bank::hash(),
computed from the parent bank hash, signature count, last_blockhash, accounts
hash, and any hard-fork mixins. block_id is the value used in consensus votes
and is not computed by hashing aggregate_bytes directly. This binds consensus to
aggregate_bytes because the replay log is deterministically derived from the
aggregate and any mismatch invalidates the block as specified in Section 3.6.

ConsensusBlock Wire Format (variable length)
```text
+-------------------+------------------------------+
| Field             | Size (bytes)                 |
+-------------------+------------------------------+
| version           | 1                            |
| slot              | 8                            |
| leader_index      | 4                            |
| aggregate_len     | 4                            |
| aggregate_bytes   | aggregate_len                |
| consensus_meta_len| 4                            |
| consensus_meta    | consensus_meta_len           |
| delayed_bankhash  | 32                           |
| leader_sig        | 64                           |
+-------------------+------------------------------+
```

7.6. Vote

A Vote message is serialized as slot (u64), validator_index (u32), block_hash
(32 bytes), vote_type (u8), timestamp (i64), and signature (64 bytes). The
block_hash field MUST equal block_id, which is the bank hash for the
corresponding slot. The vote_type encoding is defined by the underlying
consensus protocol and is not changed by MCP. validator_index MUST be less than
the length of the validator registry for the epoch. The signature is computed
as Ed25519Sign over "MCP-VOTE-V1" || slot || validator_index || block_hash ||
vote_type || timestamp and MUST verify against the validator identity public key
at validator_index.


Vote Wire Format
```text
+-----------------+------------------------------+
| Field           | Size (bytes)                 |
+-----------------+------------------------------+
| slot            | 8                            |
| validator_index | 4                            |
| block_hash      | 32                           |
| vote_type       | 1                            |
| timestamp       | 8                            |
| signature       | 64                           |
+-----------------+------------------------------+
```

8. Handling Fee Payer DOS

Because multiple proposers can include transactions from the same payer in a
single slot, fee validation MUST follow the underlying ledger rules in a
deterministic replay order. The fee payer is Addresses[0]. The base fee for a
transaction is lamports_per_signature multiplied by NumRequiredSignatures,
where lamports_per_signature is the fee rate associated with the
LifetimeSpecifier under the underlying ledger rules. A transaction is a durable
nonce transaction if its LifetimeSpecifier matches a valid nonce value and it
contains the standard nonce advance instruction; such transactions are subject
to the ledger's rent-exempt minimum balance rules for the nonce account. MCP does
not introduce additional fee charging beyond the ledger's existing rules.
Ordering_fee and inclusion_fee are not charged during replay. Duplicate
transactions are handled by the ledger's status cache keyed by message_hash and
recent blockhash and are rejected as AlreadyProcessed. Proposers and relays are
not required to perform balance checks; all fee sufficiency and rent checks are
performed during replay in the deterministic transaction order.

9. Bankless Leader Requirement

The leader and proposers MUST be able to produce and broadcast shreds without a
fully executing bank for the slot. Execution is deferred to replay after
consensus. Any implementation detail that requires execution or balance checks
before shred production MUST be removed or modified.

10. Error Handling and Security Considerations

Invalid messages MUST be discarded and MUST NOT advance protocol state. The
aggregate rules prevent a single equivocation from forcing inclusion; any
proposer with multiple commitments in the aggregate is excluded. Relays and
leaders are not trusted and their signatures only authenticate what they say
they saw. Validators MUST perform all signature and witness checks before
voting or replaying to avoid accepting unavailable or corrupted batches.
Malformed length fields, out-of-range indices, or duplicate proposer_index
entries within a relay entry MUST cause that relay entry to be discarded.
Multiple RelayAttestation messages with the same (slot, relay_index) are treated
as relay equivocation; validators MUST accept at most one valid relay entry for
that (slot, relay_index) and discard the rest. Proposer equivocation is detected
when multiple distinct commitments are attested for the same (slot,
proposer_index); such proposers are excluded from inclusion as specified in
Section 3.5.

11. Changelog

This revision clarifies that stages may be pipelined across slots without
changing per-slot rules, removes any prescriptive transaction prioritization
policy for proposers, and makes per-proposer resource division explicit. It also
adds a batch size bound tied to DATA_SHREDS_PER_FEC_BLOCK and SHRED_DATA_BYTES
so that each proposer encodes exactly one shred per relay and requires each
Shred message to carry its witness.

This revision further states that each relay emits at most one RelayAttestation
per (slot, relay_index), and it relaxes the schedule rules to permit duplicate
identities in proposer and relay lists when the underlying schedule produces
them.

This revision labels the non-MCP baseline diagram, defines validator identity
and schedule generation in terms of Agave's stake-weighted leader schedule
algorithm with domain-separated seeds, and fixes Shred v1 sizing by adopting
20-byte Merkle proof entries with fixed witness length. It also makes relay
attestation validation all-or-nothing, defines block_id as the Agave bank hash,
and specifies duplicate transaction handling within a proposer batch and
ordering_fee defaults during replay.

This revision tightens consensus-critical determinism by defining erasure coding
as systematic Reed-Solomon over GF(2^8), constraining payload size to
DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES, and requiring deterministic shard
selection during reconstruction. It specifies Merkle tree construction and proof
direction derivation, adds domain-separated signature preimages for all signed
messages, defines timing offsets and bankhash delay parameters, and clarifies
transaction ordering, replay, and vote semantics with explicit index checks and
aggregate length bounds.
