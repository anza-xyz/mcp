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


Constellation
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
trailing zero bytes added for padding MUST be ignored by decoders.

3.2 Proposal Stage

Each proposer collects pending transactions into a batch. Global block-level
constraints on compute units (CU) and loaded account data are divided among the
proposers. Proposers
SHOULD prioritize transactions based on inclusion fee. The proposer then encodes
the batch into NUM_RELAYS shreds using erasure coding with the parameters from
Section 4. Each shred has SHRED_DATA_BYTES bytes. The encoder MUST define shred
indices from 0 to NUM_RELAYS-1 and MUST output shreds in that order. The proposer
computes the Merkle commitment over all shreds, computes the witness for each
shred index, and signs the commitment. The proposer MUST send exactly one Shred
message to each relay in Relays[s], with shred_index equal to that relay's index,
and MUST NOT send conflicting commitments for the same slot.

3.3 Relay and Retransmit Stage

Each relay validates each received Shred message for slot s by checking that the
proposer_index is in Proposers[s], that the proposer_signature verifies against
the commitment, and that the witness verifies against the commitment for the
relay's own index. If any check fails, the relay MUST discard the shred. If the
checks pass, the relay stores the shred keyed by (slot, proposer_index,
shred_index) and MUST broadcast the same Shred message to all validators. The
relay MUST create at most one attestation entry per proposer per slot. If a
relay receives multiple valid shreds that imply different commitments for the
same proposer and slot, it SHOULD NOT attest to any of them. At the relay
deadline for slot s, each relay constructs RelayAttestation v1 containing all
valid proposer entries it accepted for the slot, sorted by proposer_index,
signs it, and sends it to Leader[s]. The relay MUST include the
proposer_signature received in each entry so that other nodes can verify the
commitment without contacting the proposer.

3.4 Consensus Leader Stage

The leader collects RelayAttestation messages until its aggregation deadline.
For each relay message, the leader verifies the relay_signature and then checks
each proposer_signature inside it. The leader MUST discard a relay message if
its relay_signature is invalid. The leader MUST ignore any entry with an invalid
proposer signature and MAY keep the remaining entries from that relay
attestation. The leader
builds an AggregateAttestation containing all valid relay entries, sorted by
relay_index. The leader MUST compute the block commitment used as block_id
according to the underlying ledger rules, and MUST include that commitment in
consensus_meta or another consensus-defined field that all validators can
verify. The leader then constructs a ConsensusBlock with the aggregate,
consensus_meta, and delayed_bankhash, signs it, and submits it to the consensus
protocol. If the number of relay entries in the aggregate is less
than ATTESTATION_THRESHOLD * NUM_RELAYS, the leader SHOULD submit an empty
consensus result instead of a block, and validators MUST treat any block below
this threshold as invalid.

3.5 Consensus Voting Stage

When a validator receives a ConsensusBlock for slot s, it MUST verify the
leader_signature, check that the leader_index matches Leader[s], and verify
delayed_bankhash against the local bank hash for the delayed slot defined by the
consensus protocol. If any check fails, the validator MUST NOT vote for the
block. The validator MUST verify each relay_signature and proposer_signature in
the AggregateAttestation and MUST ignore any relay entry that fails
verification. The validator computes the implied blocks by examining the
AggregateAttestation. For each proposer_index in Proposers[s], the validator
collects all commitments attested by relays in the aggregate. If the set of
commitments contains more than one distinct value, the proposer is treated as
equivocating and MUST be excluded. If there is exactly one commitment and the
number of distinct relay attestations for it is at least
INCLUSION_THRESHOLD * NUM_RELAYS, the proposer is included with that
commitment. For each included proposer, the validator counts the number of
locally stored shreds that pass witness verification for that commitment. If
any included proposer has fewer than RECONSTRUCTION_THRESHOLD * NUM_RELAYS valid
shreds, the validator MUST NOT vote for the block. If all included proposers
meet the threshold, the validator submits a consensus vote with block_hash equal
to block_id.

3.6 Reconstruct and Replay Stage

When consensus outputs a block for slot s, validators reconstruct proposer
batches for all included proposers. For each proposer, reconstruction begins
when at least RECONSTRUCTION_THRESHOLD * NUM_RELAYS valid shreds are available.
The validator decodes the batch using the erasure code, re-encodes it, and
recomputes the commitment. If the recomputed commitment does not match the
included commitment, the proposer batch MUST be discarded. After reconstruction,
validators concatenate the transactions from the surviving proposer batches and
order them by ordering_fee. If two transactions have the same ordering_fee,
their relative order MUST follow their order in the concatenated proposer
batches ordered by proposer_index. The resulting ordered transaction list is
the execution output for the slot. If consensus outputs an empty result for
slot s, validators MUST output an empty execution result for the slot.

4. System Parameters

The protocol uses system parameters that MUST be identical for all nodes and
MUST be set by genesis or a network-wide feature gate. These parameters include
NUM_PROPOSERS, NUM_RELAYS, ATTESTATION_THRESHOLD, INCLUSION_THRESHOLD,
RECONSTRUCTION_THRESHOLD, DATA_SHREDS_PER_FEC_BLOCK, CODING_SHREDS_PER_FEC_BLOCK,
and SHRED_DATA_BYTES. The recommended values for this version are
NUM_PROPOSERS=16, NUM_RELAYS=200, ATTESTATION_THRESHOLD=0.6,
INCLUSION_THRESHOLD=0.4, RECONSTRUCTION_THRESHOLD=0.2,
DATA_SHREDS_PER_FEC_BLOCK=40, and CODING_SHREDS_PER_FEC_BLOCK=160. The erasure
coding parameters MUST satisfy DATA_SHREDS_PER_FEC_BLOCK plus
CODING_SHREDS_PER_FEC_BLOCK equals NUM_RELAYS. The erasure coding rate is
defined as RECONSTRUCTION_THRESHOLD=DATA_SHREDS_PER_FEC_BLOCK/NUM_RELAYS.
INCLUSION_THRESHOLD SHOULD be greater than or equal to
RECONSTRUCTION_THRESHOLD so that an included proposer is reconstructable with
high probability. SHRED_DATA_BYTES MUST be chosen so that a full Shred message
fits the chosen transport MTU or the transport MUST support fragmentation.
When a threshold is applied to a relay count, the required count is the
smallest integer greater than or equal to threshold multiplied by NUM_RELAYS.

5. Schedules and Indices

For each epoch, every validator MUST derive deterministic, stake-weighted
schedules for proposers, relays, and consensus leaders using the same stake set
and the same leader schedule algorithm used by the consensus protocol. The
proposer and relay schedules MUST use domain separation distinct from the leader
schedule so that the roles are independently randomized. The schedules MUST
produce an ordered list of validator identities for the epoch. For each slot s,
Proposers[s] is the ordered list of NUM_PROPOSERS identities obtained by taking
the next NUM_PROPOSERS entries from the proposer schedule starting at the slot's
index within the epoch, with wrap-around. Relays[s] is defined the same way from
the relay schedule. Leader[s] is the consensus leader for slot s. A proposer
index is the position of a validator in Proposers[s]. Proposers[s] and
Relays[s] MUST contain distinct identities. A relay index is the
position of a validator in Relays[s]. A leader index is the position of the
leader in the consensus leader schedule for the slot. These indices are
slot-scoped and MUST be used in message formats.

6. Cryptographic Primitives

Hash denotes the 32-byte output of SHA-256. Signature denotes a 64-byte
Ed25519 signature. Public keys are 32-byte Ed25519 public keys. A Merkle
commitment is computed over the ordered list of NUM_RELAYS shreds. The leaf
hash for shred i is SHA-256(0x00 || slot || proposer_index || i || shred_data),
where slot is encoded as a u64, proposer_index as a u32, i as a u32, and
shred_data is SHRED_DATA_BYTES bytes. Internal node hashes are computed as
SHA-256(0x01 || left || right). When a level has an odd number of nodes, the
last node is paired with itself. The commitment is the root hash of the tree.
The witness is the ordered list of sibling hashes from leaf to root. The
expected witness length is ceil(log2(NUM_RELAYS)). A witness verifies if it
recomputes the commitment for the given index and leaf.

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
NumRequiredSignatures refers to the first value in that triple.
TransactionConfigMask is a u32 bitmask that controls which config values are
present. Bit 0 controls inclusion_fee, bit 1 controls ordering_fee, bit 2
controls compute_unit_limit, bit 3 controls accounts_data_size_limit, bit 4
controls heap_size, and bit 5 controls target_proposer. When a bit is set, the
corresponding 4-byte value MUST appear in ascending bit order. Each
InstructionHeader is a tuple (ProgramAccountIndex, NumInstructionAccounts,
NumInstructionDataBytes). Each InstructionPayload is the concatenation of
InstructionAccountIndexes, a u8 array of length NumInstructionAccounts, and
InstructionData, a u8 array of length NumInstructionDataBytes. This protocol
does not change the signature semantics or instruction semantics beyond the
additional config fields. The fee and targeting fields are interpreted by local
policy except where constrained by Section 8.


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
(witness_len consecutive 32-byte hashes), and proposer_signature (64 bytes).
The proposer_signature is computed by the proposer over the 32-byte commitment.
The shred_index MUST equal the relay index for the intended relay. The
witness_len value MUST match the Merkle proof length implied by NUM_RELAYS and
the Merkle construction in Section 6. The witness MUST be a valid Merkle proof
for shred_index under the commitment.


Shred Wire Format (variable length)
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
| witness         | 32 * witness_len             |
| proposer_sig    | 64                           |
+-----------------+------------------------------+
```

7.3. RelayAttestation

RelayAttestation v1 is serialized as version (u8), slot (u64), relay_index
(u32), entries_len (u8), entries (entries_len repetitions of proposer_index
u32, commitment 32 bytes, proposer_signature 64 bytes), and relay_signature
(64 bytes). Entries MUST be sorted by proposer_index in ascending order and
MUST NOT contain duplicates. The relay_signature is computed over the bytes of
version, slot, relay_index, entries_len, and entries in that order.


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
sorted by proposer_index in ascending order. AggregateAttestation does not
include a leader signature. The canonical bytes of AggregateAttestation are the
exact serialization defined in this section.


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
ConsensusBlock. The consensus_meta field is an opaque payload defined by the
consensus protocol and MUST be interpreted consistently by all validators. The
block_id is defined as the block commitment produced by the underlying ledger
rules and carried in consensus_meta or another consensus-defined field. It is
the value used in consensus votes and is not computed by hashing
aggregate_bytes.

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
block_hash field MUST equal block_id for the corresponding ConsensusBlock. The
vote_type encoding is defined by the underlying consensus protocol and is not
changed by MCP.


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
single slot, fee validation MUST be conservative. A payer MUST be able to cover
NUM_PROPOSERS times the base fee for standard transactions and NUM_PROPOSERS
times the base fee plus the minimum rent for nonce transactions. Implementations
MUST track per-slot cumulative fee commitments per payer so that a payer cannot
be over-committed across proposer batches. Replay MUST proceed in two passes. In
the first pass, validators MUST deduct fees for all transactions that pass
signature and basic validity checks, even if later execution fails. In the
second pass, validators apply state transitions without re-charging fees.

9. Bankless Leader Requirement

The leader and proposers MUST be able to produce and broadcast shreds without a
fully executing bank for the slot. Execution is deferred to replay after
consensus. Any implementation detail that requires execution before shred
production MUST be removed or modified.

10. Error Handling and Security Considerations

Invalid messages MUST be discarded and MUST NOT advance protocol state. The
aggregate rules prevent a single equivocation from forcing inclusion; any
proposer with multiple commitments in the aggregate is excluded. Relays and
leaders are not trusted and their signatures only authenticate what they say
they saw. Validators MUST perform all signature and witness checks before 
voting or replaying to avoid accepting unavailable or corrupted batches.
