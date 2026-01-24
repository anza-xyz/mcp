//! MCP (Multiple Concurrent Proposers) Shred Wire Format
//!
//! This module implements the `McpShredV1` wire format as defined in the MCP specification §7.2.
//! MCP shreds have a variable-length format:
//!
//! | Field | Type | Bytes |
//! |---|---|---:|
//! | slot | u64 | 8 |
//! | proposer_index | u32 | 4 |
//! | shred_index | u32 | 4 |
//! | commitment | [u8; 32] | 32 |
//! | shred_data | [u8; SHRED_DATA_BYTES] | SHRED_DATA_BYTES |
//! | witness_len | u8 | 1 |
//! | witness | [u8; 32 * witness_len] | 32 * witness_len |
//! | proposer_signature | [u8; 64] | 64 |
//!
//! Per spec §7.2: witness uses full 32-byte hashes, witness_len = ceil(log2(NUM_RELAYS))

use {
    crate::mcp::{NUM_PROPOSERS, NUM_RELAYS},
    solana_clock::Slot,
    solana_pubkey::Pubkey,
    solana_signature::{Signature, SIGNATURE_BYTES},
    std::io::{self, Read, Write},
    thiserror::Error,
};

/// Size of the shred payload (transaction data) in bytes.
/// Per spec §4: SHRED_DATA_BYTES is a system parameter.
pub const SHRED_DATA_BYTES: usize = 1024;

/// Alias for backward compatibility.
pub const MCP_SHRED_PAYLOAD_BYTES: usize = SHRED_DATA_BYTES;

/// Size of the Merkle root/commitment in bytes.
pub const MERKLE_ROOT_BYTES: usize = 32;

/// Size of each Merkle proof entry in bytes (full 32-byte hash per spec §7.2).
pub const MERKLE_PROOF_ENTRY_BYTES: usize = 32;

/// Number of Merkle proof entries (tree depth = ceil(log2(NUM_RELAYS))).
/// With NUM_RELAYS=200, this is ceil(log2(200)) = 8.
pub const MERKLE_PROOF_ENTRIES: usize = 8;

/// Total size of the Merkle witness in bytes.
pub const MERKLE_PROOF_BYTES: usize = MERKLE_PROOF_ENTRY_BYTES * MERKLE_PROOF_ENTRIES; // 256

/// Fixed header size before shred_data: slot(8) + proposer_index(4) + shred_index(4) + commitment(32)
const SHRED_HEADER_BYTES: usize = 8 + 4 + 4 + 32; // 48

/// Total size of an MCP shred in bytes (variable, but fixed for given parameters).
/// header(48) + shred_data(1024) + witness_len(1) + witness(256) + signature(64) = 1393
pub const MCP_SHRED_TOTAL_BYTES: usize = SHRED_HEADER_BYTES + SHRED_DATA_BYTES + 1 + MERKLE_PROOF_BYTES + SIGNATURE_BYTES;

// Offset constants for field access
const OFFSET_SLOT: usize = 0;
const OFFSET_PROPOSER_INDEX: usize = 8;
const OFFSET_SHRED_INDEX: usize = 12;
const OFFSET_COMMITMENT: usize = 16;
const OFFSET_SHRED_DATA: usize = 48;
const OFFSET_WITNESS_LEN: usize = OFFSET_SHRED_DATA + SHRED_DATA_BYTES; // 1072
const OFFSET_WITNESS: usize = OFFSET_WITNESS_LEN + 1; // 1073
const OFFSET_SIGNATURE: usize = OFFSET_WITNESS + MERKLE_PROOF_BYTES; // 1329

// Verify total size at compile time
const _: () = assert!(
    OFFSET_SIGNATURE + SIGNATURE_BYTES == MCP_SHRED_TOTAL_BYTES,
    "MCP shred size calculation mismatch"
);

/// Errors that can occur when parsing MCP shreds.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum McpShredError {
    #[error("Invalid payload size: expected {MCP_SHRED_TOTAL_BYTES}, got {0}")]
    InvalidSize(usize),

    #[error("Invalid proposer index: {0} >= {NUM_PROPOSERS}")]
    InvalidProposerIndex(u32),

    #[error("Invalid shred index: {0} >= {NUM_RELAYS}")]
    InvalidShredIndex(u32),

    #[error("Invalid witness length: expected {MERKLE_PROOF_ENTRIES}, got {0}")]
    InvalidWitnessLen(u8),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Merkle proof verification failed")]
    MerkleVerificationFailed,

    #[error("IO error: {0}")]
    Io(String),
}

impl From<io::Error> for McpShredError {
    fn from(err: io::Error) -> Self {
        McpShredError::Io(err.to_string())
    }
}

/// MCP Shred V1 wire format.
///
/// This is the on-wire representation of an MCP shred. The shred contains:
/// - Slot and proposer identification
/// - Erasure-coded payload data
/// - Merkle commitment and witness for data integrity
/// - Proposer signature for authenticity
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpShredV1 {
    /// The slot this shred belongs to.
    pub slot: Slot,

    /// Index of the proposer in the slot's proposer committee [0, NUM_PROPOSERS-1].
    pub proposer_index: u32,

    /// Index of this shred within the proposer's payload [0, NUM_RELAYS-1].
    /// For unicast to relays, this equals the target relay's index.
    pub shred_index: u32,

    /// Merkle root commitment over the full shred vector.
    /// All shreds from the same proposer in the same slot share this commitment.
    pub commitment: [u8; MERKLE_ROOT_BYTES],

    /// Erasure-coded payload data.
    pub shred_data: [u8; SHRED_DATA_BYTES],

    /// Merkle witness (full 32-byte hash entries per spec §7.2).
    /// Contains `MERKLE_PROOF_ENTRIES` siblings along the path from leaf to root.
    pub witness: [[u8; MERKLE_PROOF_ENTRY_BYTES]; MERKLE_PROOF_ENTRIES],

    /// Proposer's signature over commitment (per spec §5.2).
    pub proposer_signature: Signature,
}

impl Default for McpShredV1 {
    fn default() -> Self {
        Self {
            slot: 0,
            proposer_index: 0,
            shred_index: 0,
            commitment: [0u8; MERKLE_ROOT_BYTES],
            shred_data: [0u8; SHRED_DATA_BYTES],
            witness: [[0u8; MERKLE_PROOF_ENTRY_BYTES]; MERKLE_PROOF_ENTRIES],
            proposer_signature: Signature::default(),
        }
    }
}

impl McpShredV1 {
    /// Create a new MCP shred with the given parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        slot: Slot,
        proposer_index: u32,
        shred_index: u32,
        commitment: [u8; MERKLE_ROOT_BYTES],
        shred_data: [u8; SHRED_DATA_BYTES],
        witness: [[u8; MERKLE_PROOF_ENTRY_BYTES]; MERKLE_PROOF_ENTRIES],
        proposer_signature: Signature,
    ) -> Self {
        Self {
            slot,
            proposer_index,
            shred_index,
            commitment,
            shred_data,
            witness,
            proposer_signature,
        }
    }

    /// Deserialize an MCP shred from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, McpShredError> {
        if data.len() != MCP_SHRED_TOTAL_BYTES {
            return Err(McpShredError::InvalidSize(data.len()));
        }

        let slot = u64::from_le_bytes(
            data[OFFSET_SLOT..OFFSET_SLOT + 8]
                .try_into()
                .expect("slice length checked"),
        );

        let proposer_index = u32::from_le_bytes(
            data[OFFSET_PROPOSER_INDEX..OFFSET_PROPOSER_INDEX + 4]
                .try_into()
                .expect("slice length checked"),
        );
        if proposer_index >= NUM_PROPOSERS as u32 {
            return Err(McpShredError::InvalidProposerIndex(proposer_index));
        }

        let shred_index = u32::from_le_bytes(
            data[OFFSET_SHRED_INDEX..OFFSET_SHRED_INDEX + 4]
                .try_into()
                .expect("slice length checked"),
        );
        if shred_index >= NUM_RELAYS as u32 {
            return Err(McpShredError::InvalidShredIndex(shred_index));
        }

        let commitment: [u8; MERKLE_ROOT_BYTES] = data
            [OFFSET_COMMITMENT..OFFSET_COMMITMENT + MERKLE_ROOT_BYTES]
            .try_into()
            .expect("slice length checked");

        let shred_data: [u8; SHRED_DATA_BYTES] = data
            [OFFSET_SHRED_DATA..OFFSET_SHRED_DATA + SHRED_DATA_BYTES]
            .try_into()
            .expect("slice length checked");

        let witness_len = data[OFFSET_WITNESS_LEN];
        if witness_len != MERKLE_PROOF_ENTRIES as u8 {
            return Err(McpShredError::InvalidWitnessLen(witness_len));
        }

        let mut witness = [[0u8; MERKLE_PROOF_ENTRY_BYTES]; MERKLE_PROOF_ENTRIES];
        for (i, entry) in witness.iter_mut().enumerate() {
            let start = OFFSET_WITNESS + i * MERKLE_PROOF_ENTRY_BYTES;
            entry.copy_from_slice(&data[start..start + MERKLE_PROOF_ENTRY_BYTES]);
        }

        let signature_bytes: [u8; SIGNATURE_BYTES] = data
            [OFFSET_SIGNATURE..OFFSET_SIGNATURE + SIGNATURE_BYTES]
            .try_into()
            .expect("slice length checked");
        let proposer_signature = Signature::from(signature_bytes);

        Ok(Self {
            slot,
            proposer_index,
            shred_index,
            commitment,
            shred_data,
            witness,
            proposer_signature,
        })
    }

    /// Serialize the MCP shred to a byte vector.
    pub fn to_bytes(&self) -> [u8; MCP_SHRED_TOTAL_BYTES] {
        let mut buf = [0u8; MCP_SHRED_TOTAL_BYTES];
        self.write_to_slice(&mut buf);
        buf
    }

    /// Write the MCP shred to a mutable slice.
    /// Panics if the slice is smaller than `MCP_SHRED_TOTAL_BYTES`.
    pub fn write_to_slice(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= MCP_SHRED_TOTAL_BYTES,
            "buffer too small for MCP shred"
        );

        buf[OFFSET_SLOT..OFFSET_SLOT + 8].copy_from_slice(&self.slot.to_le_bytes());
        buf[OFFSET_PROPOSER_INDEX..OFFSET_PROPOSER_INDEX + 4]
            .copy_from_slice(&self.proposer_index.to_le_bytes());
        buf[OFFSET_SHRED_INDEX..OFFSET_SHRED_INDEX + 4]
            .copy_from_slice(&self.shred_index.to_le_bytes());
        buf[OFFSET_COMMITMENT..OFFSET_COMMITMENT + MERKLE_ROOT_BYTES]
            .copy_from_slice(&self.commitment);
        buf[OFFSET_SHRED_DATA..OFFSET_SHRED_DATA + SHRED_DATA_BYTES]
            .copy_from_slice(&self.shred_data);
        buf[OFFSET_WITNESS_LEN] = MERKLE_PROOF_ENTRIES as u8;
        for (i, entry) in self.witness.iter().enumerate() {
            let start = OFFSET_WITNESS + i * MERKLE_PROOF_ENTRY_BYTES;
            buf[start..start + MERKLE_PROOF_ENTRY_BYTES].copy_from_slice(entry);
        }
        buf[OFFSET_SIGNATURE..OFFSET_SIGNATURE + SIGNATURE_BYTES]
            .copy_from_slice(self.proposer_signature.as_ref());
    }

    /// Serialize the shred to a writer.
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.to_bytes())
    }

    /// Deserialize a shred from a reader.
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, McpShredError> {
        let mut buf = [0u8; MCP_SHRED_TOTAL_BYTES];
        reader.read_exact(&mut buf)?;
        Self::from_bytes(&buf)
    }

    /// Returns the message that should be signed by the proposer.
    ///
    /// Per MCP spec §5.2:
    /// ```text
    /// proposer_sig_msg = ASCII("mcp:commitment:v1") || commitment32
    /// ```
    /// The commitment already binds to slot/proposer because the payload header
    /// is inside the committed RS shards.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(17 + 32);
        msg.extend_from_slice(b"mcp:commitment:v1");
        msg.extend_from_slice(&self.commitment);
        msg
    }

    /// Verify the proposer signature.
    pub fn verify_signature(&self, proposer_pubkey: &Pubkey) -> bool {
        let msg = self.signing_message();
        self.proposer_signature.verify(proposer_pubkey.as_ref(), &msg)
    }

    /// Get the relay index that should receive this shred.
    /// Per MCP spec, shred_index equals the target relay's index.
    pub fn target_relay_index(&self) -> u16 {
        self.shred_index as u16
    }

    /// Check if this shred's index matches the expected relay index.
    pub fn is_for_relay(&self, relay_index: u16) -> bool {
        self.shred_index == relay_index as u32
    }

    /// Verify the Merkle witness for this shred.
    ///
    /// Per MCP spec §6: Verify that the Merkle witness for shred_data at
    /// index shred_index yields the commitment.
    pub fn verify_merkle_witness(&self) -> bool {
        use crate::mcp_merkle::{MerkleProof, HASH_SIZE, PROOF_ENTRIES};

        // The shred_index % 256 gives the leaf index (tree has 256 leaves)
        let leaf_index = (self.shred_index % 256) as u8;

        // Convert the witness to the format expected by MerkleProof
        let mut siblings = [[0u8; HASH_SIZE]; PROOF_ENTRIES];
        for (i, entry) in self.witness.iter().enumerate() {
            siblings[i] = *entry;
        }

        let proof = MerkleProof::new(leaf_index, siblings);
        let commitment = solana_hash::Hash::new_from_array(self.commitment);

        proof.verify(&commitment, &self.shred_data)
    }
}

// ============================================================================
// Wire format extraction helpers (for packet processing without full parsing)
// ============================================================================

/// Extract the slot from an MCP shred payload without full parsing.
#[inline]
pub fn get_mcp_slot(data: &[u8]) -> Option<Slot> {
    if data.len() < OFFSET_SLOT + 8 {
        return None;
    }
    let bytes: [u8; 8] = data[OFFSET_SLOT..OFFSET_SLOT + 8].try_into().ok()?;
    Some(Slot::from_le_bytes(bytes))
}

/// Extract the proposer index from an MCP shred payload without full parsing.
#[inline]
pub fn get_mcp_proposer_index(data: &[u8]) -> Option<u32> {
    if data.len() < OFFSET_PROPOSER_INDEX + 4 {
        return None;
    }
    let bytes: [u8; 4] = data[OFFSET_PROPOSER_INDEX..OFFSET_PROPOSER_INDEX + 4]
        .try_into()
        .ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Extract the shred index from an MCP shred payload without full parsing.
#[inline]
pub fn get_mcp_shred_index(data: &[u8]) -> Option<u32> {
    if data.len() < OFFSET_SHRED_INDEX + 4 {
        return None;
    }
    let bytes: [u8; 4] = data[OFFSET_SHRED_INDEX..OFFSET_SHRED_INDEX + 4]
        .try_into()
        .ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Extract the commitment from an MCP shred payload without full parsing.
#[inline]
pub fn get_mcp_commitment(data: &[u8]) -> Option<[u8; MERKLE_ROOT_BYTES]> {
    if data.len() < OFFSET_COMMITMENT + MERKLE_ROOT_BYTES {
        return None;
    }
    data[OFFSET_COMMITMENT..OFFSET_COMMITMENT + MERKLE_ROOT_BYTES]
        .try_into()
        .ok()
}

/// Extract the signature from an MCP shred payload without full parsing.
#[inline]
pub fn get_mcp_signature(data: &[u8]) -> Option<Signature> {
    if data.len() < OFFSET_SIGNATURE + SIGNATURE_BYTES {
        return None;
    }
    let bytes: [u8; SIGNATURE_BYTES] = data[OFFSET_SIGNATURE..OFFSET_SIGNATURE + SIGNATURE_BYTES]
        .try_into()
        .ok()?;
    Some(Signature::from(bytes))
}

/// Check if a packet could be an MCP shred based on size and format validation.
///
/// Per MCP spec §7.2, MCP shreds have a variable-length format determined by
/// SHRED_DATA_BYTES and witness_len. For current parameters this is 1393 bytes.
/// We validate both the size and the witness_len field to distinguish
/// MCP shreds from legacy shreds.
#[inline]
pub fn is_mcp_shred_packet(data: &[u8]) -> bool {
    if data.len() != MCP_SHRED_TOTAL_BYTES {
        return false;
    }
    // Validate witness_len field per spec - must be MERKLE_PROOF_ENTRIES (8)
    // This provides format validation beyond just size checking
    data[OFFSET_WITNESS_LEN] == MERKLE_PROOF_ENTRIES as u8
}

/// Get the shred data payload range.
#[inline]
pub const fn get_mcp_shred_data_range() -> std::ops::Range<usize> {
    OFFSET_SHRED_DATA..OFFSET_SHRED_DATA + SHRED_DATA_BYTES
}

/// Get the witness range.
#[inline]
pub const fn get_mcp_witness_range() -> std::ops::Range<usize> {
    OFFSET_WITNESS..OFFSET_WITNESS + MERKLE_PROOF_BYTES
}

/// Get the signature range.
#[inline]
pub const fn get_mcp_signature_range() -> std::ops::Range<usize> {
    OFFSET_SIGNATURE..OFFSET_SIGNATURE + SIGNATURE_BYTES
}

// ============================================================================
// Relay Attestation V1 Wire Format (MCP spec §6.2)
// ============================================================================

/// An entry in a relay attestation, attesting to a single proposer's commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationEntryV1 {
    /// Index of the proposer being attested [0, NUM_PROPOSERS-1].
    pub proposer_index: u32,
    /// The commitment (Merkle root) the relay received from this proposer.
    pub commitment: [u8; MERKLE_ROOT_BYTES],
    /// The proposer's signature over commitment (per spec §5.2).
    pub proposer_signature: Signature,
}

impl AttestationEntryV1 {
    /// Size of a serialized attestation entry in bytes.
    pub const SIZE: usize = 4 + MERKLE_ROOT_BYTES + SIGNATURE_BYTES; // 4 + 32 + 64 = 100

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.proposer_index.to_le_bytes());
        buf[4..36].copy_from_slice(&self.commitment);
        buf[36..100].copy_from_slice(self.proposer_signature.as_ref());
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, McpShredError> {
        if data.len() < Self::SIZE {
            return Err(McpShredError::InvalidSize(data.len()));
        }
        let proposer_index = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if proposer_index >= NUM_PROPOSERS as u32 {
            return Err(McpShredError::InvalidProposerIndex(proposer_index));
        }
        let commitment: [u8; MERKLE_ROOT_BYTES] = data[4..36].try_into().unwrap();
        let proposer_signature = Signature::from(<[u8; 64]>::try_from(&data[36..100]).unwrap());
        Ok(Self {
            proposer_index,
            commitment,
            proposer_signature,
        })
    }
}

/// Relay Attestation V1 wire format (MCP spec §6.2).
///
/// A relay sends this to the slot leader to attest to the shreds it received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAttestationV1 {
    /// The slot this attestation is for.
    pub slot: Slot,
    /// The relay's index in the slot's relay committee [0, NUM_RELAYS-1].
    pub relay_index: u32,
    /// The attestation entries (one per verified proposer).
    pub entries: Vec<AttestationEntryV1>,
    /// The relay's signature over the attestation.
    pub relay_signature: Signature,
}

impl RelayAttestationV1 {
    /// Maximum number of attestation entries (one per proposer).
    pub const MAX_ENTRIES: usize = NUM_PROPOSERS as usize;

    /// Create a new relay attestation.
    pub fn new(
        slot: Slot,
        relay_index: u32,
        entries: Vec<AttestationEntryV1>,
        relay_signature: Signature,
    ) -> Self {
        Self {
            slot,
            relay_index,
            entries,
            relay_signature,
        }
    }

    /// Returns the message that should be signed by the relay.
    ///
    /// Per MCP spec §6.2:
    /// ```text
    /// relay_sig_msg = ASCII("mcp:relay-attestation:v1") || serialize_without_relay_signature(attestation)
    /// ```
    pub fn signing_message(&self) -> Vec<u8> {
        let prefix = b"mcp:relay-attestation:v1";
        let body_size = 8 + 4 + 1 + self.entries.len() * AttestationEntryV1::SIZE;
        let mut msg = Vec::with_capacity(prefix.len() + body_size);
        msg.extend_from_slice(prefix);
        msg.extend_from_slice(&self.slot.to_le_bytes());
        msg.extend_from_slice(&self.relay_index.to_le_bytes());
        msg.push(self.entries.len() as u8);
        for entry in &self.entries {
            msg.extend_from_slice(&entry.to_bytes());
        }
        msg
    }

    /// Verify the relay signature.
    pub fn verify_signature(&self, relay_pubkey: &Pubkey) -> bool {
        let msg = self.signing_message();
        self.relay_signature.verify(relay_pubkey.as_ref(), &msg)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = 8 + 4 + 1 + self.entries.len() * AttestationEntryV1::SIZE + SIGNATURE_BYTES;
        let mut buf = Vec::with_capacity(size);
        buf.extend_from_slice(&self.slot.to_le_bytes());
        buf.extend_from_slice(&self.relay_index.to_le_bytes());
        buf.push(self.entries.len() as u8);
        for entry in &self.entries {
            buf.extend_from_slice(&entry.to_bytes());
        }
        buf.extend_from_slice(self.relay_signature.as_ref());
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, McpShredError> {
        if data.len() < 8 + 4 + 1 + SIGNATURE_BYTES {
            return Err(McpShredError::InvalidSize(data.len()));
        }
        let slot = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let relay_index = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if relay_index >= NUM_RELAYS as u32 {
            return Err(McpShredError::InvalidShredIndex(relay_index));
        }
        let num_entries = data[12] as usize;
        if num_entries > Self::MAX_ENTRIES {
            return Err(McpShredError::InvalidProposerIndex(num_entries as u32));
        }
        let expected_size = 13 + num_entries * AttestationEntryV1::SIZE + SIGNATURE_BYTES;
        if data.len() < expected_size {
            return Err(McpShredError::InvalidSize(data.len()));
        }
        let mut entries = Vec::with_capacity(num_entries);
        let mut offset = 13;
        for _ in 0..num_entries {
            let entry = AttestationEntryV1::from_bytes(&data[offset..offset + AttestationEntryV1::SIZE])?;
            entries.push(entry);
            offset += AttestationEntryV1::SIZE;
        }
        let relay_signature = Signature::from(<[u8; 64]>::try_from(&data[offset..offset + 64]).unwrap());
        Ok(Self {
            slot,
            relay_index,
            entries,
            relay_signature,
        })
    }

    /// Check that entries are sorted by proposer_index and unique.
    pub fn validate_entry_ordering(&self) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        let mut prev = self.entries[0].proposer_index;
        for entry in self.entries.iter().skip(1) {
            if entry.proposer_index <= prev {
                return false;
            }
            prev = entry.proposer_index;
        }
        true
    }
}

// ============================================================================
// MCP Block V1 Wire Format (MCP spec §6.3)
// ============================================================================

/// A relay entry in the MCP block, containing the relay's attestations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayEntryV1 {
    /// The relay's index [0, NUM_RELAYS-1].
    pub relay_index: u32,
    /// The attestation entries from this relay.
    pub entries: Vec<AttestationEntryV1>,
    /// The relay's signature over its attestation.
    pub relay_signature: Signature,
}

impl RelayEntryV1 {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = 4 + 1 + self.entries.len() * AttestationEntryV1::SIZE + SIGNATURE_BYTES;
        let mut buf = Vec::with_capacity(size);
        buf.extend_from_slice(&self.relay_index.to_le_bytes());
        buf.push(self.entries.len() as u8);
        for entry in &self.entries {
            buf.extend_from_slice(&entry.to_bytes());
        }
        buf.extend_from_slice(self.relay_signature.as_ref());
        buf
    }

    /// Get the serialized size.
    pub fn serialized_size(&self) -> usize {
        4 + 1 + self.entries.len() * AttestationEntryV1::SIZE + SIGNATURE_BYTES
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), McpShredError> {
        if data.len() < 5 + SIGNATURE_BYTES {
            return Err(McpShredError::InvalidSize(data.len()));
        }
        let relay_index = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if relay_index >= NUM_RELAYS as u32 {
            return Err(McpShredError::InvalidShredIndex(relay_index));
        }
        let num_entries = data[4] as usize;
        if num_entries > NUM_PROPOSERS as usize {
            return Err(McpShredError::InvalidProposerIndex(num_entries as u32));
        }
        let expected_size = 5 + num_entries * AttestationEntryV1::SIZE + SIGNATURE_BYTES;
        if data.len() < expected_size {
            return Err(McpShredError::InvalidSize(data.len()));
        }
        let mut entries = Vec::with_capacity(num_entries);
        let mut offset = 5;
        for _ in 0..num_entries {
            let entry = AttestationEntryV1::from_bytes(&data[offset..offset + AttestationEntryV1::SIZE])?;
            entries.push(entry);
            offset += AttestationEntryV1::SIZE;
        }
        let relay_signature = Signature::from(<[u8; 64]>::try_from(&data[offset..offset + 64]).unwrap());
        Ok((
            Self {
                relay_index,
                entries,
                relay_signature,
            },
            expected_size,
        ))
    }
}

/// MCP Block V1 wire format (MCP spec §6.3).
///
/// This is the MCP payload inside an Alpenglow block for a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpBlockV1 {
    /// The slot this block is for.
    pub slot: Slot,
    /// The leader's validator index.
    pub leader_index: u32,
    /// The bank hash from BANKHASH_DELAY_SLOTS ago.
    pub delayed_bankhash: [u8; 32],
    /// The relay entries containing attestations.
    pub relay_entries: Vec<RelayEntryV1>,
    /// The leader's signature over the block.
    pub leader_signature: Signature,
}

impl McpBlockV1 {
    /// Minimum number of relay entries for a valid block.
    /// Per spec: MIN_RELAYS_IN_BLOCK = ceil(0.60 * 200) = 120
    pub const MIN_RELAY_ENTRIES: usize = 120;

    /// Create a new MCP block.
    pub fn new(
        slot: Slot,
        leader_index: u32,
        delayed_bankhash: [u8; 32],
        relay_entries: Vec<RelayEntryV1>,
        leader_signature: Signature,
    ) -> Self {
        Self {
            slot,
            leader_index,
            delayed_bankhash,
            relay_entries,
            leader_signature,
        }
    }

    /// Compute the block hash.
    ///
    /// Per MCP spec §6.3:
    /// ```text
    /// block_body = serialize_without_leader_signature(McpBlockV1)
    /// block_hash = SHA256(ASCII("mcp:block-hash:v1") || block_body)
    /// ```
    pub fn block_hash(&self) -> [u8; 32] {
        use solana_sha256_hasher::Hasher;
        let prefix = b"mcp:block-hash:v1";
        let body = self.serialize_without_signature();
        let mut hasher = Hasher::default();
        hasher.hash(prefix);
        hasher.hash(&body);
        hasher.result().to_bytes()
    }

    /// Returns the message that should be signed by the leader.
    ///
    /// Per MCP spec §6.3:
    /// ```text
    /// leader_signature = Ed25519Sign(SK_leader, ASCII("mcp:block-sig:v1") || block_hash)
    /// ```
    pub fn signing_message(&self) -> Vec<u8> {
        let prefix = b"mcp:block-sig:v1";
        let block_hash = self.block_hash();
        let mut msg = Vec::with_capacity(prefix.len() + 32);
        msg.extend_from_slice(prefix);
        msg.extend_from_slice(&block_hash);
        msg
    }

    /// Verify the leader signature.
    pub fn verify_signature(&self, leader_pubkey: &Pubkey) -> bool {
        let msg = self.signing_message();
        self.leader_signature.verify(leader_pubkey.as_ref(), &msg)
    }

    /// Serialize without the leader signature (for computing block hash).
    fn serialize_without_signature(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.slot.to_le_bytes());
        buf.extend_from_slice(&self.leader_index.to_le_bytes());
        buf.extend_from_slice(&self.delayed_bankhash);
        buf.extend_from_slice(&(self.relay_entries.len() as u16).to_le_bytes());
        for entry in &self.relay_entries {
            buf.extend_from_slice(&entry.to_bytes());
        }
        buf
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.serialize_without_signature();
        buf.extend_from_slice(self.leader_signature.as_ref());
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, McpShredError> {
        if data.len() < 8 + 4 + 32 + 2 + SIGNATURE_BYTES {
            return Err(McpShredError::InvalidSize(data.len()));
        }
        let slot = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let leader_index = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let delayed_bankhash: [u8; 32] = data[12..44].try_into().unwrap();
        let num_relays = u16::from_le_bytes(data[44..46].try_into().unwrap()) as usize;

        let mut relay_entries = Vec::with_capacity(num_relays);
        let mut offset = 46;
        for _ in 0..num_relays {
            if offset >= data.len() - SIGNATURE_BYTES {
                return Err(McpShredError::InvalidSize(data.len()));
            }
            let (entry, size) = RelayEntryV1::from_bytes(&data[offset..])?;
            relay_entries.push(entry);
            offset += size;
        }

        if data.len() < offset + SIGNATURE_BYTES {
            return Err(McpShredError::InvalidSize(data.len()));
        }
        let leader_signature = Signature::from(
            <[u8; 64]>::try_from(&data[offset..offset + 64]).unwrap()
        );

        Ok(Self {
            slot,
            leader_index,
            delayed_bankhash,
            relay_entries,
            leader_signature,
        })
    }

    /// Check that the block has enough relay attestations.
    pub fn has_enough_relays(&self) -> bool {
        self.relay_entries.len() >= Self::MIN_RELAY_ENTRIES
    }

    /// Check that relay entries are sorted by relay_index and unique.
    pub fn validate_relay_ordering(&self) -> bool {
        if self.relay_entries.is_empty() {
            return true;
        }
        let mut prev = self.relay_entries[0].relay_index;
        for entry in self.relay_entries.iter().skip(1) {
            if entry.relay_index <= prev {
                return false;
            }
            prev = entry.relay_index;
        }
        true
    }

    /// Count attestations for a specific proposer across all relays.
    pub fn count_attestations_for_proposer(&self, proposer_index: u32) -> usize {
        self.relay_entries
            .iter()
            .filter(|relay| {
                relay.entries.iter().any(|e| e.proposer_index == proposer_index)
            })
            .count()
    }

    /// Get the commitment for a proposer if it has enough attestations.
    /// Returns the commitment if >= MIN_RELAYS_PER_PROPOSER (80) relays attest to it.
    pub fn get_included_proposer_commitment(&self, proposer_index: u32) -> Option<[u8; MERKLE_ROOT_BYTES]> {
        const MIN_RELAYS_PER_PROPOSER: usize = 80; // ceil(0.40 * 200)

        let mut commitment: Option<[u8; MERKLE_ROOT_BYTES]> = None;
        let mut count = 0;

        for relay in &self.relay_entries {
            for entry in &relay.entries {
                if entry.proposer_index == proposer_index {
                    if let Some(c) = commitment {
                        if c != entry.commitment {
                            // Conflicting commitments - proposer equivocated
                            return None;
                        }
                    } else {
                        commitment = Some(entry.commitment);
                    }
                    count += 1;
                    break;
                }
            }
        }

        if count >= MIN_RELAYS_PER_PROPOSER {
            commitment
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_keypair::Keypair;
    use solana_signer::Signer;

    #[test]
    fn test_shred_size_constants() {
        // Verify the layout matches the spec §7.2
        // With SHRED_DATA_BYTES=1024, 32-byte witness hashes, 8 entries
        assert_eq!(MCP_SHRED_TOTAL_BYTES, 1393);
        assert_eq!(SHRED_DATA_BYTES, 1024);
        assert_eq!(MERKLE_ROOT_BYTES, 32);
        assert_eq!(MERKLE_PROOF_ENTRY_BYTES, 32); // Full 32-byte hashes per spec
        assert_eq!(MERKLE_PROOF_ENTRIES, 8);
        assert_eq!(MERKLE_PROOF_BYTES, 256);

        // Verify layout offsets sum correctly
        let expected_size = 8  // slot
            + 4  // proposer_index
            + 4  // shred_index
            + 32 // commitment
            + 1024 // shred_data (SHRED_DATA_BYTES)
            + 1  // witness_len
            + 256 // witness (8 * 32)
            + 64; // signature
        assert_eq!(expected_size, MCP_SHRED_TOTAL_BYTES);
    }

    #[test]
    fn test_roundtrip() {
        let original = McpShredV1 {
            slot: 12345,
            proposer_index: 5,
            shred_index: 42,
            commitment: [0xAB; MERKLE_ROOT_BYTES],
            shred_data: [0xCD; SHRED_DATA_BYTES],
            witness: [[0xEF; MERKLE_PROOF_ENTRY_BYTES]; MERKLE_PROOF_ENTRIES],
            proposer_signature: Signature::new_unique(),
        };

        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), MCP_SHRED_TOTAL_BYTES);

        let parsed = McpShredV1::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_invalid_size() {
        let small = vec![0u8; MCP_SHRED_TOTAL_BYTES - 1];
        let err = McpShredV1::from_bytes(&small).unwrap_err();
        assert!(matches!(err, McpShredError::InvalidSize(_)));

        let large = vec![0u8; MCP_SHRED_TOTAL_BYTES + 1];
        let err = McpShredV1::from_bytes(&large).unwrap_err();
        assert!(matches!(err, McpShredError::InvalidSize(_)));
    }

    #[test]
    fn test_invalid_proposer_index() {
        let mut bytes = [0u8; MCP_SHRED_TOTAL_BYTES];
        // Set proposer_index to NUM_PROPOSERS (out of range)
        bytes[OFFSET_PROPOSER_INDEX..OFFSET_PROPOSER_INDEX + 4]
            .copy_from_slice(&(NUM_PROPOSERS as u32).to_le_bytes());
        // Set valid witness_len
        bytes[OFFSET_WITNESS_LEN] = MERKLE_PROOF_ENTRIES as u8;

        let err = McpShredV1::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, McpShredError::InvalidProposerIndex(_)));
    }

    #[test]
    fn test_invalid_shred_index() {
        let mut bytes = [0u8; MCP_SHRED_TOTAL_BYTES];
        // Set valid proposer_index
        bytes[OFFSET_PROPOSER_INDEX..OFFSET_PROPOSER_INDEX + 4].copy_from_slice(&0u32.to_le_bytes());
        // Set shred_index to NUM_RELAYS (out of range)
        bytes[OFFSET_SHRED_INDEX..OFFSET_SHRED_INDEX + 4]
            .copy_from_slice(&(NUM_RELAYS as u32).to_le_bytes());
        // Set valid witness_len
        bytes[OFFSET_WITNESS_LEN] = MERKLE_PROOF_ENTRIES as u8;

        let err = McpShredV1::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, McpShredError::InvalidShredIndex(_)));
    }

    #[test]
    fn test_invalid_witness_len() {
        let mut bytes = [0u8; MCP_SHRED_TOTAL_BYTES];
        // Set valid proposer_index and shred_index
        bytes[OFFSET_PROPOSER_INDEX..OFFSET_PROPOSER_INDEX + 4].copy_from_slice(&0u32.to_le_bytes());
        bytes[OFFSET_SHRED_INDEX..OFFSET_SHRED_INDEX + 4].copy_from_slice(&0u32.to_le_bytes());
        // Set invalid witness_len
        bytes[OFFSET_WITNESS_LEN] = 7; // Should be 8

        let err = McpShredV1::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, McpShredError::InvalidWitnessLen(7)));
    }

    #[test]
    fn test_wire_helpers() {
        let shred = McpShredV1 {
            slot: 999,
            proposer_index: 3,
            shred_index: 100,
            commitment: [0x11; MERKLE_ROOT_BYTES],
            shred_data: [0x22; SHRED_DATA_BYTES],
            witness: [[0x33; MERKLE_PROOF_ENTRY_BYTES]; MERKLE_PROOF_ENTRIES],
            proposer_signature: Signature::new_unique(),
        };

        let bytes = shred.to_bytes();

        assert_eq!(get_mcp_slot(&bytes), Some(999));
        assert_eq!(get_mcp_proposer_index(&bytes), Some(3));
        assert_eq!(get_mcp_shred_index(&bytes), Some(100));
        assert_eq!(get_mcp_commitment(&bytes), Some([0x11; MERKLE_ROOT_BYTES]));
        assert!(is_mcp_shred_packet(&bytes));
    }

    #[test]
    fn test_signing_message() {
        let shred = McpShredV1 {
            slot: 12345,
            proposer_index: 5,
            shred_index: 42,
            commitment: [0xAB; MERKLE_ROOT_BYTES],
            ..Default::default()
        };

        let msg = shred.signing_message();

        // Verify message structure per spec §5.2: domain || commitment only
        assert_eq!(&msg[..17], b"mcp:commitment:v1");
        assert_eq!(&msg[17..49], &[0xAB; 32]);
        assert_eq!(msg.len(), 17 + 32);
    }

    #[test]
    fn test_signature_verification() {
        let keypair = Keypair::new();
        let proposer_pubkey = keypair.pubkey();

        let mut shred = McpShredV1 {
            slot: 12345,
            proposer_index: 5,
            shred_index: 42,
            commitment: [0xAB; MERKLE_ROOT_BYTES],
            shred_data: [0xCD; SHRED_DATA_BYTES],
            witness: [[0xEF; MERKLE_PROOF_ENTRY_BYTES]; MERKLE_PROOF_ENTRIES],
            proposer_signature: Signature::default(),
        };

        // Sign the shred
        let msg = shred.signing_message();
        shred.proposer_signature = keypair.sign_message(&msg);

        // Verify with correct pubkey
        assert!(shred.verify_signature(&proposer_pubkey));

        // Verify with wrong pubkey fails
        let wrong_keypair = Keypair::new();
        assert!(!shred.verify_signature(&wrong_keypair.pubkey()));
    }

    #[test]
    fn test_target_relay() {
        let shred = McpShredV1 {
            shred_index: 42,
            ..Default::default()
        };

        assert_eq!(shred.target_relay_index(), 42);
        assert!(shred.is_for_relay(42));
        assert!(!shred.is_for_relay(43));
    }
}
