//! MCP Relay Attestation Wire Format and Storage
//!
//! This module defines the `RelayAttestation` struct for MCP relay attestations,
//! including deterministic encoding and signature verification.
//!
//! # Wire Format (v1) - Per MCP spec §7.3
//!
//! ```text
//! | version (1 byte) | slot (8 bytes) | relay_index (4 bytes) |
//! | entries_len (1 byte) | entries (variable) | relay_signature (64 bytes) |
//! ```
//!
//! Each entry in the entries array (AttestationEntryV1):
//! ```text
//! | proposer_index (4 bytes) | commitment (32 bytes) | proposer_signature (64 bytes) |
//! ```
//!
//! Entries MUST be sorted by proposer_index in ascending order.
//! The relay signature is computed over all preceding bytes.

use {
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    std::io::{self, Read, Write},
};

/// Current version of the relay attestation wire format.
pub const RELAY_ATTESTATION_VERSION: u8 = 1;

/// Size of a single attestation entry (proposer_index + commitment + proposer_signature).
/// Per spec §6.2: proposer_index(4) + commitment(32) + proposer_signature(64) = 100 bytes
pub const ATTESTATION_ENTRY_SIZE: usize = 4 + 32 + 64; // 100 bytes

/// Maximum number of entries in an attestation (limited by NUM_PROPOSERS).
pub const MAX_ATTESTATION_ENTRIES: usize = 16;

/// Minimum size of a serialized attestation (header + signature, no entries).
/// version(1) + slot(8) + relay_index(4) + entries_len(1) + relay_signature(64) = 78 bytes
pub const MIN_ATTESTATION_SIZE: usize = 1 + 8 + 4 + 1 + 64; // 78 bytes

/// A single entry in a relay attestation (AttestationEntryV1).
///
/// Per MCP spec §6.2, each entry represents a proposer's batch that the relay
/// received and verified, including the proposer's signature for verification
/// by the consensus leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationEntry {
    /// The proposer index (per spec §6.2: u32, range 0 to NUM_PROPOSERS-1).
    pub proposer_index: u32,
    /// The merkle commitment of the proposer's shred batch.
    pub commitment: Hash,
    /// The proposer's signature over the commitment.
    /// Per spec §5.2: proposer_sig_msg = "mcp:commitment:v1" || commitment32
    pub proposer_signature: Signature,
}

impl AttestationEntry {
    /// Create a new attestation entry.
    pub const fn new(proposer_index: u32, commitment: Hash, proposer_signature: Signature) -> Self {
        Self {
            proposer_index,
            commitment,
            proposer_signature,
        }
    }

    /// Serialize the entry to bytes (4 + 32 + 64 = 100 bytes per spec §6.2).
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.proposer_index.to_le_bytes())?;
        writer.write_all(self.commitment.as_ref())?;
        writer.write_all(self.proposer_signature.as_ref())?;
        Ok(())
    }

    /// Deserialize an entry from bytes.
    pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut proposer_index_buf = [0u8; 4];
        reader.read_exact(&mut proposer_index_buf)?;
        let proposer_index = u32::from_le_bytes(proposer_index_buf);

        let mut commitment_buf = [0u8; 32];
        reader.read_exact(&mut commitment_buf)?;
        let commitment = Hash::from(commitment_buf);

        let mut sig_buf = [0u8; 64];
        reader.read_exact(&mut sig_buf)?;
        let proposer_signature = Signature::from(sig_buf);

        Ok(Self {
            proposer_index,
            commitment,
            proposer_signature,
        })
    }

    /// Verify the proposer signature against the given pubkey.
    ///
    /// Per spec §5.2: proposer_sig_msg = "mcp:commitment:v1" || commitment32
    /// The commitment already binds to slot/proposer because the payload header
    /// is inside the committed RS shards.
    pub fn verify_proposer_signature(&self, proposer_pubkey: &Pubkey) -> bool {
        let mut msg = Vec::with_capacity(17 + 32);
        msg.extend_from_slice(b"mcp:commitment:v1");
        msg.extend_from_slice(self.commitment.as_ref());
        self.proposer_signature.verify(proposer_pubkey.as_ref(), &msg)
    }
}

impl PartialOrd for AttestationEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AttestationEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.proposer_index.cmp(&other.proposer_index)
    }
}

/// A relay attestation for a slot.
///
/// Relays create attestations to certify which proposer batches they
/// have received and verified. The consensus leader aggregates these
/// attestations to determine which batches to include in the final block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAttestation {
    /// Wire format version (currently 1).
    pub version: u8,
    /// The slot this attestation is for.
    pub slot: u64,
    /// The relay's index within the epoch schedule (u32 per spec §7.3).
    pub relay_index: u32,
    /// Attestation entries, sorted by proposer_index.
    pub entries: Vec<AttestationEntry>,
    /// The relay's signature over the attestation data.
    pub relay_signature: Signature,
}

impl RelayAttestation {
    /// Create a new relay attestation.
    ///
    /// Entries will be sorted by proposer_index automatically.
    /// The signature should be set later after serializing the unsigned portion.
    pub fn new(slot: u64, relay_index: u32, mut entries: Vec<AttestationEntry>) -> Self {
        entries.sort();
        Self {
            version: RELAY_ATTESTATION_VERSION,
            slot,
            relay_index,
            entries,
            relay_signature: Signature::default(),
        }
    }

    /// Create a new relay attestation with a signature.
    ///
    /// Entries will be sorted by proposer_index automatically.
    pub fn new_signed(
        slot: u64,
        relay_index: u32,
        mut entries: Vec<AttestationEntry>,
        signature: Signature,
    ) -> Self {
        entries.sort();
        Self {
            version: RELAY_ATTESTATION_VERSION,
            slot,
            relay_index,
            entries,
            relay_signature: signature,
        }
    }

    /// Returns the number of entries in this attestation.
    pub fn entries_len(&self) -> u8 {
        self.entries.len() as u8
    }

    /// Serialize the attestation to bytes.
    ///
    /// Per MCP spec §7.3, the wire format is:
    /// ```text
    /// | version (1) | slot (8) | relay_index (4) | entries_len (1) |
    /// | entries (entries_len * 100) | relay_signature (64) |
    /// ```
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut bytes_written = 0;

        // Version
        writer.write_all(&[self.version])?;
        bytes_written += 1;

        // Slot
        writer.write_all(&self.slot.to_le_bytes())?;
        bytes_written += 8;

        // Relay index (u32 per spec §7.3)
        writer.write_all(&self.relay_index.to_le_bytes())?;
        bytes_written += 4;

        // Number of attestation entries (u8 per spec)
        let entries_len = self.entries.len() as u8;
        writer.write_all(&[entries_len])?;
        bytes_written += 1;

        // Entries
        for entry in &self.entries {
            entry.serialize(writer)?;
            bytes_written += ATTESTATION_ENTRY_SIZE;
        }

        // Relay signature
        writer.write_all(self.relay_signature.as_ref())?;
        bytes_written += 64;

        Ok(bytes_written)
    }

    /// Serialize only the portion that needs to be signed (everything except signature).
    /// Per spec §7.3: relay_sig is computed over version, slot, relay_index, entries_len, entries
    pub fn serialize_for_signing<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut bytes_written = 0;

        // Version
        writer.write_all(&[self.version])?;
        bytes_written += 1;

        // Slot
        writer.write_all(&self.slot.to_le_bytes())?;
        bytes_written += 8;

        // Relay index (u32 per spec §7.3)
        writer.write_all(&self.relay_index.to_le_bytes())?;
        bytes_written += 4;

        // Number of attestation entries (u8 per spec)
        let entries_len = self.entries.len() as u8;
        writer.write_all(&[entries_len])?;
        bytes_written += 1;

        // Entries
        for entry in &self.entries {
            entry.serialize(writer)?;
            bytes_written += ATTESTATION_ENTRY_SIZE;
        }

        Ok(bytes_written)
    }

    /// Get the bytes to be signed.
    pub fn get_signing_data(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.signing_data_size());
        self.serialize_for_signing(&mut buffer)
            .expect("serialization to Vec should not fail");
        buffer
    }

    /// Returns the size of the signing data (attestation without signature).
    pub fn signing_data_size(&self) -> usize {
        1 + 8 + 4 + 1 + (self.entries.len() * ATTESTATION_ENTRY_SIZE) // header + entries
    }

    /// Returns the size of just the wire-serialized attestation (with signature).
    pub fn wire_size(&self) -> usize {
        1 + 8 + 4 + 1 + (self.entries.len() * ATTESTATION_ENTRY_SIZE) + 64 // header + entries + signature
    }

    /// Returns the total serialized size of this attestation (wire format).
    pub fn serialized_size(&self) -> usize {
        self.wire_size()
    }

    /// Deserialize a relay attestation from bytes.
    pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        // Version
        let mut version_buf = [0u8; 1];
        reader.read_exact(&mut version_buf)?;
        let version = version_buf[0];

        if version != RELAY_ATTESTATION_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported attestation version: {}, expected {}",
                    version, RELAY_ATTESTATION_VERSION
                ),
            ));
        }

        // Slot
        let mut slot_buf = [0u8; 8];
        reader.read_exact(&mut slot_buf)?;
        let slot = u64::from_le_bytes(slot_buf);

        // Relay index (u32 per spec §7.3)
        let mut relay_index_buf = [0u8; 4];
        reader.read_exact(&mut relay_index_buf)?;
        let relay_index = u32::from_le_bytes(relay_index_buf);

        // Number of attestation entries (u8 per spec)
        let mut num_attestations_buf = [0u8; 1];
        reader.read_exact(&mut num_attestations_buf)?;
        let num_attestations = num_attestations_buf[0] as usize;

        if num_attestations > MAX_ATTESTATION_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "too many attestation entries: {}, max {}",
                    num_attestations, MAX_ATTESTATION_ENTRIES
                ),
            ));
        }

        // Entries
        let mut entries = Vec::with_capacity(num_attestations);
        for _ in 0..num_attestations {
            entries.push(AttestationEntry::deserialize(reader)?);
        }

        // Verify entries are sorted by proposer_index
        for window in entries.windows(2) {
            if window[0].proposer_index >= window[1].proposer_index {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "attestation entries not sorted by proposer_index",
                ));
            }
        }

        // Relay signature
        let mut sig_buf = [0u8; 64];
        reader.read_exact(&mut sig_buf)?;
        let relay_signature = Signature::from(sig_buf);

        Ok(Self {
            version,
            slot,
            relay_index,
            entries,
            relay_signature,
        })
    }

    /// Verify the relay's signature on this attestation.
    ///
    /// Returns `Ok(())` if the signature is valid, or an error otherwise.
    pub fn verify_signature(&self, relay_pubkey: &Pubkey) -> Result<(), AttestationError> {
        let signing_data = self.get_signing_data();
        if self.relay_signature.verify(relay_pubkey.as_ref(), &signing_data) {
            Ok(())
        } else {
            Err(AttestationError::InvalidSignature)
        }
    }

    /// Check if this attestation contains an entry for the given proposer.
    pub fn has_proposer(&self, proposer_index: u32) -> bool {
        self.entries
            .binary_search_by_key(&proposer_index, |e| e.proposer_index)
            .is_ok()
    }

    /// Get the commitment for a specific proposer, if attested.
    pub fn get_commitment(&self, proposer_index: u32) -> Option<&Hash> {
        self.entries
            .binary_search_by_key(&proposer_index, |e| e.proposer_index)
            .ok()
            .map(|idx| &self.entries[idx].commitment)
    }

    /// Get the full attestation entry for a specific proposer, if attested.
    pub fn get_entry(&self, proposer_index: u32) -> Option<&AttestationEntry> {
        self.entries
            .binary_search_by_key(&proposer_index, |e| e.proposer_index)
            .ok()
            .map(|idx| &self.entries[idx])
    }

    /// Verify all proposer signatures in this attestation.
    ///
    /// Takes a function to look up proposer pubkeys by their index.
    pub fn verify_proposer_signatures<F>(&self, get_proposer_pubkey: F) -> Result<(), AttestationError>
    where
        F: Fn(u32) -> Option<Pubkey>,
    {
        for entry in &self.entries {
            let Some(proposer_pubkey) = get_proposer_pubkey(entry.proposer_index) else {
                return Err(AttestationError::InvalidProposerIndex(entry.proposer_index));
            };
            if !entry.verify_proposer_signature(&proposer_pubkey) {
                return Err(AttestationError::InvalidProposerSignature(entry.proposer_index));
            }
        }
        Ok(())
    }
}

/// Errors that can occur when working with attestations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The relay signature is invalid.
    InvalidSignature,
    /// The attestation version is unsupported.
    UnsupportedVersion(u8),
    /// Entries are not properly sorted.
    EntriesNotSorted,
    /// Too many entries in the attestation.
    TooManyEntries(usize),
    /// Duplicate proposer index in entries.
    DuplicateProposer(u32),
    /// Invalid proposer index (not in schedule).
    InvalidProposerIndex(u32),
    /// Invalid proposer signature for entry.
    InvalidProposerSignature(u32),
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid relay signature"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported attestation version: {}", v),
            Self::EntriesNotSorted => write!(f, "attestation entries not sorted by proposer_index"),
            Self::TooManyEntries(n) => write!(f, "too many attestation entries: {}", n),
            Self::DuplicateProposer(id) => write!(f, "duplicate proposer_index in entries: {}", id),
            Self::InvalidProposerIndex(id) => write!(f, "invalid proposer index: {}", id),
            Self::InvalidProposerSignature(id) => write!(f, "invalid proposer signature for index: {}", id),
        }
    }
}

impl std::error::Error for AttestationError {}

/// Builder for creating relay attestations.
///
/// This provides a convenient way to accumulate entries and then
/// create a signed attestation.
#[derive(Debug, Default)]
pub struct RelayAttestationBuilder {
    slot: u64,
    relay_index: u32,
    entries: Vec<AttestationEntry>,
}

impl RelayAttestationBuilder {
    /// Create a new attestation builder for a slot.
    pub fn new(slot: u64, relay_index: u32) -> Self {
        Self {
            slot,
            relay_index,
            entries: Vec::new(),
        }
    }

    /// Add an attestation entry for a proposer.
    ///
    /// Per MCP spec §7.3, each entry must include the proposer's signature
    /// over the commitment to enable verification by the consensus leader.
    pub fn add_entry(
        mut self,
        proposer_index: u32,
        commitment: Hash,
        proposer_signature: Signature,
    ) -> Self {
        self.entries
            .push(AttestationEntry::new(proposer_index, commitment, proposer_signature));
        self
    }

    /// Build an unsigned attestation.
    pub fn build_unsigned(self) -> RelayAttestation {
        RelayAttestation::new(self.slot, self.relay_index, self.entries)
    }

    /// Build a signed attestation.
    ///
    /// The signature is computed over the serialized attestation data.
    pub fn build_signed(self, signature: Signature) -> RelayAttestation {
        RelayAttestation::new_signed(self.slot, self.relay_index, self.entries, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    fn make_test_sig(seed: u8) -> Signature {
        Signature::from([seed; 64])
    }

    #[test]
    fn test_attestation_entry_serialization() {
        let entry = AttestationEntry::new(5, make_test_hash(42), make_test_sig(0xAB));

        let mut buffer = Vec::new();
        entry.serialize(&mut buffer).unwrap();
        assert_eq!(buffer.len(), ATTESTATION_ENTRY_SIZE);

        let mut cursor = std::io::Cursor::new(&buffer);
        let deserialized = AttestationEntry::deserialize(&mut cursor).unwrap();

        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_attestation_entry_ordering() {
        let entry1 = AttestationEntry::new(1, make_test_hash(1), make_test_sig(1));
        let entry2 = AttestationEntry::new(5, make_test_hash(2), make_test_sig(2));
        let entry3 = AttestationEntry::new(10, make_test_hash(3), make_test_sig(3));

        assert!(entry1 < entry2);
        assert!(entry2 < entry3);
        assert!(entry1 < entry3);
    }

    #[test]
    fn test_relay_attestation_serialization_roundtrip() {
        let entries = vec![
            AttestationEntry::new(3, make_test_hash(3), make_test_sig(3)),
            AttestationEntry::new(1, make_test_hash(1), make_test_sig(1)),
            AttestationEntry::new(7, make_test_hash(7), make_test_sig(7)),
        ];

        let attestation = RelayAttestation::new_signed(
            12345,
            42,
            entries,
            Signature::from([0xAB; 64]),
        );

        let mut buffer = Vec::new();
        let written = attestation.serialize(&mut buffer).unwrap();
        assert_eq!(written, attestation.serialized_size());

        let mut cursor = std::io::Cursor::new(&buffer);
        let deserialized = RelayAttestation::deserialize(&mut cursor).unwrap();

        assert_eq!(attestation.version, deserialized.version);
        assert_eq!(attestation.slot, deserialized.slot);
        assert_eq!(attestation.relay_index, deserialized.relay_index);
        assert_eq!(attestation.entries, deserialized.entries);
        assert_eq!(attestation.relay_signature, deserialized.relay_signature);
    }

    #[test]
    fn test_entries_sorted_on_creation() {
        let entries = vec![
            AttestationEntry::new(10, make_test_hash(10), make_test_sig(10)),
            AttestationEntry::new(2, make_test_hash(2), make_test_sig(2)),
            AttestationEntry::new(5, make_test_hash(5), make_test_sig(5)),
        ];

        let attestation = RelayAttestation::new(100, 1, entries);

        // Entries should be sorted by proposer_index
        assert_eq!(attestation.entries[0].proposer_index, 2);
        assert_eq!(attestation.entries[1].proposer_index, 5);
        assert_eq!(attestation.entries[2].proposer_index, 10);
    }

    #[test]
    fn test_has_proposer() {
        let entries = vec![
            AttestationEntry::new(1, make_test_hash(1), make_test_sig(1)),
            AttestationEntry::new(5, make_test_hash(5), make_test_sig(5)),
            AttestationEntry::new(10, make_test_hash(10), make_test_sig(10)),
        ];

        let attestation = RelayAttestation::new(100, 1, entries);

        assert!(attestation.has_proposer(1));
        assert!(attestation.has_proposer(5));
        assert!(attestation.has_proposer(10));
        assert!(!attestation.has_proposer(0));
        assert!(!attestation.has_proposer(3));
        assert!(!attestation.has_proposer(15));
    }

    #[test]
    fn test_get_commitment() {
        let entries = vec![
            AttestationEntry::new(1, make_test_hash(1), make_test_sig(1)),
            AttestationEntry::new(5, make_test_hash(5), make_test_sig(5)),
        ];

        let attestation = RelayAttestation::new(100, 1, entries);

        assert_eq!(attestation.get_commitment(1), Some(&make_test_hash(1)));
        assert_eq!(attestation.get_commitment(5), Some(&make_test_hash(5)));
        assert_eq!(attestation.get_commitment(3), None);
    }

    #[test]
    fn test_builder() {
        let attestation = RelayAttestationBuilder::new(100, 42)
            .add_entry(5, make_test_hash(5), make_test_sig(5))
            .add_entry(1, make_test_hash(1), make_test_sig(1))
            .add_entry(10, make_test_hash(10), make_test_sig(10))
            .build_unsigned();

        assert_eq!(attestation.slot, 100);
        assert_eq!(attestation.relay_index, 42);
        assert_eq!(attestation.entries.len(), 3);
        // Should be sorted
        assert_eq!(attestation.entries[0].proposer_index, 1);
        assert_eq!(attestation.entries[1].proposer_index, 5);
        assert_eq!(attestation.entries[2].proposer_index, 10);
    }

    #[test]
    fn test_empty_attestation() {
        let attestation = RelayAttestation::new(100, 1, vec![]);

        let mut buffer = Vec::new();
        attestation.serialize(&mut buffer).unwrap();

        let mut cursor = std::io::Cursor::new(&buffer);
        let deserialized = RelayAttestation::deserialize(&mut cursor).unwrap();

        assert_eq!(attestation.entries.len(), 0);
        assert_eq!(deserialized.entries.len(), 0);
    }

    #[test]
    fn test_signing_data_size() {
        let entries = vec![
            AttestationEntry::new(1, make_test_hash(1), make_test_sig(1)),
            AttestationEntry::new(5, make_test_hash(5), make_test_sig(5)),
        ];

        let attestation = RelayAttestation::new(100, 1, entries);

        // Signing data per spec §7.3: 1 (version) + 8 (slot) + 4 (relay_index) + 1 (entries_len) + 2 * 100 (entries)
        let expected_signing = 1 + 8 + 4 + 1 + 2 * ATTESTATION_ENTRY_SIZE;
        assert_eq!(attestation.signing_data_size(), expected_signing);

        // Wire size: 1 (version) + 8 (slot) + 4 (relay_index) + 1 (entries_len) + 2 * 100 (entries) + 64 (sig)
        let expected_wire = 1 + 8 + 4 + 1 + 2 * ATTESTATION_ENTRY_SIZE + 64;
        assert_eq!(attestation.serialized_size(), expected_wire);
    }

    #[test]
    fn test_deserialize_rejects_unsorted() {
        // Manually construct invalid wire format with unsorted entries
        let mut buffer = Vec::new();
        buffer.push(RELAY_ATTESTATION_VERSION); // version
        buffer.extend_from_slice(&100u64.to_le_bytes()); // slot
        buffer.extend_from_slice(&1u32.to_le_bytes()); // relay_index (u32 per spec §7.3)
        buffer.push(2); // entries_len = 2 (u8)

        // Entry 1: proposer_index = 5 (u32), commitment (32 bytes), proposer_sig (64 bytes)
        buffer.extend_from_slice(&5u32.to_le_bytes());
        buffer.extend_from_slice(&[1u8; 32]); // commitment
        buffer.extend_from_slice(&[1u8; 64]); // proposer_sig

        // Entry 2: proposer_index = 3 (out of order!)
        buffer.extend_from_slice(&3u32.to_le_bytes());
        buffer.extend_from_slice(&[2u8; 32]); // commitment
        buffer.extend_from_slice(&[2u8; 64]); // proposer_sig

        // Relay signature
        buffer.extend_from_slice(&[0u8; 64]);

        let mut cursor = std::io::Cursor::new(&buffer);
        let result = RelayAttestation::deserialize(&mut cursor);
        assert!(result.is_err());
    }
}
