//! MCP Relay Attestation Wire Format and Storage
//!
//! This module defines the `RelayAttestation` struct for MCP relay attestations,
//! including deterministic encoding and signature verification.
//!
//! # Wire Format (v1)
//!
//! ```text
//! | version (1 byte) | slot (8 bytes) | relay_id (2 bytes) |
//! | entries_len (2 bytes) | entries (variable) | relay_signature (64 bytes) |
//! ```
//!
//! Each entry in the entries array:
//! ```text
//! | proposer_id (1 byte) | merkle_root (32 bytes) |
//! ```
//!
//! Entries MUST be sorted by proposer_id in ascending order.
//! The relay signature is computed over all preceding bytes.

use {
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    std::io::{self, Read, Write},
};

/// Current version of the relay attestation wire format.
pub const RELAY_ATTESTATION_VERSION: u8 = 1;

/// Size of a single attestation entry (proposer_id + merkle_root).
pub const ATTESTATION_ENTRY_SIZE: usize = 1 + 32; // 33 bytes

/// Maximum number of entries in an attestation (limited by NUM_PROPOSERS).
pub const MAX_ATTESTATION_ENTRIES: usize = 16;

/// Minimum size of a serialized attestation (header + signature, no entries).
pub const MIN_ATTESTATION_SIZE: usize = 1 + 8 + 2 + 2 + 64; // 77 bytes

/// A single entry in a relay attestation.
///
/// Each entry represents a proposer's batch that the relay received
/// and verified, identified by the merkle root of the shred batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationEntry {
    /// The proposer ID (0-15 for standard proposers, 0xFF for consensus).
    pub proposer_id: u8,
    /// The merkle root of the proposer's shred batch.
    pub merkle_root: Hash,
}

impl AttestationEntry {
    /// Create a new attestation entry.
    pub const fn new(proposer_id: u8, merkle_root: Hash) -> Self {
        Self {
            proposer_id,
            merkle_root,
        }
    }

    /// Serialize the entry to bytes.
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[self.proposer_id])?;
        writer.write_all(self.merkle_root.as_ref())?;
        Ok(())
    }

    /// Deserialize an entry from bytes.
    pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut proposer_id_buf = [0u8; 1];
        reader.read_exact(&mut proposer_id_buf)?;
        let proposer_id = proposer_id_buf[0];

        let mut merkle_root_buf = [0u8; 32];
        reader.read_exact(&mut merkle_root_buf)?;
        let merkle_root = Hash::from(merkle_root_buf);

        Ok(Self {
            proposer_id,
            merkle_root,
        })
    }
}

impl PartialOrd for AttestationEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AttestationEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.proposer_id.cmp(&other.proposer_id)
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
    /// The relay's ID within the epoch schedule.
    pub relay_id: u16,
    /// Attestation entries, sorted by proposer_id.
    pub entries: Vec<AttestationEntry>,
    /// The relay's signature over the attestation data.
    pub relay_signature: Signature,
}

impl RelayAttestation {
    /// Create a new relay attestation.
    ///
    /// Entries will be sorted by proposer_id automatically.
    /// The signature should be set later after serializing the unsigned portion.
    pub fn new(slot: u64, relay_id: u16, mut entries: Vec<AttestationEntry>) -> Self {
        entries.sort();
        Self {
            version: RELAY_ATTESTATION_VERSION,
            slot,
            relay_id,
            entries,
            relay_signature: Signature::default(),
        }
    }

    /// Create a new relay attestation with a signature.
    ///
    /// Entries will be sorted by proposer_id automatically.
    pub fn new_signed(
        slot: u64,
        relay_id: u16,
        mut entries: Vec<AttestationEntry>,
        signature: Signature,
    ) -> Self {
        entries.sort();
        Self {
            version: RELAY_ATTESTATION_VERSION,
            slot,
            relay_id,
            entries,
            relay_signature: signature,
        }
    }

    /// Returns the number of entries in this attestation.
    pub fn entries_len(&self) -> u16 {
        self.entries.len() as u16
    }

    /// Serialize the attestation to bytes.
    ///
    /// The wire format is:
    /// ```text
    /// | version (1) | slot (8) | relay_id (2) | entries_len (2) |
    /// | entries (entries_len * 33) | relay_signature (64) |
    /// ```
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut bytes_written = 0;

        // Version
        writer.write_all(&[self.version])?;
        bytes_written += 1;

        // Slot
        writer.write_all(&self.slot.to_le_bytes())?;
        bytes_written += 8;

        // Relay ID
        writer.write_all(&self.relay_id.to_le_bytes())?;
        bytes_written += 2;

        // Entries length
        let entries_len = self.entries.len() as u16;
        writer.write_all(&entries_len.to_le_bytes())?;
        bytes_written += 2;

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
    pub fn serialize_for_signing<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut bytes_written = 0;

        // Version
        writer.write_all(&[self.version])?;
        bytes_written += 1;

        // Slot
        writer.write_all(&self.slot.to_le_bytes())?;
        bytes_written += 8;

        // Relay ID
        writer.write_all(&self.relay_id.to_le_bytes())?;
        bytes_written += 2;

        // Entries length
        let entries_len = self.entries.len() as u16;
        writer.write_all(&entries_len.to_le_bytes())?;
        bytes_written += 2;

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
        1 + 8 + 2 + 2 + (self.entries.len() * ATTESTATION_ENTRY_SIZE)
    }

    /// Returns the total serialized size of this attestation.
    pub fn serialized_size(&self) -> usize {
        self.signing_data_size() + 64 // + signature
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

        // Relay ID
        let mut relay_id_buf = [0u8; 2];
        reader.read_exact(&mut relay_id_buf)?;
        let relay_id = u16::from_le_bytes(relay_id_buf);

        // Entries length
        let mut entries_len_buf = [0u8; 2];
        reader.read_exact(&mut entries_len_buf)?;
        let entries_len = u16::from_le_bytes(entries_len_buf) as usize;

        if entries_len > MAX_ATTESTATION_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "too many attestation entries: {}, max {}",
                    entries_len, MAX_ATTESTATION_ENTRIES
                ),
            ));
        }

        // Entries
        let mut entries = Vec::with_capacity(entries_len);
        for _ in 0..entries_len {
            entries.push(AttestationEntry::deserialize(reader)?);
        }

        // Verify entries are sorted
        for window in entries.windows(2) {
            if window[0].proposer_id >= window[1].proposer_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "attestation entries not sorted by proposer_id",
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
            relay_id,
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
    pub fn has_proposer(&self, proposer_id: u8) -> bool {
        self.entries
            .binary_search_by_key(&proposer_id, |e| e.proposer_id)
            .is_ok()
    }

    /// Get the merkle root for a specific proposer, if attested.
    pub fn get_merkle_root(&self, proposer_id: u8) -> Option<&Hash> {
        self.entries
            .binary_search_by_key(&proposer_id, |e| e.proposer_id)
            .ok()
            .map(|idx| &self.entries[idx].merkle_root)
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
    /// Duplicate proposer ID in entries.
    DuplicateProposer(u8),
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid relay signature"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported attestation version: {}", v),
            Self::EntriesNotSorted => write!(f, "attestation entries not sorted by proposer_id"),
            Self::TooManyEntries(n) => write!(f, "too many attestation entries: {}", n),
            Self::DuplicateProposer(id) => write!(f, "duplicate proposer_id in entries: {}", id),
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
    relay_id: u16,
    entries: Vec<AttestationEntry>,
}

impl RelayAttestationBuilder {
    /// Create a new attestation builder for a slot.
    pub fn new(slot: u64, relay_id: u16) -> Self {
        Self {
            slot,
            relay_id,
            entries: Vec::new(),
        }
    }

    /// Add an attestation entry for a proposer.
    pub fn add_entry(&mut self, proposer_id: u8, merkle_root: Hash) -> &mut Self {
        self.entries
            .push(AttestationEntry::new(proposer_id, merkle_root));
        self
    }

    /// Build an unsigned attestation.
    pub fn build_unsigned(self) -> RelayAttestation {
        RelayAttestation::new(self.slot, self.relay_id, self.entries)
    }

    /// Build a signed attestation.
    ///
    /// The signature is computed over the serialized attestation data.
    pub fn build_signed(self, signature: Signature) -> RelayAttestation {
        RelayAttestation::new_signed(self.slot, self.relay_id, self.entries, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    #[test]
    fn test_attestation_entry_serialization() {
        let entry = AttestationEntry::new(5, make_test_hash(42));

        let mut buffer = Vec::new();
        entry.serialize(&mut buffer).unwrap();
        assert_eq!(buffer.len(), ATTESTATION_ENTRY_SIZE);

        let mut cursor = std::io::Cursor::new(&buffer);
        let deserialized = AttestationEntry::deserialize(&mut cursor).unwrap();

        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_attestation_entry_ordering() {
        let entry1 = AttestationEntry::new(1, make_test_hash(1));
        let entry2 = AttestationEntry::new(5, make_test_hash(2));
        let entry3 = AttestationEntry::new(10, make_test_hash(3));

        assert!(entry1 < entry2);
        assert!(entry2 < entry3);
        assert!(entry1 < entry3);
    }

    #[test]
    fn test_relay_attestation_serialization_roundtrip() {
        let entries = vec![
            AttestationEntry::new(3, make_test_hash(3)),
            AttestationEntry::new(1, make_test_hash(1)),
            AttestationEntry::new(7, make_test_hash(7)),
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
        assert_eq!(attestation.relay_id, deserialized.relay_id);
        assert_eq!(attestation.entries, deserialized.entries);
        assert_eq!(attestation.relay_signature, deserialized.relay_signature);
    }

    #[test]
    fn test_entries_sorted_on_creation() {
        let entries = vec![
            AttestationEntry::new(10, make_test_hash(10)),
            AttestationEntry::new(2, make_test_hash(2)),
            AttestationEntry::new(5, make_test_hash(5)),
        ];

        let attestation = RelayAttestation::new(100, 1, entries);

        // Entries should be sorted by proposer_id
        assert_eq!(attestation.entries[0].proposer_id, 2);
        assert_eq!(attestation.entries[1].proposer_id, 5);
        assert_eq!(attestation.entries[2].proposer_id, 10);
    }

    #[test]
    fn test_has_proposer() {
        let entries = vec![
            AttestationEntry::new(1, make_test_hash(1)),
            AttestationEntry::new(5, make_test_hash(5)),
            AttestationEntry::new(10, make_test_hash(10)),
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
    fn test_get_merkle_root() {
        let entries = vec![
            AttestationEntry::new(1, make_test_hash(1)),
            AttestationEntry::new(5, make_test_hash(5)),
        ];

        let attestation = RelayAttestation::new(100, 1, entries);

        assert_eq!(attestation.get_merkle_root(1), Some(&make_test_hash(1)));
        assert_eq!(attestation.get_merkle_root(5), Some(&make_test_hash(5)));
        assert_eq!(attestation.get_merkle_root(3), None);
    }

    #[test]
    fn test_builder() {
        let attestation = RelayAttestationBuilder::new(100, 42)
            .add_entry(5, make_test_hash(5))
            .add_entry(1, make_test_hash(1))
            .add_entry(10, make_test_hash(10))
            .build_unsigned();

        assert_eq!(attestation.slot, 100);
        assert_eq!(attestation.relay_id, 42);
        assert_eq!(attestation.entries.len(), 3);
        // Should be sorted
        assert_eq!(attestation.entries[0].proposer_id, 1);
        assert_eq!(attestation.entries[1].proposer_id, 5);
        assert_eq!(attestation.entries[2].proposer_id, 10);
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
            AttestationEntry::new(1, make_test_hash(1)),
            AttestationEntry::new(5, make_test_hash(5)),
        ];

        let attestation = RelayAttestation::new(100, 1, entries);

        // 1 (version) + 8 (slot) + 2 (relay_id) + 2 (entries_len) + 2 * 33 (entries)
        let expected = 1 + 8 + 2 + 2 + 2 * ATTESTATION_ENTRY_SIZE;
        assert_eq!(attestation.signing_data_size(), expected);
        assert_eq!(attestation.serialized_size(), expected + 64);
    }

    #[test]
    fn test_deserialize_rejects_unsorted() {
        // Manually construct invalid wire format with unsorted entries
        let mut buffer = Vec::new();
        buffer.push(RELAY_ATTESTATION_VERSION); // version
        buffer.extend_from_slice(&100u64.to_le_bytes()); // slot
        buffer.extend_from_slice(&1u16.to_le_bytes()); // relay_id
        buffer.extend_from_slice(&2u16.to_le_bytes()); // entries_len = 2

        // Entry 1: proposer_id = 5
        buffer.push(5);
        buffer.extend_from_slice(&[1u8; 32]);

        // Entry 2: proposer_id = 3 (out of order!)
        buffer.push(3);
        buffer.extend_from_slice(&[2u8; 32]);

        // Signature
        buffer.extend_from_slice(&[0u8; 64]);

        let mut cursor = std::io::Cursor::new(&buffer);
        let result = RelayAttestation::deserialize(&mut cursor);
        assert!(result.is_err());
    }
}
