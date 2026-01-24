//! MCP Storage Schema
//!
//! This module defines the storage schema for MCP data as specified in §14:
//!
//! | Column Family | Key | Value |
//! |---|---|---|
//! | `McpShred` | `(slot, proposer_index, shred_index)` | `McpShredV1` bytes |
//! | `McpRelayAttestation` | `(slot, relay_index)` | `RelayAttestationV1` bytes |
//! | `McpBlock` | `(slot, block_hash)` | `McpBlockV1` bytes |
//! | `McpReconstructedPayload` | `(slot, block_hash, proposer_index)` | `McpPayloadV1` bytes or ⊥ |
//! | `McpExecutionOutput` | `(slot, block_hash)` | execution result |
//!
//! This module provides:
//! - Key encoding/decoding for each column family
//! - Type definitions for stored values
//! - Helper functions for working with MCP storage

use {
    solana_clock::Slot,
    solana_hash::Hash,
    std::io::{self, Read, Write},
};

// ============================================================================
// Column Family Names
// ============================================================================

/// Column family name for MCP shreds
pub const MCP_SHRED_CF: &str = "mcp_shred";

/// Column family name for relay attestations
pub const MCP_RELAY_ATTESTATION_CF: &str = "mcp_relay_attestation";

/// Column family name for MCP blocks
pub const MCP_BLOCK_CF: &str = "mcp_block";

/// Column family name for reconstructed payloads
pub const MCP_RECONSTRUCTED_PAYLOAD_CF: &str = "mcp_reconstructed_payload";

/// Column family name for execution outputs
pub const MCP_EXECUTION_OUTPUT_CF: &str = "mcp_execution_output";

/// All MCP column family names
pub const MCP_COLUMN_FAMILIES: &[&str] = &[
    MCP_SHRED_CF,
    MCP_RELAY_ATTESTATION_CF,
    MCP_BLOCK_CF,
    MCP_RECONSTRUCTED_PAYLOAD_CF,
    MCP_EXECUTION_OUTPUT_CF,
];

// ============================================================================
// Key Types
// ============================================================================

/// Key for MCP shreds: (slot, proposer_index, shred_index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct McpShredKey {
    pub slot: Slot,
    pub proposer_index: u8,
    pub shred_index: u16,
}

impl McpShredKey {
    /// Create a new shred key
    pub const fn new(slot: Slot, proposer_index: u8, shred_index: u16) -> Self {
        Self {
            slot,
            proposer_index,
            shred_index,
        }
    }

    /// Encode to bytes (big-endian for lexicographic ordering)
    pub fn encode(&self) -> [u8; 11] {
        let mut key = [0u8; 11];
        key[0..8].copy_from_slice(&self.slot.to_be_bytes());
        key[8] = self.proposer_index;
        key[9..11].copy_from_slice(&self.shred_index.to_be_bytes());
        key
    }

    /// Decode from bytes
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 11 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Key too short"));
        }
        let slot = Slot::from_be_bytes(bytes[0..8].try_into().unwrap());
        let proposer_index = bytes[8];
        let shred_index = u16::from_be_bytes(bytes[9..11].try_into().unwrap());
        Ok(Self {
            slot,
            proposer_index,
            shred_index,
        })
    }

    /// Create a prefix key for iterating all shreds in a slot
    pub fn slot_prefix(slot: Slot) -> [u8; 8] {
        slot.to_be_bytes()
    }

    /// Create a prefix key for iterating all shreds for a proposer in a slot
    pub fn proposer_prefix(slot: Slot, proposer_index: u8) -> [u8; 9] {
        let mut prefix = [0u8; 9];
        prefix[0..8].copy_from_slice(&slot.to_be_bytes());
        prefix[8] = proposer_index;
        prefix
    }
}

/// Key for relay attestations: (slot, relay_index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct McpRelayAttestationKey {
    pub slot: Slot,
    pub relay_index: u16,
}

impl McpRelayAttestationKey {
    /// Create a new attestation key
    pub const fn new(slot: Slot, relay_index: u16) -> Self {
        Self { slot, relay_index }
    }

    /// Encode to bytes
    pub fn encode(&self) -> [u8; 10] {
        let mut key = [0u8; 10];
        key[0..8].copy_from_slice(&self.slot.to_be_bytes());
        key[8..10].copy_from_slice(&self.relay_index.to_be_bytes());
        key
    }

    /// Decode from bytes
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 10 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Key too short"));
        }
        let slot = Slot::from_be_bytes(bytes[0..8].try_into().unwrap());
        let relay_index = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
        Ok(Self { slot, relay_index })
    }

    /// Create a prefix key for iterating all attestations in a slot
    pub fn slot_prefix(slot: Slot) -> [u8; 8] {
        slot.to_be_bytes()
    }
}

/// Key for MCP blocks: (slot, block_hash)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct McpBlockKey {
    pub slot: Slot,
    pub block_hash: Hash,
}

impl McpBlockKey {
    /// Create a new block key
    pub const fn new(slot: Slot, block_hash: Hash) -> Self {
        Self { slot, block_hash }
    }

    /// Encode to bytes
    pub fn encode(&self) -> [u8; 40] {
        let mut key = [0u8; 40];
        key[0..8].copy_from_slice(&self.slot.to_be_bytes());
        key[8..40].copy_from_slice(self.block_hash.as_ref());
        key
    }

    /// Decode from bytes
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 40 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Key too short"));
        }
        let slot = Slot::from_be_bytes(bytes[0..8].try_into().unwrap());
        let block_hash = Hash::new_from_array(bytes[8..40].try_into().unwrap());
        Ok(Self { slot, block_hash })
    }

    /// Create a prefix key for iterating all blocks in a slot
    pub fn slot_prefix(slot: Slot) -> [u8; 8] {
        slot.to_be_bytes()
    }
}

/// Key for reconstructed payloads: (slot, block_hash, proposer_index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct McpReconstructedPayloadKey {
    pub slot: Slot,
    pub block_hash: Hash,
    pub proposer_index: u8,
}

impl McpReconstructedPayloadKey {
    /// Create a new payload key
    pub const fn new(slot: Slot, block_hash: Hash, proposer_index: u8) -> Self {
        Self {
            slot,
            block_hash,
            proposer_index,
        }
    }

    /// Encode to bytes
    pub fn encode(&self) -> [u8; 41] {
        let mut key = [0u8; 41];
        key[0..8].copy_from_slice(&self.slot.to_be_bytes());
        key[8..40].copy_from_slice(self.block_hash.as_ref());
        key[40] = self.proposer_index;
        key
    }

    /// Decode from bytes
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 41 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Key too short"));
        }
        let slot = Slot::from_be_bytes(bytes[0..8].try_into().unwrap());
        let block_hash = Hash::new_from_array(bytes[8..40].try_into().unwrap());
        let proposer_index = bytes[40];
        Ok(Self {
            slot,
            block_hash,
            proposer_index,
        })
    }

    /// Create a prefix key for iterating all payloads for a block
    pub fn block_prefix(slot: Slot, block_hash: &Hash) -> [u8; 40] {
        let mut prefix = [0u8; 40];
        prefix[0..8].copy_from_slice(&slot.to_be_bytes());
        prefix[8..40].copy_from_slice(block_hash.as_ref());
        prefix
    }
}

/// Key for execution outputs: (slot, block_hash)
pub type McpExecutionOutputKey = McpBlockKey;

// ============================================================================
// Value Types
// ============================================================================

/// Marker for a payload that failed reconstruction
pub const RECONSTRUCTION_FAILED_MARKER: &[u8] = b"\x00FAILED";

/// Result of payload reconstruction for storage
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredPayloadResult {
    /// Successfully reconstructed payload
    Success(Vec<u8>),
    /// Reconstruction failed (⊥)
    Failed,
}

impl StoredPayloadResult {
    /// Encode for storage
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Success(data) => data.clone(),
            Self::Failed => RECONSTRUCTION_FAILED_MARKER.to_vec(),
        }
    }

    /// Decode from storage
    pub fn decode(bytes: &[u8]) -> Self {
        if bytes == RECONSTRUCTION_FAILED_MARKER {
            Self::Failed
        } else {
            Self::Success(bytes.to_vec())
        }
    }

    /// Check if this is a successful result
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }
}

/// Execution output status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecutionStatus {
    /// Execution completed successfully
    Success = 0,
    /// Execution failed
    Failed = 1,
    /// Execution not yet complete
    Pending = 2,
}

impl From<u8> for ExecutionStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::Failed,
            _ => Self::Pending,
        }
    }
}

/// Stored execution output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredExecutionOutput {
    /// Execution status
    pub status: ExecutionStatus,
    /// Number of transactions processed
    pub tx_count: u32,
    /// Number of successful transactions
    pub success_count: u32,
    /// Number of failed transactions
    pub failed_count: u32,
    /// Total validator fees collected
    pub validator_fees: u64,
    /// Total proposer fees collected
    pub proposer_fees: u64,
    /// Final bank hash (if available)
    pub final_hash: Option<Hash>,
}

impl StoredExecutionOutput {
    /// Encode for storage
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[self.status as u8])?;
        writer.write_all(&self.tx_count.to_le_bytes())?;
        writer.write_all(&self.success_count.to_le_bytes())?;
        writer.write_all(&self.failed_count.to_le_bytes())?;
        writer.write_all(&self.validator_fees.to_le_bytes())?;
        writer.write_all(&self.proposer_fees.to_le_bytes())?;

        // Optional hash
        match &self.final_hash {
            Some(hash) => {
                writer.write_all(&[1])?;
                writer.write_all(hash.as_ref())?;
            }
            None => {
                writer.write_all(&[0])?;
            }
        }

        Ok(())
    }

    /// Decode from storage
    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut status = [0u8; 1];
        reader.read_exact(&mut status)?;
        let status = ExecutionStatus::from(status[0]);

        let mut tx_count = [0u8; 4];
        reader.read_exact(&mut tx_count)?;
        let tx_count = u32::from_le_bytes(tx_count);

        let mut success_count = [0u8; 4];
        reader.read_exact(&mut success_count)?;
        let success_count = u32::from_le_bytes(success_count);

        let mut failed_count = [0u8; 4];
        reader.read_exact(&mut failed_count)?;
        let failed_count = u32::from_le_bytes(failed_count);

        let mut validator_fees = [0u8; 8];
        reader.read_exact(&mut validator_fees)?;
        let validator_fees = u64::from_le_bytes(validator_fees);

        let mut proposer_fees = [0u8; 8];
        reader.read_exact(&mut proposer_fees)?;
        let proposer_fees = u64::from_le_bytes(proposer_fees);

        let mut has_hash = [0u8; 1];
        reader.read_exact(&mut has_hash)?;
        let final_hash = if has_hash[0] == 1 {
            let mut hash_bytes = [0u8; 32];
            reader.read_exact(&mut hash_bytes)?;
            Some(Hash::new_from_array(hash_bytes))
        } else {
            None
        };

        Ok(Self {
            status,
            tx_count,
            success_count,
            failed_count,
            validator_fees,
            proposer_fees,
            final_hash,
        })
    }

    /// Serialized size
    pub fn serialized_size(&self) -> usize {
        1 + 4 + 4 + 4 + 8 + 8 + 1 + if self.final_hash.is_some() { 32 } else { 0 }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_shred_key_encoding() {
        let key = McpShredKey::new(12345, 7, 199);
        let encoded = key.encode();
        let decoded = McpShredKey::decode(&encoded).unwrap();

        assert_eq!(decoded.slot, 12345);
        assert_eq!(decoded.proposer_index, 7);
        assert_eq!(decoded.shred_index, 199);
    }

    #[test]
    fn test_mcp_shred_key_ordering() {
        let key1 = McpShredKey::new(100, 0, 0);
        let key2 = McpShredKey::new(100, 0, 1);
        let key3 = McpShredKey::new(100, 1, 0);
        let key4 = McpShredKey::new(101, 0, 0);

        // Lexicographic ordering should match logical ordering
        assert!(key1.encode() < key2.encode());
        assert!(key2.encode() < key3.encode());
        assert!(key3.encode() < key4.encode());
    }

    #[test]
    fn test_relay_attestation_key_encoding() {
        let key = McpRelayAttestationKey::new(12345, 199);
        let encoded = key.encode();
        let decoded = McpRelayAttestationKey::decode(&encoded).unwrap();

        assert_eq!(decoded.slot, 12345);
        assert_eq!(decoded.relay_index, 199);
    }

    #[test]
    fn test_block_key_encoding() {
        let hash = Hash::new_from_array([42u8; 32]);
        let key = McpBlockKey::new(12345, hash);
        let encoded = key.encode();
        let decoded = McpBlockKey::decode(&encoded).unwrap();

        assert_eq!(decoded.slot, 12345);
        assert_eq!(decoded.block_hash, hash);
    }

    #[test]
    fn test_reconstructed_payload_key_encoding() {
        let hash = Hash::new_from_array([42u8; 32]);
        let key = McpReconstructedPayloadKey::new(12345, hash, 7);
        let encoded = key.encode();
        let decoded = McpReconstructedPayloadKey::decode(&encoded).unwrap();

        assert_eq!(decoded.slot, 12345);
        assert_eq!(decoded.block_hash, hash);
        assert_eq!(decoded.proposer_index, 7);
    }

    #[test]
    fn test_stored_payload_result() {
        let success = StoredPayloadResult::Success(vec![1, 2, 3, 4]);
        let encoded = success.encode();
        let decoded = StoredPayloadResult::decode(&encoded);
        assert!(decoded.is_success());
        assert_eq!(decoded, success);

        let failed = StoredPayloadResult::Failed;
        let encoded = failed.encode();
        let decoded = StoredPayloadResult::decode(&encoded);
        assert!(!decoded.is_success());
        assert_eq!(decoded, failed);
    }

    #[test]
    fn test_stored_execution_output() {
        let output = StoredExecutionOutput {
            status: ExecutionStatus::Success,
            tx_count: 100,
            success_count: 95,
            failed_count: 5,
            validator_fees: 500_000,
            proposer_fees: 100_000,
            final_hash: Some(Hash::new_from_array([42u8; 32])),
        };

        let mut buffer = Vec::new();
        output.encode(&mut buffer).unwrap();

        let decoded = StoredExecutionOutput::decode(&mut buffer.as_slice()).unwrap();

        assert_eq!(decoded.status, ExecutionStatus::Success);
        assert_eq!(decoded.tx_count, 100);
        assert_eq!(decoded.success_count, 95);
        assert_eq!(decoded.failed_count, 5);
        assert_eq!(decoded.validator_fees, 500_000);
        assert_eq!(decoded.proposer_fees, 100_000);
        assert!(decoded.final_hash.is_some());
    }

    #[test]
    fn test_stored_execution_output_no_hash() {
        let output = StoredExecutionOutput {
            status: ExecutionStatus::Pending,
            tx_count: 0,
            success_count: 0,
            failed_count: 0,
            validator_fees: 0,
            proposer_fees: 0,
            final_hash: None,
        };

        let mut buffer = Vec::new();
        output.encode(&mut buffer).unwrap();

        let decoded = StoredExecutionOutput::decode(&mut buffer.as_slice()).unwrap();

        assert_eq!(decoded.status, ExecutionStatus::Pending);
        assert!(decoded.final_hash.is_none());
    }

    #[test]
    fn test_prefix_keys() {
        // Shred prefix
        let prefix = McpShredKey::slot_prefix(100);
        assert_eq!(prefix, 100u64.to_be_bytes());

        let proposer_prefix = McpShredKey::proposer_prefix(100, 5);
        assert_eq!(&proposer_prefix[0..8], &100u64.to_be_bytes());
        assert_eq!(proposer_prefix[8], 5);

        // Block prefix
        let hash = Hash::new_from_array([42u8; 32]);
        let block_prefix = McpReconstructedPayloadKey::block_prefix(100, &hash);
        assert_eq!(&block_prefix[0..8], &100u64.to_be_bytes());
        assert_eq!(&block_prefix[8..40], hash.as_ref());
    }
}
