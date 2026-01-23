//! MCP Replay Reconstruction
//!
//! This module implements the replay reconstruction pipeline for MCP:
//! 1. Deterministic ECC decode - reconstruct proposer payloads from shreds
//! 2. Global ordering - concatenate transactions from proposers
//! 3. De-duplication - remove duplicate transactions
//! 4. Two-phase processing - fee deduction then execution
//!
//! Per MCP spec §12:
//! - Reconstruction requires K_DATA_SHREDS (40) distinct shreds
//! - Proposers are processed in order of proposer_index
//! - First occurrence of a transaction wins (determines which proposer gets fees)

use {
    solana_clock::Slot,
    solana_hash::Hash,
    solana_ledger::{
        mcp::{fec::MCP_DATA_SHREDS_PER_FEC_BLOCK, NUM_PROPOSERS},
        mcp_merkle::{McpMerkleTree, LEAF_PAYLOAD_SIZE},
        mcp_reed_solomon::McpReedSolomon,
    },
    std::{
        collections::{HashMap, HashSet},
        io::{self, Read},
    },
};

/// Alias for the number of data shreds needed for reconstruction
const K_DATA_SHREDS: usize = MCP_DATA_SHREDS_PER_FEC_BLOCK;

/// Result of reconstructing a proposer's payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconstructionResult {
    /// Successfully reconstructed payload
    Success(McpPayload),
    /// Not enough shreds to reconstruct
    InsufficientShreds { available: usize, required: usize },
    /// Reconstruction failed verification (commitment mismatch)
    CommitmentMismatch,
    /// Payload parsing failed
    MalformedPayload(String),
}

/// MCP payload wire format per spec §5.
///
/// Wire format (McpPayloadV1):
/// ```text
/// | payload_version (1) | slot (8) | proposer_index (4) | payload_len (4) |
/// | tx_count (2) | TxEntry[tx_count] | reserved (zero-padded) |
///
/// TxEntry = | tx_len (2) | tx_bytes[tx_len] |
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpPayload {
    /// Payload version (must be 1)
    pub payload_version: u8,
    /// Slot number
    pub slot: u64,
    /// Proposer index [0..NUM_PROPOSERS-1]
    pub proposer_index: u32,
    /// Payload body length (bytes after this field)
    pub payload_len: u32,
    /// Number of transactions
    pub tx_count: u16,
    /// Raw transaction data
    pub tx_data: Vec<Vec<u8>>,
}

impl McpPayload {
    /// Create an empty payload for a given slot and proposer
    pub fn empty(slot: u64, proposer_index: u32) -> Self {
        Self {
            payload_version: 1,
            slot,
            proposer_index,
            payload_len: 2, // just tx_count (2 bytes)
            tx_count: 0,
            tx_data: Vec::new(),
        }
    }

    /// Parse payload from raw bytes per spec §5
    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);

        // Read payload_version (1 byte)
        let mut buf1 = [0u8; 1];
        cursor.read_exact(&mut buf1)?;
        let payload_version = buf1[0];
        if payload_version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid payload version: {}", payload_version),
            ));
        }

        // Read slot (8 bytes)
        let mut buf8 = [0u8; 8];
        cursor.read_exact(&mut buf8)?;
        let slot = u64::from_le_bytes(buf8);

        // Read proposer_index (4 bytes)
        let mut buf4 = [0u8; 4];
        cursor.read_exact(&mut buf4)?;
        let proposer_index = u32::from_le_bytes(buf4);

        // Read payload_len (4 bytes)
        cursor.read_exact(&mut buf4)?;
        let payload_len = u32::from_le_bytes(buf4);

        // Read tx_count (2 bytes)
        let mut buf2 = [0u8; 2];
        cursor.read_exact(&mut buf2)?;
        let tx_count = u16::from_le_bytes(buf2);

        // Read TxEntries: each is tx_len (2 bytes) + tx_bytes
        let mut tx_data = Vec::with_capacity(tx_count as usize);
        for _ in 0..tx_count {
            // Read tx_len (2 bytes)
            cursor.read_exact(&mut buf2)?;
            let tx_len = u16::from_le_bytes(buf2);

            // Read tx_bytes
            let mut tx_bytes = vec![0u8; tx_len as usize];
            cursor.read_exact(&mut tx_bytes)?;
            tx_data.push(tx_bytes);
        }

        Ok(Self {
            payload_version,
            slot,
            proposer_index,
            payload_len,
            tx_count,
            tx_data,
        })
    }

    /// Serialize payload to bytes per spec §5
    pub fn to_bytes(&self) -> Vec<u8> {
        // Calculate payload body size: tx_count (2) + sum(2 + tx_len for each tx)
        let body_len: usize = 2 + self.tx_data.iter().map(|tx| 2 + tx.len()).sum::<usize>();

        let mut bytes = Vec::with_capacity(17 + body_len);
        bytes.push(self.payload_version);
        bytes.extend_from_slice(&self.slot.to_le_bytes());
        bytes.extend_from_slice(&self.proposer_index.to_le_bytes());
        bytes.extend_from_slice(&(body_len as u32).to_le_bytes());
        bytes.extend_from_slice(&self.tx_count.to_le_bytes());

        // Write TxEntries
        for tx in &self.tx_data {
            bytes.extend_from_slice(&(tx.len() as u16).to_le_bytes());
            bytes.extend_from_slice(tx);
        }
        bytes
    }
}

/// Shred data needed for reconstruction
#[derive(Debug, Clone)]
pub struct ShredData {
    /// Shred index (0-199)
    pub index: u16,
    /// Whether this is a data shard (index < K_DATA_SHREDS)
    pub is_data: bool,
    /// The shred payload
    pub data: Vec<u8>,
    /// Merkle proof for verification (32-byte hashes per spec §6)
    pub merkle_proof: Vec<[u8; 32]>,
}

impl ShredData {
    /// Check if this is a data shred
    pub fn is_data_shred(&self) -> bool {
        self.index < K_DATA_SHREDS as u16
    }
}

/// Tracks shreds for a single proposer within a slot
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ProposerShreds {
    /// Map of shred index to shred data
    shreds: HashMap<u16, ShredData>,
    /// The expected merkle commitment
    commitment: Option<Hash>,
}

impl ProposerShreds {
    /// Create a new tracker with expected commitment
    pub fn new(commitment: Hash) -> Self {
        Self {
            shreds: HashMap::new(),
            commitment: Some(commitment),
        }
    }

    /// Add a shred (must be verified before calling)
    pub fn add_shred(&mut self, shred: ShredData) {
        // Only keep first shred at each index
        self.shreds.entry(shred.index).or_insert(shred);
    }

    /// Get the number of distinct shreds
    pub fn shred_count(&self) -> usize {
        self.shreds.len()
    }

    /// Check if we have enough shreds to reconstruct
    pub fn can_reconstruct(&self) -> bool {
        self.shreds.len() >= K_DATA_SHREDS
    }

    /// Get the lowest K shred indices (for deterministic reconstruction)
    pub fn get_reconstruction_indices(&self) -> Vec<u16> {
        let mut indices: Vec<u16> = self.shreds.keys().copied().collect();
        indices.sort();
        indices.truncate(K_DATA_SHREDS);
        indices
    }

    /// Get shreds for reconstruction
    pub fn get_reconstruction_shreds(&self) -> Vec<&ShredData> {
        let indices = self.get_reconstruction_indices();
        indices
            .iter()
            .filter_map(|idx| self.shreds.get(idx))
            .collect()
    }
}

/// Tracks all shreds for a slot across all proposers
#[derive(Debug, Default)]
pub struct SlotReconstructionState {
    /// Slot number
    pub slot: Slot,
    /// Shred data per proposer
    pub proposers: HashMap<u32, ProposerShreds>,
    /// Set of implied proposers from the block
    pub implied_proposers: HashSet<u32>,
}

impl SlotReconstructionState {
    /// Create a new state for a slot
    pub fn new(slot: Slot) -> Self {
        Self {
            slot,
            proposers: HashMap::new(),
            implied_proposers: HashSet::new(),
        }
    }

    /// Set the implied proposers from the consensus block
    pub fn set_implied_proposers(&mut self, proposers: Vec<(u32, Hash)>) {
        for (proposer_id, commitment) in proposers {
            self.implied_proposers.insert(proposer_id);
            self.proposers
                .entry(proposer_id)
                .or_insert_with(|| ProposerShreds::new(commitment));
        }
    }

    /// Add a shred for a proposer
    pub fn add_shred(&mut self, proposer_id: u32, shred: ShredData) {
        self.proposers
            .entry(proposer_id)
            .or_default()
            .add_shred(shred);
    }

    /// Check if all implied proposers can be reconstructed
    pub fn can_reconstruct_all(&self) -> bool {
        self.implied_proposers.iter().all(|p| {
            self.proposers
                .get(p)
                .map(|ps| ps.can_reconstruct())
                .unwrap_or(false)
        })
    }

    /// Get reconstruction status for each proposer
    pub fn get_reconstruction_status(&self) -> Vec<(u32, bool, usize)> {
        (0..NUM_PROPOSERS as u32)
            .map(|p| {
                let (can_reconstruct, count) = self
                    .proposers
                    .get(&p)
                    .map(|ps| (ps.can_reconstruct(), ps.shred_count()))
                    .unwrap_or((false, 0));
                (p, can_reconstruct, count)
            })
            .collect()
    }
}

/// Transaction with its source proposer for de-duplication
#[derive(Debug, Clone)]
pub struct OrderedTransaction {
    /// The proposer that included this transaction
    pub proposer_id: u32,
    /// The raw transaction bytes
    pub tx_bytes: Vec<u8>,
    /// Transaction ID (SHA256 of tx_bytes)
    pub txid: Hash,
}

impl OrderedTransaction {
    /// Create a new ordered transaction
    pub fn new(proposer_id: u32, tx_bytes: Vec<u8>) -> Self {
        // Compute txid = SHA256(tx_bytes)
        use solana_sha256_hasher::Hasher;
        let mut hasher = Hasher::default();
        hasher.hash(&tx_bytes);
        let txid = Hash::new_from_array(hasher.result().to_bytes());

        Self {
            proposer_id,
            tx_bytes,
            txid,
        }
    }
}

/// Result of reconstruction for the entire slot
#[derive(Debug)]
pub struct SlotReconstruction {
    /// Slot number
    pub slot: Slot,
    /// Reconstructed payloads per proposer (None if failed)
    pub payloads: HashMap<u32, ReconstructionResult>,
    /// Global ordered and de-duplicated transaction list
    pub ordered_transactions: Vec<OrderedTransaction>,
}

impl SlotReconstruction {
    /// Create a new slot reconstruction result
    pub fn new(slot: Slot) -> Self {
        Self {
            slot,
            payloads: HashMap::new(),
            ordered_transactions: Vec::new(),
        }
    }

    /// Add a payload reconstruction result
    pub fn add_payload(&mut self, proposer_id: u32, result: ReconstructionResult) {
        self.payloads.insert(proposer_id, result);
    }

    /// Build the global ordered transaction list from payloads
    pub fn build_ordered_transactions(&mut self) {
        let mut seen_txids: HashSet<Hash> = HashSet::new();
        let mut ordered = Vec::new();

        // Iterate proposers by increasing proposer_id
        for proposer_id in 0..NUM_PROPOSERS as u32 {
            if let Some(ReconstructionResult::Success(payload)) = self.payloads.get(&proposer_id) {
                // Add transactions from this proposer
                for tx_bytes in &payload.tx_data {
                    let tx = OrderedTransaction::new(proposer_id, tx_bytes.clone());

                    // De-duplication: only keep first occurrence
                    if seen_txids.insert(tx.txid) {
                        ordered.push(tx);
                    }
                }
            }
        }

        self.ordered_transactions = ordered;
    }

    /// Get the number of successfully reconstructed proposers
    pub fn successful_proposer_count(&self) -> usize {
        self.payloads
            .values()
            .filter(|r| matches!(r, ReconstructionResult::Success(_)))
            .count()
    }

    /// Get the total transaction count after de-duplication
    pub fn transaction_count(&self) -> usize {
        self.ordered_transactions.len()
    }
}

// ============================================================================
// Reconstruction Functions
// ============================================================================

/// Reed-Solomon decoder wrapper for deterministic reconstruction.
///
/// Per spec §12.1, reconstruction uses the first K_DATA_SHREDS indices
/// to deterministically decode the original payload.
pub struct DeterministicDecoder {
    rs_codec: McpReedSolomon,
}

impl Default for DeterministicDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DeterministicDecoder {
    /// Create a new decoder
    pub fn new() -> Self {
        Self {
            rs_codec: McpReedSolomon::default(),
        }
    }

    /// Decode payload from shreds using Reed-Solomon.
    ///
    /// Per spec §12.1:
    /// 1. Collect shreds with valid Merkle proofs
    /// 2. Take first K_DATA_SHREDS indices (sorted)
    /// 3. Decode RS to recover M_padded
    /// 4. Re-encode and verify commitment matches
    pub fn decode(
        &self,
        shreds: &[&ShredData],
        expected_commitment: &Hash,
    ) -> Result<Vec<u8>, String> {
        if shreds.len() < K_DATA_SHREDS {
            return Err(format!(
                "Not enough shreds: {} < {}",
                shreds.len(),
                K_DATA_SHREDS
            ));
        }

        // Build (index, data) pairs for RS reconstruction
        let available_shards: Vec<(usize, Vec<u8>)> = shreds
            .iter()
            .take(K_DATA_SHREDS) // Take first K (already sorted by caller)
            .map(|s| {
                // Ensure shred data is exactly LEAF_PAYLOAD_SIZE
                let mut data = s.data.clone();
                data.resize(LEAF_PAYLOAD_SIZE, 0);
                (s.index as usize, data)
            })
            .collect();

        // Use RS codec to reconstruct
        let decoded = self.rs_codec.reconstruct(&available_shards)
            .map_err(|e| format!("RS reconstruction failed: {}", e))?;

        // Verify the commitment by re-encoding and computing Merkle root
        if !self.verify_commitment(&decoded, expected_commitment) {
            return Err("Commitment verification failed".to_string());
        }

        Ok(decoded)
    }

    /// Verify that decoded data matches the expected commitment.
    ///
    /// Per spec §12.1 step 5:
    /// 1. Re-encode M_padded using RS
    /// 2. Compute Merkle commitment root
    /// 3. Compare against expected commitment
    fn verify_commitment(&self, data: &[u8], expected_commitment: &Hash) -> bool {
        // Re-encode using RS to get all shards
        let all_shards = match self.rs_codec.encode(data) {
            Ok(shards) => shards,
            Err(_) => return false,
        };

        // Build Merkle tree from the shards
        let payload_refs: Vec<&[u8]> = all_shards.iter().map(|s| s.as_slice()).collect();
        let tree = McpMerkleTree::from_payloads(&payload_refs);
        let computed_commitment = tree.commitment();

        // Compare against expected
        computed_commitment == *expected_commitment
    }
}

/// Decode payload using Reed-Solomon (convenience function)
pub fn decode_reed_solomon(
    shreds: &[&ShredData],
    expected_commitment: &Hash,
) -> Result<Vec<u8>, String> {
    let decoder = DeterministicDecoder::new();
    decoder.decode(shreds, expected_commitment)
}

/// Verify that decoded data matches the expected commitment.
pub fn verify_commitment(data: &[u8], expected_commitment: &Hash) -> bool {
    let decoder = DeterministicDecoder::new();
    decoder.verify_commitment(data, expected_commitment)
}

/// Reconstruct a single proposer's payload
pub fn reconstruct_proposer_payload(
    shreds: &ProposerShreds,
    commitment: &Hash,
) -> ReconstructionResult {
    // Check if we have enough shreds
    if !shreds.can_reconstruct() {
        return ReconstructionResult::InsufficientShreds {
            available: shreds.shred_count(),
            required: K_DATA_SHREDS,
        };
    }

    // Get the shreds for reconstruction (lowest K indices)
    let reconstruction_shreds = shreds.get_reconstruction_shreds();

    // Decode using Reed-Solomon
    let decoded_data = match decode_reed_solomon(&reconstruction_shreds, commitment) {
        Ok(data) => data,
        Err(e) => return ReconstructionResult::MalformedPayload(e),
    };

    // Verify commitment
    if !verify_commitment(&decoded_data, commitment) {
        return ReconstructionResult::CommitmentMismatch;
    }

    // Parse the payload
    match McpPayload::from_bytes(&decoded_data) {
        Ok(payload) => ReconstructionResult::Success(payload),
        Err(e) => ReconstructionResult::MalformedPayload(e.to_string()),
    }
}

/// Reconstruct all proposers for a slot
pub fn reconstruct_slot(
    state: &SlotReconstructionState,
    implied_proposers: &[(u32, Hash)],
) -> SlotReconstruction {
    let mut result = SlotReconstruction::new(state.slot);

    // Reconstruct each implied proposer
    for (proposer_id, commitment) in implied_proposers {
        let reconstruction_result = if let Some(shreds) = state.proposers.get(proposer_id) {
            reconstruct_proposer_payload(shreds, commitment)
        } else {
            ReconstructionResult::InsufficientShreds {
                available: 0,
                required: K_DATA_SHREDS,
            }
        };

        result.add_payload(*proposer_id, reconstruction_result);
    }

    // Build the global ordered transaction list
    result.build_ordered_transactions();

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    fn make_test_shred(index: u16, data: &[u8]) -> ShredData {
        ShredData {
            index,
            is_data: index < K_DATA_SHREDS as u16,
            data: data.to_vec(),
            merkle_proof: Vec::new(),
        }
    }

    #[test]
    fn test_mcp_payload_serialization() {
        let payload = McpPayload {
            payload_version: 1,
            slot: 12345,
            proposer_index: 3,
            payload_len: 56, // 2 + (2+20) + (2+30) = 56
            tx_count: 2,
            tx_data: vec![vec![1u8; 20], vec![2u8; 30]],
        };

        let bytes = payload.to_bytes();
        let parsed = McpPayload::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.payload_version, 1);
        assert_eq!(parsed.slot, 12345);
        assert_eq!(parsed.proposer_index, 3);
        assert_eq!(parsed.tx_count, 2);
        assert_eq!(parsed.tx_data.len(), 2);
        assert_eq!(parsed.tx_data[0].len(), 20);
        assert_eq!(parsed.tx_data[1].len(), 30);
    }

    #[test]
    fn test_proposer_shreds_tracking() {
        let mut shreds = ProposerShreds::new(make_test_hash(1));

        // Add shreds
        for i in 0..K_DATA_SHREDS {
            shreds.add_shred(make_test_shred(i as u16, &[i as u8; 100]));
        }

        assert!(shreds.can_reconstruct());
        assert_eq!(shreds.shred_count(), K_DATA_SHREDS);

        let indices = shreds.get_reconstruction_indices();
        assert_eq!(indices.len(), K_DATA_SHREDS);
        assert_eq!(indices[0], 0);
    }

    #[test]
    fn test_proposer_shreds_insufficient() {
        let mut shreds = ProposerShreds::new(make_test_hash(1));

        // Add only half the required shreds
        for i in 0..(K_DATA_SHREDS / 2) {
            shreds.add_shred(make_test_shred(i as u16, &[i as u8; 100]));
        }

        assert!(!shreds.can_reconstruct());
        assert_eq!(shreds.shred_count(), K_DATA_SHREDS / 2);
    }

    #[test]
    fn test_slot_reconstruction_state() {
        let mut state = SlotReconstructionState::new(100);

        // Set implied proposers
        state.set_implied_proposers(vec![
            (0, make_test_hash(1)),
            (1, make_test_hash(2)),
        ]);

        // Add shreds for proposer 0
        for i in 0..K_DATA_SHREDS {
            state.add_shred(0, make_test_shred(i as u16, &[i as u8; 100]));
        }

        // Add insufficient shreds for proposer 1
        for i in 0..10 {
            state.add_shred(1, make_test_shred(i as u16, &[i as u8; 100]));
        }

        assert!(!state.can_reconstruct_all());

        let status = state.get_reconstruction_status();
        assert_eq!(status[0], (0, true, K_DATA_SHREDS));
        assert_eq!(status[1], (1, false, 10));
    }

    #[test]
    fn test_ordered_transaction_dedup() {
        let mut result = SlotReconstruction::new(100);

        // Create payloads with duplicate transactions
        let tx1 = vec![1u8; 50];
        let tx2 = vec![2u8; 50];
        let tx3 = vec![3u8; 50];

        // Proposer 0 has tx1, tx2
        result.add_payload(
            0,
            ReconstructionResult::Success(McpPayload {
                payload_version: 1,
                slot: 100,
                proposer_index: 0,
                payload_len: 106, // 2 + (2+50) + (2+50)
                tx_count: 2,
                tx_data: vec![tx1.clone(), tx2.clone()],
            }),
        );

        // Proposer 1 has tx2 (duplicate), tx3
        result.add_payload(
            1,
            ReconstructionResult::Success(McpPayload {
                payload_version: 1,
                slot: 100,
                proposer_index: 1,
                payload_len: 106,
                tx_count: 2,
                tx_data: vec![tx2.clone(), tx3.clone()],
            }),
        );

        result.build_ordered_transactions();

        // Should have 3 unique transactions
        assert_eq!(result.transaction_count(), 3);

        // tx1 should come from proposer 0
        assert_eq!(result.ordered_transactions[0].proposer_id, 0);
        assert_eq!(result.ordered_transactions[0].tx_bytes, tx1);

        // tx2 should come from proposer 0 (first occurrence)
        assert_eq!(result.ordered_transactions[1].proposer_id, 0);
        assert_eq!(result.ordered_transactions[1].tx_bytes, tx2);

        // tx3 should come from proposer 1
        assert_eq!(result.ordered_transactions[2].proposer_id, 1);
        assert_eq!(result.ordered_transactions[2].tx_bytes, tx3);
    }

    #[test]
    fn test_reconstruction_result_variants() {
        let payload = McpPayload::empty(100, 0);

        let success = ReconstructionResult::Success(payload);
        assert!(matches!(success, ReconstructionResult::Success(_)));

        let insufficient = ReconstructionResult::InsufficientShreds {
            available: 20,
            required: 40,
        };
        assert!(matches!(insufficient, ReconstructionResult::InsufficientShreds { .. }));

        let mismatch = ReconstructionResult::CommitmentMismatch;
        assert!(matches!(mismatch, ReconstructionResult::CommitmentMismatch));

        let malformed = ReconstructionResult::MalformedPayload("test".to_string());
        assert!(matches!(malformed, ReconstructionResult::MalformedPayload(_)));
    }
}
