//! MCP Proposer Operations
//!
//! This module implements the proposer operations for MCP as defined in spec §8:
//! 1. Transaction intake and filtering
//! 2. Ordering and packing
//! 3. Encoding and commitment
//! 4. Shred generation
//!
//! Proposers collect transactions, pack them into a payload, erasure-encode
//! the payload into shreds, compute the Merkle commitment, and distribute
//! shreds to relays.

use {
    solana_clock::Slot,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::{
        mcp::NUM_PROPOSERS,
        mcp_merkle::{
            McpMerkleTree, LEAF_PAYLOAD_SIZE, PROOF_ENTRIES, HASH_SIZE, WitnessHash,
        },
        mcp_reed_solomon::{McpReedSolomon, McpRsError, K_DATA_SHARDS, MCP_SHARD_SIZE, N_TOTAL_SHARDS},
    },
    solana_sha256_hasher::Hasher,
    solana_signer::Signer,
    std::io::{self, Write},
};

/// Maximum payload size in bytes (K * shard_size)
pub const MAX_PROPOSER_PAYLOAD_BYTES: usize = K_DATA_SHARDS * MCP_SHARD_SIZE;

/// Maximum serialized transaction size
pub const MAX_TX_SIZE: usize = 4096;

/// Domain separator for proposer signature
/// Domain prefix for proposer commitment signature per spec §5.2.
pub const PROPOSER_SIG_DOMAIN: &[u8] = b"mcp:commitment:v1";

/// Error type for proposer operations
#[derive(Debug)]
pub enum ProposerError {
    /// Transaction too large
    TransactionTooLarge { size: usize, max: usize },
    /// Payload too large
    PayloadTooLarge { size: usize, max: usize },
    /// Reed-Solomon encoding failed
    EncodingFailed(McpRsError),
    /// IO error
    IoError(io::Error),
    /// Invalid proposer ID
    InvalidProposerId(u8),
}

impl std::fmt::Display for ProposerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TransactionTooLarge { size, max } => {
                write!(f, "Transaction too large: {} bytes (max {})", size, max)
            }
            Self::PayloadTooLarge { size, max } => {
                write!(f, "Payload too large: {} bytes (max {})", size, max)
            }
            Self::EncodingFailed(e) => write!(f, "Encoding failed: {}", e),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::InvalidProposerId(id) => {
                write!(f, "Invalid proposer ID: {} (max {})", id, NUM_PROPOSERS - 1)
            }
        }
    }
}

impl std::error::Error for ProposerError {}

impl From<McpRsError> for ProposerError {
    fn from(e: McpRsError) -> Self {
        Self::EncodingFailed(e)
    }
}

impl From<io::Error> for ProposerError {
    fn from(e: io::Error) -> Self {
        Self::IoError(e)
    }
}

/// A transaction with its ordering metadata
#[derive(Debug, Clone)]
pub struct OrderedTransaction {
    /// Serialized transaction bytes
    pub tx_bytes: Vec<u8>,
    /// Ordering fee (higher = earlier in ordering)
    pub ordering_fee: u64,
    /// Hash of the transaction bytes for deterministic ordering
    pub tx_hash: Hash,
    /// Target proposer (if specified)
    pub target_proposer: Option<u8>,
}

impl OrderedTransaction {
    /// Create a new ordered transaction
    pub fn new(tx_bytes: Vec<u8>, ordering_fee: u64, target_proposer: Option<u8>) -> Self {
        // Compute tx_hash = SHA256(tx_bytes)
        let mut hasher = Hasher::default();
        hasher.hash(&tx_bytes);
        let tx_hash = Hash::new_from_array(hasher.result().to_bytes());

        Self {
            tx_bytes,
            ordering_fee,
            tx_hash,
            target_proposer,
        }
    }

    /// Get the size of this transaction
    pub fn size(&self) -> usize {
        self.tx_bytes.len()
    }
}

/// MCP Payload wire format
///
/// - payload_len: u32 (total bytes excluding this field)
/// - tx_count: u32
/// - tx_len[]: tx_count × u32
/// - tx_data[]: concatenated transaction bytes
#[derive(Debug, Clone, Default)]
pub struct McpPayload {
    pub transactions: Vec<Vec<u8>>,
}

impl McpPayload {
    /// Create an empty payload
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
        }
    }

    /// Add a transaction to the payload
    pub fn add_transaction(&mut self, tx_bytes: Vec<u8>) {
        self.transactions.push(tx_bytes);
    }

    /// Get the total serialized size of this payload
    pub fn serialized_size(&self) -> usize {
        // payload_len (4) + tx_count (4) + tx_len[] + tx_data[]
        let header_size = 4 + 4 + (self.transactions.len() * 4);
        let data_size: usize = self.transactions.iter().map(|t| t.len()).sum();
        header_size + data_size
    }

    /// Serialize the payload to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.serialized_size());

        // Calculate payload_len (everything after this field)
        let payload_len = self.serialized_size() - 4;
        buffer.extend_from_slice(&(payload_len as u32).to_le_bytes());

        // tx_count
        buffer.extend_from_slice(&(self.transactions.len() as u32).to_le_bytes());

        // tx_len[]
        for tx in &self.transactions {
            buffer.extend_from_slice(&(tx.len() as u32).to_le_bytes());
        }

        // tx_data[]
        for tx in &self.transactions {
            buffer.extend_from_slice(tx);
        }

        buffer
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> io::Result<Self> {
        use std::io::Read;
        let mut cursor = std::io::Cursor::new(data);

        let mut buf = [0u8; 4];
        cursor.read_exact(&mut buf)?;
        let _payload_len = u32::from_le_bytes(buf);

        cursor.read_exact(&mut buf)?;
        let tx_count = u32::from_le_bytes(buf) as usize;

        let mut tx_lengths = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            cursor.read_exact(&mut buf)?;
            tx_lengths.push(u32::from_le_bytes(buf) as usize);
        }

        let mut transactions = Vec::with_capacity(tx_count);
        for len in tx_lengths {
            let mut tx_bytes = vec![0u8; len];
            cursor.read_exact(&mut tx_bytes)?;
            transactions.push(tx_bytes);
        }

        Ok(Self { transactions })
    }

    /// Get the number of transactions
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
}

/// An MCP shred ready to send to a relay
#[derive(Debug, Clone)]
pub struct McpShred {
    /// Slot number
    pub slot: Slot,
    /// Proposer ID (0-15)
    pub proposer_id: u8,
    /// Shred index (0-199, corresponds to relay index)
    pub shred_index: u16,
    /// Merkle commitment (32 bytes)
    pub commitment: Hash,
    /// Shred payload (1024 bytes per spec §4)
    pub shred_data: Vec<u8>,
    /// Merkle witness (8 × 32 bytes per spec §6)
    pub witness: [WitnessHash; PROOF_ENTRIES],
    /// Proposer signature (64 bytes)
    pub proposer_signature: [u8; 64],
}

impl McpShred {
    /// Total size of a serialized MCP shred
    pub const SIZE: usize = 8 + 4 + 4 + 32 + MCP_SHARD_SIZE + 1 + (PROOF_ENTRIES * HASH_SIZE) + 64;

    /// Serialize to bytes
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.slot.to_le_bytes())?;
        writer.write_all(&(self.proposer_id as u32).to_le_bytes())?;
        writer.write_all(&(self.shred_index as u32).to_le_bytes())?;
        writer.write_all(self.commitment.as_ref())?;
        writer.write_all(&self.shred_data)?;
        writer.write_all(&[PROOF_ENTRIES as u8])?; // witness_len
        for entry in &self.witness {
            writer.write_all(entry)?;
        }
        writer.write_all(&self.proposer_signature)?;
        Ok(())
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> io::Result<Self> {
        use std::io::Read;
        let mut cursor = std::io::Cursor::new(data);

        let mut slot_bytes = [0u8; 8];
        cursor.read_exact(&mut slot_bytes)?;
        let slot = Slot::from_le_bytes(slot_bytes);

        let mut proposer_id_bytes = [0u8; 4];
        cursor.read_exact(&mut proposer_id_bytes)?;
        let proposer_id = u32::from_le_bytes(proposer_id_bytes) as u8;

        let mut shred_index_bytes = [0u8; 4];
        cursor.read_exact(&mut shred_index_bytes)?;
        let shred_index = u32::from_le_bytes(shred_index_bytes) as u16;

        let mut commitment_bytes = [0u8; 32];
        cursor.read_exact(&mut commitment_bytes)?;
        let commitment = Hash::from(commitment_bytes);

        let mut shred_data = vec![0u8; MCP_SHARD_SIZE];
        cursor.read_exact(&mut shred_data)?;

        let mut witness_len = [0u8; 1];
        cursor.read_exact(&mut witness_len)?;
        assert_eq!(witness_len[0] as usize, PROOF_ENTRIES);

        let mut witness = [[0u8; HASH_SIZE]; PROOF_ENTRIES];
        for entry in &mut witness {
            cursor.read_exact(entry)?;
        }

        let mut proposer_signature = [0u8; 64];
        cursor.read_exact(&mut proposer_signature)?;

        Ok(Self {
            slot,
            proposer_id,
            shred_index,
            commitment,
            shred_data,
            witness,
            proposer_signature,
        })
    }
}

/// MCP Proposer - creates shreds from transactions
pub struct McpProposer {
    /// Proposer ID (0-15)
    proposer_id: u8,
    /// Current slot
    slot: Slot,
    /// Keypair for signing
    keypair: Keypair,
    /// RS codec
    rs_codec: McpReedSolomon,
}

impl McpProposer {
    /// Create a new proposer
    pub fn new(proposer_id: u8, slot: Slot, keypair: Keypair) -> Result<Self, ProposerError> {
        if proposer_id >= NUM_PROPOSERS {
            return Err(ProposerError::InvalidProposerId(proposer_id));
        }

        Ok(Self {
            proposer_id,
            slot,
            keypair,
            rs_codec: McpReedSolomon::default(),
        })
    }

    /// Filter transactions for this proposer
    pub fn filter_transactions(&self, transactions: Vec<OrderedTransaction>) -> Vec<OrderedTransaction> {
        transactions
            .into_iter()
            .filter(|tx| {
                // Filter by target_proposer if specified
                match tx.target_proposer {
                    Some(target) => target == self.proposer_id,
                    None => true,
                }
            })
            .filter(|tx| tx.size() <= MAX_TX_SIZE)
            .collect()
    }

    /// Order transactions by ordering_fee (desc) then tx_hash (asc)
    pub fn order_transactions(&self, mut transactions: Vec<OrderedTransaction>) -> Vec<OrderedTransaction> {
        transactions.sort_by(|a, b| {
            // First by ordering_fee descending
            match b.ordering_fee.cmp(&a.ordering_fee) {
                std::cmp::Ordering::Equal => {
                    // Then by tx_hash ascending
                    a.tx_hash.cmp(&b.tx_hash)
                }
                other => other,
            }
        });
        transactions
    }

    /// Pack transactions into a payload
    pub fn pack_payload(&self, transactions: Vec<OrderedTransaction>) -> McpPayload {
        let mut payload = McpPayload::new();
        let mut current_size = 8; // Header size (payload_len + tx_count)

        for tx in transactions {
            // Size if we add this transaction: +4 for tx_len + tx_bytes
            let additional_size = 4 + tx.tx_bytes.len();

            if current_size + additional_size > MAX_PROPOSER_PAYLOAD_BYTES {
                break;
            }

            current_size += additional_size;
            payload.add_transaction(tx.tx_bytes);
        }

        payload
    }

    /// Create shreds from a payload
    pub fn create_shreds(&self, payload: &McpPayload) -> Result<Vec<McpShred>, ProposerError> {
        let payload_bytes = payload.serialize();

        if payload_bytes.len() > MAX_PROPOSER_PAYLOAD_BYTES {
            return Err(ProposerError::PayloadTooLarge {
                size: payload_bytes.len(),
                max: MAX_PROPOSER_PAYLOAD_BYTES,
            });
        }

        // Step 1: Erasure encode the payload into shards
        let shards = self.rs_codec.encode(&payload_bytes)?;

        // Step 2: Pad shards to LEAF_PAYLOAD_SIZE for Merkle tree
        let padded_shards: Vec<Vec<u8>> = shards
            .iter()
            .map(|s| {
                let mut padded = vec![0u8; LEAF_PAYLOAD_SIZE];
                padded[..s.len()].copy_from_slice(s);
                padded
            })
            .collect();

        // Step 3: Build Merkle tree and get commitment
        let shard_refs: Vec<&[u8]> = padded_shards.iter().map(|s| s.as_slice()).collect();
        let merkle_tree = McpMerkleTree::from_payloads(&shard_refs);
        let commitment = merkle_tree.commitment();

        // Step 4: Sign the commitment
        let proposer_signature = self.sign_commitment(&commitment);

        // Step 5: Create shreds with witnesses
        let mut mcp_shreds = Vec::with_capacity(N_TOTAL_SHARDS);

        for (i, shard) in shards.into_iter().enumerate() {
            let proof = merkle_tree.get_proof(i as u8);

            mcp_shreds.push(McpShred {
                slot: self.slot,
                proposer_id: self.proposer_id,
                shred_index: i as u16,
                commitment,
                shred_data: shard,
                witness: proof.siblings,
                proposer_signature,
            });
        }

        Ok(mcp_shreds)
    }

    /// Sign the commitment: Ed25519Sign(SK, domain || commitment)
    /// Per spec §5.2: proposer_sig_msg = "mcp:commitment:v1" || commitment32
    fn sign_commitment(&self, commitment: &Hash) -> [u8; 64] {
        let mut message = Vec::with_capacity(PROPOSER_SIG_DOMAIN.len() + 32);
        message.extend_from_slice(PROPOSER_SIG_DOMAIN);
        message.extend_from_slice(commitment.as_ref());

        let signature = self.keypair.sign_message(&message);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature.as_ref());
        sig_bytes
    }

    /// Full proposer workflow: filter, order, pack, encode
    pub fn process_transactions(
        &self,
        transactions: Vec<OrderedTransaction>,
    ) -> Result<Vec<McpShred>, ProposerError> {
        let filtered = self.filter_transactions(transactions);
        let ordered = self.order_transactions(filtered);
        let payload = self.pack_payload(ordered);
        self.create_shreds(&payload)
    }

    /// Get the proposer ID
    pub fn proposer_id(&self) -> u8 {
        self.proposer_id
    }

    /// Get the slot
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Get the public key
    pub fn pubkey(&self) -> solana_pubkey::Pubkey {
        self.keypair.pubkey()
    }
}

/// Verify a proposer's signature on a commitment.
/// Per spec §5.2: proposer_sig_msg = "mcp:commitment:v1" || commitment32
pub fn verify_proposer_signature(
    proposer_pubkey: &solana_pubkey::Pubkey,
    commitment: &Hash,
    signature: &[u8; 64],
) -> bool {
    let mut message = Vec::with_capacity(PROPOSER_SIG_DOMAIN.len() + 32);
    message.extend_from_slice(PROPOSER_SIG_DOMAIN);
    message.extend_from_slice(commitment.as_ref());

    let sig = solana_signature::Signature::from(*signature);
    sig.verify(proposer_pubkey.as_ref(), &message)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_tx(id: u8, size: usize) -> Vec<u8> {
        vec![id; size]
    }

    fn make_ordered_tx(id: u8, size: usize, ordering_fee: u64, target: Option<u8>) -> OrderedTransaction {
        OrderedTransaction::new(make_test_tx(id, size), ordering_fee, target)
    }

    #[test]
    fn test_ordered_transaction_hash() {
        let tx1 = OrderedTransaction::new(vec![1, 2, 3], 0, None);
        let tx2 = OrderedTransaction::new(vec![1, 2, 3], 0, None);
        let tx3 = OrderedTransaction::new(vec![1, 2, 4], 0, None);

        assert_eq!(tx1.tx_hash, tx2.tx_hash);
        assert_ne!(tx1.tx_hash, tx3.tx_hash);
    }

    #[test]
    fn test_payload_serialization() {
        let mut payload = McpPayload::new();
        payload.add_transaction(vec![1, 2, 3, 4, 5]);
        payload.add_transaction(vec![6, 7, 8]);

        let bytes = payload.serialize();
        let deserialized = McpPayload::deserialize(&bytes).unwrap();

        assert_eq!(deserialized.tx_count(), 2);
        assert_eq!(deserialized.transactions[0], vec![1, 2, 3, 4, 5]);
        assert_eq!(deserialized.transactions[1], vec![6, 7, 8]);
    }

    #[test]
    fn test_filter_transactions() {
        let keypair = Keypair::new();
        let proposer = McpProposer::new(5, 100, keypair).unwrap();

        let transactions = vec![
            make_ordered_tx(1, 100, 0, None),           // No target - include
            make_ordered_tx(2, 100, 0, Some(5)),       // Target 5 - include
            make_ordered_tx(3, 100, 0, Some(6)),       // Target 6 - exclude
            make_ordered_tx(4, MAX_TX_SIZE + 1, 0, None), // Too large - exclude
        ];

        let filtered = proposer.filter_transactions(transactions);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_order_transactions() {
        let keypair = Keypair::new();
        let proposer = McpProposer::new(0, 100, keypair).unwrap();

        let transactions = vec![
            make_ordered_tx(1, 100, 100, None),
            make_ordered_tx(2, 100, 200, None),
            make_ordered_tx(3, 100, 100, None),
        ];

        let ordered = proposer.order_transactions(transactions);

        // First should be tx2 (highest fee)
        assert_eq!(ordered[0].ordering_fee, 200);

        // tx1 and tx3 have same fee, ordered by hash
        assert_eq!(ordered[1].ordering_fee, 100);
        assert_eq!(ordered[2].ordering_fee, 100);
        assert!(ordered[1].tx_hash < ordered[2].tx_hash);
    }

    #[test]
    fn test_pack_payload_size_limit() {
        let keypair = Keypair::new();
        let proposer = McpProposer::new(0, 100, keypair).unwrap();

        // Create transactions that would exceed payload limit
        let tx_size = 1000;
        let max_count = MAX_PROPOSER_PAYLOAD_BYTES / (tx_size + 4); // +4 for length field

        let transactions: Vec<OrderedTransaction> = (0..max_count + 10)
            .map(|i| make_ordered_tx(i as u8, tx_size, 0, None))
            .collect();

        let payload = proposer.pack_payload(transactions);

        assert!(payload.serialized_size() <= MAX_PROPOSER_PAYLOAD_BYTES);
        assert!(payload.tx_count() < max_count + 10);
    }

    #[test]
    fn test_create_shreds() {
        let keypair = Keypair::new();
        let proposer = McpProposer::new(0, 100, keypair).unwrap();

        let mut payload = McpPayload::new();
        payload.add_transaction(vec![1, 2, 3, 4, 5]);
        payload.add_transaction(vec![6, 7, 8, 9, 10]);

        let shreds = proposer.create_shreds(&payload).unwrap();

        assert_eq!(shreds.len(), N_TOTAL_SHARDS);

        // Check all shreds have correct metadata
        for (i, shred) in shreds.iter().enumerate() {
            assert_eq!(shred.slot, 100);
            assert_eq!(shred.proposer_id, 0);
            assert_eq!(shred.shred_index, i as u16);
            assert_eq!(shred.shred_data.len(), MCP_SHARD_SIZE);
            assert_eq!(shred.witness.len(), PROOF_ENTRIES);
        }

        // All shreds should have the same commitment
        let commitment = shreds[0].commitment;
        for shred in &shreds {
            assert_eq!(shred.commitment, commitment);
        }
    }

    #[test]
    fn test_shred_serialization() {
        let keypair = Keypair::new();
        let proposer = McpProposer::new(0, 100, keypair).unwrap();

        let mut payload = McpPayload::new();
        payload.add_transaction(vec![1, 2, 3]);

        let shreds = proposer.create_shreds(&payload).unwrap();
        let shred = &shreds[0];

        let mut buffer = Vec::new();
        shred.serialize(&mut buffer).unwrap();

        let deserialized = McpShred::deserialize(&buffer).unwrap();

        assert_eq!(deserialized.slot, shred.slot);
        assert_eq!(deserialized.proposer_id, shred.proposer_id);
        assert_eq!(deserialized.shred_index, shred.shred_index);
        assert_eq!(deserialized.commitment, shred.commitment);
        assert_eq!(deserialized.shred_data, shred.shred_data);
        assert_eq!(deserialized.witness, shred.witness);
        assert_eq!(deserialized.proposer_signature, shred.proposer_signature);
    }

    #[test]
    fn test_verify_proposer_signature() {
        let keypair = Keypair::new();
        let proposer = McpProposer::new(3, 100, keypair).unwrap();

        let mut payload = McpPayload::new();
        payload.add_transaction(vec![1, 2, 3]);

        let shreds = proposer.create_shreds(&payload).unwrap();
        let shred = &shreds[0];

        // Verify signature - per spec §5.2, signature is over domain || commitment only
        assert!(verify_proposer_signature(
            &proposer.pubkey(),
            &shred.commitment,
            &shred.proposer_signature,
        ));

        // Wrong pubkey should fail
        let wrong_keypair = Keypair::new();
        assert!(!verify_proposer_signature(
            &wrong_keypair.pubkey(),
            &shred.commitment,
            &shred.proposer_signature,
        ));
    }

    #[test]
    fn test_full_proposer_workflow() {
        let keypair = Keypair::new();
        let proposer = McpProposer::new(0, 100, keypair).unwrap();

        let transactions = vec![
            make_ordered_tx(1, 100, 500, None),
            make_ordered_tx(2, 200, 100, None),
            make_ordered_tx(3, 150, 500, None),
        ];

        let shreds = proposer.process_transactions(transactions).unwrap();

        assert_eq!(shreds.len(), N_TOTAL_SHARDS);
        assert_eq!(shreds[0].slot, 100);
        assert_eq!(shreds[0].proposer_id, 0);
    }
}
