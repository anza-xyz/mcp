//! MCP Merkle Tree Implementation
//!
//! This module implements the MCP Merkle commitment scheme as defined in spec §6:
//! - Fixed-depth tree with NUM_RELAYS leaves (200, padded to 256)
//! - Full 32-byte hash entries in witness proofs
//! - Domain-separated leaf and node hashing
//!
//! Per spec §6: "The witness is the ordered list of sibling hashes from leaf to root."
//! Each witness entry is a full 32-byte hash.

use {
    solana_hash::Hash,
    solana_sha256_hasher::Hasher,
    std::io::{self, Read, Write},
};

/// Domain separation prefix for leaf hashes
pub const LEAF_PREFIX: u8 = 0x00;

/// Domain separation prefix for node hashes
pub const NODE_PREFIX: u8 = 0x01;

/// Domain string for leaf hashes (spec §4.4.1)
pub const LEAF_DOMAIN: &[u8] = b"SOLANA_MERKLE_SHREDS_LEAF";

/// Domain string for node hashes (spec §4.4.1)
pub const NODE_DOMAIN: &[u8] = b"SOLANA_MERKLE_SHREDS_NODE";

/// Number of leaves in the fixed-depth tree (2^8 = 256)
pub const NUM_LEAVES: usize = 256;

/// Tree depth (log2 of NUM_LEAVES)
pub const TREE_DEPTH: usize = 8;

/// Size of a hash (32 bytes)
pub const HASH_SIZE: usize = 32;

/// Number of proof entries (equals tree depth)
pub const PROOF_ENTRIES: usize = TREE_DEPTH;

/// Total proof size in bytes (8 entries × 32 bytes each)
pub const PROOF_SIZE: usize = PROOF_ENTRIES * HASH_SIZE;

/// Payload size for each leaf (SHRED_DATA_BYTES)
pub const LEAF_PAYLOAD_SIZE: usize = 1024;

/// A 32-byte hash used in Merkle proofs (per spec §6)
pub type WitnessHash = [u8; HASH_SIZE];

/// A Merkle proof for a single leaf
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleProof {
    /// The index of the leaf in the tree (0-255)
    pub leaf_index: u8,
    /// The sibling hashes along the path to the root (full 32-byte hashes per spec §6)
    pub siblings: [WitnessHash; PROOF_ENTRIES],
}

impl Default for MerkleProof {
    fn default() -> Self {
        Self {
            leaf_index: 0,
            siblings: [[0u8; HASH_SIZE]; PROOF_ENTRIES],
        }
    }
}

impl MerkleProof {
    /// Create a new proof with the given leaf index and siblings
    pub fn new(leaf_index: u8, siblings: [WitnessHash; PROOF_ENTRIES]) -> Self {
        Self {
            leaf_index,
            siblings,
        }
    }

    /// Serialize the proof to bytes (just the siblings, not the leaf index)
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        for sibling in &self.siblings {
            writer.write_all(sibling)?;
        }
        Ok(())
    }

    /// Deserialize siblings from bytes
    pub fn deserialize_siblings<R: Read>(reader: &mut R) -> io::Result<[WitnessHash; PROOF_ENTRIES]> {
        let mut siblings = [[0u8; HASH_SIZE]; PROOF_ENTRIES];
        for sibling in &mut siblings {
            reader.read_exact(sibling)?;
        }
        Ok(siblings)
    }

    /// Verify this proof against a commitment and leaf data
    ///
    /// Per spec §6: Uses full 32-byte hashes throughout the tree.
    pub fn verify(&self, commitment: &Hash, leaf_data: &[u8]) -> bool {
        // Compute leaf hash
        let leaf_hash = compute_leaf_hash(leaf_data);
        let mut current = hash_to_witness(&leaf_hash);

        // Walk up the tree
        let mut index = self.leaf_index as usize;

        for sibling in self.siblings.iter() {
            let (left, right) = if index % 2 == 0 {
                (&current, sibling)
            } else {
                (sibling, &current)
            };

            let node_hash = compute_node_hash(left, right);
            current = hash_to_witness(&node_hash);
            index /= 2;
        }

        // Compare root against commitment
        current == commitment.as_ref()
    }
}

/// Compute the leaf hash with domain separation
///
/// leaf_hash = SHA256(LEAF_PREFIX || LEAF_DOMAIN || leaf_bytes)
pub fn compute_leaf_hash(leaf_data: &[u8]) -> Hash {
    let mut hasher = Hasher::default();
    hasher.hash(&[LEAF_PREFIX]);
    hasher.hash(LEAF_DOMAIN);
    hasher.hash(leaf_data);
    Hash::new_from_array(hasher.result().to_bytes())
}

/// Compute the node hash from two child hashes with domain separation
///
/// node_hash = SHA256(NODE_PREFIX || NODE_DOMAIN || left || right)
pub fn compute_node_hash(left: &WitnessHash, right: &WitnessHash) -> Hash {
    let mut hasher = Hasher::default();
    hasher.hash(&[NODE_PREFIX]);
    hasher.hash(NODE_DOMAIN);
    hasher.hash(left);
    hasher.hash(right);
    Hash::new_from_array(hasher.result().to_bytes())
}

/// Convert a Hash to a WitnessHash (same size, just different type)
pub fn hash_to_witness(hash: &Hash) -> WitnessHash {
    let mut result = [0u8; HASH_SIZE];
    result.copy_from_slice(hash.as_ref());
    result
}

/// MCP Merkle tree builder
///
/// Builds a fixed-depth Merkle tree from shred payloads and generates proofs.
#[allow(dead_code)]
pub struct McpMerkleTree {
    /// Leaf hashes (full 32-byte hashes per spec §6)
    leaf_hashes: Vec<WitnessHash>,
    /// Internal node hashes at each level (full 32-byte hashes)
    /// Level 0 = leaves, Level 7 = just below root
    levels: Vec<Vec<WitnessHash>>,
    /// The commitment (full 32-byte root hash)
    commitment: Hash,
}

impl McpMerkleTree {
    /// Build a Merkle tree from shred payloads
    ///
    /// Payloads must be exactly LEAF_PAYLOAD_SIZE bytes each.
    /// Missing payloads (up to NUM_LEAVES) are padded with zeros.
    pub fn from_payloads(payloads: &[&[u8]]) -> Self {
        assert!(payloads.len() <= NUM_LEAVES, "Too many payloads");

        // Compute leaf hashes
        let mut leaf_hashes = Vec::with_capacity(NUM_LEAVES);
        for payload in payloads {
            assert_eq!(payload.len(), LEAF_PAYLOAD_SIZE, "Invalid payload size");
            let hash = compute_leaf_hash(payload);
            leaf_hashes.push(hash_to_witness(&hash));
        }

        // Pad with zero-payload leaves if needed
        let zero_payload = [0u8; LEAF_PAYLOAD_SIZE];
        let zero_leaf_hash = hash_to_witness(&compute_leaf_hash(&zero_payload));
        while leaf_hashes.len() < NUM_LEAVES {
            leaf_hashes.push(zero_leaf_hash);
        }

        // Build the tree levels from bottom up
        let mut levels = Vec::with_capacity(TREE_DEPTH);
        let mut current_level = leaf_hashes.clone();

        for _ in 0..TREE_DEPTH {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = &current_level[i + 1];
                let node_hash = compute_node_hash(left, right);
                next_level.push(hash_to_witness(&node_hash));
            }
            levels.push(current_level);
            current_level = next_level;
        }

        // The root is the final hash
        assert_eq!(current_level.len(), 1);

        // Compute full 32-byte commitment from the last level's two children
        let last_level = levels.last().unwrap();
        let root_hash = compute_node_hash(&last_level[0], &last_level[1]);

        Self {
            leaf_hashes,
            levels,
            commitment: root_hash,
        }
    }

    /// Get the 32-byte commitment (root hash)
    pub fn commitment(&self) -> Hash {
        self.commitment
    }

    /// Get the commitment as a WitnessHash
    pub fn commitment_as_witness(&self) -> WitnessHash {
        hash_to_witness(&self.commitment)
    }

    /// Generate a proof for the given leaf index
    pub fn get_proof(&self, leaf_index: u8) -> MerkleProof {
        assert!((leaf_index as usize) < NUM_LEAVES, "Invalid leaf index");

        let mut siblings = [[0u8; HASH_SIZE]; PROOF_ENTRIES];
        let mut index = leaf_index as usize;

        for (depth, level) in self.levels.iter().enumerate() {
            // The sibling is at index ^ 1 (flip the last bit)
            let sibling_index = index ^ 1;
            siblings[depth] = level[sibling_index];
            index /= 2;
        }

        MerkleProof {
            leaf_index,
            siblings,
        }
    }

    /// Verify that a proof is valid for this tree
    pub fn verify_proof(&self, proof: &MerkleProof, leaf_data: &[u8]) -> bool {
        proof.verify(&self.commitment, leaf_data)
    }
}

/// Builder for constructing MCP Merkle commitments incrementally
pub struct MerkleCommitmentBuilder {
    payloads: Vec<Vec<u8>>,
}

impl Default for MerkleCommitmentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleCommitmentBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            payloads: Vec::with_capacity(NUM_LEAVES),
        }
    }

    /// Add a payload (must be exactly LEAF_PAYLOAD_SIZE bytes)
    pub fn add_payload(&mut self, payload: &[u8]) -> &mut Self {
        assert_eq!(payload.len(), LEAF_PAYLOAD_SIZE, "Invalid payload size");
        assert!(self.payloads.len() < NUM_LEAVES, "Tree is full");
        self.payloads.push(payload.to_vec());
        self
    }

    /// Build the Merkle tree
    pub fn build(self) -> McpMerkleTree {
        let payload_refs: Vec<&[u8]> = self.payloads.iter().map(|p| p.as_slice()).collect();
        McpMerkleTree::from_payloads(&payload_refs)
    }

    /// Get the number of payloads added
    pub fn len(&self) -> usize {
        self.payloads.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_payload(seed: u8) -> Vec<u8> {
        vec![seed; LEAF_PAYLOAD_SIZE]
    }

    #[test]
    fn test_leaf_hash_deterministic() {
        let payload = make_test_payload(42);
        let hash1 = compute_leaf_hash(&payload);
        let hash2 = compute_leaf_hash(&payload);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_domain_separation() {
        let payload = make_test_payload(42);
        let leaf_hash = compute_leaf_hash(&payload);

        // Hash without domain separation should be different
        let mut plain_hasher = Hasher::default();
        plain_hasher.hash(&payload);
        let plain_hash = Hash::new_from_array(plain_hasher.result().to_bytes());

        assert_ne!(leaf_hash, plain_hash);
    }

    #[test]
    fn test_node_hash_deterministic() {
        let left = [1u8; HASH_SIZE];
        let right = [2u8; HASH_SIZE];
        let hash1 = compute_node_hash(&left, &right);
        let hash2 = compute_node_hash(&left, &right);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_node_hash_order_matters() {
        let left = [1u8; HASH_SIZE];
        let right = [2u8; HASH_SIZE];
        let hash_lr = compute_node_hash(&left, &right);
        let hash_rl = compute_node_hash(&right, &left);
        assert_ne!(hash_lr, hash_rl);
    }

    #[test]
    fn test_hash_to_witness() {
        let hash = Hash::from([42u8; 32]);
        let witness = hash_to_witness(&hash);
        assert_eq!(witness.len(), HASH_SIZE);
        assert_eq!(witness, [42u8; HASH_SIZE]);
    }

    #[test]
    fn test_merkle_tree_single_payload() {
        let payload = make_test_payload(1);
        let tree = McpMerkleTree::from_payloads(&[&payload]);

        // Should have valid commitment
        let commitment = tree.commitment();
        assert_ne!(commitment, Hash::default());

        // Proof should verify
        let proof = tree.get_proof(0);
        assert!(proof.verify(&commitment, &payload));
    }

    #[test]
    fn test_merkle_tree_multiple_payloads() {
        let payloads: Vec<Vec<u8>> = (0..10).map(|i| make_test_payload(i)).collect();
        let payload_refs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        let tree = McpMerkleTree::from_payloads(&payload_refs);

        let commitment = tree.commitment();

        // Each proof should verify for its payload
        for (i, payload) in payloads.iter().enumerate() {
            let proof = tree.get_proof(i as u8);
            assert!(proof.verify(&commitment, payload), "Proof failed for index {}", i);
        }
    }

    #[test]
    fn test_merkle_tree_full() {
        // Build a full tree with all 256 leaves
        let payloads: Vec<Vec<u8>> = (0..NUM_LEAVES).map(|i| make_test_payload(i as u8)).collect();
        let payload_refs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        let tree = McpMerkleTree::from_payloads(&payload_refs);

        let commitment = tree.commitment();

        // Spot check some proofs
        for i in [0usize, 1, 127, 128, 255] {
            let proof = tree.get_proof(i as u8);
            assert!(proof.verify(&commitment, &payloads[i]), "Proof failed for index {}", i);
        }
    }

    #[test]
    fn test_merkle_proof_wrong_data_fails() {
        let payload = make_test_payload(1);
        let tree = McpMerkleTree::from_payloads(&[&payload]);

        let commitment = tree.commitment();
        let proof = tree.get_proof(0);

        // Proof with wrong data should fail
        let wrong_payload = make_test_payload(2);
        assert!(!proof.verify(&commitment, &wrong_payload));
    }

    #[test]
    fn test_merkle_proof_wrong_index_fails() {
        let payloads: Vec<Vec<u8>> = (0..2).map(|i| make_test_payload(i)).collect();
        let payload_refs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        let tree = McpMerkleTree::from_payloads(&payload_refs);

        let commitment = tree.commitment();

        // Get proof for index 0 but try to verify with payload 1
        let proof = tree.get_proof(0);
        assert!(!proof.verify(&commitment, &payloads[1]));
    }

    #[test]
    fn test_commitment_builder() {
        let mut builder = MerkleCommitmentBuilder::new();

        for i in 0..5 {
            let payload = make_test_payload(i);
            builder.add_payload(&payload);
        }

        assert_eq!(builder.len(), 5);
        assert!(!builder.is_empty());

        let tree = builder.build();
        assert_ne!(tree.commitment(), Hash::default());
    }

    #[test]
    fn test_proof_serialization() {
        let payload = make_test_payload(42);
        let tree = McpMerkleTree::from_payloads(&[&payload]);
        let proof = tree.get_proof(0);

        // Serialize
        let mut buffer = Vec::new();
        proof.serialize(&mut buffer).unwrap();
        assert_eq!(buffer.len(), PROOF_SIZE);

        // Deserialize
        let siblings = MerkleProof::deserialize_siblings(&mut buffer.as_slice()).unwrap();
        let reconstructed = MerkleProof::new(proof.leaf_index, siblings);

        assert_eq!(proof.siblings, reconstructed.siblings);
    }

    #[test]
    fn test_deterministic_padding() {
        // Two trees with same data should have same commitment
        let payload = make_test_payload(1);
        let tree1 = McpMerkleTree::from_payloads(&[&payload]);
        let tree2 = McpMerkleTree::from_payloads(&[&payload]);

        assert_eq!(tree1.commitment(), tree2.commitment());
    }

    #[test]
    fn test_different_payloads_different_commitments() {
        let payload1 = make_test_payload(1);
        let payload2 = make_test_payload(2);
        let tree1 = McpMerkleTree::from_payloads(&[&payload1]);
        let tree2 = McpMerkleTree::from_payloads(&[&payload2]);

        assert_ne!(tree1.commitment(), tree2.commitment());
    }
}
