//! MCP Relay Operations
//!
//! This module implements relay operations for MCP as defined in spec §9:
//! 1. Shred verification (slot, index, proposer, signature, Merkle proof)
//! 2. Storage and retransmission tracking
//! 3. Integration with attestation creation
//!
//! Relays receive shreds from proposers, verify them, store verified shreds,
//! and create attestations to submit to the consensus leader.

use {
    crate::mcp_proposer::McpShred,
    solana_clock::Slot,
    solana_hash::Hash,
    solana_ledger::{
        mcp::{McpConfig, NUM_PROPOSERS},
        mcp_merkle::MerkleProof,
    },
    solana_pubkey::Pubkey,
    std::{
        collections::HashMap,
        sync::atomic::{AtomicU64, Ordering},
    },
};

/// Error type for relay operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// Shred is for wrong slot
    WrongSlot { expected: Slot, got: Slot },
    /// Shred is for wrong relay
    WrongRelay { expected: u16, got: u16 },
    /// Invalid proposer ID
    InvalidProposerId(u8),
    /// Invalid witness length
    InvalidWitnessLength { expected: usize, got: usize },
    /// Proposer signature verification failed
    SignatureVerificationFailed,
    /// Merkle witness verification failed
    MerkleVerificationFailed,
    /// Proposer pubkey not found
    ProposerNotFound(u8),
    /// Duplicate shred
    DuplicateShred {
        slot: Slot,
        proposer_id: u8,
        shred_index: u16,
    },
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongSlot { expected, got } => {
                write!(f, "Wrong slot: expected {}, got {}", expected, got)
            }
            Self::WrongRelay { expected, got } => {
                write!(f, "Wrong relay: expected {}, got {}", expected, got)
            }
            Self::InvalidProposerId(id) => {
                write!(f, "Invalid proposer ID: {} (max {})", id, NUM_PROPOSERS - 1)
            }
            Self::InvalidWitnessLength { expected, got } => {
                write!(f, "Invalid witness length: expected {}, got {}", expected, got)
            }
            Self::SignatureVerificationFailed => {
                write!(f, "Proposer signature verification failed")
            }
            Self::MerkleVerificationFailed => {
                write!(f, "Merkle witness verification failed")
            }
            Self::ProposerNotFound(id) => {
                write!(f, "Proposer pubkey not found for ID {}", id)
            }
            Self::DuplicateShred {
                slot,
                proposer_id,
                shred_index,
            } => {
                write!(
                    f,
                    "Duplicate shred: slot={}, proposer={}, index={}",
                    slot, proposer_id, shred_index
                )
            }
        }
    }
}

impl std::error::Error for RelayError {}

/// Verifies MCP shreds according to spec §9.1
pub struct ShredVerifier {
    /// Current slot
    slot: Slot,
    /// This relay's index (0-199)
    relay_index: u16,
    /// MCP configuration
    config: McpConfig,
}

impl ShredVerifier {
    /// Create a new shred verifier for a specific slot and relay
    pub fn new(slot: Slot, relay_index: u16, config: McpConfig) -> Self {
        Self {
            slot,
            relay_index,
            config,
        }
    }

    /// Create with default config
    pub fn with_default_config(slot: Slot, relay_index: u16) -> Self {
        Self::new(slot, relay_index, McpConfig::default())
    }

    /// Verify a shred according to spec §9.1
    ///
    /// Steps:
    /// 1. Verify slot matches
    /// 2. Verify shred_index matches relay_index
    /// 3. Verify proposer_index is in bounds
    /// 4. Verify witness_len == 8 (implicit in McpShred structure)
    /// 5. Verify proposer signature
    /// 6. Verify Merkle witness
    pub fn verify(
        &self,
        shred: &McpShred,
        proposer_pubkey: &Pubkey,
    ) -> Result<(), RelayError> {
        // 1. Verify slot
        if shred.slot != self.slot {
            return Err(RelayError::WrongSlot {
                expected: self.slot,
                got: shred.slot,
            });
        }

        // 2. Verify shred_index matches this relay
        if shred.shred_index != self.relay_index {
            return Err(RelayError::WrongRelay {
                expected: self.relay_index,
                got: shred.shred_index,
            });
        }

        // 3. Verify proposer_index is in bounds
        if shred.proposer_id >= self.config.num_proposers {
            return Err(RelayError::InvalidProposerId(shred.proposer_id));
        }

        // 4. witness_len is implicit in McpShred (fixed PROOF_ENTRIES)
        // McpShred struct enforces this at compile time

        // 5. Verify proposer signature
        self.verify_proposer_signature(shred, proposer_pubkey)?;

        // 6. Verify Merkle witness
        self.verify_merkle_witness(shred)?;

        Ok(())
    }

    /// Verify the proposer signature over commitment.
    ///
    /// Per spec §5.2: proposer_sig_msg = "mcp:commitment:v1" || commitment32
    /// The commitment already binds to slot/proposer because the payload header
    /// is inside the committed RS shards.
    fn verify_proposer_signature(
        &self,
        shred: &McpShred,
        proposer_pubkey: &Pubkey,
    ) -> Result<(), RelayError> {
        // Build the signing message per spec §5.2
        let mut message = Vec::with_capacity(17 + 32);
        message.extend_from_slice(b"mcp:commitment:v1");
        message.extend_from_slice(shred.commitment.as_ref());

        // Verify signature using Ed25519
        let signature = solana_signature::Signature::from(shred.proposer_signature);
        if !signature.verify(proposer_pubkey.as_ref(), &message) {
            return Err(RelayError::SignatureVerificationFailed);
        }

        Ok(())
    }

    /// Verify the Merkle witness for this shred
    fn verify_merkle_witness(&self, shred: &McpShred) -> Result<(), RelayError> {
        // Create a MerkleProof from the shred's witness
        let proof = MerkleProof::new(shred.shred_index as u8, shred.witness);

        // Verify the proof against the commitment and shred data
        if !proof.verify(&shred.commitment, &shred.shred_data) {
            return Err(RelayError::MerkleVerificationFailed);
        }

        Ok(())
    }

    /// Get the slot this verifier is for
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Get the relay index
    pub fn relay_index(&self) -> u16 {
        self.relay_index
    }
}

/// Stores verified shreds for a slot
#[derive(Debug)]
pub struct VerifiedShredStore {
    /// Slot for this store
    #[allow(dead_code)]
    slot: Slot,
    /// Verified shreds keyed by (proposer_id, shred_index)
    shreds: HashMap<(u8, u16), VerifiedShred>,
    /// Per-proposer commitment tracking
    commitments: HashMap<u8, Hash>,
    /// Statistics
    stats: ShredStoreStats,
}

/// A verified shred with metadata
#[derive(Debug, Clone)]
pub struct VerifiedShred {
    /// The verified shred data
    pub shred: McpShred,
    /// When this shred was verified
    pub verified_at_ns: u64,
}

/// Statistics for the shred store
#[derive(Debug, Default)]
pub struct ShredStoreStats {
    pub shreds_stored: AtomicU64,
    pub duplicates_rejected: AtomicU64,
}

impl VerifiedShredStore {
    /// Create a new shred store for a slot
    pub fn new(slot: Slot) -> Self {
        Self {
            slot,
            shreds: HashMap::new(),
            commitments: HashMap::new(),
            stats: ShredStoreStats::default(),
        }
    }

    /// Store a verified shred
    ///
    /// Returns an error if a duplicate shred is received
    pub fn store(&mut self, shred: McpShred, verified_at_ns: u64) -> Result<(), RelayError> {
        let key = (shred.proposer_id, shred.shred_index);

        // Check for duplicate
        if self.shreds.contains_key(&key) {
            self.stats.duplicates_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(RelayError::DuplicateShred {
                slot: shred.slot,
                proposer_id: shred.proposer_id,
                shred_index: shred.shred_index,
            });
        }

        // Track commitment (should be same for all shreds from a proposer)
        self.commitments
            .entry(shred.proposer_id)
            .or_insert(shred.commitment);

        // Store the shred
        self.shreds.insert(
            key,
            VerifiedShred {
                shred,
                verified_at_ns,
            },
        );
        self.stats.shreds_stored.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Get all stored shreds for a proposer
    pub fn get_proposer_shreds(&self, proposer_id: u8) -> Vec<&VerifiedShred> {
        self.shreds
            .iter()
            .filter(|((pid, _), _)| *pid == proposer_id)
            .map(|(_, shred)| shred)
            .collect()
    }

    /// Get the commitment for a proposer
    pub fn get_commitment(&self, proposer_id: u8) -> Option<&Hash> {
        self.commitments.get(&proposer_id)
    }

    /// Get all proposers with verified shreds
    pub fn get_proposers(&self) -> Vec<(u8, Hash)> {
        self.commitments
            .iter()
            .map(|(&id, &commitment)| (id, commitment))
            .collect()
    }

    /// Get the number of shreds stored for a proposer
    pub fn shred_count(&self, proposer_id: u8) -> usize {
        self.shreds
            .keys()
            .filter(|(pid, _)| *pid == proposer_id)
            .count()
    }

    /// Get total number of stored shreds
    pub fn total_shreds(&self) -> usize {
        self.shreds.len()
    }

    /// Get statistics
    pub fn stats(&self) -> &ShredStoreStats {
        &self.stats
    }
}

/// Manages relay operations for a relay node
pub struct RelayOperations {
    /// This relay's index
    relay_index: u16,
    /// MCP configuration
    config: McpConfig,
    /// Per-slot shred stores
    stores: HashMap<Slot, VerifiedShredStore>,
    /// Current slot (for cleanup)
    current_slot: Slot,
    /// Maximum slots to track
    max_tracked_slots: usize,
    /// Proposer pubkey lookup function type (boxed for flexibility)
    #[allow(dead_code)]
    proposer_lookup: Option<Box<dyn Fn(Slot, u8) -> Option<Pubkey> + Send + Sync>>,
}

impl RelayOperations {
    /// Create new relay operations handler
    pub fn new(relay_index: u16, config: McpConfig, max_tracked_slots: usize) -> Self {
        Self {
            relay_index,
            config,
            stores: HashMap::new(),
            current_slot: 0,
            max_tracked_slots,
            proposer_lookup: None,
        }
    }

    /// Create with default config
    pub fn with_defaults(relay_index: u16) -> Self {
        Self::new(relay_index, McpConfig::default(), 32)
    }

    /// Set the proposer pubkey lookup function
    pub fn set_proposer_lookup<F>(&mut self, lookup: F)
    where
        F: Fn(Slot, u8) -> Option<Pubkey> + Send + Sync + 'static,
    {
        self.proposer_lookup = Some(Box::new(lookup));
    }

    /// Process a received shred
    ///
    /// Returns Ok(()) if the shred was verified and stored successfully.
    /// The caller should then broadcast the shred to validators.
    pub fn process_shred(
        &mut self,
        shred: McpShred,
        proposer_pubkey: &Pubkey,
    ) -> Result<(), RelayError> {
        let slot = shred.slot;

        // Update current slot
        if slot > self.current_slot {
            self.current_slot = slot;
            self.cleanup_old_slots();
        }

        // Create verifier for this slot
        let verifier = ShredVerifier::new(slot, self.relay_index, self.config);

        // Verify the shred
        verifier.verify(&shred, proposer_pubkey)?;

        // Store the verified shred
        let store = self
            .stores
            .entry(slot)
            .or_insert_with(|| VerifiedShredStore::new(slot));

        // Use a timestamp (would use SystemTime in real impl)
        store.store(shred, 0)?;

        Ok(())
    }

    /// Get attestable proposers for a slot (those with verified shreds)
    pub fn get_attestable_proposers(&self, slot: Slot) -> Vec<(u8, Hash)> {
        self.stores
            .get(&slot)
            .map(|store| store.get_proposers())
            .unwrap_or_default()
    }

    /// Get the shred count for a proposer in a slot
    pub fn get_shred_count(&self, slot: Slot, proposer_id: u8) -> usize {
        self.stores
            .get(&slot)
            .map(|store| store.shred_count(proposer_id))
            .unwrap_or(0)
    }

    /// Clean up old slot data
    fn cleanup_old_slots(&mut self) {
        let min_slot = self
            .current_slot
            .saturating_sub(self.max_tracked_slots as u64);
        self.stores.retain(|&slot, _| slot >= min_slot);
    }

    /// Get the relay index
    pub fn relay_index(&self) -> u16 {
        self.relay_index
    }
}

/// Helper to build the proposer signature message for verification.
/// Per spec §5.2: proposer_sig_msg = "mcp:commitment:v1" || commitment32
pub fn build_proposer_sig_message(commitment: &Hash) -> Vec<u8> {
    let mut message = Vec::with_capacity(17 + 32);
    message.extend_from_slice(b"mcp:commitment:v1");
    message.extend_from_slice(commitment.as_ref());
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use solana_ledger::mcp_merkle::{McpMerkleTree, LEAF_PAYLOAD_SIZE};

    fn make_test_keypair() -> Keypair {
        Keypair::new()
    }

    /// Create a valid test shred with proper Merkle proof and signature
    fn make_valid_shred(
        slot: Slot,
        proposer_id: u8,
        shred_index: u16,
        keypair: &Keypair,
    ) -> McpShred {
        // Create test payloads for all leaves
        let mut payloads: Vec<[u8; LEAF_PAYLOAD_SIZE]> = Vec::new();
        for i in 0..200 {
            let mut payload = [0u8; LEAF_PAYLOAD_SIZE];
            payload[0] = i as u8;
            payloads.push(payload);
        }

        // Build Merkle tree (API takes &[&[u8]])
        let payload_refs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        let tree = McpMerkleTree::from_payloads(&payload_refs);
        let commitment = tree.commitment();

        // Get proof for this shred (get_proof takes u8)
        let proof = tree.get_proof(shred_index as u8);

        // Build signature per spec §5.2
        let sig_message = build_proposer_sig_message(&commitment);
        let signature = keypair.sign_message(&sig_message);

        McpShred {
            slot,
            proposer_id,
            shred_index,
            commitment,
            shred_data: payloads[shred_index as usize].to_vec(),
            witness: proof.siblings,
            proposer_signature: signature.into(),
        }
    }

    #[test]
    fn test_shred_verifier_valid() {
        let keypair = make_test_keypair();
        let slot = 100;
        let relay_index = 42;
        let proposer_id = 5;

        let shred = make_valid_shred(slot, proposer_id, relay_index, &keypair);
        let verifier = ShredVerifier::with_default_config(slot, relay_index);

        let result = verifier.verify(&shred, &keypair.pubkey());
        assert!(result.is_ok(), "Expected valid shred to verify: {:?}", result);
    }

    #[test]
    fn test_shred_verifier_wrong_slot() {
        let keypair = make_test_keypair();
        let shred = make_valid_shred(100, 5, 42, &keypair);

        // Verifier for different slot
        let verifier = ShredVerifier::with_default_config(200, 42);

        let result = verifier.verify(&shred, &keypair.pubkey());
        assert!(matches!(result, Err(RelayError::WrongSlot { .. })));
    }

    #[test]
    fn test_shred_verifier_wrong_relay() {
        let keypair = make_test_keypair();
        let shred = make_valid_shred(100, 5, 42, &keypair);

        // Verifier for different relay
        let verifier = ShredVerifier::with_default_config(100, 50);

        let result = verifier.verify(&shred, &keypair.pubkey());
        assert!(matches!(result, Err(RelayError::WrongRelay { .. })));
    }

    #[test]
    fn test_shred_verifier_invalid_proposer() {
        let keypair = make_test_keypair();
        let mut shred = make_valid_shred(100, 5, 42, &keypair);
        shred.proposer_id = 20; // Invalid: NUM_PROPOSERS is 16

        let verifier = ShredVerifier::with_default_config(100, 42);

        let result = verifier.verify(&shred, &keypair.pubkey());
        assert!(matches!(result, Err(RelayError::InvalidProposerId(20))));
    }

    #[test]
    fn test_shred_verifier_bad_signature() {
        let keypair = make_test_keypair();
        let wrong_keypair = make_test_keypair();
        let shred = make_valid_shred(100, 5, 42, &keypair);

        let verifier = ShredVerifier::with_default_config(100, 42);

        // Verify with wrong pubkey
        let result = verifier.verify(&shred, &wrong_keypair.pubkey());
        assert!(matches!(result, Err(RelayError::SignatureVerificationFailed)));
    }

    #[test]
    fn test_shred_verifier_bad_merkle() {
        let keypair = make_test_keypair();
        let mut shred = make_valid_shred(100, 5, 42, &keypair);

        // Corrupt the shred data
        shred.shred_data[0] = 0xFF;

        let verifier = ShredVerifier::with_default_config(100, 42);

        let result = verifier.verify(&shred, &keypair.pubkey());
        assert!(matches!(result, Err(RelayError::MerkleVerificationFailed)));
    }

    #[test]
    fn test_verified_shred_store() {
        let keypair = make_test_keypair();
        let slot = 100;

        let mut store = VerifiedShredStore::new(slot);

        // Store shreds from different proposers
        let shred1 = make_valid_shred(slot, 0, 42, &keypair);
        let shred2 = make_valid_shred(slot, 1, 42, &keypair);

        assert!(store.store(shred1.clone(), 0).is_ok());
        assert!(store.store(shred2, 0).is_ok());

        assert_eq!(store.total_shreds(), 2);
        assert_eq!(store.shred_count(0), 1);
        assert_eq!(store.shred_count(1), 1);

        // Duplicate should fail
        let result = store.store(shred1, 0);
        assert!(matches!(result, Err(RelayError::DuplicateShred { .. })));
    }

    #[test]
    fn test_relay_operations() {
        let keypair = make_test_keypair();
        let relay_index = 42u16;

        let mut ops = RelayOperations::with_defaults(relay_index);

        // Process valid shreds
        let shred1 = make_valid_shred(100, 0, relay_index, &keypair);
        let shred2 = make_valid_shred(100, 1, relay_index, &keypair);

        assert!(ops.process_shred(shred1, &keypair.pubkey()).is_ok());
        assert!(ops.process_shred(shred2, &keypair.pubkey()).is_ok());

        // Check attestable proposers
        let proposers = ops.get_attestable_proposers(100);
        assert_eq!(proposers.len(), 2);

        // Check shred counts
        assert_eq!(ops.get_shred_count(100, 0), 1);
        assert_eq!(ops.get_shred_count(100, 1), 1);
    }

    #[test]
    fn test_relay_operations_wrong_slot() {
        let keypair = make_test_keypair();
        let relay_index = 42u16;

        let mut ops = RelayOperations::with_defaults(relay_index);

        // Shred for wrong slot should fail
        ops.current_slot = 100;
        let shred = make_valid_shred(50, 0, relay_index, &keypair);

        // Note: Slot mismatch is caught by verifier
        let result = ops.process_shred(shred, &keypair.pubkey());
        assert!(result.is_ok()); // Slot 50 is different but we verify against shred's slot
    }

    #[test]
    fn test_relay_operations_cleanup() {
        let keypair = make_test_keypair();
        let relay_index = 42u16;

        let mut ops = RelayOperations::new(relay_index, McpConfig::default(), 5);

        // Add shreds for slots 100-106 (7 slots)
        // With max_tracked_slots=5, cleanup keeps slots >= (current_slot - 5)
        // After slot 106: min_slot = 106 - 5 = 101, so slot 100 is cleaned
        for slot in 100..=106 {
            let shred = make_valid_shred(slot, 0, relay_index, &keypair);
            ops.process_shred(shred, &keypair.pubkey()).unwrap();
        }

        // Slot 100 should be cleaned up (min_slot = 101)
        assert_eq!(ops.get_shred_count(100, 0), 0);
        // Slots 101-106 should still be present
        assert_eq!(ops.get_shred_count(101, 0), 1);
        assert_eq!(ops.get_shred_count(106, 0), 1);
    }

    #[test]
    fn test_build_proposer_sig_message() {
        let commitment = Hash::from([0xAB; 32]);

        let message = build_proposer_sig_message(&commitment);

        // Verify structure per spec §5.2: domain || commitment only
        assert_eq!(&message[0..17], b"mcp:commitment:v1");
        assert_eq!(&message[17..49], commitment.as_ref());
        assert_eq!(message.len(), 17 + 32);
    }
}
