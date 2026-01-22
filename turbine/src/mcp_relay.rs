//! MCP Relay Shred Processing
//!
//! This module implements relay functionality for MCP:
//! - Validate proposer signatures on shred commitments
//! - Verify Merkle proofs for relay indices
//! - Store validated shreds organized by slot and proposer ID
//! - Distribute valid shreds to validators via turbine
//!
//! # Overview
//!
//! In MCP, relays are stake-weighted validators responsible for:
//! 1. Receiving shreds from proposers
//! 2. Verifying shred commitments and merkle proofs
//! 3. Broadcasting valid shreds to other validators
//! 4. Submitting attestations to the consensus leader

use {
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    std::collections::HashMap,
};

// Re-export MCP constants from canonical source (ledger/src/mcp.rs)
pub use solana_ledger::mcp::{NUM_PROPOSERS, NUM_RELAYS};

/// Maximum witness entries (merkle proof depth for 256 leaves)
pub const MAX_WITNESS_ENTRIES: usize = 8;

/// Size of each witness entry (truncated hash)
pub const WITNESS_ENTRY_SIZE: usize = 20;

/// Maximum witness bytes (8 entries * 20 bytes)
pub const MAX_WITNESS_BYTES: usize = MAX_WITNESS_ENTRIES * WITNESS_ENTRY_SIZE;

/// Maximum shred index (200 shreds per FEC block, indices 0-199)
pub const MAX_SHRED_INDEX: u32 = 199;

/// Result of validating a proposer shred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShredValidationResult {
    /// Shred is valid and should be broadcast.
    Valid,
    /// Signature verification failed.
    InvalidSignature,
    /// Merkle proof verification failed.
    InvalidMerkleProof,
    /// Shred is for wrong relay index.
    WrongRelayIndex,
    /// Duplicate shred received.
    Duplicate,
    /// Invalid proposer ID.
    InvalidProposerId,
}

/// A proposer shred message received by a relay.
///
/// Wire format: (slot, proposer_id, shred_index, commitment, shred, witness, proposer_sig)
#[derive(Debug, Clone)]
pub struct ProposerShredMessage {
    /// The slot this shred belongs to.
    pub slot: u64,
    /// The proposer ID (0-15).
    pub proposer_id: u8,
    /// The shred index within the FEC block.
    pub shred_index: u32,
    /// The commitment (merkle root) of the shred batch.
    pub commitment: Hash,
    /// The raw shred data.
    pub shred_data: Vec<u8>,
    /// The merkle witness (proof) for this relay's index.
    pub witness: Vec<u8>,
    /// The proposer's signature over (slot, proposer_id, shred_index, commitment).
    pub proposer_signature: Signature,
}

impl ProposerShredMessage {
    /// Create a new proposer shred message.
    pub fn new(
        slot: u64,
        proposer_id: u8,
        shred_index: u32,
        commitment: Hash,
        shred_data: Vec<u8>,
        witness: Vec<u8>,
        proposer_signature: Signature,
    ) -> Self {
        Self {
            slot,
            proposer_id,
            shred_index,
            commitment,
            shred_data,
            witness,
            proposer_signature,
        }
    }

    /// Get the data to be signed by the proposer.
    ///
    /// The signature binds to (slot, proposer_id, shred_index, commitment) to prevent
    /// replay of signatures across different shreds.
    pub fn get_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 1 + 4 + 32);
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.push(self.proposer_id);
        data.extend_from_slice(&self.shred_index.to_le_bytes());
        data.extend_from_slice(self.commitment.as_ref());
        data
    }

    /// Verify the proposer's signature.
    pub fn verify_proposer_signature(&self, proposer_pubkey: &Pubkey) -> bool {
        let signing_data = self.get_signing_data();
        self.proposer_signature
            .verify(proposer_pubkey.as_ref(), &signing_data)
    }
}

/// Tracks validated shreds for a slot, organized by proposer.
#[derive(Debug, Default)]
pub struct SlotShredTracker {
    /// The slot being tracked.
    slot: u64,
    /// Shreds received per proposer, keyed by shred index.
    proposer_shreds: HashMap<u8, HashMap<u32, ValidatedShred>>,
    /// Merkle roots per proposer (commitment).
    proposer_commitments: HashMap<u8, Hash>,
}

/// A validated shred ready for storage and broadcast.
#[derive(Debug, Clone)]
pub struct ValidatedShred {
    /// The raw shred data.
    pub data: Vec<u8>,
    /// The shred index within the proposer's batch.
    pub shred_index: u32,
    /// The proposer ID.
    pub proposer_id: u8,
    /// The merkle root this shred is part of.
    pub merkle_root: Hash,
}

impl SlotShredTracker {
    /// Create a new tracker for a slot.
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            proposer_shreds: HashMap::new(),
            proposer_commitments: HashMap::new(),
        }
    }

    /// Get the slot being tracked.
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Record a validated shred.
    ///
    /// Returns true if this was a new shred, false if duplicate.
    pub fn insert_shred(&mut self, shred: ValidatedShred) -> bool {
        let proposer_map = self
            .proposer_shreds
            .entry(shred.proposer_id)
            .or_default();

        if proposer_map.contains_key(&shred.shred_index) {
            return false; // Duplicate
        }

        // Record the commitment if not already set
        self.proposer_commitments
            .entry(shred.proposer_id)
            .or_insert(shred.merkle_root);

        proposer_map.insert(shred.shred_index, shred);
        true
    }

    /// Get the number of shreds received for a proposer.
    pub fn shred_count(&self, proposer_id: u8) -> usize {
        self.proposer_shreds
            .get(&proposer_id)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Check if we have a shred at the given index for a proposer.
    pub fn has_shred(&self, proposer_id: u8, shred_index: u32) -> bool {
        self.proposer_shreds
            .get(&proposer_id)
            .map(|m| m.contains_key(&shred_index))
            .unwrap_or(false)
    }

    /// Get the commitment (merkle root) for a proposer.
    pub fn get_commitment(&self, proposer_id: u8) -> Option<&Hash> {
        self.proposer_commitments.get(&proposer_id)
    }

    /// Get all proposer IDs that have shreds.
    pub fn proposers(&self) -> impl Iterator<Item = u8> + '_ {
        self.proposer_shreds.keys().copied()
    }
}

/// Relay shred processor.
///
/// Handles validation and tracking of proposer shreds for a relay.
pub struct RelayShredProcessor {
    /// This relay's ID.
    relay_id: u16,
    /// Shred trackers per slot.
    slot_trackers: HashMap<u64, SlotShredTracker>,
    /// Maximum number of slots to track.
    max_tracked_slots: usize,
}

impl RelayShredProcessor {
    /// Create a new relay shred processor.
    pub fn new(relay_id: u16) -> Self {
        Self {
            relay_id,
            slot_trackers: HashMap::new(),
            max_tracked_slots: 100, // Track last 100 slots
        }
    }

    /// Get this relay's ID.
    pub fn relay_id(&self) -> u16 {
        self.relay_id
    }

    /// Process a proposer shred message.
    ///
    /// Validates the shred and returns the result along with the validated
    /// shred if successful.
    ///
    /// The shred_index is taken from the message itself. The relay verifies
    /// that this shred is meant for them by checking
    /// `message.shred_index % NUM_RELAYS == relay_id`.
    ///
    /// Per spec §9.1, verification failures result in silent drop (return None).
    pub fn process_shred(
        &mut self,
        message: &ProposerShredMessage,
        proposer_pubkey: &Pubkey,
    ) -> Option<ValidatedShred> {
        let shred_index = message.shred_index;

        // Validate proposer ID (must be in range [0, 15])
        // Per spec: silently drop if invalid
        if message.proposer_id >= NUM_PROPOSERS {
            return None;
        }

        // Validate shred_index (must be in range [0, 199])
        // Per spec: silently drop if invalid
        if shred_index > MAX_SHRED_INDEX {
            return None;
        }

        // Validate witness length (must be <= MAX_WITNESS_BYTES = 160)
        // Per spec §9.1: silently drop if exceeded
        if message.witness.len() > MAX_WITNESS_BYTES {
            return None;
        }

        // Verify this shred is meant for this relay
        // In MCP, relay_id = shred_index % NUM_RELAYS
        // Per spec: silently drop if wrong relay
        let expected_relay = (shred_index as u16) % NUM_RELAYS;
        if expected_relay != self.relay_id {
            return None;
        }

        // Verify proposer signature
        // Note: signature binds (slot, proposer_id, shred_index, commitment)
        // Per spec: silently drop if signature verification fails
        if !message.verify_proposer_signature(proposer_pubkey) {
            return None;
        }

        // Verify merkle proof
        // The witness should prove that the shred is at shred_index
        // in the merkle tree committed to by the proposer
        // Per spec: silently drop if merkle proof fails
        if !self.verify_merkle_witness(message, shred_index) {
            return None;
        }

        // Check for duplicate
        // Per spec: silently drop duplicate (keep first received)
        if let Some(tracker) = self.slot_trackers.get(&message.slot) {
            if tracker.has_shred(message.proposer_id, shred_index) {
                return None;
            }
        }

        // Create validated shred
        let validated = ValidatedShred {
            data: message.shred_data.clone(),
            shred_index,
            proposer_id: message.proposer_id,
            merkle_root: message.commitment,
        };

        // Insert into tracker
        let tracker = self
            .slot_trackers
            .entry(message.slot)
            .or_insert_with(|| SlotShredTracker::new(message.slot));
        tracker.insert_shred(validated.clone());

        // Cleanup old slots if needed
        self.cleanup_old_slots(message.slot);

        Some(validated)
    }

    /// Verify the merkle witness for a shred.
    fn verify_merkle_witness(&self, message: &ProposerShredMessage, shred_index: u32) -> bool {
        // The witness should be a merkle proof from the shred hash to the commitment
        // Use the merkle_tree module for verification
        use solana_ledger::shred::merkle_tree::verify_merkle_proof;

        // Compute the leaf hash from shred data using the standard prefix
        // Defense against second preimage attack
        const MERKLE_HASH_PREFIX_LEAF: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
        let leaf_hash = solana_sha256_hasher::hashv(&[
            MERKLE_HASH_PREFIX_LEAF,
            &message.shred_data,
        ]);

        // Verify the proof
        verify_merkle_proof(
            leaf_hash,
            shred_index as usize,
            &message.witness,
            message.commitment,
        )
        .is_ok()
    }

    /// Cleanup old slot trackers to prevent memory growth.
    fn cleanup_old_slots(&mut self, current_slot: u64) {
        if self.slot_trackers.len() > self.max_tracked_slots {
            // Find oldest slots to remove
            let min_slot_to_keep = current_slot.saturating_sub(self.max_tracked_slots as u64);
            self.slot_trackers
                .retain(|&slot, _| slot >= min_slot_to_keep);
        }
    }

    /// Get the tracker for a specific slot.
    pub fn get_slot_tracker(&self, slot: u64) -> Option<&SlotShredTracker> {
        self.slot_trackers.get(&slot)
    }

    /// Get mutable tracker for a specific slot.
    pub fn get_slot_tracker_mut(&mut self, slot: u64) -> Option<&mut SlotShredTracker> {
        self.slot_trackers.get_mut(&slot)
    }

    /// Get all proposers with shreds for a slot.
    pub fn get_attested_proposers(&self, slot: u64) -> Vec<(u8, Hash)> {
        self.slot_trackers
            .get(&slot)
            .map(|tracker| {
                tracker
                    .proposers()
                    .filter_map(|pid| tracker.get_commitment(pid).map(|h| (pid, *h)))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    #[test]
    fn test_proposer_shred_message() {
        let msg = ProposerShredMessage::new(
            100,
            5,
            42, // shred_index
            make_test_hash(1),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            Signature::default(),
        );

        assert_eq!(msg.slot, 100);
        assert_eq!(msg.proposer_id, 5);
        assert_eq!(msg.shred_index, 42);

        let signing_data = msg.get_signing_data();
        // 8 (slot) + 1 (proposer_id) + 4 (shred_index) + 32 (commitment) = 45
        assert_eq!(signing_data.len(), 8 + 1 + 4 + 32);
    }

    #[test]
    fn test_slot_shred_tracker() {
        let mut tracker = SlotShredTracker::new(100);

        let shred = ValidatedShred {
            data: vec![1, 2, 3],
            shred_index: 0,
            proposer_id: 1,
            merkle_root: make_test_hash(42),
        };

        // First insert should succeed
        assert!(tracker.insert_shred(shred.clone()));
        assert_eq!(tracker.shred_count(1), 1);
        assert!(tracker.has_shred(1, 0));

        // Duplicate insert should fail
        assert!(!tracker.insert_shred(shred.clone()));
        assert_eq!(tracker.shred_count(1), 1);

        // Different shred index should succeed
        let shred2 = ValidatedShred {
            data: vec![4, 5, 6],
            shred_index: 1,
            proposer_id: 1,
            merkle_root: make_test_hash(42),
        };
        assert!(tracker.insert_shred(shred2));
        assert_eq!(tracker.shred_count(1), 2);
    }

    #[test]
    fn test_relay_processor_invalid_proposer_id() {
        let mut processor = RelayShredProcessor::new(42);

        let msg = ProposerShredMessage::new(
            100,
            20, // Invalid: >= NUM_PROPOSERS
            0,  // shred_index
            make_test_hash(1),
            vec![1, 2, 3],
            vec![],
            Signature::default(),
        );

        // Per spec: silently drop invalid proposer_id
        let result = processor.process_shred(&msg, &Pubkey::new_unique());
        assert!(result.is_none());
    }

    #[test]
    fn test_relay_processor_witness_too_long() {
        let mut processor = RelayShredProcessor::new(0);

        // Create witness larger than MAX_WITNESS_BYTES (160)
        let oversized_witness = vec![0u8; MAX_WITNESS_BYTES + 1];

        let msg = ProposerShredMessage::new(
            100,
            5,
            0, // shred_index 0 maps to relay 0
            make_test_hash(1),
            vec![1, 2, 3],
            oversized_witness,
            Signature::default(),
        );

        // Per spec: silently drop if witness_len > 8 entries
        let result = processor.process_shred(&msg, &Pubkey::new_unique());
        assert!(result.is_none());
    }

    #[test]
    fn test_relay_processor_invalid_shred_index() {
        let mut processor = RelayShredProcessor::new(0);

        let msg = ProposerShredMessage::new(
            100,
            5,
            200, // Invalid: > MAX_SHRED_INDEX (199)
            make_test_hash(1),
            vec![1, 2, 3],
            vec![],
            Signature::default(),
        );

        // Per spec: silently drop invalid shred_index
        let result = processor.process_shred(&msg, &Pubkey::new_unique());
        assert!(result.is_none());
    }

    #[test]
    fn test_get_attested_proposers() {
        let mut tracker = SlotShredTracker::new(100);

        // Add shreds from two proposers
        tracker.insert_shred(ValidatedShred {
            data: vec![1],
            shred_index: 0,
            proposer_id: 1,
            merkle_root: make_test_hash(1),
        });
        tracker.insert_shred(ValidatedShred {
            data: vec![2],
            shred_index: 0,
            proposer_id: 5,
            merkle_root: make_test_hash(5),
        });

        let mut proposers: Vec<_> = tracker.proposers().collect();
        proposers.sort();
        assert_eq!(proposers, vec![1, 5]);

        assert_eq!(tracker.get_commitment(1), Some(&make_test_hash(1)));
        assert_eq!(tracker.get_commitment(5), Some(&make_test_hash(5)));
    }
}
