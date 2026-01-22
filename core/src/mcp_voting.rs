//! MCP Block Validation and Voting (MCP-14)
//!
//! This module implements validation and voting on consensus blocks.
//!
//! # Validation Steps
//!
//! 1. Verify leader's signature on consensus payload
//! 2. Verify delayed bankhash matches expected
//! 3. Check availability threshold for all implied blocks
//! 4. Vote with block_id from consensus payload
//!
//! # Voting Rules
//!
//! Nodes only vote when:
//! - Leader signature is valid
//! - Delayed bankhash is correct
//! - valid_shreds >= RECONSTRUCTION_THRESHOLD * NUM_RELAYS for all proposers

use {
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    std::collections::HashMap,
};

/// Number of proposers in MCP.
pub const NUM_PROPOSERS: u8 = 16;

/// Number of relays in MCP.
pub const NUM_RELAYS: u16 = 200;

/// Reconstruction threshold (20% of relays).
pub const RECONSTRUCTION_THRESHOLD_PERCENT: u8 = 20;

/// Minimum shreds needed for valid block.
pub const MIN_SHREDS_FOR_VALIDITY: usize =
    (NUM_RELAYS as usize * RECONSTRUCTION_THRESHOLD_PERCENT as usize) / 100;

/// Result of validating a consensus block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockValidationResult {
    /// Block is valid and can be voted on.
    Valid {
        /// The block ID to vote for.
        block_id: Hash,
    },
    /// Block validation failed.
    Invalid {
        /// Reason for invalidity.
        reason: ValidationFailure,
    },
    /// Waiting for more shreds before validation.
    Pending {
        /// Proposers that don't have enough shreds yet.
        pending_proposers: Vec<u8>,
    },
}

/// Reasons a block may fail validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationFailure {
    /// Leader signature is invalid.
    InvalidLeaderSignature,
    /// Delayed bankhash doesn't match expected.
    BankhashMismatch {
        expected: Hash,
        actual: Hash,
    },
    /// Not enough shreds for a proposer.
    InsufficientShreds {
        proposer_id: u8,
        have: usize,
        need: usize,
    },
    /// Proposer commitment mismatch.
    CommitmentMismatch {
        proposer_id: u8,
    },
    /// Invalid consensus payload format.
    InvalidPayloadFormat,
    /// Leader is not the expected leader for this slot.
    WrongLeader {
        expected: Pubkey,
        actual: Pubkey,
    },
}

/// Tracks shred availability per proposer for a slot.
#[derive(Debug, Default)]
pub struct ShredAvailability {
    /// Shred count per proposer.
    proposer_shred_counts: HashMap<u8, usize>,
    /// Proposers with verified commitments.
    verified_commitments: HashMap<u8, Hash>,
}

impl ShredAvailability {
    /// Create a new availability tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update shred count for a proposer.
    pub fn update_count(&mut self, proposer_id: u8, count: usize) {
        self.proposer_shred_counts.insert(proposer_id, count);
    }

    /// Record a verified commitment for a proposer.
    pub fn record_commitment(&mut self, proposer_id: u8, merkle_root: Hash) {
        self.verified_commitments.insert(proposer_id, merkle_root);
    }

    /// Check if a proposer has enough shreds.
    pub fn has_threshold(&self, proposer_id: u8) -> bool {
        self.proposer_shred_counts
            .get(&proposer_id)
            .map(|&count| count >= MIN_SHREDS_FOR_VALIDITY)
            .unwrap_or(false)
    }

    /// Get shred count for a proposer.
    pub fn shred_count(&self, proposer_id: u8) -> usize {
        self.proposer_shred_counts.get(&proposer_id).copied().unwrap_or(0)
    }

    /// Get verified commitment for a proposer.
    pub fn get_commitment(&self, proposer_id: u8) -> Option<&Hash> {
        self.verified_commitments.get(&proposer_id)
    }

    /// Get proposers that don't have enough shreds.
    pub fn pending_proposers(&self, required_proposers: &[u8]) -> Vec<u8> {
        required_proposers
            .iter()
            .filter(|&&pid| !self.has_threshold(pid))
            .copied()
            .collect()
    }
}

/// Validates consensus blocks.
pub struct BlockValidator {
    /// Current slot being validated.
    slot: u64,
    /// Expected leader for this slot.
    expected_leader: Pubkey,
    /// Expected delayed bankhash.
    expected_bankhash: Hash,
    /// Shred availability tracker.
    availability: ShredAvailability,
    /// Proposers that should be included (from attestations).
    required_proposers: Vec<u8>,
}

impl BlockValidator {
    /// Create a new block validator.
    pub fn new(
        slot: u64,
        expected_leader: Pubkey,
        expected_bankhash: Hash,
    ) -> Self {
        Self {
            slot,
            expected_leader,
            expected_bankhash,
            availability: ShredAvailability::new(),
            required_proposers: Vec::new(),
        }
    }

    /// Set the required proposers based on attestation aggregate.
    pub fn set_required_proposers(&mut self, proposers: Vec<u8>) {
        self.required_proposers = proposers;
    }

    /// Update shred availability for a proposer.
    pub fn update_availability(&mut self, proposer_id: u8, shred_count: usize) {
        self.availability.update_count(proposer_id, shred_count);
    }

    /// Record a verified commitment.
    pub fn record_commitment(&mut self, proposer_id: u8, merkle_root: Hash) {
        self.availability.record_commitment(proposer_id, merkle_root);
    }

    /// Validate the consensus block.
    ///
    /// This checks:
    /// 1. Leader signature (caller should verify before calling this)
    /// 2. Delayed bankhash matches
    /// 3. All required proposers have enough shreds
    pub fn validate(
        &self,
        payload_leader: &Pubkey,
        payload_bankhash: &Hash,
        payload_proposers: &[(u8, Hash)],
    ) -> BlockValidationResult {
        // Check leader
        if *payload_leader != self.expected_leader {
            return BlockValidationResult::Invalid {
                reason: ValidationFailure::WrongLeader {
                    expected: self.expected_leader,
                    actual: *payload_leader,
                },
            };
        }

        // Check delayed bankhash
        if *payload_bankhash != self.expected_bankhash {
            return BlockValidationResult::Invalid {
                reason: ValidationFailure::BankhashMismatch {
                    expected: self.expected_bankhash,
                    actual: *payload_bankhash,
                },
            };
        }

        // Check availability for all proposers
        let required: Vec<u8> = payload_proposers.iter().map(|(pid, _)| *pid).collect();
        let pending = self.availability.pending_proposers(&required);

        if !pending.is_empty() {
            return BlockValidationResult::Pending {
                pending_proposers: pending,
            };
        }

        // Verify commitments match
        for (proposer_id, expected_root) in payload_proposers {
            if let Some(verified_root) = self.availability.get_commitment(*proposer_id) {
                if verified_root != expected_root {
                    return BlockValidationResult::Invalid {
                        reason: ValidationFailure::CommitmentMismatch {
                            proposer_id: *proposer_id,
                        },
                    };
                }
            }
        }

        // All checks passed - compute block_id
        // In practice, block_id comes from the consensus payload
        // Here we simulate it for testing
        let block_id = self.compute_block_id(payload_proposers);

        BlockValidationResult::Valid { block_id }
    }

    /// Compute block ID from proposer commitments.
    fn compute_block_id(&self, proposers: &[(u8, Hash)]) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        for (pid, root) in proposers {
            data.push(*pid);
            data.extend_from_slice(root.as_ref());
        }
        solana_sha256_hasher::hash(&data)
    }
}

/// A vote on a consensus block.
#[derive(Debug, Clone)]
pub struct BlockVote {
    /// The slot being voted on.
    pub slot: u64,
    /// The block ID being voted for.
    pub block_id: Hash,
    /// The voter's pubkey.
    pub voter: Pubkey,
    /// The voter's signature.
    pub signature: solana_signature::Signature,
}

impl BlockVote {
    /// Create a new unsigned vote.
    pub fn new(slot: u64, block_id: Hash, voter: Pubkey) -> Self {
        Self {
            slot,
            block_id,
            voter,
            signature: solana_signature::Signature::default(),
        }
    }

    /// Get the data to be signed.
    pub fn get_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(self.block_id.as_ref());
        data.extend_from_slice(self.voter.as_ref());
        data
    }

    /// Sign the vote.
    pub fn sign(&mut self, keypair: &solana_keypair::Keypair) {
        use solana_signer::Signer;
        let data = self.get_signing_data();
        self.signature = keypair.sign_message(&data);
    }

    /// Verify the vote signature.
    pub fn verify(&self) -> bool {
        let data = self.get_signing_data();
        self.signature.verify(self.voter.as_ref(), &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    #[test]
    fn test_shred_availability() {
        let mut availability = ShredAvailability::new();

        // Initially no shreds
        assert!(!availability.has_threshold(1));
        assert_eq!(availability.shred_count(1), 0);

        // Add some shreds
        availability.update_count(1, 30);
        assert!(!availability.has_threshold(1)); // Need 40

        availability.update_count(1, 40);
        assert!(availability.has_threshold(1));
    }

    #[test]
    fn test_block_validator_valid() {
        let leader = Pubkey::new_unique();
        let bankhash = make_test_hash(99);
        let mut validator = BlockValidator::new(100, leader, bankhash);

        // Set up availability
        validator.update_availability(1, 50);
        validator.update_availability(2, 45);
        validator.record_commitment(1, make_test_hash(1));
        validator.record_commitment(2, make_test_hash(2));

        let proposers = vec![
            (1u8, make_test_hash(1)),
            (2u8, make_test_hash(2)),
        ];

        let result = validator.validate(&leader, &bankhash, &proposers);
        assert!(matches!(result, BlockValidationResult::Valid { .. }));
    }

    #[test]
    fn test_block_validator_wrong_leader() {
        let expected_leader = Pubkey::new_unique();
        let wrong_leader = Pubkey::new_unique();
        let bankhash = make_test_hash(99);
        let validator = BlockValidator::new(100, expected_leader, bankhash);

        let result = validator.validate(&wrong_leader, &bankhash, &[]);
        assert!(matches!(result, BlockValidationResult::Invalid {
            reason: ValidationFailure::WrongLeader { .. }
        }));
    }

    #[test]
    fn test_block_validator_bankhash_mismatch() {
        let leader = Pubkey::new_unique();
        let expected_bankhash = make_test_hash(99);
        let wrong_bankhash = make_test_hash(100);
        let validator = BlockValidator::new(100, leader, expected_bankhash);

        let result = validator.validate(&leader, &wrong_bankhash, &[]);
        assert!(matches!(result, BlockValidationResult::Invalid {
            reason: ValidationFailure::BankhashMismatch { .. }
        }));
    }

    #[test]
    fn test_block_validator_pending() {
        let leader = Pubkey::new_unique();
        let bankhash = make_test_hash(99);
        let mut validator = BlockValidator::new(100, leader, bankhash);

        // Only one proposer has enough shreds
        validator.update_availability(1, 50);
        validator.update_availability(2, 20); // Not enough

        let proposers = vec![
            (1u8, make_test_hash(1)),
            (2u8, make_test_hash(2)),
        ];

        let result = validator.validate(&leader, &bankhash, &proposers);
        assert!(matches!(result, BlockValidationResult::Pending { .. }));
        if let BlockValidationResult::Pending { pending_proposers } = result {
            assert_eq!(pending_proposers, vec![2]);
        }
    }

    #[test]
    fn test_block_vote() {
        let keypair = solana_keypair::Keypair::new();
        let mut vote = BlockVote::new(100, make_test_hash(1), keypair.pubkey());

        vote.sign(&keypair);
        assert!(vote.verify());
    }
}
