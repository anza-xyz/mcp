//! MCP Replay Stage Components
//!
//! This module implements MCP-specific replay functionality:
//!
//! - MCP-15: Handle empty consensus slots
//! - MCP-16: Reconstruct messages from shreds
//! - MCP-18: Output ordered transactions deterministically
//!
//! # Overview
//!
//! The MCP replay stage processes consensus blocks by:
//! 1. Receiving aggregated attestations from consensus leader
//! 2. Reconstructing proposer messages from shreds
//! 3. Ordering transactions deterministically across proposers
//! 4. Executing transactions with fee-only first pass
//! 5. Producing execution output for finalization

use {
    solana_hash::Hash,
    std::collections::HashMap,
};

/// Number of proposers in MCP.
pub const NUM_PROPOSERS: u8 = 16;

/// Number of relays in MCP.
pub const NUM_RELAYS: u16 = 200;

/// Reconstruction threshold (20% of relays needed to reconstruct).
pub const RECONSTRUCTION_THRESHOLD_PERCENT: u8 = 20;

// ============================================================================
// MCP-15: Empty Consensus Slots
// ============================================================================

/// Execution output for a slot.
#[derive(Debug, Clone)]
pub enum SlotExecutionOutput {
    /// Slot with transactions executed.
    Executed {
        /// The slot number.
        slot: u64,
        /// The block ID from consensus.
        block_id: Hash,
        /// Hash of the execution output.
        execution_hash: Hash,
        /// Number of transactions processed.
        transaction_count: u64,
        /// Total fees collected.
        fees_collected: u64,
    },
    /// Empty slot (consensus reached ⊥).
    Empty {
        /// The slot number.
        slot: u64,
        /// Reason for empty slot.
        reason: EmptySlotReason,
    },
}

impl SlotExecutionOutput {
    /// Create an empty execution output.
    pub fn empty(slot: u64, reason: EmptySlotReason) -> Self {
        Self::Empty { slot, reason }
    }

    /// Create an executed slot output.
    pub fn executed(
        slot: u64,
        block_id: Hash,
        execution_hash: Hash,
        transaction_count: u64,
        fees_collected: u64,
    ) -> Self {
        Self::Executed {
            slot,
            block_id,
            execution_hash,
            transaction_count,
            fees_collected,
        }
    }

    /// Get the slot number.
    pub fn slot(&self) -> u64 {
        match self {
            Self::Executed { slot, .. } => *slot,
            Self::Empty { slot, .. } => *slot,
        }
    }

    /// Check if this is an empty slot.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty { .. })
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        match self {
            Self::Executed {
                slot,
                block_id,
                execution_hash,
                transaction_count,
                fees_collected,
            } => {
                data.push(0); // Type tag: executed
                data.extend_from_slice(&slot.to_le_bytes());
                data.extend_from_slice(block_id.as_ref());
                data.extend_from_slice(execution_hash.as_ref());
                data.extend_from_slice(&transaction_count.to_le_bytes());
                data.extend_from_slice(&fees_collected.to_le_bytes());
            }
            Self::Empty { slot, reason } => {
                data.push(1); // Type tag: empty
                data.extend_from_slice(&slot.to_le_bytes());
                data.push(*reason as u8);
            }
        }
        data
    }
}

/// Reasons a slot may be empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EmptySlotReason {
    /// No proposer batches received attestation threshold.
    NoAttestations = 0,
    /// Consensus leader did not produce a block.
    LeaderTimeout = 1,
    /// All proposer batches failed reconstruction.
    ReconstructionFailed = 2,
    /// Slot was skipped by consensus.
    Skipped = 3,
}

// ============================================================================
// MCP-16: Reconstruct Messages from Shreds
// ============================================================================

/// Status of message reconstruction for a proposer.
#[derive(Debug, Clone)]
pub enum ReconstructionStatus {
    /// Still gathering shreds.
    Pending {
        /// Number of shreds received.
        shreds_received: usize,
        /// Number of shreds needed.
        shreds_needed: usize,
    },
    /// Successfully reconstructed.
    Complete {
        /// The reconstructed message data.
        data: Vec<u8>,
        /// The merkle root (commitment).
        merkle_root: Hash,
    },
    /// Reconstruction failed (proposer should be dropped).
    Failed {
        /// Reason for failure.
        reason: ReconstructionFailure,
    },
}

/// Reasons reconstruction may fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconstructionFailure {
    /// Re-encoded commitment doesn't match.
    CommitmentMismatch,
    /// Invalid erasure coding.
    ErasureCodingError,
    /// Corrupted shred data.
    CorruptedData,
    /// Timeout waiting for shreds.
    Timeout,
}

/// Tracks reconstruction progress for a proposer in a slot.
#[derive(Debug)]
pub struct ProposerReconstruction {
    /// The proposer ID.
    pub proposer_id: u8,
    /// Expected merkle root (commitment).
    pub expected_commitment: Hash,
    /// Received shred indices.
    pub received_indices: Vec<u32>,
    /// Received shred data (index -> data).
    pub shred_data: HashMap<u32, Vec<u8>>,
    /// Total shreds expected in the batch.
    pub total_shreds: u32,
    /// Reconstruction status.
    pub status: ReconstructionStatus,
}

impl ProposerReconstruction {
    /// Create a new reconstruction tracker.
    pub fn new(proposer_id: u8, expected_commitment: Hash, total_shreds: u32) -> Self {
        let shreds_needed = calculate_shreds_needed(total_shreds as usize);
        Self {
            proposer_id,
            expected_commitment,
            received_indices: Vec::new(),
            shred_data: HashMap::new(),
            total_shreds,
            status: ReconstructionStatus::Pending {
                shreds_received: 0,
                shreds_needed,
            },
        }
    }

    /// Add a received shred.
    ///
    /// Returns true if this triggers reconstruction.
    pub fn add_shred(&mut self, index: u32, data: Vec<u8>) -> bool {
        if self.shred_data.contains_key(&index) {
            return false; // Duplicate
        }

        self.shred_data.insert(index, data);
        self.received_indices.push(index);

        let shreds_needed = calculate_shreds_needed(self.total_shreds as usize);
        let shreds_received = self.shred_data.len();

        self.status = ReconstructionStatus::Pending {
            shreds_received,
            shreds_needed,
        };

        shreds_received >= shreds_needed
    }

    /// Check if we have enough shreds for reconstruction.
    pub fn can_reconstruct(&self) -> bool {
        let shreds_needed = calculate_shreds_needed(self.total_shreds as usize);
        self.shred_data.len() >= shreds_needed
    }

    /// Mark reconstruction as complete.
    pub fn mark_complete(&mut self, data: Vec<u8>, merkle_root: Hash) {
        self.status = ReconstructionStatus::Complete { data, merkle_root };
    }

    /// Mark reconstruction as failed.
    pub fn mark_failed(&mut self, reason: ReconstructionFailure) {
        self.status = ReconstructionStatus::Failed { reason };
    }
}

/// Calculate number of shreds needed based on reconstruction threshold.
fn calculate_shreds_needed(total_shreds: usize) -> usize {
    // 20% of relays needed * shreds distributed to each = data shreds
    // For MCP FEC (40 data + 160 coding = 200 total), we need 40 data shreds
    // which is 20% of 200
    let threshold = (total_shreds * RECONSTRUCTION_THRESHOLD_PERCENT as usize) / 100;
    threshold.max(1) // At least 1 shred needed
}

// ============================================================================
// MCP-18: Ordered Transaction Output
// ============================================================================

/// A transaction with ordering metadata.
#[derive(Debug, Clone)]
pub struct OrderedTransaction {
    /// The proposer that included this transaction.
    pub proposer_id: u8,
    /// Position within the proposer's batch.
    pub position_in_batch: u32,
    /// The transaction hash.
    pub transaction_hash: Hash,
    /// The transaction data.
    pub transaction_data: Vec<u8>,
    /// Ordering fee paid.
    pub ordering_fee: u64,
}

impl OrderedTransaction {
    /// Create a new ordered transaction.
    pub fn new(
        proposer_id: u8,
        position_in_batch: u32,
        transaction_hash: Hash,
        transaction_data: Vec<u8>,
        ordering_fee: u64,
    ) -> Self {
        Self {
            proposer_id,
            position_in_batch,
            transaction_hash,
            transaction_data,
            ordering_fee,
        }
    }

    /// Get the canonical ordering key.
    ///
    /// Transactions are ordered by:
    /// 1. Proposer ID (ascending)
    /// 2. Position within batch (ascending)
    pub fn ordering_key(&self) -> (u8, u32) {
        (self.proposer_id, self.position_in_batch)
    }
}

/// Produces deterministically ordered transaction output.
#[derive(Debug, Default)]
pub struct OrderedOutputBuilder {
    /// Transactions per proposer.
    proposer_transactions: HashMap<u8, Vec<OrderedTransaction>>,
}

impl OrderedOutputBuilder {
    /// Create a new output builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add transactions from a proposer.
    pub fn add_proposer_batch(&mut self, proposer_id: u8, transactions: Vec<OrderedTransaction>) {
        self.proposer_transactions.insert(proposer_id, transactions);
    }

    /// Build the ordered output.
    ///
    /// Transactions are ordered deterministically:
    /// 1. By proposer ID (ascending, 0 to 15)
    /// 2. By position within batch (ascending)
    pub fn build(self) -> Vec<OrderedTransaction> {
        let mut all_transactions = Vec::new();

        // Process proposers in order
        for proposer_id in 0..NUM_PROPOSERS {
            if let Some(mut transactions) = self.proposer_transactions.get(&proposer_id).cloned() {
                // Sort by position within batch
                transactions.sort_by_key(|tx| tx.position_in_batch);
                all_transactions.extend(transactions);
            }
        }

        all_transactions
    }

    /// Get the number of proposers with transactions.
    pub fn proposer_count(&self) -> usize {
        self.proposer_transactions.len()
    }

    /// Get the total number of transactions.
    pub fn transaction_count(&self) -> usize {
        self.proposer_transactions.values().map(|v| v.len()).sum()
    }
}

/// Slot reconstruction and ordering result.
#[derive(Debug)]
pub struct SlotReplayResult {
    /// The slot number.
    pub slot: u64,
    /// Block ID from consensus.
    pub block_id: Hash,
    /// Ordered transactions to execute.
    pub ordered_transactions: Vec<OrderedTransaction>,
    /// Proposers that were dropped (failed reconstruction).
    pub dropped_proposers: Vec<(u8, ReconstructionFailure)>,
    /// Final execution output.
    pub execution_output: Option<SlotExecutionOutput>,
}

impl SlotReplayResult {
    /// Create a new replay result.
    pub fn new(slot: u64, block_id: Hash) -> Self {
        Self {
            slot,
            block_id,
            ordered_transactions: Vec::new(),
            dropped_proposers: Vec::new(),
            execution_output: None,
        }
    }

    /// Set the ordered transactions.
    pub fn set_transactions(&mut self, transactions: Vec<OrderedTransaction>) {
        self.ordered_transactions = transactions;
    }

    /// Record a dropped proposer.
    pub fn drop_proposer(&mut self, proposer_id: u8, reason: ReconstructionFailure) {
        self.dropped_proposers.push((proposer_id, reason));
    }

    /// Set the execution output.
    pub fn set_execution_output(&mut self, output: SlotExecutionOutput) {
        self.execution_output = Some(output);
    }

    /// Check if the slot is empty.
    pub fn is_empty(&self) -> bool {
        self.ordered_transactions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    #[test]
    fn test_empty_slot_output() {
        let output = SlotExecutionOutput::empty(100, EmptySlotReason::NoAttestations);
        assert!(output.is_empty());
        assert_eq!(output.slot(), 100);

        let bytes = output.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_executed_slot_output() {
        let output = SlotExecutionOutput::executed(
            100,
            make_test_hash(1),
            make_test_hash(2),
            50,
            10000,
        );
        assert!(!output.is_empty());
        assert_eq!(output.slot(), 100);
    }

    #[test]
    fn test_proposer_reconstruction() {
        let mut recon = ProposerReconstruction::new(1, make_test_hash(1), 200);

        // Add shreds until we can reconstruct
        for i in 0..40 {
            let can_recon = recon.add_shred(i, vec![i as u8]);
            if i < 39 {
                assert!(!can_recon);
            } else {
                assert!(can_recon);
            }
        }

        assert!(recon.can_reconstruct());
    }

    #[test]
    fn test_ordered_output_builder() {
        let mut builder = OrderedOutputBuilder::new();

        // Add transactions from proposer 2 first
        builder.add_proposer_batch(2, vec![
            OrderedTransaction::new(2, 0, make_test_hash(1), vec![1], 100),
            OrderedTransaction::new(2, 1, make_test_hash(2), vec![2], 50),
        ]);

        // Add transactions from proposer 0
        builder.add_proposer_batch(0, vec![
            OrderedTransaction::new(0, 0, make_test_hash(3), vec![3], 200),
        ]);

        // Add transactions from proposer 1
        builder.add_proposer_batch(1, vec![
            OrderedTransaction::new(1, 1, make_test_hash(5), vec![5], 75),
            OrderedTransaction::new(1, 0, make_test_hash(4), vec![4], 150),
        ]);

        let ordered = builder.build();

        // Should be ordered by proposer_id, then by position
        assert_eq!(ordered.len(), 5);
        assert_eq!(ordered[0].proposer_id, 0);
        assert_eq!(ordered[1].proposer_id, 1);
        assert_eq!(ordered[1].position_in_batch, 0);
        assert_eq!(ordered[2].proposer_id, 1);
        assert_eq!(ordered[2].position_in_batch, 1);
        assert_eq!(ordered[3].proposer_id, 2);
        assert_eq!(ordered[3].position_in_batch, 0);
        assert_eq!(ordered[4].proposer_id, 2);
        assert_eq!(ordered[4].position_in_batch, 1);
    }

    #[test]
    fn test_calculate_shreds_needed() {
        // 20% of 200 = 40
        assert_eq!(calculate_shreds_needed(200), 40);

        // 20% of 100 = 20
        assert_eq!(calculate_shreds_needed(100), 20);

        // 20% of 1 = 0, but minimum is 1
        assert_eq!(calculate_shreds_needed(1), 1);
    }

    #[test]
    fn test_slot_replay_result() {
        let mut result = SlotReplayResult::new(100, make_test_hash(1));

        assert!(result.is_empty());

        result.set_transactions(vec![
            OrderedTransaction::new(0, 0, make_test_hash(2), vec![1], 100),
        ]);

        assert!(!result.is_empty());

        result.drop_proposer(5, ReconstructionFailure::CommitmentMismatch);
        assert_eq!(result.dropped_proposers.len(), 1);
    }
}
