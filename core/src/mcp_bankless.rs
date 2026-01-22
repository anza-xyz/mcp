//! MCP Bankless Leader/Proposer (MCP-19)
//!
//! This module implements the bankless leader concept where leaders can:
//! - Record transactions without executing them
//! - Generate shreds without a functioning bank
//! - Defer execution to the replay stage
//!
//! # Overview
//!
//! Traditional Solana leaders execute transactions before recording them.
//! In MCP, proposers generate shreds containing transaction batches without
//! execution, deferring all execution to the replay stage.
//!
//! # Benefits
//!
//! 1. Faster block production (no execution delay)
//! 2. Cleaner separation of concerns
//! 3. Supports parallel proposer model
//! 4. Enables deferred fee charging

use solana_hash::Hash;

/// Status of bankless transaction recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingStatus {
    /// Transaction recorded successfully.
    Recorded,
    /// Transaction failed signature verification.
    InvalidSignature,
    /// Transaction is a duplicate.
    Duplicate,
    /// Transaction exceeds size limits.
    TooLarge,
}

/// A batch of transactions ready for shredding (without execution).
#[derive(Debug)]
pub struct BanklessBatch {
    /// The slot this batch is for.
    pub slot: u64,
    /// The proposer ID.
    pub proposer_id: u8,
    /// Transactions in the batch (raw bytes).
    pub transactions: Vec<Vec<u8>>,
    /// Transaction hashes for deduplication.
    pub transaction_hashes: Vec<Hash>,
    /// Ordering fees for deterministic sorting.
    ordering_fees: Vec<u64>,
    /// Total size in bytes.
    pub total_bytes: usize,
}

impl BanklessBatch {
    /// Create a new bankless batch.
    pub fn new(slot: u64, proposer_id: u8) -> Self {
        Self {
            slot,
            proposer_id,
            transactions: Vec::new(),
            transaction_hashes: Vec::new(),
            ordering_fees: Vec::new(),
            total_bytes: 0,
        }
    }

    /// Add a transaction to the batch with ordering fee.
    ///
    /// The ordering_fee is used to sort transactions before serialization
    /// (higher fee = earlier in batch, per spec §8.1).
    ///
    /// Returns the recording status.
    pub fn add_transaction_with_fee(
        &mut self,
        tx_data: Vec<u8>,
        tx_hash: Hash,
        ordering_fee: u64,
    ) -> RecordingStatus {
        // Check for duplicate
        if self.transaction_hashes.contains(&tx_hash) {
            return RecordingStatus::Duplicate;
        }

        // Check size limit (per spec §2.5: MAX_PROPOSER_PAYLOAD_BYTES = 38,080)
        if self.total_bytes + tx_data.len() > Self::MAX_BATCH_SIZE {
            return RecordingStatus::TooLarge;
        }

        // Check transaction count limit (per spec §2.5: 65,536)
        if self.transactions.len() >= Self::MAX_TRANSACTIONS_PER_BATCH {
            return RecordingStatus::TooLarge;
        }

        // Check individual transaction size (per spec §2.5: MAX_TX_SIZE = 4,096)
        if tx_data.len() > Self::MAX_TRANSACTION_SIZE {
            return RecordingStatus::TooLarge;
        }

        self.total_bytes += tx_data.len();
        self.transactions.push(tx_data);
        self.transaction_hashes.push(tx_hash);
        self.ordering_fees.push(ordering_fee);

        RecordingStatus::Recorded
    }

    /// Add a transaction to the batch (with zero ordering fee).
    ///
    /// Returns the recording status.
    pub fn add_transaction(&mut self, tx_data: Vec<u8>, tx_hash: Hash) -> RecordingStatus {
        self.add_transaction_with_fee(tx_data, tx_hash, 0)
    }

    /// Sort transactions for serialization.
    ///
    /// Per spec §8.1: Order by ordering_fee descending, then by
    /// SHA256(serialized_transaction) ascending for determinism.
    pub fn sort_for_serialization(&mut self) {
        // Create indices for sorting
        let mut indices: Vec<usize> = (0..self.transactions.len()).collect();

        // Sort by: ordering_fee DESC, then tx_hash ASC
        indices.sort_by(|&a, &b| {
            let fee_a = self.ordering_fees.get(a).copied().unwrap_or(0);
            let fee_b = self.ordering_fees.get(b).copied().unwrap_or(0);

            // First compare by ordering_fee descending
            match fee_b.cmp(&fee_a) {
                std::cmp::Ordering::Equal => {
                    // Then by tx_hash ascending (for determinism)
                    self.transaction_hashes[a].cmp(&self.transaction_hashes[b])
                }
                other => other,
            }
        });

        // Reorder all vectors according to sorted indices
        let transactions: Vec<_> = indices.iter().map(|&i| self.transactions[i].clone()).collect();
        let hashes: Vec<_> = indices.iter().map(|&i| self.transaction_hashes[i]).collect();
        let fees: Vec<_> = indices
            .iter()
            .map(|&i| self.ordering_fees.get(i).copied().unwrap_or(0))
            .collect();

        self.transactions = transactions;
        self.transaction_hashes = hashes;
        self.ordering_fees = fees;
    }

    /// Get the number of transactions.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Serialize the batch for shredding.
    ///
    /// Note: Call `sort_for_serialization()` before this to ensure
    /// deterministic ordering per spec §8.1.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Header
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.push(self.proposer_id);
        data.extend_from_slice(&(self.transactions.len() as u32).to_le_bytes());

        // Transactions (already sorted by caller via sort_for_serialization)
        for tx in &self.transactions {
            data.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            data.extend_from_slice(tx);
        }

        data
    }

    /// Serialize the batch with automatic sorting.
    ///
    /// Per spec §8.1: Orders by ordering_fee descending, then tx hash ascending.
    pub fn serialize_sorted(&mut self) -> Vec<u8> {
        self.sort_for_serialization();
        self.serialize()
    }

    /// Maximum number of transactions allowed in a batch (per spec §2.5).
    pub const MAX_TRANSACTIONS_PER_BATCH: usize = 65_536;

    /// Maximum size of a single transaction in bytes (per spec §2.5).
    pub const MAX_TRANSACTION_SIZE: usize = 4_096; // MAX_TX_SIZE per spec

    /// Maximum total batch size in bytes (per spec §2.5).
    /// K_DATA_SHREDS (40) × MCP_SHRED_PAYLOAD_BYTES (952) = 38,080
    pub const MAX_BATCH_SIZE: usize = 38_080; // MAX_PROPOSER_PAYLOAD_BYTES

    /// Deserialize a batch with bounds checking to prevent memory DoS.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        // Check minimum header size
        if data.len() < 8 + 1 + 4 {
            return None;
        }

        // Reject obviously oversized input
        if data.len() > Self::MAX_BATCH_SIZE {
            return None;
        }

        let mut offset = 0;

        let slot = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let proposer_id = data[offset];
        offset += 1;

        let tx_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        // Bounds check: reject unreasonable transaction counts
        if tx_count > Self::MAX_TRANSACTIONS_PER_BATCH {
            return None;
        }

        let mut batch = Self::new(slot, proposer_id);

        // Pre-allocate with bounded capacity
        batch.transactions.reserve(tx_count.min(1000));
        batch.transaction_hashes.reserve(tx_count.min(1000));

        for _ in 0..tx_count {
            if data.len() < offset + 4 {
                return None;
            }

            let tx_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
            offset += 4;

            // Bounds check: reject unreasonable transaction sizes
            if tx_len > Self::MAX_TRANSACTION_SIZE {
                return None;
            }

            if data.len() < offset + tx_len {
                return None;
            }

            let tx_data = data[offset..offset + tx_len].to_vec();
            offset += tx_len;

            let tx_hash = solana_sha256_hasher::hash(&tx_data);
            batch.transactions.push(tx_data);
            batch.transaction_hashes.push(tx_hash);
        }

        batch.total_bytes = offset - 13; // Exclude header

        Some(batch)
    }
}

/// Configuration for bankless proposer mode.
#[derive(Debug, Clone, Copy)]
pub struct BanklessConfig {
    /// Maximum batch size in bytes.
    pub max_batch_size: usize,
    /// Maximum transactions per batch.
    pub max_transactions: usize,
    /// Whether to verify signatures on receipt.
    pub verify_signatures: bool,
}

impl Default for BanklessConfig {
    fn default() -> Self {
        Self {
            max_batch_size: BanklessBatch::MAX_BATCH_SIZE,       // 38,080 per spec
            max_transactions: BanklessBatch::MAX_TRANSACTIONS_PER_BATCH, // 65,536 per spec
            verify_signatures: true,
        }
    }
}

/// Tracks bankless recording state for a proposer.
#[derive(Debug)]
pub struct BanklessRecorder {
    /// This proposer's ID.
    proposer_id: u8,
    /// Current slot.
    current_slot: u64,
    /// Current batch being built.
    current_batch: Option<BanklessBatch>,
    /// Configuration.
    config: BanklessConfig,
    /// Completed batches ready for shredding.
    completed_batches: Vec<BanklessBatch>,
}

impl BanklessRecorder {
    /// Create a new bankless recorder.
    pub fn new(proposer_id: u8, config: BanklessConfig) -> Self {
        Self {
            proposer_id,
            current_slot: 0,
            current_batch: None,
            config,
            completed_batches: Vec::new(),
        }
    }

    /// Start recording for a new slot.
    pub fn start_slot(&mut self, slot: u64) {
        // Finalize current batch if any
        if let Some(batch) = self.current_batch.take() {
            if !batch.is_empty() {
                self.completed_batches.push(batch);
            }
        }

        self.current_slot = slot;
        self.current_batch = Some(BanklessBatch::new(slot, self.proposer_id));
    }

    /// Record a transaction (without execution).
    pub fn record_transaction(&mut self, tx_data: Vec<u8>) -> RecordingStatus {
        let tx_hash = solana_sha256_hasher::hash(&tx_data);

        // Ensure we have a current batch
        if self.current_batch.is_none() {
            self.current_batch = Some(BanklessBatch::new(self.current_slot, self.proposer_id));
        }

        let batch = self.current_batch.as_mut().unwrap();

        // Check transaction limit
        if batch.transaction_count() >= self.config.max_transactions {
            return RecordingStatus::TooLarge;
        }

        batch.add_transaction(tx_data, tx_hash)
    }

    /// Finalize the current batch and get it for shredding.
    pub fn finalize_batch(&mut self) -> Option<BanklessBatch> {
        self.current_batch.take()
    }

    /// Get all completed batches.
    pub fn take_completed_batches(&mut self) -> Vec<BanklessBatch> {
        std::mem::take(&mut self.completed_batches)
    }

    /// Get the current slot.
    pub fn current_slot(&self) -> u64 {
        self.current_slot
    }

    /// Get the proposer ID.
    pub fn proposer_id(&self) -> u8 {
        self.proposer_id
    }
}

/// Metadata for a bankless-recorded entry (for PoH).
#[derive(Debug, Clone)]
pub struct BanklessEntryMeta {
    /// The slot.
    pub slot: u64,
    /// The proposer ID.
    pub proposer_id: u8,
    /// Number of transactions.
    pub transaction_count: u32,
    /// Hash of the batch.
    pub batch_hash: Hash,
}

impl BanklessEntryMeta {
    /// Create entry metadata from a batch.
    pub fn from_batch(batch: &BanklessBatch) -> Self {
        let serialized = batch.serialize();
        let batch_hash = solana_sha256_hasher::hash(&serialized);

        Self {
            slot: batch.slot,
            proposer_id: batch.proposer_id,
            transaction_count: batch.transaction_count() as u32,
            batch_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bankless_batch() {
        let mut batch = BanklessBatch::new(100, 5);

        let tx1 = vec![1, 2, 3, 4, 5];
        let hash1 = solana_sha256_hasher::hash(&tx1);

        assert_eq!(batch.add_transaction(tx1.clone(), hash1), RecordingStatus::Recorded);
        assert_eq!(batch.transaction_count(), 1);

        // Duplicate should fail
        assert_eq!(batch.add_transaction(tx1, hash1), RecordingStatus::Duplicate);
        assert_eq!(batch.transaction_count(), 1);

        // Different transaction should succeed
        let tx2 = vec![6, 7, 8];
        let hash2 = solana_sha256_hasher::hash(&tx2);
        assert_eq!(batch.add_transaction(tx2, hash2), RecordingStatus::Recorded);
        assert_eq!(batch.transaction_count(), 2);
    }

    #[test]
    fn test_batch_serialization() {
        let mut batch = BanklessBatch::new(100, 5);
        batch.add_transaction(vec![1, 2, 3], solana_sha256_hasher::hash(&[1, 2, 3]));
        batch.add_transaction(vec![4, 5], solana_sha256_hasher::hash(&[4, 5]));

        let serialized = batch.serialize();
        let deserialized = BanklessBatch::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.slot, 100);
        assert_eq!(deserialized.proposer_id, 5);
        assert_eq!(deserialized.transaction_count(), 2);
        assert_eq!(deserialized.transactions[0], vec![1, 2, 3]);
        assert_eq!(deserialized.transactions[1], vec![4, 5]);
    }

    #[test]
    fn test_bankless_recorder() {
        let config = BanklessConfig::default();
        let mut recorder = BanklessRecorder::new(3, config);

        recorder.start_slot(100);
        assert_eq!(recorder.current_slot(), 100);

        recorder.record_transaction(vec![1, 2, 3]);
        recorder.record_transaction(vec![4, 5, 6]);

        let batch = recorder.finalize_batch().unwrap();
        assert_eq!(batch.slot, 100);
        assert_eq!(batch.proposer_id, 3);
        assert_eq!(batch.transaction_count(), 2);
    }

    #[test]
    fn test_slot_transition() {
        let config = BanklessConfig::default();
        let mut recorder = BanklessRecorder::new(1, config);

        recorder.start_slot(100);
        recorder.record_transaction(vec![1, 2, 3]);

        // Start new slot should finalize previous
        recorder.start_slot(101);

        let completed = recorder.take_completed_batches();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].slot, 100);
    }
}
