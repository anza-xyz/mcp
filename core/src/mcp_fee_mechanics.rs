//! MCP Fee Mechanics
//!
//! This module implements the MCP fee system as defined in spec §13:
//! 1. Fee types: signature, prioritization, inclusion, ordering
//! 2. Including proposer determination (first occurrence wins)
//! 3. Two-phase processing: fee deduction (Phase A) then execution (Phase B)
//! 4. Fee routing to proposers
//!
//! Key differences from standard Solana fees:
//! - inclusion_fee: paid to proposer for including the transaction
//! - ordering_fee: paid to proposer for ordering priority within their batch
//! - Fees are non-refundable even if execution fails

use {
    crate::mcp_replay_reconstruction::OrderedTransaction,
    solana_account::AccountSharedData,
    solana_clock::Slot,
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_svm::account_loader::{execute_fee_phase, FeePhaseResult, McpFeeBreakdown},
    std::collections::HashMap,
};

/// MCP fee configuration from transaction config mask.
///
/// Per spec §7.2, these fields are optionally present in transactions:
/// - Bit 0: inclusion_fee (u32 lamports)
/// - Bit 1: ordering_fee (u32 lamports)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct McpFeeConfig {
    /// Fee paid to proposer for inclusion (bit 0)
    pub inclusion_fee: u64,
    /// Fee paid to proposer for ordering priority (bit 1)
    pub ordering_fee: u64,
}

impl McpFeeConfig {
    /// Create a new MCP fee config
    pub const fn new(inclusion_fee: u64, ordering_fee: u64) -> Self {
        Self {
            inclusion_fee,
            ordering_fee,
        }
    }

    /// Get total MCP fees (paid to proposer)
    pub const fn total_mcp_fee(&self) -> u64 {
        self.inclusion_fee.saturating_add(self.ordering_fee)
    }

    /// Parse MCP fees from transaction config mask and data.
    ///
    /// The config_mask is a u32 where:
    /// - Bit 0 set: inclusion_fee is present (4 bytes)
    /// - Bit 1 set: ordering_fee is present (4 bytes)
    ///
    /// Fields are serialized in bit order after the config mask.
    pub fn from_config_data(config_mask: u32, config_data: &[u8]) -> Self {
        let mut offset = 0;
        let mut config = Self::default();

        // Bit 0: inclusion_fee
        if config_mask & 1 != 0 {
            if config_data.len() >= offset + 4 {
                let bytes: [u8; 4] = config_data[offset..offset + 4].try_into().unwrap();
                config.inclusion_fee = u32::from_le_bytes(bytes) as u64;
                offset += 4;
            }
        }

        // Bit 1: ordering_fee
        if config_mask & 2 != 0 {
            if config_data.len() >= offset + 4 {
                let bytes: [u8; 4] = config_data[offset..offset + 4].try_into().unwrap();
                config.ordering_fee = u32::from_le_bytes(bytes) as u64;
            }
        }

        config
    }
}

/// Complete fee breakdown for a transaction
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransactionFees {
    /// Standard signature fee (goes to validators)
    pub signature_fee: u64,
    /// Prioritization fee / compute unit price (goes to validators)
    pub prioritization_fee: u64,
    /// MCP inclusion fee (goes to proposer)
    pub inclusion_fee: u64,
    /// MCP ordering fee (goes to proposer)
    pub ordering_fee: u64,
}

impl TransactionFees {
    /// Total fees paid by the transaction
    pub const fn total(&self) -> u64 {
        self.signature_fee
            .saturating_add(self.prioritization_fee)
            .saturating_add(self.inclusion_fee)
            .saturating_add(self.ordering_fee)
    }

    /// Fees going to validators (standard fees)
    pub const fn validator_fees(&self) -> u64 {
        self.signature_fee.saturating_add(self.prioritization_fee)
    }

    /// Fees going to the including proposer (MCP fees)
    pub const fn proposer_fees(&self) -> u64 {
        self.inclusion_fee.saturating_add(self.ordering_fee)
    }
}

/// Result of Phase A fee deduction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeDeductionResult {
    /// Fees successfully deducted
    Success {
        fees: TransactionFees,
        including_proposer: u32,
    },
    /// Fee payer couldn't cover the fees
    InsufficientFunds {
        required: u64,
        available: u64,
    },
    /// Transaction failed pre-checks (signature, lifetime, etc.)
    PreCheckFailed(String),
}

/// Tracks fee routing for a slot
#[derive(Debug, Default)]
pub struct SlotFeeTracker {
    /// Slot number
    pub slot: Slot,
    /// Fees accumulated per proposer
    pub proposer_fees: HashMap<u32, u64>,
    /// Total validator fees accumulated
    pub validator_fees: u64,
    /// Number of transactions processed
    pub tx_count: usize,
    /// Number of transactions that failed fee deduction
    pub failed_tx_count: usize,
}

impl SlotFeeTracker {
    /// Create a new fee tracker for a slot
    pub fn new(slot: Slot) -> Self {
        Self {
            slot,
            proposer_fees: HashMap::new(),
            validator_fees: 0,
            tx_count: 0,
            failed_tx_count: 0,
        }
    }

    /// Record a successful fee deduction
    pub fn record_fee_deduction(&mut self, result: &FeeDeductionResult) {
        match result {
            FeeDeductionResult::Success { fees, including_proposer } => {
                self.tx_count += 1;
                self.validator_fees = self.validator_fees.saturating_add(fees.validator_fees());
                *self.proposer_fees.entry(*including_proposer).or_default() +=
                    fees.proposer_fees();
            }
            FeeDeductionResult::InsufficientFunds { .. }
            | FeeDeductionResult::PreCheckFailed(_) => {
                self.failed_tx_count += 1;
            }
        }
    }

    /// Get total fees collected
    pub fn total_fees(&self) -> u64 {
        self.validator_fees
            .saturating_add(self.proposer_fees.values().sum::<u64>())
    }

    /// Get fees for a specific proposer
    pub fn get_proposer_fee(&self, proposer_id: u32) -> u64 {
        self.proposer_fees.get(&proposer_id).copied().unwrap_or(0)
    }
}

/// Two-phase transaction processing for MCP.
///
/// Phase A: Fee deduction (pre-execution)
/// - Perform standard prechecks
/// - Calculate total fees
/// - Deduct from fee payer
/// - Route MCP fees to proposer
///
/// Phase B: Execution (state transitions)
/// - Execute only transactions that passed Phase A
/// - No additional fee charging
/// - Record success/failure outcomes
pub struct TwoPhaseProcessor {
    /// Fee tracker for the current slot
    fee_tracker: SlotFeeTracker,
    /// Map of txid -> proposer_id for fee routing
    tx_proposer_map: HashMap<Hash, u32>,
}

impl TwoPhaseProcessor {
    /// Create a new two-phase processor for a slot
    pub fn new(slot: Slot) -> Self {
        Self {
            fee_tracker: SlotFeeTracker::new(slot),
            tx_proposer_map: HashMap::new(),
        }
    }

    /// Initialize with ordered transactions (determines including proposers)
    ///
    /// Per spec §13.2: The including proposer is the one whose list
    /// contributed the transaction's first occurrence.
    pub fn set_ordered_transactions(&mut self, transactions: &[OrderedTransaction]) {
        for tx in transactions {
            // First occurrence wins (OrderedTransaction is already de-duplicated)
            self.tx_proposer_map.entry(tx.txid).or_insert(tx.proposer_id);
        }
    }

    /// Get the including proposer for a transaction
    pub fn get_including_proposer(&self, txid: &Hash) -> Option<u32> {
        self.tx_proposer_map.get(txid).copied()
    }

    /// Process Phase A for a transaction (fee deduction)
    ///
    /// Returns the fee deduction result. In a real implementation,
    /// this would interact with the bank to deduct fees.
    pub fn process_phase_a(
        &mut self,
        txid: &Hash,
        fees: TransactionFees,
        _fee_payer: &Pubkey,
        fee_payer_balance: u64,
    ) -> FeeDeductionResult {
        // Check if fee payer has sufficient balance
        let total_fees = fees.total();
        if fee_payer_balance < total_fees {
            let result = FeeDeductionResult::InsufficientFunds {
                required: total_fees,
                available: fee_payer_balance,
            };
            self.fee_tracker.record_fee_deduction(&result);
            return result;
        }

        // Determine including proposer
        let including_proposer = match self.get_including_proposer(txid) {
            Some(p) => p,
            None => {
                let result = FeeDeductionResult::PreCheckFailed(
                    "Transaction not in ordered list".to_string(),
                );
                self.fee_tracker.record_fee_deduction(&result);
                return result;
            }
        };

        // Success - fees would be deducted here in real implementation
        let result = FeeDeductionResult::Success {
            fees,
            including_proposer,
        };
        self.fee_tracker.record_fee_deduction(&result);
        result
    }

    /// Get the fee tracker
    pub fn fee_tracker(&self) -> &SlotFeeTracker {
        &self.fee_tracker
    }

    /// Get mutable fee tracker
    pub fn fee_tracker_mut(&mut self) -> &mut SlotFeeTracker {
        &mut self.fee_tracker
    }

    /// Execute Phase A fee deduction through SVM account_loader.
    ///
    /// This is the integration point that connects MCP two-phase processing
    /// with the actual SVM fee deduction logic.
    ///
    /// Per MCP spec §13.3: Phase A deducts all fees from the fee payer
    /// before any transaction execution occurs.
    pub fn execute_fee_phase_on_account(
        &mut self,
        txid: &Hash,
        fee_payer: &Pubkey,
        fee_payer_account: &mut AccountSharedData,
        fees: TransactionFees,
        min_balance: u64,
    ) -> FeeDeductionResult {
        // Determine including proposer first
        let including_proposer = match self.get_including_proposer(txid) {
            Some(p) => p,
            None => {
                let result = FeeDeductionResult::PreCheckFailed(
                    "Transaction not in ordered list".to_string(),
                );
                self.fee_tracker.record_fee_deduction(&result);
                return result;
            }
        };

        // Convert MCP fees to SVM fee breakdown
        let mcp_fee_breakdown = McpFeeBreakdown {
            signature_fee: fees.signature_fee,
            prioritization_fee: fees.prioritization_fee,
            inclusion_fee: fees.inclusion_fee,
            ordering_fee: fees.ordering_fee,
        };

        // Execute fee phase through SVM
        let fee_result = execute_fee_phase(
            fee_payer,
            fee_payer_account,
            mcp_fee_breakdown,
            min_balance,
        );

        // Convert FeePhaseResult to FeeDeductionResult
        let result = match fee_result {
            FeePhaseResult::Success { fees: breakdown, .. } => {
                FeeDeductionResult::Success {
                    fees: TransactionFees {
                        signature_fee: breakdown.signature_fee,
                        prioritization_fee: breakdown.prioritization_fee,
                        inclusion_fee: breakdown.inclusion_fee,
                        ordering_fee: breakdown.ordering_fee,
                    },
                    including_proposer,
                }
            }
            FeePhaseResult::Failure { error, .. } => {
                FeeDeductionResult::PreCheckFailed(format!("{:?}", error))
            }
        };

        self.fee_tracker.record_fee_deduction(&result);
        result
    }
}

/// Calculate MCP fees from transaction bytes.
///
/// This is a simplified fee calculator. In a real implementation,
/// this would parse the full transaction and extract config fields.
pub fn calculate_mcp_fees(
    _tx_bytes: &[u8],
    mcp_config: McpFeeConfig,
    signature_count: u32,
    compute_units: u64,
    compute_unit_price: u64,
) -> TransactionFees {
    // Standard signature fee (5000 lamports per signature)
    const LAMPORTS_PER_SIGNATURE: u64 = 5000;
    let signature_fee = (signature_count as u64).saturating_mul(LAMPORTS_PER_SIGNATURE);

    // Prioritization fee
    let prioritization_fee = compute_units
        .saturating_mul(compute_unit_price)
        .saturating_div(1_000_000); // micro-lamports to lamports

    TransactionFees {
        signature_fee,
        prioritization_fee,
        inclusion_fee: mcp_config.inclusion_fee,
        ordering_fee: mcp_config.ordering_fee,
    }
}

/// Builder for creating fee distributions to proposers
#[derive(Debug, Default)]
pub struct FeeDistributionBuilder {
    /// Map of proposer pubkey -> accumulated fees
    distributions: HashMap<Pubkey, u64>,
}

impl FeeDistributionBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add fees for a proposer
    pub fn add_fee(&mut self, proposer_pubkey: Pubkey, amount: u64) {
        *self.distributions.entry(proposer_pubkey).or_default() += amount;
    }

    /// Build the final distribution
    pub fn build(self) -> Vec<(Pubkey, u64)> {
        self.distributions.into_iter().collect()
    }

    /// Get total fees to distribute
    pub fn total(&self) -> u64 {
        self.distributions.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_fee_config() {
        let config = McpFeeConfig::new(1000, 2000);
        assert_eq!(config.inclusion_fee, 1000);
        assert_eq!(config.ordering_fee, 2000);
        assert_eq!(config.total_mcp_fee(), 3000);
    }

    #[test]
    fn test_mcp_fee_config_from_data() {
        // Both bits set: inclusion_fee and ordering_fee present
        let config_mask = 0b11;
        let config_data = [
            0xe8, 0x03, 0x00, 0x00, // 1000 in LE
            0xd0, 0x07, 0x00, 0x00, // 2000 in LE
        ];

        let config = McpFeeConfig::from_config_data(config_mask, &config_data);
        assert_eq!(config.inclusion_fee, 1000);
        assert_eq!(config.ordering_fee, 2000);
    }

    #[test]
    fn test_mcp_fee_config_partial() {
        // Only inclusion_fee set
        let config_mask = 0b01;
        let config_data = [0xe8, 0x03, 0x00, 0x00]; // 1000 in LE

        let config = McpFeeConfig::from_config_data(config_mask, &config_data);
        assert_eq!(config.inclusion_fee, 1000);
        assert_eq!(config.ordering_fee, 0);
    }

    #[test]
    fn test_transaction_fees() {
        let fees = TransactionFees {
            signature_fee: 5000,
            prioritization_fee: 1000,
            inclusion_fee: 500,
            ordering_fee: 200,
        };

        assert_eq!(fees.total(), 6700);
        assert_eq!(fees.validator_fees(), 6000);
        assert_eq!(fees.proposer_fees(), 700);
    }

    #[test]
    fn test_slot_fee_tracker() {
        let mut tracker = SlotFeeTracker::new(100);

        // Record successful fee deduction
        tracker.record_fee_deduction(&FeeDeductionResult::Success {
            fees: TransactionFees {
                signature_fee: 5000,
                prioritization_fee: 1000,
                inclusion_fee: 500,
                ordering_fee: 200,
            },
            including_proposer: 0,
        });

        assert_eq!(tracker.tx_count, 1);
        assert_eq!(tracker.validator_fees, 6000);
        assert_eq!(tracker.get_proposer_fee(0), 700);

        // Record another for a different proposer
        tracker.record_fee_deduction(&FeeDeductionResult::Success {
            fees: TransactionFees {
                signature_fee: 5000,
                prioritization_fee: 0,
                inclusion_fee: 100,
                ordering_fee: 0,
            },
            including_proposer: 1,
        });

        assert_eq!(tracker.tx_count, 2);
        assert_eq!(tracker.validator_fees, 11000);
        assert_eq!(tracker.get_proposer_fee(1), 100);
        assert_eq!(tracker.total_fees(), 11800);
    }

    #[test]
    fn test_slot_fee_tracker_failures() {
        let mut tracker = SlotFeeTracker::new(100);

        tracker.record_fee_deduction(&FeeDeductionResult::InsufficientFunds {
            required: 10000,
            available: 5000,
        });

        assert_eq!(tracker.tx_count, 0);
        assert_eq!(tracker.failed_tx_count, 1);
    }

    #[test]
    fn test_two_phase_processor() {
        let mut processor = TwoPhaseProcessor::new(100);

        // Set up ordered transactions
        let tx1 = OrderedTransaction::new(0, vec![1u8; 50]);
        let tx2 = OrderedTransaction::new(1, vec![2u8; 50]);
        processor.set_ordered_transactions(&[tx1.clone(), tx2.clone()]);

        // Check including proposers
        assert_eq!(processor.get_including_proposer(&tx1.txid), Some(0));
        assert_eq!(processor.get_including_proposer(&tx2.txid), Some(1));
    }

    #[test]
    fn test_phase_a_success() {
        let mut processor = TwoPhaseProcessor::new(100);

        let tx = OrderedTransaction::new(5, vec![1u8; 50]);
        processor.set_ordered_transactions(&[tx.clone()]);

        let fees = TransactionFees {
            signature_fee: 5000,
            prioritization_fee: 1000,
            inclusion_fee: 500,
            ordering_fee: 200,
        };

        let result = processor.process_phase_a(
            &tx.txid,
            fees,
            &Pubkey::new_unique(),
            10000, // Sufficient balance
        );

        assert!(matches!(
            result,
            FeeDeductionResult::Success {
                including_proposer: 5,
                ..
            }
        ));
    }

    #[test]
    fn test_phase_a_insufficient_funds() {
        let mut processor = TwoPhaseProcessor::new(100);

        let tx = OrderedTransaction::new(0, vec![1u8; 50]);
        processor.set_ordered_transactions(&[tx.clone()]);

        let fees = TransactionFees {
            signature_fee: 5000,
            prioritization_fee: 1000,
            inclusion_fee: 500,
            ordering_fee: 200,
        };

        let result = processor.process_phase_a(
            &tx.txid,
            fees,
            &Pubkey::new_unique(),
            100, // Insufficient balance
        );

        assert!(matches!(
            result,
            FeeDeductionResult::InsufficientFunds { .. }
        ));
    }

    #[test]
    fn test_calculate_mcp_fees() {
        let mcp_config = McpFeeConfig::new(1000, 2000);

        let fees = calculate_mcp_fees(
            &[],
            mcp_config,
            2,       // 2 signatures
            100_000, // 100k compute units
            1_000,   // 1000 micro-lamports per CU = 0.001 lamports per CU
        );

        assert_eq!(fees.signature_fee, 10000); // 2 * 5000
        // prioritization_fee = 100k CU * 1000 micro-lamports / 1M = 100 lamports
        assert_eq!(fees.prioritization_fee, 100);
        assert_eq!(fees.inclusion_fee, 1000);
        assert_eq!(fees.ordering_fee, 2000);
    }

    #[test]
    fn test_fee_distribution_builder() {
        let mut builder = FeeDistributionBuilder::new();

        let pubkey1 = Pubkey::new_unique();
        let pubkey2 = Pubkey::new_unique();

        builder.add_fee(pubkey1, 1000);
        builder.add_fee(pubkey1, 500);
        builder.add_fee(pubkey2, 2000);

        assert_eq!(builder.total(), 3500);

        let distribution = builder.build();
        assert_eq!(distribution.len(), 2);
    }
}
