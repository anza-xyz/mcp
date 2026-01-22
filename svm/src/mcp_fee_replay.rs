//! MCP Fee-Only Replay Pass
//!
//! This module implements the two-phase transaction processing for MCP:
//!
//! 1. **Fee Phase**: Deduct all fees (signature, prioritization, inclusion, ordering)
//!    regardless of whether execution will succeed
//! 2. **Execution Phase**: Apply state transitions without re-charging fees
//!
//! # Rationale
//!
//! In MCP, proposers are compensated for data availability via inclusion fees.
//! These fees must be collected even if transaction execution fails. This
//! ensures proposers are paid for their work and prevents griefing attacks
//! where users submit transactions that fail but avoid paying fees.
//!
//! # Implementation
//!
//! The fee phase:
//! - Loads the fee payer account
//! - Validates sufficient balance for all fees
//! - Deducts fees atomically
//! - Records the fee payment
//!
//! The execution phase:
//! - Receives pre-paid transactions
//! - Executes state transitions
//! - Does NOT attempt to charge fees again
//! - Records success/failure status

use {
    solana_account::AccountSharedData,
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_transaction_error::TransactionError,
    std::collections::HashMap,
};

/// MCP fee breakdown for a transaction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct McpFeeBreakdown {
    /// Standard signature fee.
    pub signature_fee: u64,
    /// Prioritization fee (for execution priority).
    pub prioritization_fee: u64,
    /// MCP inclusion fee (for data availability).
    pub inclusion_fee: u64,
    /// MCP ordering fee (for ordering within proposer batch).
    pub ordering_fee: u64,
}

impl McpFeeBreakdown {
    /// Create a new fee breakdown.
    pub const fn new(
        signature_fee: u64,
        prioritization_fee: u64,
        inclusion_fee: u64,
        ordering_fee: u64,
    ) -> Self {
        Self {
            signature_fee,
            prioritization_fee,
            inclusion_fee,
            ordering_fee,
        }
    }

    /// Total fees to be charged.
    pub const fn total(&self) -> u64 {
        self.signature_fee
            .saturating_add(self.prioritization_fee)
            .saturating_add(self.inclusion_fee)
            .saturating_add(self.ordering_fee)
    }

    /// Fees that are charged regardless of execution outcome.
    ///
    /// In MCP, inclusion fees are always charged to compensate proposers.
    pub const fn unconditional_fees(&self) -> u64 {
        self.inclusion_fee
    }

    /// Fees that are only charged on successful execution.
    pub const fn conditional_fees(&self) -> u64 {
        self.signature_fee
            .saturating_add(self.prioritization_fee)
            .saturating_add(self.ordering_fee)
    }
}

/// Result of the fee-only phase.
#[derive(Debug, Clone)]
pub enum FeePhaseResult {
    /// Fees were successfully deducted.
    Success {
        /// The fee payer's pubkey.
        fee_payer: Pubkey,
        /// The fees that were charged.
        fees: McpFeeBreakdown,
        /// The fee payer's balance after fee deduction.
        post_fee_balance: u64,
    },
    /// Fee deduction failed.
    Failure {
        /// The fee payer's pubkey.
        fee_payer: Pubkey,
        /// The error that occurred.
        error: TransactionError,
    },
}

impl FeePhaseResult {
    /// Returns true if fees were successfully deducted.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Get the fee payer pubkey.
    pub fn fee_payer(&self) -> &Pubkey {
        match self {
            Self::Success { fee_payer, .. } => fee_payer,
            Self::Failure { fee_payer, .. } => fee_payer,
        }
    }
}

/// Tracks fee payments within a slot.
#[derive(Debug, Default)]
pub struct SlotFeeTracker {
    /// The slot being tracked.
    slot: u64,
    /// Total fees collected in this slot.
    total_fees_collected: u64,
    /// Fees per fee payer.
    payer_fees: HashMap<Pubkey, u64>,
    /// Fees per proposer.
    proposer_fees: HashMap<u8, u64>,
}

impl SlotFeeTracker {
    /// Create a new tracker for a slot.
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            total_fees_collected: 0,
            payer_fees: HashMap::new(),
            proposer_fees: HashMap::new(),
        }
    }

    /// Record a fee payment.
    pub fn record_fee_payment(
        &mut self,
        fee_payer: Pubkey,
        proposer_id: u8,
        fees: &McpFeeBreakdown,
    ) {
        let total = fees.total();
        self.total_fees_collected = self.total_fees_collected.saturating_add(total);

        *self.payer_fees.entry(fee_payer).or_insert(0) += total;
        *self.proposer_fees.entry(proposer_id).or_insert(0) += fees.inclusion_fee;
    }

    /// Get total fees collected.
    pub fn total_fees(&self) -> u64 {
        self.total_fees_collected
    }

    /// Get fees paid by a specific payer.
    pub fn payer_fees(&self, payer: &Pubkey) -> u64 {
        self.payer_fees.get(payer).copied().unwrap_or(0)
    }

    /// Get inclusion fees for a proposer.
    pub fn proposer_inclusion_fees(&self, proposer_id: u8) -> u64 {
        self.proposer_fees.get(&proposer_id).copied().unwrap_or(0)
    }
}

/// Configuration for MCP fee-only replay.
#[derive(Debug, Clone, Copy)]
pub struct McpFeeReplayConfig {
    /// Whether to charge inclusion fees regardless of execution outcome.
    pub charge_unconditional_fees: bool,
    /// Whether to track per-proposer fees.
    pub track_proposer_fees: bool,
}

impl Default for McpFeeReplayConfig {
    fn default() -> Self {
        Self {
            charge_unconditional_fees: true,
            track_proposer_fees: true,
        }
    }
}

/// Performs the fee-only phase of transaction processing.
///
/// This is called before executing state transitions to ensure fees
/// are collected regardless of execution outcome.
pub fn execute_fee_phase(
    fee_payer: &Pubkey,
    fee_payer_account: &mut AccountSharedData,
    fees: McpFeeBreakdown,
    min_balance: u64,
) -> FeePhaseResult {
    use solana_account::ReadableAccount;

    let balance = fee_payer_account.lamports();
    let total_fees = fees.total();
    let required = min_balance.saturating_add(total_fees);

    // Check sufficient balance
    if balance < required {
        return FeePhaseResult::Failure {
            fee_payer: *fee_payer,
            error: TransactionError::InsufficientFundsForFee,
        };
    }

    // Deduct fees
    use solana_account::WritableAccount;
    let new_balance = balance.saturating_sub(total_fees);
    fee_payer_account.set_lamports(new_balance);

    FeePhaseResult::Success {
        fee_payer: *fee_payer,
        fees,
        post_fee_balance: new_balance,
    }
}

/// Marker indicating a transaction has completed fee phase.
#[derive(Debug, Clone)]
pub struct FeePhaseCompleted {
    /// The transaction hash.
    pub transaction_hash: Hash,
    /// The fee payer.
    pub fee_payer: Pubkey,
    /// The fees that were charged.
    pub fees: McpFeeBreakdown,
    /// The proposer that included this transaction.
    pub proposer_id: u8,
}

impl FeePhaseCompleted {
    /// Create a new completion marker.
    pub fn new(
        transaction_hash: Hash,
        fee_payer: Pubkey,
        fees: McpFeeBreakdown,
        proposer_id: u8,
    ) -> Self {
        Self {
            transaction_hash,
            fee_payer,
            fees,
            proposer_id,
        }
    }
}

/// Result of the execution phase (after fees have been paid).
#[derive(Debug, Clone)]
pub struct ExecutionPhaseResult {
    /// The transaction that was executed.
    pub fee_phase: FeePhaseCompleted,
    /// Whether execution succeeded.
    pub execution_success: bool,
    /// Error if execution failed (but fees were still charged).
    pub execution_error: Option<TransactionError>,
}

impl ExecutionPhaseResult {
    /// Create a successful execution result.
    pub fn success(fee_phase: FeePhaseCompleted) -> Self {
        Self {
            fee_phase,
            execution_success: true,
            execution_error: None,
        }
    }

    /// Create a failed execution result (fees still charged).
    pub fn failure(fee_phase: FeePhaseCompleted, error: TransactionError) -> Self {
        Self {
            fee_phase,
            execution_success: false,
            execution_error: Some(error),
        }
    }

    /// Returns true if the full transaction succeeded.
    pub fn is_success(&self) -> bool {
        self.execution_success
    }

    /// Returns the total fees paid (regardless of execution outcome).
    pub fn fees_paid(&self) -> u64 {
        self.fee_phase.fees.total()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_breakdown() {
        let fees = McpFeeBreakdown::new(5000, 1000, 2000, 500);

        assert_eq!(fees.total(), 8500);
        assert_eq!(fees.unconditional_fees(), 2000); // Only inclusion_fee
        assert_eq!(fees.conditional_fees(), 6500); // Everything else
    }

    #[test]
    fn test_execute_fee_phase_success() {
        let fee_payer = Pubkey::new_unique();
        let mut account = AccountSharedData::new(10000, 0, &solana_sdk_ids::system_program::ID);
        let fees = McpFeeBreakdown::new(5000, 0, 2000, 0);

        let result = execute_fee_phase(&fee_payer, &mut account, fees, 0);

        assert!(result.is_success());
        if let FeePhaseResult::Success { post_fee_balance, .. } = result {
            assert_eq!(post_fee_balance, 10000 - 7000);
        }

        use solana_account::ReadableAccount;
        assert_eq!(account.lamports(), 3000);
    }

    #[test]
    fn test_execute_fee_phase_insufficient_funds() {
        let fee_payer = Pubkey::new_unique();
        let mut account = AccountSharedData::new(1000, 0, &solana_sdk_ids::system_program::ID);
        let fees = McpFeeBreakdown::new(5000, 0, 0, 0);

        let result = execute_fee_phase(&fee_payer, &mut account, fees, 0);

        assert!(!result.is_success());
        if let FeePhaseResult::Failure { error, .. } = result {
            assert_eq!(error, TransactionError::InsufficientFundsForFee);
        }
    }

    #[test]
    fn test_slot_fee_tracker() {
        let mut tracker = SlotFeeTracker::new(100);
        let payer = Pubkey::new_unique();
        let fees = McpFeeBreakdown::new(5000, 1000, 2000, 500);

        tracker.record_fee_payment(payer, 5, &fees);

        assert_eq!(tracker.total_fees(), 8500);
        assert_eq!(tracker.payer_fees(&payer), 8500);
        assert_eq!(tracker.proposer_inclusion_fees(5), 2000);
    }

    #[test]
    fn test_execution_phase_result() {
        let fee_phase = FeePhaseCompleted::new(
            Hash::default(),
            Pubkey::new_unique(),
            McpFeeBreakdown::new(5000, 0, 2000, 0),
            1,
        );

        let success = ExecutionPhaseResult::success(fee_phase.clone());
        assert!(success.is_success());
        assert_eq!(success.fees_paid(), 7000);

        let failure = ExecutionPhaseResult::failure(
            fee_phase,
            TransactionError::InsufficientFundsForRent { account_index: 0 },
        );
        assert!(!failure.is_success());
        assert_eq!(failure.fees_paid(), 7000); // Fees still paid!
    }
}
