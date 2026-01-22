//! MCP Fee Payer Validation
//!
//! This module provides MCP-specific fee payer validation to prevent
//! DA (Data Availability) fee payer attacks in multi-proposer scenarios.
//!
//! # Problem
//!
//! In MCP, a transaction may be included by multiple proposers in the same slot.
//! If a fee payer has balance for exactly one fee payment, they could be included
//! by multiple proposers, causing later proposers to fail fee collection.
//!
//! # Solution
//!
//! 1. Require fee payers to have balance for `NUM_PROPOSERS * fee` upfront
//! 2. Track cumulative fee commitments per payer within each slot
//! 3. Ensure a single payer cannot be over-committed across proposer batches

use {
    solana_account::{AccountSharedData, ReadableAccount},
    solana_nonce::state::State as NonceState,
    solana_nonce_account::{get_system_account_kind, SystemAccountKind},
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    std::collections::HashMap,
};

/// Number of proposers in MCP (mirrored from ledger/src/mcp.rs)
pub const NUM_PROPOSERS: u8 = 16;

/// Errors that can occur during MCP fee payer validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpFeePayerError {
    /// Fee payer has insufficient funds for MCP multi-proposer scenario.
    InsufficientFundsForMcp {
        available: u64,
        required: u64,
    },
    /// Fee payer has exceeded their per-slot commitment limit.
    OverCommitted {
        payer: Pubkey,
        committed: u64,
        max_allowed: u64,
    },
}

impl std::fmt::Display for McpFeePayerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientFundsForMcp { available, required } => {
                write!(
                    f,
                    "insufficient funds for MCP: available {}, required {} (for {} proposers)",
                    available, required, NUM_PROPOSERS
                )
            }
            Self::OverCommitted {
                payer,
                committed,
                max_allowed,
            } => {
                write!(
                    f,
                    "fee payer {} over-committed: {} committed, max allowed {}",
                    payer, committed, max_allowed
                )
            }
        }
    }
}

impl std::error::Error for McpFeePayerError {}

/// Tracker for per-slot fee payer commitments.
///
/// This tracks how much each fee payer has committed to pay in fees
/// within a single slot, across all proposer batches.
#[derive(Debug, Default)]
pub struct SlotFeePayerTracker {
    /// Maps fee payer pubkey to total committed fees in this slot.
    commitments: HashMap<Pubkey, u64>,
    /// The slot this tracker is for.
    slot: u64,
}

impl SlotFeePayerTracker {
    /// Create a new tracker for a slot.
    pub fn new(slot: u64) -> Self {
        Self {
            commitments: HashMap::new(),
            slot,
        }
    }

    /// Get the slot this tracker is for.
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Get the total committed fees for a payer.
    pub fn get_commitment(&self, payer: &Pubkey) -> u64 {
        self.commitments.get(payer).copied().unwrap_or(0)
    }

    /// Add a fee commitment for a payer.
    ///
    /// Returns the new total commitment for this payer.
    pub fn add_commitment(&mut self, payer: Pubkey, fee: u64) -> u64 {
        let entry = self.commitments.entry(payer).or_insert(0);
        *entry = entry.saturating_add(fee);
        *entry
    }

    /// Check if a payer can commit additional fees without exceeding their limit.
    ///
    /// The limit is based on the payer's available balance accounting for
    /// the MCP multi-proposer requirement.
    pub fn can_commit(
        &self,
        payer: &Pubkey,
        fee: u64,
        available_balance: u64,
        min_balance: u64,
    ) -> Result<(), McpFeePayerError> {
        let current_commitment = self.get_commitment(payer);
        let new_total = current_commitment.saturating_add(fee);

        // The payer's spendable balance after reserving min_balance
        let spendable = available_balance.saturating_sub(min_balance);

        // Maximum they can commit across all proposers
        // For safety, we allow up to their full spendable balance
        // (they won't actually be charged by all proposers)
        if new_total > spendable {
            return Err(McpFeePayerError::OverCommitted {
                payer: *payer,
                committed: new_total,
                max_allowed: spendable,
            });
        }

        Ok(())
    }

    /// Clear all commitments (for slot rollover).
    pub fn clear(&mut self) {
        self.commitments.clear();
    }

    /// Reset for a new slot.
    pub fn reset_for_slot(&mut self, slot: u64) {
        self.commitments.clear();
        self.slot = slot;
    }
}

/// Validate that a fee payer has sufficient funds for MCP multi-proposer scenario.
///
/// In MCP, we require fee payers to have enough balance to potentially pay
/// fees to all proposers, even though in practice they'll only pay to one.
/// This prevents griefing attacks where a payer submits to multiple proposers
/// with insufficient funds.
///
/// # Arguments
///
/// * `payer_account` - The fee payer's account
/// * `fee` - The fee for a single proposer
/// * `rent` - Rent parameters for calculating minimum balance
/// * `is_nonce` - Whether this is a nonce account
///
/// # Returns
///
/// `Ok(())` if the payer has sufficient funds, or an error describing why not.
pub fn validate_mcp_fee_payer(
    payer_account: &AccountSharedData,
    fee: u64,
    rent: &Rent,
    is_nonce: bool,
) -> Result<(), McpFeePayerError> {
    let balance = payer_account.lamports();

    // Calculate minimum balance requirement
    let min_balance = if is_nonce {
        rent.minimum_balance(NonceState::size())
    } else {
        0
    };

    // For MCP, we require balance for all proposers' fees
    let mcp_fee_requirement = fee.saturating_mul(NUM_PROPOSERS as u64);
    let total_required = min_balance.saturating_add(mcp_fee_requirement);

    if balance < total_required {
        return Err(McpFeePayerError::InsufficientFundsForMcp {
            available: balance,
            required: total_required,
        });
    }

    Ok(())
}

/// Calculate the MCP-adjusted fee requirement for a transaction.
///
/// This returns the total amount a fee payer should have available
/// to safely submit a transaction in MCP.
pub fn calculate_mcp_fee_requirement(fee: u64, is_nonce: bool, rent: &Rent) -> u64 {
    let min_balance = if is_nonce {
        rent.minimum_balance(NonceState::size())
    } else {
        0
    };

    let mcp_fee = fee.saturating_mul(NUM_PROPOSERS as u64);
    min_balance.saturating_add(mcp_fee)
}

/// Check if an account is a nonce account using system account kind.
pub fn is_nonce_account(account: &AccountSharedData) -> bool {
    matches!(
        get_system_account_kind(account),
        Some(SystemAccountKind::Nonce)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_fee_payer_tracker() {
        let mut tracker = SlotFeePayerTracker::new(100);
        let payer = Pubkey::new_unique();

        assert_eq!(tracker.get_commitment(&payer), 0);

        tracker.add_commitment(payer, 1000);
        assert_eq!(tracker.get_commitment(&payer), 1000);

        tracker.add_commitment(payer, 500);
        assert_eq!(tracker.get_commitment(&payer), 1500);
    }

    #[test]
    fn test_can_commit() {
        let mut tracker = SlotFeePayerTracker::new(100);
        let payer = Pubkey::new_unique();

        // With 10000 lamports available and 0 min_balance
        assert!(tracker.can_commit(&payer, 5000, 10000, 0).is_ok());

        // Add a commitment
        tracker.add_commitment(payer, 5000);

        // Now we have 5000 committed, can commit 5000 more
        assert!(tracker.can_commit(&payer, 5000, 10000, 0).is_ok());

        // But not 5001 more
        assert!(tracker.can_commit(&payer, 5001, 10000, 0).is_err());
    }

    #[test]
    fn test_validate_mcp_fee_payer() {
        let rent = Rent::default();
        let fee = 5000;

        // System account needs NUM_PROPOSERS * fee
        let required = 5000 * NUM_PROPOSERS as u64;

        // Account with exactly enough
        let account = AccountSharedData::new(required, 0, &solana_sdk_ids::system_program::ID);
        assert!(validate_mcp_fee_payer(&account, fee, &rent, false).is_ok());

        // Account with not quite enough
        let account = AccountSharedData::new(required - 1, 0, &solana_sdk_ids::system_program::ID);
        assert!(validate_mcp_fee_payer(&account, fee, &rent, false).is_err());
    }

    #[test]
    fn test_calculate_mcp_fee_requirement() {
        let rent = Rent::default();
        let fee = 5000;

        // For system account: just NUM_PROPOSERS * fee
        let required = calculate_mcp_fee_requirement(fee, false, &rent);
        assert_eq!(required, 5000 * NUM_PROPOSERS as u64);

        // For nonce account: add rent minimum
        let nonce_required = calculate_mcp_fee_requirement(fee, true, &rent);
        let nonce_min_balance = rent.minimum_balance(NonceState::size());
        assert_eq!(nonce_required, 5000 * NUM_PROPOSERS as u64 + nonce_min_balance);
    }

    #[test]
    fn test_tracker_reset() {
        let mut tracker = SlotFeePayerTracker::new(100);
        let payer = Pubkey::new_unique();

        tracker.add_commitment(payer, 1000);
        assert_eq!(tracker.get_commitment(&payer), 1000);

        tracker.reset_for_slot(101);
        assert_eq!(tracker.slot(), 101);
        assert_eq!(tracker.get_commitment(&payer), 0);
    }
}
