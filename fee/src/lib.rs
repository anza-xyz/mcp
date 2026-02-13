use {
    agave_feature_set::{enable_secp256r1_precompile, FeatureSet},
    agave_transaction_view::mcp_transaction::McpTransaction,
    solana_fee_structure::FeeDetails,
    solana_svm_transaction::svm_message::SVMMessage,
};

// Keep in sync with `solana_ledger::mcp::NUM_PROPOSERS`; duplicated here to
// avoid introducing a `fee -> ledger` dependency edge. A cross-crate unit test
// in `solana-core` enforces this invariant.
pub const MCP_NUM_PROPOSERS: usize = 16;

/// Bools indicating the activation of features relevant
/// to the fee calculation.
// DEVELOPER NOTE:
// This struct may become empty at some point. It is preferable to keep it
// instead of removing, since fees will naturally be changed via feature-gates
// in the future. Keeping this struct will help keep things organized.
#[derive(Copy, Clone)]
pub struct FeeFeatures {
    pub enable_secp256r1_precompile: bool,
}

impl From<&FeatureSet> for FeeFeatures {
    fn from(feature_set: &FeatureSet) -> Self {
        Self {
            enable_secp256r1_precompile: feature_set.is_active(&enable_secp256r1_precompile::ID),
        }
    }
}

/// Calculate fee for `SanitizedMessage`
pub fn calculate_fee(
    message: &impl SVMMessage,
    zero_fees_for_test: bool,
    lamports_per_signature: u64,
    prioritization_fee: u64,
    fee_features: FeeFeatures,
) -> u64 {
    calculate_fee_details(
        message,
        zero_fees_for_test,
        lamports_per_signature,
        prioritization_fee,
        fee_features,
    )
    .total_fee()
}

pub fn calculate_fee_details(
    message: &impl SVMMessage,
    zero_fees_for_test: bool,
    lamports_per_signature: u64,
    prioritization_fee: u64,
    fee_features: FeeFeatures,
) -> FeeDetails {
    if zero_fees_for_test {
        return FeeDetails::default();
    }

    FeeDetails::new(
        calculate_signature_fee(
            SignatureCounts::from(message),
            lamports_per_signature,
            fee_features.enable_secp256r1_precompile,
        ),
        prioritization_fee,
    )
}

pub fn calculate_fee_details_with_mcp(
    message: &impl SVMMessage,
    zero_fees_for_test: bool,
    lamports_per_signature: u64,
    prioritization_fee: u64,
    fee_features: FeeFeatures,
    mcp_transaction: Option<&McpTransaction>,
) -> FeeDetails {
    let base = calculate_fee_details(
        message,
        zero_fees_for_test,
        lamports_per_signature,
        prioritization_fee,
        fee_features,
    );
    apply_mcp_fee_components(base, mcp_transaction)
}

pub fn apply_mcp_fee_components(
    base: FeeDetails,
    mcp_transaction: Option<&McpTransaction>,
) -> FeeDetails {
    let Some(mcp_transaction) = mcp_transaction else {
        return base;
    };

    apply_mcp_fee_component_values(
        base,
        u64::from(mcp_transaction.inclusion_fee().unwrap_or_default()),
        u64::from(mcp_transaction.ordering_fee().unwrap_or_default()),
    )
}

pub fn apply_mcp_fee_component_values(
    base: FeeDetails,
    inclusion_fee: u64,
    ordering_fee: u64,
) -> FeeDetails {
    FeeDetails::new(
        base.transaction_fee().saturating_add(inclusion_fee),
        base.prioritization_fee().saturating_add(ordering_fee),
    )
}

/// Calculate fees from signatures.
pub fn calculate_signature_fee(
    SignatureCounts {
        num_transaction_signatures,
        num_ed25519_signatures,
        num_secp256k1_signatures,
        num_secp256r1_signatures,
    }: SignatureCounts,
    lamports_per_signature: u64,
    enable_secp256r1_precompile: bool,
) -> u64 {
    let signature_count = num_transaction_signatures
        .saturating_add(num_ed25519_signatures)
        .saturating_add(num_secp256k1_signatures)
        .saturating_add(
            u64::from(enable_secp256r1_precompile).wrapping_mul(num_secp256r1_signatures),
        );
    signature_count.saturating_mul(lamports_per_signature)
}

pub struct SignatureCounts {
    pub num_transaction_signatures: u64,
    pub num_ed25519_signatures: u64,
    pub num_secp256k1_signatures: u64,
    pub num_secp256r1_signatures: u64,
}

impl<Tx: SVMMessage> From<&Tx> for SignatureCounts {
    fn from(message: &Tx) -> Self {
        Self {
            num_transaction_signatures: message.num_transaction_signatures(),
            num_ed25519_signatures: message.num_ed25519_signatures(),
            num_secp256k1_signatures: message.num_secp256k1_signatures(),
            num_secp256r1_signatures: message.num_secp256r1_signatures(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agave_transaction_view::mcp_transaction::{
        LegacyHeader, McpTransaction, MCP_TX_CONFIG_BIT_INCLUSION_FEE,
        MCP_TX_CONFIG_BIT_ORDERING_FEE,
    };

    #[test]
    fn test_calculate_signature_fee() {
        const LAMPORTS_PER_SIGNATURE: u64 = 5_000;

        // Impossible case - 0 signatures.
        assert_eq!(
            calculate_signature_fee(
                SignatureCounts {
                    num_transaction_signatures: 0,
                    num_ed25519_signatures: 0,
                    num_secp256k1_signatures: 0,
                    num_secp256r1_signatures: 0,
                },
                LAMPORTS_PER_SIGNATURE,
                true,
            ),
            0
        );

        // Simple signature
        assert_eq!(
            calculate_signature_fee(
                SignatureCounts {
                    num_transaction_signatures: 1,
                    num_ed25519_signatures: 0,
                    num_secp256k1_signatures: 0,
                    num_secp256r1_signatures: 0,
                },
                LAMPORTS_PER_SIGNATURE,
                true,
            ),
            LAMPORTS_PER_SIGNATURE
        );

        // Pre-compile signatures.
        assert_eq!(
            calculate_signature_fee(
                SignatureCounts {
                    num_transaction_signatures: 1,
                    num_ed25519_signatures: 2,
                    num_secp256k1_signatures: 3,
                    num_secp256r1_signatures: 4,
                },
                LAMPORTS_PER_SIGNATURE,
                true,
            ),
            10 * LAMPORTS_PER_SIGNATURE
        );

        // Pre-compile signatures (no secp256r1)
        assert_eq!(
            calculate_signature_fee(
                SignatureCounts {
                    num_transaction_signatures: 1,
                    num_ed25519_signatures: 2,
                    num_secp256k1_signatures: 3,
                    num_secp256r1_signatures: 4,
                },
                LAMPORTS_PER_SIGNATURE,
                false,
            ),
            6 * LAMPORTS_PER_SIGNATURE
        );
    }

    #[test]
    fn test_apply_mcp_fee_components_adds_inclusion_and_ordering_fee() {
        let mcp_tx = McpTransaction {
            version: 1,
            legacy_header: LegacyHeader {
                num_required_signatures: 0,
                num_readonly_signed: 0,
                num_readonly_unsigned: 0,
            },
            transaction_config_mask: (1u32 << MCP_TX_CONFIG_BIT_INCLUSION_FEE)
                | (1u32 << MCP_TX_CONFIG_BIT_ORDERING_FEE),
            lifetime_specifier: [0u8; 32],
            addresses: vec![],
            config_values: vec![17, 29],
            instruction_headers: vec![],
            instruction_payloads: vec![],
            signatures: vec![],
        };

        let base = FeeDetails::new(100, 5);
        let with_mcp = apply_mcp_fee_components(base, Some(&mcp_tx));
        assert_eq!(with_mcp.transaction_fee(), 117);
        assert_eq!(with_mcp.prioritization_fee(), 34);
        assert_eq!(with_mcp.total_fee(), 151);
    }

    #[test]
    fn test_apply_mcp_fee_components_is_noop_without_mcp_tx() {
        let base = FeeDetails::new(55, 44);
        assert_eq!(apply_mcp_fee_components(base, None), base);
    }

    #[test]
    fn test_apply_mcp_fee_component_values_adds_fee_components() {
        let base = FeeDetails::new(9, 4);
        let updated = apply_mcp_fee_component_values(base, 6, 2);
        assert_eq!(updated.transaction_fee(), 15);
        assert_eq!(updated.prioritization_fee(), 6);
        assert_eq!(updated.total_fee(), 21);
    }
}
