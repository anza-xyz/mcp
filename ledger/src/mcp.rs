//! MCP (Multiple Concurrent Proposers) protocol configuration and constants.
//!
//! This module centralizes all MCP protocol constants so that all nodes
//! derive identical values from genesis/config.
//!
//! # Protocol Overview
//!
//! MCP enables multiple proposers to submit transaction batches in parallel,
//! which are then aggregated by relays and finalized by the consensus leader.
//!
//! # Thresholds
//!
//! - `ATTESTATION_THRESHOLD`: Fraction of stake required for a relay attestation
//!   to be considered valid (60%)
//! - `INCLUSION_THRESHOLD`: Minimum stake fraction for a proposer batch to be
//!   included in the final block (40%)
//! - `RECONSTRUCTION_THRESHOLD`: Minimum stake fraction of shreds needed to
//!   reconstruct a proposer's batch (20%)

use solana_votor_messages::fraction::Fraction;

/// Number of proposers that can submit batches per slot.
///
/// Each proposer is assigned a unique `proposer_id` in the range `[0, NUM_PROPOSERS)`.
/// Proposer IDs are deterministically assigned based on stake-weighted epoch schedules.
pub const NUM_PROPOSERS: u8 = 16;

/// Number of relays that aggregate and attest to proposer shreds.
///
/// Relays are stake-weighted validators responsible for:
/// 1. Receiving shreds from proposers
/// 2. Verifying shred commitments
/// 3. Submitting attestations to the consensus leader
pub const NUM_RELAYS: u16 = 200;

/// Fraction of stake required for a relay attestation to be valid.
///
/// When aggregating relay attestations, the consensus leader requires
/// attestations representing at least this fraction of total stake
/// before including a proposer batch in the consensus block.
pub const ATTESTATION_THRESHOLD: Fraction = Fraction::from_percentage(60);

/// Minimum stake fraction for a proposer batch to be included.
///
/// A proposer's batch is included in the final ordered output only if
/// at least this fraction of relays (by stake) have attested to receiving
/// the complete batch.
pub const INCLUSION_THRESHOLD: Fraction = Fraction::from_percentage(40);

/// Minimum stake fraction of shreds needed for reconstruction.
///
/// With erasure coding, a proposer's batch can be reconstructed from
/// a subset of shreds. This threshold defines the minimum stake fraction
/// of shreds that must be received before reconstruction is attempted.
pub const RECONSTRUCTION_THRESHOLD: Fraction = Fraction::from_percentage(20);

/// Reserved proposer ID for consensus payload shreds.
///
/// Shreds with this proposer_id contain consensus-level data (e.g., certificates,
/// votes) rather than proposer transaction batches.
pub const CONSENSUS_PAYLOAD_PROPOSER_ID: u8 = 0xFF;

/// MCP-specific FEC (Forward Error Correction) parameters.
///
/// MCP uses a different FEC rate than the standard shred encoding to optimize
/// for the multi-proposer scenario where data availability is critical.
pub mod fec {
    /// Number of data shreds per FEC block for MCP proposers.
    ///
    /// This is lower than standard encoding to allow more redundancy.
    pub const MCP_DATA_SHREDS_PER_FEC_BLOCK: usize = 40;

    /// Number of coding (parity) shreds per FEC block for MCP proposers.
    ///
    /// With 160 coding shreds for 40 data shreds, we have 4:1 redundancy,
    /// meaning recovery is possible with only 20% of total shreds (40 out of 200).
    pub const MCP_CODING_SHREDS_PER_FEC_BLOCK: usize = 160;

    /// Total shreds per FEC block (data + coding).
    pub const MCP_SHREDS_PER_FEC_BLOCK: usize =
        MCP_DATA_SHREDS_PER_FEC_BLOCK + MCP_CODING_SHREDS_PER_FEC_BLOCK;
}

/// Configuration structure for MCP protocol parameters.
///
/// This struct allows runtime configuration of MCP parameters, typically
/// loaded from genesis or feature gates. Default values match the protocol
/// specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpConfig {
    /// Number of proposers per slot
    pub num_proposers: u8,
    /// Number of relays
    pub num_relays: u16,
    /// Attestation threshold (stake fraction)
    pub attestation_threshold: Fraction,
    /// Inclusion threshold (stake fraction)
    pub inclusion_threshold: Fraction,
    /// Reconstruction threshold (stake fraction)
    pub reconstruction_threshold: Fraction,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            num_proposers: NUM_PROPOSERS,
            num_relays: NUM_RELAYS,
            attestation_threshold: ATTESTATION_THRESHOLD,
            inclusion_threshold: INCLUSION_THRESHOLD,
            reconstruction_threshold: RECONSTRUCTION_THRESHOLD,
        }
    }
}

impl McpConfig {
    /// Create a new MCP configuration with custom parameters.
    pub const fn new(
        num_proposers: u8,
        num_relays: u16,
        attestation_threshold: Fraction,
        inclusion_threshold: Fraction,
        reconstruction_threshold: Fraction,
    ) -> Self {
        Self {
            num_proposers,
            num_relays,
            attestation_threshold,
            inclusion_threshold,
            reconstruction_threshold,
        }
    }

    /// Returns true if the given proposer_id is valid for this config.
    pub const fn is_valid_proposer_id(&self, proposer_id: u8) -> bool {
        proposer_id < self.num_proposers || proposer_id == CONSENSUS_PAYLOAD_PROPOSER_ID
    }

    /// Returns true if the given relay_id is valid for this config.
    pub const fn is_valid_relay_id(&self, relay_id: u16) -> bool {
        relay_id < self.num_relays
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = McpConfig::default();
        assert_eq!(config.num_proposers, 16);
        assert_eq!(config.num_relays, 200);
        assert_eq!(config.attestation_threshold, Fraction::from_percentage(60));
        assert_eq!(config.inclusion_threshold, Fraction::from_percentage(40));
        assert_eq!(
            config.reconstruction_threshold,
            Fraction::from_percentage(20)
        );
    }

    #[test]
    fn test_valid_proposer_id() {
        let config = McpConfig::default();
        // Valid proposer IDs: 0-15
        for id in 0..16 {
            assert!(config.is_valid_proposer_id(id));
        }
        // Invalid: 16-254
        for id in 16..255 {
            assert!(!config.is_valid_proposer_id(id));
        }
        // Special: consensus payload ID (0xFF)
        assert!(config.is_valid_proposer_id(CONSENSUS_PAYLOAD_PROPOSER_ID));
    }

    #[test]
    fn test_valid_relay_id() {
        let config = McpConfig::default();
        // Valid relay IDs: 0-199
        for id in 0..200 {
            assert!(config.is_valid_relay_id(id));
        }
        // Invalid: 200+
        assert!(!config.is_valid_relay_id(200));
        assert!(!config.is_valid_relay_id(1000));
    }

    #[test]
    fn test_fec_constants() {
        use fec::*;
        assert_eq!(MCP_DATA_SHREDS_PER_FEC_BLOCK, 40);
        assert_eq!(MCP_CODING_SHREDS_PER_FEC_BLOCK, 160);
        assert_eq!(MCP_SHREDS_PER_FEC_BLOCK, 200);

        // Verify reconstruction is possible with RECONSTRUCTION_THRESHOLD
        // 20% of 200 shreds = 40 shreds = exactly the data shreds needed
        let min_shreds_for_recovery =
            (MCP_SHREDS_PER_FEC_BLOCK as f64 * 0.2).ceil() as usize;
        assert_eq!(min_shreds_for_recovery, MCP_DATA_SHREDS_PER_FEC_BLOCK);
    }
}
