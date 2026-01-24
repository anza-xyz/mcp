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

use {
    solana_votor_messages::fraction::Fraction,
    std::io::{self, Read, Write},
};

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

/// MCP Transaction Configuration Module
///
/// Defines the extended transaction format for MCP including:
/// - `inclusion_fee`: Fee paid to proposers for including the transaction
/// - `ordering_fee`: Fee paid for transaction ordering priority
/// - `target_proposer`: Optional target proposer for the transaction
pub mod transaction {
    use super::*;

    /// Bit flags for MCP transaction configuration mask (u32 per spec §7.2).
    ///
    /// These flags indicate which optional fields are present in the
    /// serialized MCP transaction config.
    pub mod config_mask {
        /// Bit 0: inclusion_fee field is present
        pub const INCLUSION_FEE: u32 = 1 << 0;
        /// Bit 1: ordering_fee field is present
        pub const ORDERING_FEE: u32 = 1 << 1;
        /// Bit 2: compute_unit_limit field is present
        pub const COMPUTE_UNIT_LIMIT: u32 = 1 << 2;
        /// Bit 3: accounts_data_size_limit field is present
        pub const ACCOUNTS_DATA_SIZE_LIMIT: u32 = 1 << 3;
        /// Bit 4: heap_size field is present
        pub const HEAP_SIZE: u32 = 1 << 4;
        /// Bit 5: target_proposer field is present
        pub const TARGET_PROPOSER: u32 = 1 << 5;
    }

    /// MCP-specific transaction configuration per spec §7.
    ///
    /// This config extends standard Solana transactions with MCP-specific
    /// fee fields and targeting options. When serialized, only non-default
    /// fields are included, prefixed by a config mask.
    ///
    /// # Serialization Format (per MCP spec §7.2)
    ///
    /// ```text
    /// | config_mask (4 bytes) | fields in ascending bit order (4 bytes each) |
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct McpTransactionConfig {
        /// Fee paid to proposers for data availability (lamports, u32).
        pub inclusion_fee: u32,

        /// Fee paid for transaction ordering priority (lamports, u32).
        pub ordering_fee: u32,

        /// Requested compute unit limit.
        pub compute_unit_limit: Option<u32>,

        /// Requested accounts data size limit.
        pub accounts_data_size_limit: Option<u32>,

        /// Requested heap size.
        pub heap_size: Option<u32>,

        /// Optional target proposer index [0..NUM_PROPOSERS-1].
        pub target_proposer: Option<u32>,
    }

    impl McpTransactionConfig {
        /// Create a new MCP transaction config with the specified fees.
        pub const fn new(inclusion_fee: u32, ordering_fee: u32) -> Self {
            Self {
                inclusion_fee,
                ordering_fee,
                compute_unit_limit: None,
                accounts_data_size_limit: None,
                heap_size: None,
                target_proposer: None,
            }
        }

        /// Create a new MCP transaction config targeting a specific proposer.
        /// Per MCP spec §7, target_proposer is an index (0 to NUM_PROPOSERS-1).
        pub const fn with_target_proposer(
            inclusion_fee: u32,
            ordering_fee: u32,
            target_proposer: u32,
        ) -> Self {
            Self {
                inclusion_fee,
                ordering_fee,
                compute_unit_limit: None,
                accounts_data_size_limit: None,
                heap_size: None,
                target_proposer: Some(target_proposer),
            }
        }

        /// Returns the config mask (u32) indicating which fields are present.
        pub fn config_mask(&self) -> u32 {
            let mut mask = 0u32;
            if self.inclusion_fee > 0 {
                mask |= config_mask::INCLUSION_FEE;
            }
            if self.ordering_fee > 0 {
                mask |= config_mask::ORDERING_FEE;
            }
            if self.compute_unit_limit.is_some() {
                mask |= config_mask::COMPUTE_UNIT_LIMIT;
            }
            if self.accounts_data_size_limit.is_some() {
                mask |= config_mask::ACCOUNTS_DATA_SIZE_LIMIT;
            }
            if self.heap_size.is_some() {
                mask |= config_mask::HEAP_SIZE;
            }
            if self.target_proposer.is_some() {
                mask |= config_mask::TARGET_PROPOSER;
            }
            mask
        }

        /// Returns the total MCP fees (inclusion + ordering).
        pub const fn total_mcp_fees(&self) -> u64 {
            (self.inclusion_fee as u64).saturating_add(self.ordering_fee as u64)
        }

        /// Serialize the MCP transaction config to bytes per spec §7.2.
        ///
        /// Fields are serialized in ascending bit index order.
        pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
            let mask = self.config_mask();
            writer.write_all(&mask.to_le_bytes())?;
            let mut bytes_written = 4;

            if mask & config_mask::INCLUSION_FEE != 0 {
                writer.write_all(&self.inclusion_fee.to_le_bytes())?;
                bytes_written += 4;
            }
            if mask & config_mask::ORDERING_FEE != 0 {
                writer.write_all(&self.ordering_fee.to_le_bytes())?;
                bytes_written += 4;
            }
            if mask & config_mask::COMPUTE_UNIT_LIMIT != 0 {
                if let Some(limit) = self.compute_unit_limit {
                    writer.write_all(&limit.to_le_bytes())?;
                    bytes_written += 4;
                }
            }
            if mask & config_mask::ACCOUNTS_DATA_SIZE_LIMIT != 0 {
                if let Some(limit) = self.accounts_data_size_limit {
                    writer.write_all(&limit.to_le_bytes())?;
                    bytes_written += 4;
                }
            }
            if mask & config_mask::HEAP_SIZE != 0 {
                if let Some(size) = self.heap_size {
                    writer.write_all(&size.to_le_bytes())?;
                    bytes_written += 4;
                }
            }
            if mask & config_mask::TARGET_PROPOSER != 0 {
                if let Some(proposer_index) = self.target_proposer {
                    writer.write_all(&proposer_index.to_le_bytes())?;
                    bytes_written += 4;
                }
            }

            Ok(bytes_written)
        }

        /// Deserialize MCP transaction config from bytes per spec §7.2.
        pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
            let mut mask_buf = [0u8; 4];
            reader.read_exact(&mut mask_buf)?;
            let mask = u32::from_le_bytes(mask_buf);

            let mut buf4 = [0u8; 4];

            let inclusion_fee = if mask & config_mask::INCLUSION_FEE != 0 {
                reader.read_exact(&mut buf4)?;
                u32::from_le_bytes(buf4)
            } else {
                0
            };

            let ordering_fee = if mask & config_mask::ORDERING_FEE != 0 {
                reader.read_exact(&mut buf4)?;
                u32::from_le_bytes(buf4)
            } else {
                0
            };

            let compute_unit_limit = if mask & config_mask::COMPUTE_UNIT_LIMIT != 0 {
                reader.read_exact(&mut buf4)?;
                Some(u32::from_le_bytes(buf4))
            } else {
                None
            };

            let accounts_data_size_limit = if mask & config_mask::ACCOUNTS_DATA_SIZE_LIMIT != 0 {
                reader.read_exact(&mut buf4)?;
                Some(u32::from_le_bytes(buf4))
            } else {
                None
            };

            let heap_size = if mask & config_mask::HEAP_SIZE != 0 {
                reader.read_exact(&mut buf4)?;
                Some(u32::from_le_bytes(buf4))
            } else {
                None
            };

            let target_proposer = if mask & config_mask::TARGET_PROPOSER != 0 {
                reader.read_exact(&mut buf4)?;
                Some(u32::from_le_bytes(buf4))
            } else {
                None
            };

            Ok(Self {
                inclusion_fee,
                ordering_fee,
                compute_unit_limit,
                accounts_data_size_limit,
                heap_size,
                target_proposer,
            })
        }

        /// Returns the serialized size in bytes.
        pub fn serialized_size(&self) -> usize {
            let mask = self.config_mask();
            let mut size = 4; // config mask (u32)
            if mask & config_mask::INCLUSION_FEE != 0 {
                size += 4;
            }
            if mask & config_mask::ORDERING_FEE != 0 {
                size += 4;
            }
            if mask & config_mask::COMPUTE_UNIT_LIMIT != 0 {
                size += 4;
            }
            if mask & config_mask::ACCOUNTS_DATA_SIZE_LIMIT != 0 {
                size += 4;
            }
            if mask & config_mask::HEAP_SIZE != 0 {
                size += 4;
            }
            if mask & config_mask::TARGET_PROPOSER != 0 {
                size += 4;
            }
            size
        }
    }

    /// Extended fee details that include MCP-specific fees.
    ///
    /// This wraps the standard FeeDetails with additional MCP fees.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct McpFeeDetails {
        /// Standard transaction fee (signature fees)
        pub transaction_fee: u64,
        /// Standard prioritization fee
        pub prioritization_fee: u64,
        /// MCP inclusion fee (charged regardless of execution)
        pub inclusion_fee: u64,
        /// MCP ordering fee (for priority within proposer batch)
        pub ordering_fee: u64,
    }

    impl McpFeeDetails {
        /// Create new MCP fee details.
        pub const fn new(
            transaction_fee: u64,
            prioritization_fee: u64,
            inclusion_fee: u64,
            ordering_fee: u64,
        ) -> Self {
            Self {
                transaction_fee,
                prioritization_fee,
                inclusion_fee,
                ordering_fee,
            }
        }

        /// Returns the total of all fees.
        pub const fn total_fee(&self) -> u64 {
            self.transaction_fee
                .saturating_add(self.prioritization_fee)
                .saturating_add(self.inclusion_fee)
                .saturating_add(self.ordering_fee)
        }

        /// Returns the total MCP-specific fees (inclusion + ordering).
        pub const fn total_mcp_fees(&self) -> u64 {
            self.inclusion_fee.saturating_add(self.ordering_fee)
        }

        /// Returns the total standard fees (transaction + prioritization).
        pub const fn total_standard_fees(&self) -> u64 {
            self.transaction_fee.saturating_add(self.prioritization_fee)
        }

        /// Fees that are charged regardless of transaction execution outcome.
        ///
        /// In MCP, inclusion fees are always charged to compensate proposers
        /// for data availability, even if the transaction fails.
        pub const fn fees_charged_regardless_of_execution(&self) -> u64 {
            self.inclusion_fee
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_default_config() {
            let config = McpTransactionConfig::default();
            assert_eq!(config.inclusion_fee, 0);
            assert_eq!(config.ordering_fee, 0);
            assert!(config.target_proposer.is_none());
            assert_eq!(config.config_mask(), 0);
        }

        #[test]
        fn test_config_with_fees() {
            let config = McpTransactionConfig::new(1000, 500);
            assert_eq!(config.inclusion_fee, 1000);
            assert_eq!(config.ordering_fee, 500);
            assert!(config.target_proposer.is_none());
            assert_eq!(config.total_mcp_fees(), 1500);
            assert_eq!(
                config.config_mask(),
                config_mask::INCLUSION_FEE | config_mask::ORDERING_FEE
            );
        }

        #[test]
        fn test_config_with_target_proposer() {
            let proposer_index = 5u32;
            let config = McpTransactionConfig::with_target_proposer(100, 50, proposer_index);
            assert_eq!(config.target_proposer, Some(proposer_index));
            assert_eq!(
                config.config_mask(),
                config_mask::INCLUSION_FEE
                    | config_mask::ORDERING_FEE
                    | config_mask::TARGET_PROPOSER
            );
        }

        #[test]
        fn test_serialization_roundtrip() {
            let proposer_index = 12u32;
            let original = McpTransactionConfig::with_target_proposer(1000, 500, proposer_index);

            let mut buffer = Vec::new();
            let written = original.serialize(&mut buffer).unwrap();
            assert_eq!(written, original.serialized_size());

            let mut cursor = std::io::Cursor::new(&buffer);
            let deserialized = McpTransactionConfig::deserialize(&mut cursor).unwrap();

            assert_eq!(original, deserialized);
        }

        #[test]
        fn test_serialization_empty_config() {
            let config = McpTransactionConfig::default();
            let mut buffer = Vec::new();
            let written = config.serialize(&mut buffer).unwrap();
            assert_eq!(written, 4); // Only mask (u32)

            let mut cursor = std::io::Cursor::new(&buffer);
            let deserialized = McpTransactionConfig::deserialize(&mut cursor).unwrap();
            assert_eq!(config, deserialized);
        }

        #[test]
        fn test_serialization_partial_config() {
            // Only inclusion fee
            let config = McpTransactionConfig {
                inclusion_fee: 1000,
                ordering_fee: 0,
                compute_unit_limit: None,
                accounts_data_size_limit: None,
                heap_size: None,
                target_proposer: None,
            };
            let mut buffer = Vec::new();
            config.serialize(&mut buffer).unwrap();
            assert_eq!(buffer.len(), 8); // 4 mask + 4 inclusion_fee

            let mut cursor = std::io::Cursor::new(&buffer);
            let deserialized = McpTransactionConfig::deserialize(&mut cursor).unwrap();
            assert_eq!(config, deserialized);
        }

        #[test]
        fn test_mcp_fee_details() {
            let fees = McpFeeDetails::new(5000, 1000, 2000, 500);
            assert_eq!(fees.total_fee(), 8500);
            assert_eq!(fees.total_mcp_fees(), 2500);
            assert_eq!(fees.total_standard_fees(), 6000);
            assert_eq!(fees.fees_charged_regardless_of_execution(), 2000);
        }
    }
}
