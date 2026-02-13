//! MCP protocol constants and deterministic threshold helpers.
//!
//! These values are fixed for MCP v1 and must match
//! `docs/src/proposals/mcp-protocol-spec.md`.

/// Number of proposers selected per slot.
pub const NUM_PROPOSERS: usize = 16;
/// Number of relays selected per slot.
pub const NUM_RELAYS: usize = 200;

/// Number of data shreds in each MCP FEC block.
pub const DATA_SHREDS_PER_FEC_BLOCK: usize = 40;
/// Number of coding shreds in each MCP FEC block.
pub const CODING_SHREDS_PER_FEC_BLOCK: usize = 160;

/// Data bytes carried by each MCP shred.
pub const SHRED_DATA_BYTES: usize = 863;
/// QUIC control payload cap used by MCP control message codecs.
pub const MAX_QUIC_CONTROL_PAYLOAD_BYTES: usize = 512 * 1024;
/// Slot window retained for in-memory MCP consensus block caches.
pub const CONSENSUS_BLOCK_RETENTION_SLOTS: u64 = 512;

/// Threshold ratios in rational form to keep compile-time arithmetic exact.
pub const ATTESTATION_THRESHOLD_NUMERATOR: usize = 3;
pub const ATTESTATION_THRESHOLD_DENOMINATOR: usize = 5;
pub const INCLUSION_THRESHOLD_NUMERATOR: usize = 2;
pub const INCLUSION_THRESHOLD_DENOMINATOR: usize = 5;
pub const RECONSTRUCTION_THRESHOLD_NUMERATOR: usize = 1;
pub const RECONSTRUCTION_THRESHOLD_DENOMINATOR: usize = 5;

/// Required relay counts computed with ceil(threshold * NUM_RELAYS).
pub const REQUIRED_ATTESTATIONS: usize = ceil_threshold_count(
    ATTESTATION_THRESHOLD_NUMERATOR,
    ATTESTATION_THRESHOLD_DENOMINATOR,
    NUM_RELAYS,
);
pub const REQUIRED_INCLUSIONS: usize = ceil_threshold_count(
    INCLUSION_THRESHOLD_NUMERATOR,
    INCLUSION_THRESHOLD_DENOMINATOR,
    NUM_RELAYS,
);
pub const REQUIRED_RECONSTRUCTION: usize = ceil_threshold_count(
    RECONSTRUCTION_THRESHOLD_NUMERATOR,
    RECONSTRUCTION_THRESHOLD_DENOMINATOR,
    NUM_RELAYS,
);

/// Maximum serialized proposer payload bytes.
///
/// We use the lower of the two spec expressions:
/// - NUM_RELAYS * SHRED_DATA_BYTES
/// - DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES
pub const MAX_PROPOSER_PAYLOAD: usize =
    if NUM_RELAYS * SHRED_DATA_BYTES < DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES {
        NUM_RELAYS * SHRED_DATA_BYTES
    } else {
        DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES
    };

/// Compatibility alias retained for existing MCP helpers.
pub const MAX_PAYLOAD_BYTES: usize = MAX_PROPOSER_PAYLOAD;
/// Expected witness length for MCP Merkle proofs.
pub const MCP_WITNESS_LEN: usize = ceil_log2(NUM_RELAYS);

/// ceil((numerator / denominator) * total), integer-only.
pub const fn ceil_threshold_count(numerator: usize, denominator: usize, total: usize) -> usize {
    assert!(denominator != 0, "threshold denominator must be non-zero");
    // ceil(a / b) for integers is (a + b - 1) / b.
    let scaled = numerator * total;
    (scaled + denominator - 1) / denominator
}

/// ceil(log2(n)) for n >= 1.
pub const fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }

    let mut value = 1usize;
    let mut bits = 0usize;
    while value < n {
        value <<= 1;
        bits += 1;
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_sizes_match_num_relays() {
        assert_eq!(
            DATA_SHREDS_PER_FEC_BLOCK + CODING_SHREDS_PER_FEC_BLOCK,
            NUM_RELAYS
        );
    }

    #[test]
    fn test_threshold_counts() {
        assert_eq!(REQUIRED_ATTESTATIONS, 120);
        assert_eq!(REQUIRED_INCLUSIONS, 80);
        assert_eq!(REQUIRED_RECONSTRUCTION, 40);
        assert_eq!(REQUIRED_RECONSTRUCTION, DATA_SHREDS_PER_FEC_BLOCK);
    }

    #[test]
    fn test_payload_bound_uses_lower_of_spec_bounds() {
        let upper_spec_bound = NUM_RELAYS * SHRED_DATA_BYTES;
        let rs_capacity_bound = DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES;
        assert_eq!(MAX_PROPOSER_PAYLOAD, rs_capacity_bound);
        assert_eq!(MAX_PAYLOAD_BYTES, MAX_PROPOSER_PAYLOAD);
        assert!(MAX_PROPOSER_PAYLOAD <= upper_spec_bound);
    }

    #[test]
    fn test_witness_len_for_num_relays() {
        assert_eq!(MCP_WITNESS_LEN, 8);
    }

    #[test]
    #[should_panic(expected = "threshold denominator must be non-zero")]
    fn test_threshold_count_guard_zero_denominator() {
        let _ = ceil_threshold_count(3, 0, 200);
    }

    #[test]
    fn test_ceil_log2_edge_cases() {
        assert_eq!(ceil_log2(0), 0);
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
    }

    #[test]
    fn test_threshold_count_handles_ratio_above_one() {
        assert_eq!(ceil_threshold_count(6, 5, 200), 240);
    }
}
