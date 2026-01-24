//! MCP Reed-Solomon Erasure Coding
//!
//! This module implements the Reed-Solomon erasure coding for MCP shreds as defined in spec §4.4:
//! - N = 200 total shreds per proposer
//! - K = 40 data shreds
//! - N-K = 160 coding (parity) shreds
//!
//! With these parameters, the original payload can be reconstructed from any K shreds,
//! providing 5x redundancy.

use {
    crate::mcp::fec::{MCP_CODING_SHREDS_PER_FEC_BLOCK, MCP_DATA_SHREDS_PER_FEC_BLOCK},
    reed_solomon_erasure::{galois_8::Field, ReedSolomon},
    std::sync::Arc,
};

/// Number of data shards (K)
pub const K_DATA_SHARDS: usize = MCP_DATA_SHREDS_PER_FEC_BLOCK; // 40

/// Number of parity shards (N-K)
pub const K_PARITY_SHARDS: usize = MCP_CODING_SHREDS_PER_FEC_BLOCK; // 160

/// Total number of shards (N)
pub const N_TOTAL_SHARDS: usize = K_DATA_SHARDS + K_PARITY_SHARDS; // 200

/// MCP shred payload size (from spec)
pub const MCP_SHARD_SIZE: usize = 952;

/// Error type for MCP RS operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpRsError {
    /// Not enough shards to reconstruct
    InsufficientShards { available: usize, required: usize },
    /// Shard index out of range
    InvalidShardIndex(usize),
    /// Shard data wrong size
    InvalidShardSize { expected: usize, actual: usize },
    /// Reconstruction failed
    ReconstructionFailed(String),
    /// Encoding failed
    EncodingFailed(String),
    /// RS codec initialization failed
    CodecInitFailed(String),
}

impl std::fmt::Display for McpRsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientShards { available, required } => {
                write!(f, "Insufficient shards: have {}, need {}", available, required)
            }
            Self::InvalidShardIndex(idx) => {
                write!(f, "Invalid shard index: {} (max {})", idx, N_TOTAL_SHARDS - 1)
            }
            Self::InvalidShardSize { expected, actual } => {
                write!(f, "Invalid shard size: expected {}, got {}", expected, actual)
            }
            Self::ReconstructionFailed(msg) => {
                write!(f, "Reconstruction failed: {}", msg)
            }
            Self::EncodingFailed(msg) => {
                write!(f, "Encoding failed: {}", msg)
            }
            Self::CodecInitFailed(msg) => {
                write!(f, "Codec initialization failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for McpRsError {}

/// MCP Reed-Solomon codec with K=40, N=200 parameters
pub struct McpReedSolomon {
    codec: Arc<ReedSolomon<Field>>,
}

impl Default for McpReedSolomon {
    fn default() -> Self {
        Self::new().expect("Failed to create MCP RS codec")
    }
}

impl McpReedSolomon {
    /// Create a new MCP RS codec
    pub fn new() -> Result<Self, McpRsError> {
        let codec = ReedSolomon::new(K_DATA_SHARDS, K_PARITY_SHARDS)
            .map_err(|e| McpRsError::CodecInitFailed(e.to_string()))?;
        Ok(Self {
            codec: Arc::new(codec),
        })
    }

    /// Encode a payload into K data shards and N-K parity shards
    ///
    /// Input: payload bytes (up to K * MCP_SHARD_SIZE bytes)
    /// Output: N shards, each MCP_SHARD_SIZE bytes
    pub fn encode(&self, payload: &[u8]) -> Result<Vec<Vec<u8>>, McpRsError> {
        let max_payload = K_DATA_SHARDS * MCP_SHARD_SIZE;
        if payload.len() > max_payload {
            return Err(McpRsError::InvalidShardSize {
                expected: max_payload,
                actual: payload.len(),
            });
        }

        // Create data shards from payload (pad with zeros if needed)
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(N_TOTAL_SHARDS);

        // Data shards
        for i in 0..K_DATA_SHARDS {
            let start = i * MCP_SHARD_SIZE;
            let end = (start + MCP_SHARD_SIZE).min(payload.len());

            let mut shard = vec![0u8; MCP_SHARD_SIZE];
            if start < payload.len() {
                let len = end - start;
                shard[..len].copy_from_slice(&payload[start..end]);
            }
            shards.push(shard);
        }

        // Parity shards (initially empty, will be filled by encode)
        for _ in 0..K_PARITY_SHARDS {
            shards.push(vec![0u8; MCP_SHARD_SIZE]);
        }

        // Encode - this fills in the parity shards
        self.codec
            .encode(&mut shards)
            .map_err(|e| McpRsError::EncodingFailed(e.to_string()))?;

        Ok(shards)
    }

    /// Reconstruct the original payload from K or more shards
    ///
    /// Input: Vec of (shard_index, shard_data) pairs
    /// Output: Reconstructed payload
    pub fn reconstruct(
        &self,
        available_shards: &[(usize, Vec<u8>)],
    ) -> Result<Vec<u8>, McpRsError> {
        if available_shards.len() < K_DATA_SHARDS {
            return Err(McpRsError::InsufficientShards {
                available: available_shards.len(),
                required: K_DATA_SHARDS,
            });
        }

        // Validate shard indices and sizes
        for (idx, data) in available_shards {
            if *idx >= N_TOTAL_SHARDS {
                return Err(McpRsError::InvalidShardIndex(*idx));
            }
            if data.len() != MCP_SHARD_SIZE {
                return Err(McpRsError::InvalidShardSize {
                    expected: MCP_SHARD_SIZE,
                    actual: data.len(),
                });
            }
        }

        // Create shard array with Option<Vec<u8>> for reconstruction
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; N_TOTAL_SHARDS];
        for (idx, data) in available_shards {
            shards[*idx] = Some(data.clone());
        }

        // Reconstruct missing shards
        self.codec
            .reconstruct(&mut shards)
            .map_err(|e| McpRsError::ReconstructionFailed(e.to_string()))?;

        // Extract data shards to reconstruct payload
        let mut payload = Vec::with_capacity(K_DATA_SHARDS * MCP_SHARD_SIZE);
        for i in 0..K_DATA_SHARDS {
            if let Some(ref shard) = shards[i] {
                payload.extend_from_slice(shard);
            } else {
                // This shouldn't happen after successful reconstruction
                return Err(McpRsError::ReconstructionFailed(
                    format!("Data shard {} missing after reconstruction", i)
                ));
            }
        }

        Ok(payload)
    }

    /// Reconstruct only the data shards (more efficient if parity shards not needed)
    pub fn reconstruct_data(
        &self,
        available_shards: &[(usize, Vec<u8>)],
    ) -> Result<Vec<Vec<u8>>, McpRsError> {
        if available_shards.len() < K_DATA_SHARDS {
            return Err(McpRsError::InsufficientShards {
                available: available_shards.len(),
                required: K_DATA_SHARDS,
            });
        }

        // Validate shard indices and sizes
        for (idx, data) in available_shards {
            if *idx >= N_TOTAL_SHARDS {
                return Err(McpRsError::InvalidShardIndex(*idx));
            }
            if data.len() != MCP_SHARD_SIZE {
                return Err(McpRsError::InvalidShardSize {
                    expected: MCP_SHARD_SIZE,
                    actual: data.len(),
                });
            }
        }

        // Create shard array with Option<Vec<u8>>
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; N_TOTAL_SHARDS];
        for (idx, data) in available_shards {
            shards[*idx] = Some(data.clone());
        }

        // Reconstruct only data shards
        self.codec
            .reconstruct_data(&mut shards)
            .map_err(|e| McpRsError::ReconstructionFailed(e.to_string()))?;

        // Extract data shards
        let mut data_shards = Vec::with_capacity(K_DATA_SHARDS);
        for i in 0..K_DATA_SHARDS {
            if let Some(shard) = shards[i].take() {
                data_shards.push(shard);
            } else {
                return Err(McpRsError::ReconstructionFailed(
                    format!("Data shard {} missing after reconstruction", i)
                ));
            }
        }

        Ok(data_shards)
    }

    /// Verify that shards are consistent (re-encode data and compare parity)
    pub fn verify(&self, shards: &[Vec<u8>]) -> Result<bool, McpRsError> {
        if shards.len() != N_TOTAL_SHARDS {
            return Err(McpRsError::InvalidShardSize {
                expected: N_TOTAL_SHARDS,
                actual: shards.len(),
            });
        }

        for shard in shards.iter() {
            if shard.len() != MCP_SHARD_SIZE {
                return Err(McpRsError::InvalidShardSize {
                    expected: MCP_SHARD_SIZE,
                    actual: shard.len(),
                });
            }
        }

        // Create a mutable copy for verification
        let shard_refs: Vec<&[u8]> = shards.iter().map(|s| s.as_slice()).collect();

        Ok(self.codec.verify(&shard_refs).unwrap_or(false))
    }

    /// Get the number of data shards
    pub fn data_shard_count(&self) -> usize {
        K_DATA_SHARDS
    }

    /// Get the number of parity shards
    pub fn parity_shard_count(&self) -> usize {
        K_PARITY_SHARDS
    }

    /// Get the total number of shards
    pub fn total_shard_count(&self) -> usize {
        N_TOTAL_SHARDS
    }

    /// Get the shard size
    pub fn shard_size(&self) -> usize {
        MCP_SHARD_SIZE
    }
}

/// Helper function to select the K lowest indices for deterministic reconstruction
pub fn select_reconstruction_indices(available_indices: &[usize]) -> Vec<usize> {
    let mut sorted: Vec<usize> = available_indices.to_vec();
    sorted.sort();
    sorted.truncate(K_DATA_SHARDS);
    sorted
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_payload(size: usize) -> Vec<u8> {
        (0..size).map(|i| i as u8).collect()
    }

    #[test]
    fn test_codec_creation() {
        let codec = McpReedSolomon::new();
        assert!(codec.is_ok());

        let codec = codec.unwrap();
        assert_eq!(codec.data_shard_count(), K_DATA_SHARDS);
        assert_eq!(codec.parity_shard_count(), K_PARITY_SHARDS);
        assert_eq!(codec.total_shard_count(), N_TOTAL_SHARDS);
    }

    #[test]
    fn test_encode_small_payload() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(1000);

        let shards = codec.encode(&payload).unwrap();
        assert_eq!(shards.len(), N_TOTAL_SHARDS);

        // Each shard should be MCP_SHARD_SIZE
        for shard in &shards {
            assert_eq!(shard.len(), MCP_SHARD_SIZE);
        }

        // Verify the encoding
        assert!(codec.verify(&shards).unwrap());
    }

    #[test]
    fn test_encode_full_payload() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(K_DATA_SHARDS * MCP_SHARD_SIZE);

        let shards = codec.encode(&payload).unwrap();
        assert_eq!(shards.len(), N_TOTAL_SHARDS);

        // Verify the encoding
        assert!(codec.verify(&shards).unwrap());
    }

    #[test]
    fn test_encode_payload_too_large() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(K_DATA_SHARDS * MCP_SHARD_SIZE + 1);

        let result = codec.encode(&payload);
        assert!(matches!(result, Err(McpRsError::InvalidShardSize { .. })));
    }

    #[test]
    fn test_reconstruct_from_all_shards() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(10000);

        let shards = codec.encode(&payload).unwrap();

        // Reconstruct from all shards
        let available: Vec<(usize, Vec<u8>)> = shards
            .into_iter()
            .enumerate()
            .collect();

        let reconstructed = codec.reconstruct(&available).unwrap();

        // Reconstructed payload should start with original payload
        assert_eq!(&reconstructed[..payload.len()], &payload[..]);
    }

    #[test]
    fn test_reconstruct_from_data_shards_only() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(10000);

        let shards = codec.encode(&payload).unwrap();

        // Reconstruct from only data shards
        let available: Vec<(usize, Vec<u8>)> = shards[..K_DATA_SHARDS]
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.clone()))
            .collect();

        let reconstructed = codec.reconstruct(&available).unwrap();

        assert_eq!(&reconstructed[..payload.len()], &payload[..]);
    }

    #[test]
    fn test_reconstruct_from_parity_shards_only() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(10000);

        let shards = codec.encode(&payload).unwrap();

        // Reconstruct from only parity shards (first K of them)
        let available: Vec<(usize, Vec<u8>)> = shards[K_DATA_SHARDS..(K_DATA_SHARDS + K_DATA_SHARDS)]
            .iter()
            .enumerate()
            .map(|(i, s)| (K_DATA_SHARDS + i, s.clone()))
            .collect();

        let reconstructed = codec.reconstruct(&available).unwrap();

        assert_eq!(&reconstructed[..payload.len()], &payload[..]);
    }

    #[test]
    fn test_reconstruct_from_mixed_shards() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(10000);

        let shards = codec.encode(&payload).unwrap();

        // Use first 20 data shards and first 20 parity shards
        let mut available: Vec<(usize, Vec<u8>)> = shards[..20]
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.clone()))
            .collect();

        available.extend(
            shards[K_DATA_SHARDS..(K_DATA_SHARDS + 20)]
                .iter()
                .enumerate()
                .map(|(i, s)| (K_DATA_SHARDS + i, s.clone()))
        );

        let reconstructed = codec.reconstruct(&available).unwrap();

        assert_eq!(&reconstructed[..payload.len()], &payload[..]);
    }

    #[test]
    fn test_reconstruct_insufficient_shards() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(10000);

        let shards = codec.encode(&payload).unwrap();

        // Try to reconstruct with only K-1 shards
        let available: Vec<(usize, Vec<u8>)> = shards[..(K_DATA_SHARDS - 1)]
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.clone()))
            .collect();

        let result = codec.reconstruct(&available);
        assert!(matches!(result, Err(McpRsError::InsufficientShards { .. })));
    }

    #[test]
    fn test_reconstruct_data_only() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(K_DATA_SHARDS * MCP_SHARD_SIZE);

        let shards = codec.encode(&payload).unwrap();

        // Use K shards scattered across data and parity
        let available: Vec<(usize, Vec<u8>)> = vec![
            (0, shards[0].clone()),
            (5, shards[5].clone()),
            (10, shards[10].clone()),
            (15, shards[15].clone()),
            (20, shards[20].clone()),
            (25, shards[25].clone()),
            (30, shards[30].clone()),
            (35, shards[35].clone()),
            (K_DATA_SHARDS, shards[K_DATA_SHARDS].clone()),
            (K_DATA_SHARDS + 10, shards[K_DATA_SHARDS + 10].clone()),
            (K_DATA_SHARDS + 20, shards[K_DATA_SHARDS + 20].clone()),
            (K_DATA_SHARDS + 30, shards[K_DATA_SHARDS + 30].clone()),
            (K_DATA_SHARDS + 40, shards[K_DATA_SHARDS + 40].clone()),
            (K_DATA_SHARDS + 50, shards[K_DATA_SHARDS + 50].clone()),
            (K_DATA_SHARDS + 60, shards[K_DATA_SHARDS + 60].clone()),
            (K_DATA_SHARDS + 70, shards[K_DATA_SHARDS + 70].clone()),
            (K_DATA_SHARDS + 80, shards[K_DATA_SHARDS + 80].clone()),
            (K_DATA_SHARDS + 90, shards[K_DATA_SHARDS + 90].clone()),
            (K_DATA_SHARDS + 100, shards[K_DATA_SHARDS + 100].clone()),
            (K_DATA_SHARDS + 110, shards[K_DATA_SHARDS + 110].clone()),
            (K_DATA_SHARDS + 120, shards[K_DATA_SHARDS + 120].clone()),
            (K_DATA_SHARDS + 130, shards[K_DATA_SHARDS + 130].clone()),
            (K_DATA_SHARDS + 140, shards[K_DATA_SHARDS + 140].clone()),
            (K_DATA_SHARDS + 150, shards[K_DATA_SHARDS + 150].clone()),
            // Fill rest from data shards we haven't used
            (1, shards[1].clone()),
            (2, shards[2].clone()),
            (3, shards[3].clone()),
            (4, shards[4].clone()),
            (6, shards[6].clone()),
            (7, shards[7].clone()),
            (8, shards[8].clone()),
            (9, shards[9].clone()),
            (11, shards[11].clone()),
            (12, shards[12].clone()),
            (13, shards[13].clone()),
            (14, shards[14].clone()),
            (16, shards[16].clone()),
            (17, shards[17].clone()),
            (18, shards[18].clone()),
            (19, shards[19].clone()),
        ];

        let data_shards = codec.reconstruct_data(&available).unwrap();
        assert_eq!(data_shards.len(), K_DATA_SHARDS);

        // Concatenate and compare
        let mut reconstructed = Vec::new();
        for shard in data_shards {
            reconstructed.extend_from_slice(&shard);
        }

        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn test_select_reconstruction_indices() {
        let available = vec![150, 10, 5, 100, 0, 199, 50, 25, 75, 199];
        let selected = select_reconstruction_indices(&available);

        // Should select first K (40) unique sorted indices
        assert_eq!(selected.len(), available.len().min(K_DATA_SHARDS));
        assert_eq!(selected[0], 0);
        assert_eq!(selected[1], 5);
        assert_eq!(selected[2], 10);
    }

    #[test]
    fn test_verify_valid_shards() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(10000);

        let shards = codec.encode(&payload).unwrap();
        assert!(codec.verify(&shards).unwrap());
    }

    #[test]
    fn test_verify_corrupted_shards() {
        let codec = McpReedSolomon::default();
        let payload = make_test_payload(10000);

        let mut shards = codec.encode(&payload).unwrap();

        // Corrupt a data shard
        shards[0][0] ^= 0xFF;

        // Verification should fail
        assert!(!codec.verify(&shards).unwrap());
    }
}
