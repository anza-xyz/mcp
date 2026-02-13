use crate::{mcp, mcp_erasure, mcp_merkle};

pub use mcp_erasure::{
    McpErasureError, MCP_CODING_SHREDS_PER_FEC_BLOCK, MCP_DATA_SHREDS_PER_FEC_BLOCK,
    MCP_MAX_PAYLOAD_BYTES, MCP_NUM_RELAYS, MCP_SHRED_DATA_BYTES,
};

/// Encode payload bytes into fixed-size MCP data+coding shards.
pub fn encode_payload(payload: &[u8]) -> Result<Vec<[u8; MCP_SHRED_DATA_BYTES]>, McpErasureError> {
    mcp_erasure::encode_fec_set(payload)
}

/// Recover missing shards in-place and return reconstructed data shards.
pub fn recover_data_shards(
    shards: &mut [Option<[u8; MCP_SHRED_DATA_BYTES]>],
) -> Result<Vec<[u8; MCP_SHRED_DATA_BYTES]>, McpErasureError> {
    mcp_erasure::recover_data_shards(shards)
}

/// Decode payload bytes from available shards.
pub fn decode_payload(
    shards: &mut [Option<[u8; MCP_SHRED_DATA_BYTES]>],
    payload_len: usize,
) -> Result<Vec<u8>, McpErasureError> {
    mcp_erasure::decode_payload(shards, payload_len)
}

/// Derive commitment root and witnesses for all relay shards.
pub fn commitment_and_witnesses(
    slot: u64,
    proposer_index: u32,
    shreds: &[[u8; MCP_SHRED_DATA_BYTES]],
) -> Result<([u8; 32], Vec<[[u8; 32]; mcp::MCP_WITNESS_LEN]>), mcp_merkle::McpMerkleError> {
    mcp_merkle::commitment_and_witnesses::<MCP_SHRED_DATA_BYTES, { mcp::MCP_WITNESS_LEN }>(
        slot,
        proposer_index,
        shreds,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shredder_round_trip() {
        let payload = vec![42u8; 1024];
        let encoded = encode_payload(&payload).unwrap();
        let mut shards = encoded
            .into_iter()
            .map(Some)
            .collect::<Vec<Option<[u8; MCP_SHRED_DATA_BYTES]>>>();
        let decoded = decode_payload(&mut shards, payload.len()).unwrap();
        assert_eq!(decoded, payload);
    }
}
