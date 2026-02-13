use {
    crate::{mcp, mcp_merkle},
    reed_solomon_erasure::galois_8::ReedSolomon,
    std::sync::OnceLock,
};

pub const MCP_DATA_SHREDS_PER_FEC_BLOCK: usize = mcp::DATA_SHREDS_PER_FEC_BLOCK;
pub const MCP_CODING_SHREDS_PER_FEC_BLOCK: usize = mcp::CODING_SHREDS_PER_FEC_BLOCK;
pub const MCP_NUM_RELAYS: usize = mcp::NUM_RELAYS;
pub const MCP_SHRED_DATA_BYTES: usize = mcp::SHRED_DATA_BYTES;
pub const MCP_MAX_PAYLOAD_BYTES: usize = mcp::MAX_PAYLOAD_BYTES;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum McpErasureError {
    #[error("payload exceeds MCP max payload bytes: {0}")]
    PayloadTooLarge(usize),
    #[error("invalid shard layout: expected {expected}, got {actual}")]
    InvalidShardLayout { expected: usize, actual: usize },
    #[error("invalid payload length for decode: {0}")]
    InvalidPayloadLength(usize),
    #[error("insufficient shards for reconstruction: have {present}, need at least {required}")]
    InsufficientShards { present: usize, required: usize },
    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),
    #[error("merkle error: {0}")]
    Merkle(#[from] mcp_merkle::McpMerkleError),
}

pub fn encode_fec_set(payload: &[u8]) -> Result<Vec<[u8; MCP_SHRED_DATA_BYTES]>, McpErasureError> {
    if payload.len() > MCP_MAX_PAYLOAD_BYTES {
        return Err(McpErasureError::PayloadTooLarge(payload.len()));
    }

    let mut shards: Vec<Vec<u8>> = payload_to_data_shards(payload)
        .into_iter()
        .map(Vec::from)
        .collect();
    shards.extend(std::iter::repeat_n(
        vec![0u8; MCP_SHRED_DATA_BYTES],
        MCP_CODING_SHREDS_PER_FEC_BLOCK,
    ));

    reed_solomon()?
        .encode(&mut shards)
        .map_err(|err| McpErasureError::ReedSolomon(err.to_string()))?;

    Ok(shards
        .into_iter()
        .map(|shard| {
            let mut out = [0u8; MCP_SHRED_DATA_BYTES];
            out.copy_from_slice(&shard);
            out
        })
        .collect())
}

pub fn recover_data_shards(
    shards: &mut [Option<[u8; MCP_SHRED_DATA_BYTES]>],
) -> Result<Vec<[u8; MCP_SHRED_DATA_BYTES]>, McpErasureError> {
    if shards.len() != MCP_NUM_RELAYS {
        return Err(McpErasureError::InvalidShardLayout {
            expected: MCP_NUM_RELAYS,
            actual: shards.len(),
        });
    }

    let present = shards.iter().filter(|shard| shard.is_some()).count();
    if present < MCP_DATA_SHREDS_PER_FEC_BLOCK {
        return Err(McpErasureError::InsufficientShards {
            present,
            required: MCP_DATA_SHREDS_PER_FEC_BLOCK,
        });
    }

    let mut rs_shards: Vec<Option<Vec<u8>>> = shards
        .iter()
        .map(|shard| shard.as_ref().map(|bytes| bytes.to_vec()))
        .collect();

    reed_solomon()?
        .reconstruct(&mut rs_shards)
        .map_err(|err| McpErasureError::ReedSolomon(err.to_string()))?;

    let mut out = Vec::with_capacity(MCP_DATA_SHREDS_PER_FEC_BLOCK);
    for shard in rs_shards
        .iter()
        .take(MCP_DATA_SHREDS_PER_FEC_BLOCK)
        .map(|shard| shard.as_ref())
    {
        let Some(shard) = shard else {
            return Err(McpErasureError::InsufficientShards {
                present,
                required: MCP_DATA_SHREDS_PER_FEC_BLOCK,
            });
        };
        let mut bytes = [0u8; MCP_SHRED_DATA_BYTES];
        bytes.copy_from_slice(shard);
        out.push(bytes);
    }

    // Restore caller-provided shards with reconstructed output.
    for (index, shard) in rs_shards.into_iter().enumerate() {
        shards[index] = shard.map(|bytes| {
            let mut out = [0u8; MCP_SHRED_DATA_BYTES];
            out.copy_from_slice(&bytes);
            out
        });
    }

    Ok(out)
}

pub fn decode_payload(
    shards: &mut [Option<[u8; MCP_SHRED_DATA_BYTES]>],
    payload_len: usize,
) -> Result<Vec<u8>, McpErasureError> {
    if payload_len > MCP_MAX_PAYLOAD_BYTES {
        return Err(McpErasureError::InvalidPayloadLength(payload_len));
    }

    let data_shards = recover_data_shards(shards)?;
    let mut payload = Vec::with_capacity(MCP_MAX_PAYLOAD_BYTES);
    for shard in data_shards {
        payload.extend_from_slice(&shard);
    }
    payload.truncate(payload_len);
    Ok(payload)
}

pub fn commitment_root(
    slot: u64,
    proposer_index: u32,
    shreds: &[[u8; MCP_SHRED_DATA_BYTES]],
) -> Result<[u8; 32], McpErasureError> {
    Ok(mcp_merkle::commitment_root(slot, proposer_index, shreds)?)
}

fn payload_to_data_shards(payload: &[u8]) -> Vec<[u8; MCP_SHRED_DATA_BYTES]> {
    let mut shards = vec![[0u8; MCP_SHRED_DATA_BYTES]; MCP_DATA_SHREDS_PER_FEC_BLOCK];
    for (index, chunk) in payload.chunks(MCP_SHRED_DATA_BYTES).enumerate() {
        shards[index][..chunk.len()].copy_from_slice(chunk);
    }
    shards
}

fn reed_solomon() -> Result<&'static ReedSolomon, McpErasureError> {
    static REED_SOLOMON: OnceLock<Result<ReedSolomon, String>> = OnceLock::new();
    match REED_SOLOMON.get_or_init(|| {
        ReedSolomon::new(
            MCP_DATA_SHREDS_PER_FEC_BLOCK,
            MCP_CODING_SHREDS_PER_FEC_BLOCK,
        )
        .map_err(|err| err.to_string())
    }) {
        Ok(reed_solomon) => Ok(reed_solomon),
        Err(err) => Err(McpErasureError::ReedSolomon(err.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_fec_set_emits_exactly_200_shreds() {
        let payload = vec![42u8; MCP_MAX_PAYLOAD_BYTES];
        let shreds = encode_fec_set(&payload).unwrap();
        assert_eq!(shreds.len(), MCP_NUM_RELAYS);
        assert!(shreds
            .iter()
            .all(|shred| shred.len() == MCP_SHRED_DATA_BYTES));
    }

    #[test]
    fn test_reconstruction_succeeds_with_40_shreds() {
        let payload: Vec<u8> = (0..12_345).map(|i| (i % 251) as u8).collect();
        let encoded = encode_fec_set(&payload).unwrap();

        let mut shards = vec![None; MCP_NUM_RELAYS];
        // Keep 10 data shards and 30 coding shards; total available == 40.
        for (dst, src) in (0..10).chain(80..110).zip((0..10).chain(80..110)) {
            shards[dst] = Some(encoded[src]);
        }

        let decoded = decode_payload(&mut shards, payload.len()).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_payload_too_large_is_rejected() {
        let payload = vec![0u8; MCP_MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            encode_fec_set(&payload).unwrap_err(),
            McpErasureError::PayloadTooLarge(MCP_MAX_PAYLOAD_BYTES + 1),
        );
    }

    #[test]
    fn test_recover_fails_with_insufficient_shards() {
        let payload = vec![7u8; 1000];
        let encoded = encode_fec_set(&payload).unwrap();

        let mut shards = vec![None; MCP_NUM_RELAYS];
        for i in 0..39 {
            shards[i] = Some(encoded[i]);
        }

        assert_eq!(
            recover_data_shards(&mut shards).unwrap_err(),
            McpErasureError::InsufficientShards {
                present: 39,
                required: MCP_DATA_SHREDS_PER_FEC_BLOCK,
            },
        );
    }

    #[test]
    fn test_commitment_root_is_stable() {
        let payload = vec![1u8; 1024];
        let shreds = encode_fec_set(&payload).unwrap();

        let root_1 = commitment_root(99, 3, &shreds).unwrap();
        let root_2 = commitment_root(99, 3, &shreds).unwrap();
        assert_eq!(root_1, root_2);

        let mut modified = shreds.clone();
        modified[0][0] ^= 1;
        let root_3 = commitment_root(99, 3, &modified).unwrap();
        assert_ne!(root_1, root_3);
    }

    #[test]
    fn test_decode_payload_len_zero_returns_empty_payload() {
        let payload = vec![5u8; 2048];
        let encoded = encode_fec_set(&payload).unwrap();
        let mut shards: Vec<Option<[u8; MCP_SHRED_DATA_BYTES]>> =
            encoded.into_iter().map(Some).collect();
        let decoded = decode_payload(&mut shards, 0).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_reconstruction_from_coding_shards_only() {
        let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        let encoded = encode_fec_set(&payload).unwrap();
        let mut shards = vec![None; MCP_NUM_RELAYS];
        for src in MCP_DATA_SHREDS_PER_FEC_BLOCK..(2 * MCP_DATA_SHREDS_PER_FEC_BLOCK) {
            shards[src] = Some(encoded[src]);
        }
        let decoded = decode_payload(&mut shards, payload.len()).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_reconstruction_from_data_shards_only() {
        let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        let encoded = encode_fec_set(&payload).unwrap();
        let mut shards = vec![None; MCP_NUM_RELAYS];
        for src in 0..MCP_DATA_SHREDS_PER_FEC_BLOCK {
            shards[src] = Some(encoded[src]);
        }
        let decoded = decode_payload(&mut shards, payload.len()).unwrap();
        assert_eq!(decoded, payload);
    }
}
