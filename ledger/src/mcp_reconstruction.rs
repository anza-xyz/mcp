use {
    crate::{mcp, mcp_merkle},
    agave_transaction_view::mcp_payload::{McpPayload, McpPayloadParseError},
    reed_solomon_erasure::galois_8::ReedSolomon,
};

pub const MCP_RECON_DATA_SHREDS: usize = mcp::DATA_SHREDS_PER_FEC_BLOCK;
pub const MCP_RECON_CODING_SHREDS: usize = mcp::CODING_SHREDS_PER_FEC_BLOCK;
pub const MCP_RECON_NUM_SHREDS: usize = MCP_RECON_DATA_SHREDS + MCP_RECON_CODING_SHREDS;
pub const MCP_RECON_SHRED_BYTES: usize = mcp::SHRED_DATA_BYTES;
pub const MCP_RECON_MAX_PAYLOAD_BYTES: usize = MCP_RECON_DATA_SHREDS * MCP_RECON_SHRED_BYTES;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum McpReconstructionError {
    #[error("invalid payload length: {0}")]
    InvalidPayloadLength(usize),
    #[error("invalid shred index: {0}")]
    InvalidShredIndex(usize),
    #[error("invalid shard layout: expected {expected}, got {actual}")]
    InvalidShardLayout { expected: usize, actual: usize },
    #[error("insufficient shards: present {present}, required {required}")]
    InsufficientShards { present: usize, required: usize },
    #[error("conflicting shard for index {0}")]
    ConflictingShard(usize),
    #[error("commitment mismatch")]
    CommitmentMismatch,
    #[error("reconstruction state is poisoned after commitment mismatch")]
    PoisonedState,
    #[error("commitment root requires at least one shred")]
    EmptyShredSet,
    #[error("too many shreds for u32 indices: {0}")]
    TooManyShreds(usize),
    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),
    #[error("invalid reconstructed MCP payload: {0:?}")]
    InvalidPayload(McpPayloadParseError),
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpReconstructionAttempt {
    Pending { present: usize, required: usize },
    Reconstructed(Vec<u8>),
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpReconstructionState {
    slot: u64,
    proposer_index: u32,
    payload_len: usize,
    expected_commitment: [u8; 32],
    shards: Vec<Option<[u8; MCP_RECON_SHRED_BYTES]>>,
    poisoned: bool,
}

#[cfg(test)]
impl McpReconstructionState {
    pub fn new(
        slot: u64,
        proposer_index: u32,
        payload_len: usize,
        expected_commitment: [u8; 32],
    ) -> Result<Self, McpReconstructionError> {
        if payload_len > MCP_RECON_MAX_PAYLOAD_BYTES {
            return Err(McpReconstructionError::InvalidPayloadLength(payload_len));
        }
        Ok(Self {
            slot,
            proposer_index,
            payload_len,
            expected_commitment,
            shards: vec![None; MCP_RECON_NUM_SHREDS],
            poisoned: false,
        })
    }

    pub fn present_shards(&self) -> usize {
        self.shards.iter().filter(|shard| shard.is_some()).count()
    }

    pub fn insert_shard(
        &mut self,
        shred_index: usize,
        shred_data: [u8; MCP_RECON_SHRED_BYTES],
    ) -> Result<(), McpReconstructionError> {
        if self.poisoned {
            // A commitment mismatch indicates that at least one prior shard was invalid.
            // Clear in-memory shard state and restart accumulation on the next insert.
            self.shards.iter_mut().for_each(|shard| *shard = None);
            self.poisoned = false;
        }
        if shred_index >= MCP_RECON_NUM_SHREDS {
            return Err(McpReconstructionError::InvalidShredIndex(shred_index));
        }

        if let Some(existing) = self.shards[shred_index] {
            if existing == shred_data {
                return Ok(());
            }
            return Err(McpReconstructionError::ConflictingShard(shred_index));
        }

        self.shards[shred_index] = Some(shred_data);
        Ok(())
    }

    pub fn try_reconstruct(&mut self) -> Result<McpReconstructionAttempt, McpReconstructionError> {
        if self.poisoned {
            return Err(McpReconstructionError::PoisonedState);
        }
        let present = self.present_shards();
        if present < MCP_RECON_DATA_SHREDS {
            return Ok(McpReconstructionAttempt::Pending {
                present,
                required: MCP_RECON_DATA_SHREDS,
            });
        }

        let payload = match reconstruct_payload(
            self.slot,
            self.proposer_index,
            self.payload_len,
            self.expected_commitment,
            &mut self.shards,
        ) {
            Ok(payload) => payload,
            Err(McpReconstructionError::CommitmentMismatch) => {
                self.poisoned = true;
                return Err(McpReconstructionError::CommitmentMismatch);
            }
            Err(err) => return Err(err),
        };
        Ok(McpReconstructionAttempt::Reconstructed(payload))
    }

    pub fn insert_and_try_reconstruct(
        &mut self,
        shred_index: usize,
        shred_data: [u8; MCP_RECON_SHRED_BYTES],
    ) -> Result<McpReconstructionAttempt, McpReconstructionError> {
        self.insert_shard(shred_index, shred_data)?;
        self.try_reconstruct()
    }
}

pub fn reconstruct_payload(
    slot: u64,
    proposer_index: u32,
    payload_len: usize,
    expected_commitment: [u8; 32],
    shards: &mut [Option<[u8; MCP_RECON_SHRED_BYTES]>],
) -> Result<Vec<u8>, McpReconstructionError> {
    if payload_len > MCP_RECON_MAX_PAYLOAD_BYTES {
        return Err(McpReconstructionError::InvalidPayloadLength(payload_len));
    }
    if shards.len() != MCP_RECON_NUM_SHREDS {
        return Err(McpReconstructionError::InvalidShardLayout {
            expected: MCP_RECON_NUM_SHREDS,
            actual: shards.len(),
        });
    }

    let present = shards.iter().filter(|shard| shard.is_some()).count();
    if present < MCP_RECON_DATA_SHREDS {
        return Err(McpReconstructionError::InsufficientShards {
            present,
            required: MCP_RECON_DATA_SHREDS,
        });
    }

    let mut rs_shards: Vec<Option<Vec<u8>>> =
        shards.iter().map(|shard| shard.map(Vec::from)).collect();
    ReedSolomon::new(MCP_RECON_DATA_SHREDS, MCP_RECON_CODING_SHREDS)
        .map_err(|err| McpReconstructionError::ReedSolomon(err.to_string()))?
        .reconstruct(&mut rs_shards)
        .map_err(|err| McpReconstructionError::ReedSolomon(err.to_string()))?;

    let mut rebuilt = Vec::with_capacity(MCP_RECON_NUM_SHREDS);
    for shard in &rs_shards {
        let Some(shard) = shard else {
            return Err(McpReconstructionError::InsufficientShards {
                present,
                required: MCP_RECON_DATA_SHREDS,
            });
        };
        let mut bytes = [0u8; MCP_RECON_SHRED_BYTES];
        bytes.copy_from_slice(shard);
        rebuilt.push(bytes);
    }

    let computed = commitment_root(slot, proposer_index, &rebuilt)?;
    if computed != expected_commitment {
        return Err(McpReconstructionError::CommitmentMismatch);
    }

    // Fill in missing caller shards after successful reconstruction.
    for (index, shard) in rebuilt.iter().copied().enumerate() {
        shards[index].get_or_insert(shard);
    }

    let mut payload = Vec::with_capacity(MCP_RECON_MAX_PAYLOAD_BYTES);
    for shard in rebuilt.into_iter().take(MCP_RECON_DATA_SHREDS) {
        payload.extend_from_slice(&shard);
    }
    payload.truncate(payload_len);
    Ok(payload)
}

pub fn commitment_root(
    slot: u64,
    proposer_index: u32,
    shreds: &[[u8; MCP_RECON_SHRED_BYTES]],
) -> Result<[u8; 32], McpReconstructionError> {
    mcp_merkle::commitment_root(slot, proposer_index, shreds).map_err(map_merkle_error)
}

fn map_merkle_error(err: mcp_merkle::McpMerkleError) -> McpReconstructionError {
    match err {
        mcp_merkle::McpMerkleError::EmptyShredSet => McpReconstructionError::EmptyShredSet,
        mcp_merkle::McpMerkleError::TooManyShreds(count) => {
            McpReconstructionError::TooManyShreds(count)
        }
        mcp_merkle::McpMerkleError::InvalidLeafIndex { index, .. } => {
            McpReconstructionError::InvalidShredIndex(index)
        }
        mcp_merkle::McpMerkleError::InvalidWitnessLength { .. } => {
            unreachable!("reconstruction commitment_root does not verify witnesses")
        }
    }
}

pub fn decode_reconstructed_payload(payload: &[u8]) -> Result<McpPayload, McpReconstructionError> {
    McpPayload::from_bytes(payload).map_err(McpReconstructionError::InvalidPayload)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        agave_transaction_view::{
            mcp_payload::McpPayloadTransactionFormat,
            mcp_transaction::{
                InstructionHeader, InstructionPayload, LegacyHeader, McpTransaction,
                MCP_TX_LATEST_VERSION,
            },
        },
        solana_pubkey::Pubkey,
        solana_signature::Signature,
    };

    fn encode_payload(payload: &[u8]) -> Vec<[u8; MCP_RECON_SHRED_BYTES]> {
        let mut data = vec![[0u8; MCP_RECON_SHRED_BYTES]; MCP_RECON_DATA_SHREDS];
        for (i, chunk) in payload.chunks(MCP_RECON_SHRED_BYTES).enumerate() {
            data[i][..chunk.len()].copy_from_slice(chunk);
        }

        let mut shards: Vec<Vec<u8>> = data.iter().copied().map(Vec::from).collect();
        shards.extend(std::iter::repeat_n(
            vec![0u8; MCP_RECON_SHRED_BYTES],
            MCP_RECON_CODING_SHREDS,
        ));

        ReedSolomon::new(MCP_RECON_DATA_SHREDS, MCP_RECON_CODING_SHREDS)
            .unwrap()
            .encode(&mut shards)
            .unwrap();

        shards
            .into_iter()
            .map(|shard| {
                let mut out = [0u8; MCP_RECON_SHRED_BYTES];
                out.copy_from_slice(&shard);
                out
            })
            .collect()
    }

    fn sample_mcp_transaction() -> McpTransaction {
        McpTransaction {
            version: MCP_TX_LATEST_VERSION,
            legacy_header: LegacyHeader {
                num_required_signatures: 1,
                num_readonly_signed: 0,
                num_readonly_unsigned: 0,
            },
            transaction_config_mask: 0,
            lifetime_specifier: [1u8; 32],
            addresses: vec![Pubkey::new_unique()],
            config_values: vec![],
            instruction_headers: vec![InstructionHeader {
                program_account_index: 0,
                num_instruction_accounts: 1,
                num_instruction_data_bytes: 0,
            }],
            instruction_payloads: vec![InstructionPayload {
                account_indexes: vec![0],
                instruction_data: vec![],
            }],
            signatures: vec![Signature::from([7u8; 64])],
        }
    }

    fn encode_framed_payload(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for tx in entries {
            out.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            out.extend_from_slice(tx);
        }
        out
    }

    #[test]
    fn test_reconstruct_valid_payload() {
        let payload: Vec<u8> = (0..20_000).map(|i| (i % 256) as u8).collect();
        let shreds = encode_payload(&payload);
        let root = commitment_root(9, 2, &shreds).unwrap();

        let mut sparse = vec![None; MCP_RECON_NUM_SHREDS];
        for i in (0..20).chain(120..140) {
            sparse[i] = Some(shreds[i]);
        }

        let decoded = reconstruct_payload(9, 2, payload.len(), root, &mut sparse).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_reconstruct_rejects_commitment_mismatch() {
        let payload: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let mut shreds = encode_payload(&payload);
        let root = commitment_root(9, 2, &shreds).unwrap();
        shreds[3][0] ^= 1;

        let mut sparse = vec![None; MCP_RECON_NUM_SHREDS];
        for i in 0..MCP_RECON_DATA_SHREDS {
            sparse[i] = Some(shreds[i]);
        }

        assert_eq!(
            reconstruct_payload(9, 2, payload.len(), root, &mut sparse).unwrap_err(),
            McpReconstructionError::CommitmentMismatch
        );
    }

    #[test]
    fn test_reconstruct_rejects_insufficient_shards() {
        let payload = vec![7u8; 500];
        let shreds = encode_payload(&payload);
        let root = commitment_root(1, 0, &shreds).unwrap();

        let mut sparse = vec![None; MCP_RECON_NUM_SHREDS];
        for i in 0..39 {
            sparse[i] = Some(shreds[i]);
        }

        assert_eq!(
            reconstruct_payload(1, 0, payload.len(), root, &mut sparse).unwrap_err(),
            McpReconstructionError::InsufficientShards {
                present: 39,
                required: MCP_RECON_DATA_SHREDS
            }
        );
    }

    #[test]
    fn test_state_reconstructs_once_threshold_is_met() {
        let payload: Vec<u8> = (0..9_000).map(|i| (i % 256) as u8).collect();
        let shreds = encode_payload(&payload);
        let root = commitment_root(12, 4, &shreds).unwrap();
        let mut state = McpReconstructionState::new(12, 4, payload.len(), root).unwrap();

        for i in 0..(MCP_RECON_DATA_SHREDS - 1) {
            let attempt = state.insert_and_try_reconstruct(i, shreds[i]).unwrap();
            assert_eq!(
                attempt,
                McpReconstructionAttempt::Pending {
                    present: i + 1,
                    required: MCP_RECON_DATA_SHREDS
                }
            );
        }

        let attempt = state
            .insert_and_try_reconstruct(
                MCP_RECON_DATA_SHREDS - 1,
                shreds[MCP_RECON_DATA_SHREDS - 1],
            )
            .unwrap();
        assert_eq!(attempt, McpReconstructionAttempt::Reconstructed(payload));
    }

    #[test]
    fn test_state_rejects_conflicting_shard_at_same_index() {
        let payload: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let mut shreds = encode_payload(&payload);
        let root = commitment_root(7, 1, &shreds).unwrap();
        let mut state = McpReconstructionState::new(7, 1, payload.len(), root).unwrap();

        state.insert_shard(3, shreds[3]).unwrap();
        shreds[3][0] ^= 1;
        assert_eq!(
            state.insert_shard(3, shreds[3]).unwrap_err(),
            McpReconstructionError::ConflictingShard(3)
        );
    }

    #[test]
    fn test_state_rejects_out_of_bounds_shard_index() {
        let payload = vec![1u8; 64];
        let shreds = encode_payload(&payload);
        let root = commitment_root(1, 1, &shreds).unwrap();
        let mut state = McpReconstructionState::new(1, 1, payload.len(), root).unwrap();
        assert_eq!(
            state
                .insert_shard(MCP_RECON_NUM_SHREDS, shreds[0])
                .unwrap_err(),
            McpReconstructionError::InvalidShredIndex(MCP_RECON_NUM_SHREDS)
        );
    }

    #[test]
    fn test_commitment_mismatch_does_not_destroy_state() {
        let payload: Vec<u8> = (0..8_000).map(|i| (i % 256) as u8).collect();
        let mut shreds = encode_payload(&payload);
        let root = commitment_root(3, 5, &shreds).unwrap();
        shreds[0][0] ^= 1;

        let mut sparse = vec![None; MCP_RECON_NUM_SHREDS];
        for i in 0..MCP_RECON_DATA_SHREDS {
            sparse[i] = Some(shreds[i]);
        }
        let snapshot = sparse.clone();

        assert_eq!(
            reconstruct_payload(3, 5, payload.len(), root, &mut sparse).unwrap_err(),
            McpReconstructionError::CommitmentMismatch
        );
        assert_eq!(sparse, snapshot);
    }

    #[test]
    fn test_state_can_reconstruct_again_after_success() {
        let payload: Vec<u8> = (0..4_000).map(|i| (i % 256) as u8).collect();
        let shreds = encode_payload(&payload);
        let root = commitment_root(22, 1, &shreds).unwrap();
        let mut state = McpReconstructionState::new(22, 1, payload.len(), root).unwrap();
        for i in 0..MCP_RECON_DATA_SHREDS {
            state.insert_shard(i, shreds[i]).unwrap();
        }

        let first = state.try_reconstruct().unwrap();
        let second = state.try_reconstruct().unwrap();
        assert_eq!(
            first,
            McpReconstructionAttempt::Reconstructed(payload.clone())
        );
        assert_eq!(second, McpReconstructionAttempt::Reconstructed(payload));
    }

    #[test]
    fn test_state_is_poisoned_after_commitment_mismatch() {
        let payload: Vec<u8> = (0..4_000).map(|i| (i % 256) as u8).collect();
        let valid_shreds = encode_payload(&payload);
        let mut invalid_shreds = valid_shreds.clone();
        let root = commitment_root(31, 2, &valid_shreds).unwrap();
        invalid_shreds[0][0] ^= 1;

        let mut state = McpReconstructionState::new(31, 2, payload.len(), root).unwrap();
        for i in 0..MCP_RECON_DATA_SHREDS {
            state.insert_shard(i, invalid_shreds[i]).unwrap();
        }

        assert_eq!(
            state.try_reconstruct().unwrap_err(),
            McpReconstructionError::CommitmentMismatch
        );
        assert_eq!(
            state.try_reconstruct().unwrap_err(),
            McpReconstructionError::PoisonedState
        );

        // First insert after poisoning clears stale shards and restarts accumulation.
        state.insert_shard(0, valid_shreds[0]).unwrap();
        assert_eq!(state.present_shards(), 1);
        for i in 1..MCP_RECON_DATA_SHREDS {
            state.insert_shard(i, valid_shreds[i]).unwrap();
        }
        assert_eq!(
            state.try_reconstruct().unwrap(),
            McpReconstructionAttempt::Reconstructed(payload)
        );
    }

    #[test]
    fn test_commitment_root_rejects_empty_input() {
        assert_eq!(
            commitment_root(1, 1, &[]).unwrap_err(),
            McpReconstructionError::EmptyShredSet
        );
    }

    #[test]
    fn test_decode_reconstructed_payload_accepts_latest_and_legacy_transactions() {
        let tx = sample_mcp_transaction();
        let latest = tx.to_bytes();
        let legacy = latest[1..].to_vec();
        let payload = encode_framed_payload(&[latest, legacy]);

        let parsed = decode_reconstructed_payload(&payload).unwrap();
        assert_eq!(parsed.transactions.len(), 2);
        assert_eq!(
            parsed.transactions[0].format,
            McpPayloadTransactionFormat::Latest
        );
        assert_eq!(
            parsed.transactions[1].format,
            McpPayloadTransactionFormat::Legacy
        );
    }

    #[test]
    fn test_decode_reconstructed_payload_rejects_invalid_payload() {
        let payload = vec![0u8, 1u8, 2u8, 3u8];
        assert!(matches!(
            decode_reconstructed_payload(&payload),
            Err(McpReconstructionError::InvalidPayload(_))
        ));
    }
}
