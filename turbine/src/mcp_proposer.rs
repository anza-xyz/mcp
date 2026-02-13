use {
    solana_clock::Slot,
    solana_keypair::Keypair,
    solana_ledger::{
        mcp,
        mcp_erasure::{encode_fec_set, McpErasureError, MCP_MAX_PAYLOAD_BYTES},
        mcp_merkle,
        shred::mcp_shred::{McpShred, MCP_SHRED_WIRE_SIZE},
    },
    solana_signer::Signer,
    thiserror::Error,
};

pub(crate) const MCP_NUM_RELAYS: usize = mcp::NUM_RELAYS;
pub(crate) const MCP_SHRED_DATA_BYTES: usize = mcp::SHRED_DATA_BYTES;
pub(crate) const MCP_WITNESS_LEN: usize = mcp::MCP_WITNESS_LEN;
pub(crate) const MCP_MAX_PAYLOAD_SIZE: usize = MCP_MAX_PAYLOAD_BYTES;
pub(crate) const MCP_SHRED_MESSAGE_SIZE: usize = MCP_SHRED_WIRE_SIZE;

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum McpProposerError {
    #[error("shred list size mismatch: expected {expected}, got {actual}")]
    ShredCountMismatch { expected: usize, actual: usize },
    #[error("failed to encode MCP RS shreds: {0}")]
    Erasure(McpErasureError),
    #[error("failed to derive MCP commitment/witnesses: {0}")]
    Merkle(mcp_merkle::McpMerkleError),
}

pub(crate) fn encode_payload_to_mcp_shreds(
    payload: &[u8],
) -> Result<Vec<[u8; MCP_SHRED_DATA_BYTES]>, McpProposerError> {
    encode_fec_set(payload).map_err(McpProposerError::Erasure)
}

pub(crate) fn build_shred_messages(
    slot: Slot,
    proposer_index: u32,
    shreds: &[[u8; MCP_SHRED_DATA_BYTES]],
    proposer_keypair: &Keypair,
) -> Result<Vec<[u8; MCP_SHRED_MESSAGE_SIZE]>, McpProposerError> {
    if shreds.len() != MCP_NUM_RELAYS {
        return Err(McpProposerError::ShredCountMismatch {
            expected: MCP_NUM_RELAYS,
            actual: shreds.len(),
        });
    }

    let (commitment, witnesses) = mcp_merkle::commitment_and_witnesses::<
        MCP_SHRED_DATA_BYTES,
        MCP_WITNESS_LEN,
    >(slot, proposer_index, shreds)
    .map_err(McpProposerError::Merkle)?;
    let proposer_signature = proposer_keypair.sign_message(&commitment);
    let mut messages = Vec::with_capacity(MCP_NUM_RELAYS);

    for (relay_index, (shred_data, witness)) in shreds.iter().zip(witnesses).enumerate() {
        let message = McpShred {
            slot,
            proposer_index,
            shred_index: relay_index as u32,
            commitment,
            shred_data: *shred_data,
            witness,
            proposer_signature,
        }
        .to_bytes();
        messages.push(message);
    }

    Ok(messages)
}

#[cfg(test)]
mod tests {
    use {super::*, solana_pubkey::Pubkey};

    fn verify_message(message: &[u8], relay_index: u32, proposer_pubkey: &Pubkey) -> bool {
        let Ok(shred) = McpShred::from_bytes(message) else {
            return false;
        };
        if shred.shred_index != relay_index {
            return false;
        }
        shred.verify_signature(proposer_pubkey) && shred.verify_witness()
    }

    fn make_shreds() -> Vec<[u8; MCP_SHRED_DATA_BYTES]> {
        (0..MCP_NUM_RELAYS)
            .map(|index| {
                let mut shred = [0u8; MCP_SHRED_DATA_BYTES];
                shred.fill(index as u8);
                shred
            })
            .collect()
    }

    #[test]
    fn test_build_shred_messages_one_per_relay() {
        let keypair = Keypair::new();
        let slot = 42;
        let proposer_index = 7;
        let shreds = make_shreds();
        let messages = build_shred_messages(slot, proposer_index, &shreds, &keypair).unwrap();

        assert_eq!(messages.len(), MCP_NUM_RELAYS);
        for (relay_index, message) in messages.iter().enumerate() {
            assert!(verify_message(
                message,
                relay_index as u32,
                &keypair.pubkey(),
            ));
        }
    }

    #[test]
    fn test_encode_payload_to_mcp_shreds_emits_200_shards() {
        let payload = vec![9u8; MCP_MAX_PAYLOAD_SIZE];
        let shreds = encode_payload_to_mcp_shreds(&payload).unwrap();
        assert_eq!(shreds.len(), MCP_NUM_RELAYS);
        assert!(shreds
            .iter()
            .all(|shred| shred.len() == MCP_SHRED_DATA_BYTES));
    }
}
