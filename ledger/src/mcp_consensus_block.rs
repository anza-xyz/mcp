use {
    crate::mcp,
    solana_clock::Slot,
    solana_hash::{Hash, HASH_BYTES},
    solana_pubkey::Pubkey,
    solana_signature::{Signature, SIGNATURE_BYTES},
    solana_signer::Signer,
};

pub const CONSENSUS_BLOCK_V1: u8 = 1;
const HEADER_LEN: usize = 1 + 8 + 4 + 4 + 4;
const TRAILER_LEN: usize = HASH_BYTES + SIGNATURE_BYTES;
const RELAY_ENTRY_HEADER_LEN: usize = 4 + 1;
const PROPOSER_ENTRY_LEN: usize = 4 + HASH_BYTES + SIGNATURE_BYTES;
const MAX_AGGREGATE_ATTESTATION_BYTES: usize = 1
    + 8
    + 4
    + 2
    + (mcp::NUM_RELAYS
        * (RELAY_ENTRY_HEADER_LEN + (mcp::NUM_PROPOSERS * PROPOSER_ENTRY_LEN) + SIGNATURE_BYTES));
// Keep consensus metadata bounded to a small sidecar payload while preserving
// room for attestation bytes and the leader signature under the QUIC cap.
const MAX_CONSENSUS_META_BYTES: usize = 64 * 1024;
const MAX_CONSENSUS_BLOCK_PROTOCOL_BYTES: usize =
    HEADER_LEN + MAX_AGGREGATE_ATTESTATION_BYTES + MAX_CONSENSUS_META_BYTES + TRAILER_LEN;
const MAX_CONSENSUS_BLOCK_WIRE_BYTES: usize =
    if MAX_CONSENSUS_BLOCK_PROTOCOL_BYTES < mcp::MAX_QUIC_CONTROL_PAYLOAD_BYTES {
        MAX_CONSENSUS_BLOCK_PROTOCOL_BYTES
    } else {
        mcp::MAX_QUIC_CONTROL_PAYLOAD_BYTES
    };

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusBlock {
    pub version: u8,
    pub slot: Slot,
    pub leader_index: u32,
    pub aggregate_bytes: Vec<u8>,
    pub consensus_meta: Vec<u8>,
    // Opaque Alpenglow sidecar bytes. When present in v1, a 32-byte payload is
    // interpreted by replay as an authoritative block_id.
    pub delayed_bankhash: Hash,
    pub leader_signature: Signature,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ConsensusBlockError {
    #[error("unknown consensus block version: {0}")]
    UnknownVersion(u8),
    #[error("aggregate bytes length exceeds u32::MAX: {0}")]
    AggregateLengthOverflow(usize),
    #[error("consensus_meta length exceeds u32::MAX: {0}")]
    ConsensusMetaLengthOverflow(usize),
    #[error("aggregate attestation exceeds protocol maximum: {actual} > {max}")]
    AggregateLengthTooLarge { actual: usize, max: usize },
    #[error("consensus_meta exceeds protocol maximum: {actual} > {max}")]
    ConsensusMetaTooLarge { actual: usize, max: usize },
    #[error("consensus block is truncated")]
    Truncated,
    #[error("consensus block has trailing bytes")]
    TrailingBytes,
    #[error("consensus block exceeds protocol maximum: {actual} > {max}")]
    WireBytesTooLarge { actual: usize, max: usize },
    #[error("leader index out of range: {0}")]
    LeaderIndexOutOfRange(u32),
}

impl ConsensusBlock {
    pub fn new_unsigned(
        slot: Slot,
        leader_index: u32,
        aggregate_bytes: Vec<u8>,
        consensus_meta: Vec<u8>,
        delayed_bankhash: Hash,
    ) -> Result<Self, ConsensusBlockError> {
        ensure_leader_index_in_range(leader_index)?;
        if aggregate_bytes.len() > u32::MAX as usize {
            return Err(ConsensusBlockError::AggregateLengthOverflow(
                aggregate_bytes.len(),
            ));
        }
        if aggregate_bytes.len() > MAX_AGGREGATE_ATTESTATION_BYTES {
            return Err(ConsensusBlockError::AggregateLengthTooLarge {
                actual: aggregate_bytes.len(),
                max: MAX_AGGREGATE_ATTESTATION_BYTES,
            });
        }
        if consensus_meta.len() > u32::MAX as usize {
            return Err(ConsensusBlockError::ConsensusMetaLengthOverflow(
                consensus_meta.len(),
            ));
        }
        if consensus_meta.len() > MAX_CONSENSUS_META_BYTES {
            return Err(ConsensusBlockError::ConsensusMetaTooLarge {
                actual: consensus_meta.len(),
                max: MAX_CONSENSUS_META_BYTES,
            });
        }

        Ok(Self {
            version: CONSENSUS_BLOCK_V1,
            slot,
            leader_index,
            aggregate_bytes,
            consensus_meta,
            delayed_bankhash,
            leader_signature: Signature::default(),
        })
    }

    fn wire_body_bytes(&self) -> Result<Vec<u8>, ConsensusBlockError> {
        ensure_leader_index_in_range(self.leader_index)?;
        if self.aggregate_bytes.len() > u32::MAX as usize {
            return Err(ConsensusBlockError::AggregateLengthOverflow(
                self.aggregate_bytes.len(),
            ));
        }
        if self.aggregate_bytes.len() > MAX_AGGREGATE_ATTESTATION_BYTES {
            return Err(ConsensusBlockError::AggregateLengthTooLarge {
                actual: self.aggregate_bytes.len(),
                max: MAX_AGGREGATE_ATTESTATION_BYTES,
            });
        }
        if self.consensus_meta.len() > u32::MAX as usize {
            return Err(ConsensusBlockError::ConsensusMetaLengthOverflow(
                self.consensus_meta.len(),
            ));
        }
        if self.consensus_meta.len() > MAX_CONSENSUS_META_BYTES {
            return Err(ConsensusBlockError::ConsensusMetaTooLarge {
                actual: self.consensus_meta.len(),
                max: MAX_CONSENSUS_META_BYTES,
            });
        }

        let mut out = Vec::with_capacity(
            HEADER_LEN + self.aggregate_bytes.len() + self.consensus_meta.len() + HASH_BYTES,
        );
        out.push(self.version);
        out.extend_from_slice(&self.slot.to_le_bytes());
        out.extend_from_slice(&self.leader_index.to_le_bytes());
        out.extend_from_slice(&(self.aggregate_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.aggregate_bytes);
        out.extend_from_slice(&(self.consensus_meta.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.consensus_meta);
        out.extend_from_slice(self.delayed_bankhash.as_ref());
        Ok(out)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, ConsensusBlockError> {
        self.wire_body_bytes()
    }

    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, ConsensusBlockError> {
        let mut bytes = self.wire_body_bytes()?;
        bytes.extend_from_slice(self.leader_signature.as_ref());
        if bytes.len() > MAX_CONSENSUS_BLOCK_WIRE_BYTES {
            return Err(ConsensusBlockError::WireBytesTooLarge {
                actual: bytes.len(),
                max: MAX_CONSENSUS_BLOCK_WIRE_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ConsensusBlockError> {
        if bytes.len() > MAX_CONSENSUS_BLOCK_WIRE_BYTES {
            return Err(ConsensusBlockError::WireBytesTooLarge {
                actual: bytes.len(),
                max: MAX_CONSENSUS_BLOCK_WIRE_BYTES,
            });
        }
        if bytes.len() < HEADER_LEN + TRAILER_LEN {
            return Err(ConsensusBlockError::Truncated);
        }

        let mut cursor = 0usize;
        let version = read_u8(bytes, &mut cursor)?;
        if version != CONSENSUS_BLOCK_V1 {
            return Err(ConsensusBlockError::UnknownVersion(version));
        }

        let slot = read_u64_le(bytes, &mut cursor)?;
        let leader_index = read_u32_le(bytes, &mut cursor)?;
        ensure_leader_index_in_range(leader_index)?;
        let aggregate_len = read_u32_le(bytes, &mut cursor)? as usize;
        if aggregate_len > MAX_AGGREGATE_ATTESTATION_BYTES {
            return Err(ConsensusBlockError::AggregateLengthTooLarge {
                actual: aggregate_len,
                max: MAX_AGGREGATE_ATTESTATION_BYTES,
            });
        }
        let aggregate_bytes = read_vec(bytes, &mut cursor, aggregate_len)?;
        let consensus_meta_len = read_u32_le(bytes, &mut cursor)? as usize;
        if consensus_meta_len > MAX_CONSENSUS_META_BYTES {
            return Err(ConsensusBlockError::ConsensusMetaTooLarge {
                actual: consensus_meta_len,
                max: MAX_CONSENSUS_META_BYTES,
            });
        }
        let consensus_meta = read_vec(bytes, &mut cursor, consensus_meta_len)?;
        let delayed_bankhash = Hash::new_from_array(read_array::<HASH_BYTES>(bytes, &mut cursor)?);
        let leader_signature = Signature::from(read_array::<SIGNATURE_BYTES>(bytes, &mut cursor)?);

        if cursor != bytes.len() {
            return Err(ConsensusBlockError::TrailingBytes);
        }

        Ok(Self {
            version,
            slot,
            leader_index,
            aggregate_bytes,
            consensus_meta,
            delayed_bankhash,
            leader_signature,
        })
    }

    pub fn sign_leader<T: Signer>(&mut self, signer: &T) -> Result<(), ConsensusBlockError> {
        let signing_bytes = self.signing_bytes()?;
        self.leader_signature = signer.sign_message(&signing_bytes);
        Ok(())
    }

    pub fn verify_leader_signature(&self, leader_pubkey: &Pubkey) -> bool {
        let Ok(signing_bytes) = self.signing_bytes() else {
            return false;
        };
        self.leader_signature
            .verify(leader_pubkey.as_ref(), &signing_bytes)
    }
}

fn ensure_leader_index_in_range(leader_index: u32) -> Result<(), ConsensusBlockError> {
    if leader_index as usize >= mcp::NUM_PROPOSERS {
        return Err(ConsensusBlockError::LeaderIndexOutOfRange(leader_index));
    }
    Ok(())
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, ConsensusBlockError> {
    let Some(end) = cursor.checked_add(1) else {
        return Err(ConsensusBlockError::Truncated);
    };
    if end > bytes.len() {
        return Err(ConsensusBlockError::Truncated);
    }
    let value = bytes[*cursor];
    *cursor = end;
    Ok(value)
}

fn read_u32_le(bytes: &[u8], cursor: &mut usize) -> Result<u32, ConsensusBlockError> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, cursor)?))
}

fn read_u64_le(bytes: &[u8], cursor: &mut usize) -> Result<u64, ConsensusBlockError> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, cursor)?))
}

fn read_vec(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>, ConsensusBlockError> {
    let Some(end) = cursor.checked_add(len) else {
        return Err(ConsensusBlockError::Truncated);
    };
    if end > bytes.len() {
        return Err(ConsensusBlockError::Truncated);
    }
    let out = bytes[*cursor..end].to_vec();
    *cursor = end;
    Ok(out)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ConsensusBlockError> {
    let Some(end) = cursor.checked_add(N) else {
        return Err(ConsensusBlockError::Truncated);
    };
    if end > bytes.len() {
        return Err(ConsensusBlockError::Truncated);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use {super::*, solana_keypair::Keypair};

    #[test]
    fn test_roundtrip_and_signature_verification() {
        let leader = Keypair::new();
        let mut block = ConsensusBlock::new_unsigned(
            88,
            7,
            vec![1, 2, 3, 4],
            vec![9, 8, 7],
            Hash::new_unique(),
        )
        .unwrap();
        block.sign_leader(&leader).unwrap();

        let bytes = block.to_wire_bytes().unwrap();
        let decoded = ConsensusBlock::from_wire_bytes(&bytes).unwrap();

        assert_eq!(decoded, block);
        assert!(decoded.verify_leader_signature(&leader.pubkey()));
    }

    #[test]
    fn test_roundtrip_with_empty_aggregate_and_meta() {
        let leader = Keypair::new();
        let mut block =
            ConsensusBlock::new_unsigned(21, 3, vec![], vec![], Hash::new_unique()).unwrap();
        block.sign_leader(&leader).unwrap();

        let bytes = block.to_wire_bytes().unwrap();
        let decoded = ConsensusBlock::from_wire_bytes(&bytes).unwrap();

        assert_eq!(decoded, block);
        assert!(decoded.verify_leader_signature(&leader.pubkey()));
    }

    #[test]
    fn test_signature_verification_fails_after_tamper() {
        let leader = Keypair::new();
        let mut block =
            ConsensusBlock::new_unsigned(1, 2, vec![5, 6, 7], vec![10, 11], Hash::new_unique())
                .unwrap();
        block.sign_leader(&leader).unwrap();
        assert!(block.verify_leader_signature(&leader.pubkey()));

        block.consensus_meta.push(99);
        assert!(!block.verify_leader_signature(&leader.pubkey()));
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_key() {
        let leader = Keypair::new();
        let wrong_leader = Keypair::new();
        let mut block =
            ConsensusBlock::new_unsigned(9, 3, vec![1, 2], vec![3], Hash::new_unique()).unwrap();
        block.sign_leader(&leader).unwrap();
        assert!(!block.verify_leader_signature(&wrong_leader.pubkey()));
    }

    #[test]
    fn test_unknown_version_rejected() {
        let bytes = vec![2u8; HEADER_LEN + TRAILER_LEN];
        assert_eq!(
            ConsensusBlock::from_wire_bytes(&bytes).unwrap_err(),
            ConsensusBlockError::UnknownVersion(2)
        );
    }

    #[test]
    fn test_trailing_bytes_rejected() {
        let leader = Keypair::new();
        let mut block =
            ConsensusBlock::new_unsigned(1, 2, vec![5, 6, 7], vec![10, 11], Hash::new_unique())
                .unwrap();
        block.sign_leader(&leader).unwrap();

        let mut bytes = block.to_wire_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            ConsensusBlock::from_wire_bytes(&bytes).unwrap_err(),
            ConsensusBlockError::TrailingBytes
        );
    }

    #[test]
    fn test_truncated_payload_rejected() {
        let leader = Keypair::new();
        let mut block =
            ConsensusBlock::new_unsigned(2, 4, vec![7, 8], vec![9], Hash::new_unique()).unwrap();
        block.sign_leader(&leader).unwrap();

        let mut bytes = block.to_wire_bytes().unwrap();
        bytes.pop();
        assert_eq!(
            ConsensusBlock::from_wire_bytes(&bytes).unwrap_err(),
            ConsensusBlockError::Truncated
        );
    }

    #[test]
    fn test_oversized_aggregate_len_rejected() {
        let mut bytes = Vec::new();
        bytes.push(CONSENSUS_BLOCK_V1);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&((MAX_AGGREGATE_ATTESTATION_BYTES as u32) + 1).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(Hash::new_unique().as_ref());
        bytes.extend_from_slice(Signature::default().as_ref());

        assert_eq!(
            ConsensusBlock::from_wire_bytes(&bytes).unwrap_err(),
            ConsensusBlockError::AggregateLengthTooLarge {
                actual: MAX_AGGREGATE_ATTESTATION_BYTES + 1,
                max: MAX_AGGREGATE_ATTESTATION_BYTES,
            }
        );
    }

    #[test]
    fn test_oversized_consensus_meta_rejected() {
        let err = ConsensusBlock::new_unsigned(
            3,
            4,
            vec![],
            vec![0u8; MAX_CONSENSUS_META_BYTES + 1],
            Hash::new_unique(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConsensusBlockError::ConsensusMetaTooLarge {
                actual: MAX_CONSENSUS_META_BYTES + 1,
                max: MAX_CONSENSUS_META_BYTES,
            }
        );
    }

    #[test]
    fn test_from_wire_bytes_rejects_oversized_wire() {
        let bytes = vec![0u8; MAX_CONSENSUS_BLOCK_WIRE_BYTES + 1];
        assert_eq!(
            ConsensusBlock::from_wire_bytes(&bytes).unwrap_err(),
            ConsensusBlockError::WireBytesTooLarge {
                actual: MAX_CONSENSUS_BLOCK_WIRE_BYTES + 1,
                max: MAX_CONSENSUS_BLOCK_WIRE_BYTES,
            }
        );
    }

    #[test]
    fn test_max_wire_fits_quic_control_payload_bound() {
        assert!(MAX_CONSENSUS_BLOCK_WIRE_BYTES <= mcp::MAX_QUIC_CONTROL_PAYLOAD_BYTES);
    }

    #[test]
    fn test_sign_leader_rejects_oversized_aggregate() {
        let mut block = ConsensusBlock {
            version: CONSENSUS_BLOCK_V1,
            slot: 1,
            leader_index: 0,
            aggregate_bytes: vec![0u8; MAX_AGGREGATE_ATTESTATION_BYTES + 1],
            consensus_meta: Vec::new(),
            delayed_bankhash: Hash::new_unique(),
            leader_signature: Signature::default(),
        };
        let leader = Keypair::new();
        assert_eq!(
            block.sign_leader(&leader).unwrap_err(),
            ConsensusBlockError::AggregateLengthTooLarge {
                actual: MAX_AGGREGATE_ATTESTATION_BYTES + 1,
                max: MAX_AGGREGATE_ATTESTATION_BYTES,
            }
        );
    }

    #[test]
    fn test_new_unsigned_rejects_out_of_range_leader_index() {
        assert_eq!(
            ConsensusBlock::new_unsigned(
                1,
                mcp::NUM_PROPOSERS as u32,
                Vec::new(),
                Vec::new(),
                Hash::new_unique(),
            )
            .unwrap_err(),
            ConsensusBlockError::LeaderIndexOutOfRange(mcp::NUM_PROPOSERS as u32),
        );
    }

    #[test]
    fn test_from_wire_rejects_out_of_range_leader_index() {
        let mut bytes = Vec::new();
        bytes.push(CONSENSUS_BLOCK_V1);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&(mcp::NUM_PROPOSERS as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // aggregate_len
        bytes.extend_from_slice(&0u32.to_le_bytes()); // consensus_meta_len
        bytes.extend_from_slice(Hash::new_unique().as_ref());
        bytes.extend_from_slice(Signature::default().as_ref());

        assert_eq!(
            ConsensusBlock::from_wire_bytes(&bytes).unwrap_err(),
            ConsensusBlockError::LeaderIndexOutOfRange(mcp::NUM_PROPOSERS as u32),
        );
    }
}
