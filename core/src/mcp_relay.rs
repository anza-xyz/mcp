use {
    solana_clock::Slot,
    solana_ledger::{
        mcp,
        shred::mcp_shred::{McpShred, MCP_NUM_RELAYS},
    },
    solana_pubkey::Pubkey,
    std::collections::BTreeMap,
};

pub const MCP_NUM_PROPOSERS: usize = mcp::NUM_PROPOSERS;
pub type McpShredMessage = McpShred;
const MCP_RELAY_CACHE_MAX_ENTRIES: usize = MCP_NUM_RELAYS * MCP_NUM_PROPOSERS * 8;
const MCP_RELAY_CACHE_SLOT_WINDOW: Slot = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpDropReason {
    DecodeError,
    ProposerIndexOutOfRange,
    ShredIndexOutOfRange,
    InvalidProposerSignature,
    InvalidWitness,
    ConflictingShred,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpRelayOutcome {
    Dropped(McpDropReason),
    Duplicate,
    StoredAndBroadcast {
        slot: Slot,
        proposer_index: u32,
        shred_index: u32,
        payload: Vec<u8>,
    },
}

#[derive(Default)]
pub struct McpRelayProcessor {
    shreds: BTreeMap<(Slot, u32, u32), Vec<u8>>,
    highest_slot_seen: Slot,
}

impl McpRelayProcessor {
    pub fn stored_count(&self) -> usize {
        self.shreds.len()
    }

    pub fn prune_below_slot(&mut self, root_slot: Slot) {
        self.shreds.retain(|(slot, _, _), _| *slot >= root_slot);
    }

    pub fn process_shred(&mut self, payload: &[u8], proposer_pubkey: &Pubkey) -> McpRelayOutcome {
        let message = match McpShred::from_bytes(payload) {
            Ok(message) => message,
            Err(_) => return McpRelayOutcome::Dropped(McpDropReason::DecodeError),
        };
        if message.proposer_index as usize >= MCP_NUM_PROPOSERS {
            return McpRelayOutcome::Dropped(McpDropReason::ProposerIndexOutOfRange);
        }
        if message.shred_index as usize >= MCP_NUM_RELAYS {
            return McpRelayOutcome::Dropped(McpDropReason::ShredIndexOutOfRange);
        }
        if !message.verify_signature(proposer_pubkey) {
            return McpRelayOutcome::Dropped(McpDropReason::InvalidProposerSignature);
        }
        if !message.verify_witness() {
            return McpRelayOutcome::Dropped(McpDropReason::InvalidWitness);
        }
        self.highest_slot_seen = self.highest_slot_seen.max(message.slot);
        let min_slot = self
            .highest_slot_seen
            .saturating_sub(MCP_RELAY_CACHE_SLOT_WINDOW);
        self.shreds.retain(|(slot, _, _), _| *slot >= min_slot);

        let key = (message.slot, message.proposer_index, message.shred_index);
        if let Some(stored) = self.shreds.get(&key) {
            if stored == payload {
                return McpRelayOutcome::Duplicate;
            }
            return McpRelayOutcome::Dropped(McpDropReason::ConflictingShred);
        }
        if self.shreds.len() >= MCP_RELAY_CACHE_MAX_ENTRIES {
            if let Some(oldest_key) = self.shreds.keys().next().copied() {
                self.shreds.remove(&oldest_key);
            }
        }

        let payload = payload.to_vec();
        self.shreds.insert(key, payload.clone());
        McpRelayOutcome::StoredAndBroadcast {
            slot: message.slot,
            proposer_index: message.proposer_index,
            shred_index: message.shred_index,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_keypair::Keypair,
        solana_ledger::shred::mcp_shred::{
            McpShredError, MCP_SHRED_DATA_BYTES, MCP_SHRED_WIRE_SIZE, MCP_WITNESS_LEN,
        },
        solana_sha256_hasher::hashv,
        solana_signer::Signer,
    };

    const LEAF_DOMAIN: [u8; 1] = [0x00];
    const NODE_DOMAIN: [u8; 1] = [0x01];

    fn make_shreds() -> Vec<[u8; MCP_SHRED_DATA_BYTES]> {
        (0..MCP_NUM_RELAYS)
            .map(|i| {
                let mut shred = [0u8; MCP_SHRED_DATA_BYTES];
                shred.fill(i as u8);
                shred
            })
            .collect()
    }

    fn derive_commitment_and_witnesses(
        slot: Slot,
        proposer_index: u32,
        shreds: &[[u8; MCP_SHRED_DATA_BYTES]],
    ) -> ([u8; 32], Vec<[[u8; 32]; MCP_WITNESS_LEN]>) {
        let mut levels = vec![shreds
            .iter()
            .enumerate()
            .map(|(i, shred_data)| {
                hashv(&[
                    &LEAF_DOMAIN,
                    &slot.to_le_bytes(),
                    &proposer_index.to_le_bytes(),
                    &(i as u32).to_le_bytes(),
                    shred_data,
                ])
                .to_bytes()
            })
            .collect::<Vec<[u8; 32]>>()];

        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0usize;
            while i < prev.len() {
                let left = prev[i];
                let right = prev.get(i + 1).copied().unwrap_or(left);
                next.push(hashv(&[&NODE_DOMAIN, &left, &right]).to_bytes());
                i += 2;
            }
            levels.push(next);
        }

        let commitment = levels.last().unwrap()[0];
        let mut witnesses = vec![[[0u8; 32]; MCP_WITNESS_LEN]; MCP_NUM_RELAYS];
        for (leaf_index, witness) in witnesses.iter_mut().enumerate() {
            let mut index = leaf_index;
            for depth in 0..MCP_WITNESS_LEN {
                let level = &levels[depth];
                let sibling_index = index ^ 1;
                witness[depth] = level.get(sibling_index).copied().unwrap_or(level[index]);
                index >>= 1;
            }
        }

        (commitment, witnesses)
    }

    fn build_message(
        slot: Slot,
        proposer_index: u32,
        shred_index: u32,
        commitment: [u8; 32],
        shred_data: [u8; MCP_SHRED_DATA_BYTES],
        witness: [[u8; 32]; MCP_WITNESS_LEN],
        signer: &Keypair,
    ) -> Vec<u8> {
        McpShred {
            slot,
            proposer_index,
            shred_index,
            commitment,
            shred_data,
            witness,
            proposer_signature: signer.sign_message(&commitment),
        }
        .to_bytes()
        .to_vec()
    }

    #[test]
    fn test_valid_shred_is_stored_and_broadcast() {
        let slot = 11;
        let proposer_index = 3;
        let relay_index = 17u32;
        let proposer = Keypair::new();
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let payload = build_message(
            slot,
            proposer_index,
            relay_index,
            commitment,
            shreds[relay_index as usize],
            witnesses[relay_index as usize],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        let outcome = relay.process_shred(&payload, &proposer.pubkey());
        assert_eq!(
            outcome,
            McpRelayOutcome::StoredAndBroadcast {
                slot,
                proposer_index,
                shred_index: relay_index,
                payload: payload.clone(),
            }
        );
        assert_eq!(relay.stored_count(), 1);

        let duplicate = relay.process_shred(&payload, &proposer.pubkey());
        assert_eq!(duplicate, McpRelayOutcome::Duplicate);
    }

    #[test]
    fn test_invalid_signature_is_dropped() {
        let slot = 12;
        let proposer_index = 4;
        let relay_index = 2u32;
        let honest_proposer = Keypair::new();
        let attacker = Keypair::new();
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let payload = build_message(
            slot,
            proposer_index,
            relay_index,
            commitment,
            shreds[relay_index as usize],
            witnesses[relay_index as usize],
            &attacker,
        );

        let mut relay = McpRelayProcessor::default();
        let outcome = relay.process_shred(&payload, &honest_proposer.pubkey());
        assert_eq!(
            outcome,
            McpRelayOutcome::Dropped(McpDropReason::InvalidProposerSignature)
        );
        assert_eq!(relay.stored_count(), 0);
    }

    #[test]
    fn test_invalid_witness_is_dropped() {
        let slot = 14;
        let proposer_index = 8;
        let relay_index = 6u32;
        let proposer = Keypair::new();
        let shreds = make_shreds();
        let (commitment, mut witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        witnesses[relay_index as usize][0][0] ^= 1;

        let payload = build_message(
            slot,
            proposer_index,
            relay_index,
            commitment,
            shreds[relay_index as usize],
            witnesses[relay_index as usize],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        let outcome = relay.process_shred(&payload, &proposer.pubkey());
        assert_eq!(
            outcome,
            McpRelayOutcome::Dropped(McpDropReason::InvalidWitness)
        );
        assert_eq!(relay.stored_count(), 0);
    }

    #[test]
    fn test_conflicting_shred_is_dropped_without_overwrite() {
        let slot = 15;
        let proposer_index = 10;
        let relay_index = 5u32;
        let proposer = Keypair::new();
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let payload = build_message(
            slot,
            proposer_index,
            relay_index,
            commitment,
            shreds[relay_index as usize],
            witnesses[relay_index as usize],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        let first = relay.process_shred(&payload, &proposer.pubkey());
        assert!(matches!(first, McpRelayOutcome::StoredAndBroadcast { .. }));
        assert_eq!(relay.stored_count(), 1);

        let mut alternate_shreds = shreds.clone();
        alternate_shreds[relay_index as usize][0] ^= 1;
        let (alt_commitment, alt_witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &alternate_shreds);
        let conflicting = build_message(
            slot,
            proposer_index,
            relay_index,
            alt_commitment,
            alternate_shreds[relay_index as usize],
            alt_witnesses[relay_index as usize],
            &proposer,
        );
        let conflict_outcome = relay.process_shred(&conflicting, &proposer.pubkey());
        assert_eq!(
            conflict_outcome,
            McpRelayOutcome::Dropped(McpDropReason::ConflictingShred)
        );
        assert_eq!(relay.stored_count(), 1);
    }

    #[test]
    fn test_prune_below_slot_discards_old_entries() {
        let proposer = Keypair::new();
        let proposer_index = 1;
        let relay_index = 0u32;
        let shreds = make_shreds();

        let (commitment_a, witnesses_a) =
            derive_commitment_and_witnesses(20, proposer_index, &shreds);
        let payload_a = build_message(
            20,
            proposer_index,
            relay_index,
            commitment_a,
            shreds[relay_index as usize],
            witnesses_a[relay_index as usize],
            &proposer,
        );

        let (commitment_b, witnesses_b) =
            derive_commitment_and_witnesses(21, proposer_index, &shreds);
        let payload_b = build_message(
            21,
            proposer_index,
            relay_index,
            commitment_b,
            shreds[relay_index as usize],
            witnesses_b[relay_index as usize],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        assert!(matches!(
            relay.process_shred(&payload_a, &proposer.pubkey()),
            McpRelayOutcome::StoredAndBroadcast { .. }
        ));
        assert!(matches!(
            relay.process_shred(&payload_b, &proposer.pubkey()),
            McpRelayOutcome::StoredAndBroadcast { .. }
        ));
        assert_eq!(relay.stored_count(), 2);

        relay.prune_below_slot(21);
        assert_eq!(relay.stored_count(), 1);
    }

    #[test]
    fn test_from_bytes_rejects_wrong_size() {
        let too_short = vec![0u8; MCP_SHRED_WIRE_SIZE - 1];
        let err = McpShred::from_bytes(&too_short).unwrap_err();
        assert_eq!(
            err,
            McpShredError::InvalidSize {
                expected: MCP_SHRED_WIRE_SIZE,
                actual: MCP_SHRED_WIRE_SIZE - 1,
            }
        );
    }

    #[test]
    fn test_boundary_relay_indices_are_accepted() {
        let proposer = Keypair::new();
        let proposer_index = 2;
        let slot = 31;
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let mut relay = McpRelayProcessor::default();

        for relay_index in [0u32, (MCP_NUM_RELAYS - 1) as u32] {
            let payload = build_message(
                slot,
                proposer_index,
                relay_index,
                commitment,
                shreds[relay_index as usize],
                witnesses[relay_index as usize],
                &proposer,
            );
            let outcome = relay.process_shred(&payload, &proposer.pubkey());
            assert!(matches!(
                outcome,
                McpRelayOutcome::StoredAndBroadcast { .. }
            ));
        }
        assert_eq!(relay.stored_count(), 2);
    }

    #[test]
    fn test_out_of_range_proposer_index_is_dropped() {
        let proposer = Keypair::new();
        let relay_index = 0u32;
        let proposer_index = MCP_NUM_PROPOSERS as u32;
        let slot = 33;
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let payload = build_message(
            slot,
            proposer_index,
            relay_index,
            commitment,
            shreds[relay_index as usize],
            witnesses[relay_index as usize],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        let outcome = relay.process_shred(&payload, &proposer.pubkey());
        assert_eq!(
            outcome,
            McpRelayOutcome::Dropped(McpDropReason::DecodeError)
        );
    }

    #[test]
    fn test_out_of_range_shred_index_is_dropped() {
        let proposer = Keypair::new();
        let proposer_index = 2u32;
        let relay_index = MCP_NUM_RELAYS as u32;
        let slot = 34;
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let payload = build_message(
            slot,
            proposer_index,
            relay_index,
            commitment,
            shreds[0],
            witnesses[0],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        let outcome = relay.process_shred(&payload, &proposer.pubkey());
        assert_eq!(
            outcome,
            McpRelayOutcome::Dropped(McpDropReason::DecodeError)
        );
    }

    #[test]
    fn test_invalid_high_slot_does_not_prune_valid_cached_entries() {
        let proposer = Keypair::new();
        let attacker = Keypair::new();
        let proposer_index = 1;
        let relay_index = 4u32;
        let shreds = make_shreds();
        let mut relay = McpRelayProcessor::default();

        let (commitment_10, witnesses_10) =
            derive_commitment_and_witnesses(10, proposer_index, &shreds);
        let payload_10 = build_message(
            10,
            proposer_index,
            relay_index,
            commitment_10,
            shreds[relay_index as usize],
            witnesses_10[relay_index as usize],
            &proposer,
        );
        assert!(matches!(
            relay.process_shred(&payload_10, &proposer.pubkey()),
            McpRelayOutcome::StoredAndBroadcast { .. }
        ));

        let (commitment_1000, witnesses_1000) =
            derive_commitment_and_witnesses(1000, proposer_index, &shreds);
        let payload_1000_invalid_sig = build_message(
            1000,
            proposer_index,
            relay_index,
            commitment_1000,
            shreds[relay_index as usize],
            witnesses_1000[relay_index as usize],
            &attacker,
        );
        assert_eq!(
            relay.process_shred(&payload_1000_invalid_sig, &proposer.pubkey()),
            McpRelayOutcome::Dropped(McpDropReason::InvalidProposerSignature),
        );

        let (commitment_11, witnesses_11) =
            derive_commitment_and_witnesses(11, proposer_index, &shreds);
        let payload_11 = build_message(
            11,
            proposer_index,
            relay_index,
            commitment_11,
            shreds[relay_index as usize],
            witnesses_11[relay_index as usize],
            &proposer,
        );
        assert!(matches!(
            relay.process_shred(&payload_11, &proposer.pubkey()),
            McpRelayOutcome::StoredAndBroadcast { .. }
        ));

        assert_eq!(relay.stored_count(), 2);
    }
}
