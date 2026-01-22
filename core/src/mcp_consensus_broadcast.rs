//! MCP Consensus Block Broadcasting (MCP-13)
//!
//! This module implements consensus leader block broadcasting via turbine.
//!
//! # Overview
//!
//! The consensus leader:
//! 1. Aggregates relay attestations into a block
//! 2. Constructs consensus payload with block metadata
//! 3. Signs the payload
//! 4. Broadcasts as shreds with proposer_id=0xFF
//!
//! # Wire Format
//!
//! Consensus block payload:
//! ```text
//! | version (1) | slot (8) | leader_id (32) | aggregate (var) |
//! | consensus_meta (var) | delayed_bankhash (32) | leader_sig (64) |
//! ```

use {
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    solana_signer::Signer,
};

/// Proposer ID used for consensus payload shreds.
pub const CONSENSUS_PAYLOAD_PROPOSER_ID: u8 = 0xFF;

/// Current version of the consensus payload format.
pub const CONSENSUS_PAYLOAD_VERSION: u8 = 1;

/// Aggregated attestation data for a proposer.
#[derive(Debug, Clone)]
pub struct ProposerAggregation {
    /// The proposer ID.
    pub proposer_id: u8,
    /// The merkle root (commitment) for this proposer.
    pub merkle_root: Hash,
    /// Number of relays that attested.
    pub relay_count: u16,
    /// Total stake of attesting relays.
    pub attesting_stake: u64,
}

/// Aggregate of all proposer attestations for a slot.
#[derive(Debug, Clone)]
pub struct SlotAggregate {
    /// Aggregations per proposer.
    pub proposer_aggregations: Vec<ProposerAggregation>,
    /// Total stake that attested.
    pub total_attesting_stake: u64,
}

impl SlotAggregate {
    /// Create a new slot aggregate.
    pub fn new() -> Self {
        Self {
            proposer_aggregations: Vec::new(),
            total_attesting_stake: 0,
        }
    }

    /// Add a proposer aggregation.
    pub fn add_proposer(&mut self, agg: ProposerAggregation) {
        self.total_attesting_stake = self.total_attesting_stake.saturating_add(agg.attesting_stake);
        self.proposer_aggregations.push(agg);
    }

    /// Sort proposers by ID for deterministic serialization.
    pub fn sort(&mut self) {
        self.proposer_aggregations.sort_by_key(|a| a.proposer_id);
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Number of proposers
        data.extend_from_slice(&(self.proposer_aggregations.len() as u8).to_le_bytes());

        // Each proposer aggregation
        for agg in &self.proposer_aggregations {
            data.push(agg.proposer_id);
            data.extend_from_slice(agg.merkle_root.as_ref());
            data.extend_from_slice(&agg.relay_count.to_le_bytes());
            data.extend_from_slice(&agg.attesting_stake.to_le_bytes());
        }

        // Total attesting stake
        data.extend_from_slice(&self.total_attesting_stake.to_le_bytes());

        data
    }
}

impl Default for SlotAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Consensus metadata for a block.
#[derive(Debug, Clone)]
pub struct ConsensusMeta {
    /// Timestamp of block creation.
    pub timestamp: i64,
    /// Parent block ID.
    pub parent_block_id: Hash,
    /// Epoch of this slot.
    pub epoch: u64,
}

impl ConsensusMeta {
    /// Create new consensus metadata.
    pub fn new(timestamp: i64, parent_block_id: Hash, epoch: u64) -> Self {
        Self {
            timestamp,
            parent_block_id,
            epoch,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(self.parent_block_id.as_ref());
        data.extend_from_slice(&self.epoch.to_le_bytes());
        data
    }
}

/// Consensus block payload.
#[derive(Debug, Clone)]
pub struct ConsensusPayload {
    /// Payload version.
    pub version: u8,
    /// The slot this payload is for.
    pub slot: u64,
    /// The leader's pubkey.
    pub leader_id: Pubkey,
    /// Aggregated attestations.
    pub aggregate: SlotAggregate,
    /// Consensus metadata.
    pub consensus_meta: ConsensusMeta,
    /// Delayed bank hash (from previous slot).
    pub delayed_bankhash: Hash,
    /// Leader's signature over the payload.
    pub leader_signature: Signature,
}

impl ConsensusPayload {
    /// Create a new unsigned consensus payload.
    pub fn new(
        slot: u64,
        leader_id: Pubkey,
        aggregate: SlotAggregate,
        consensus_meta: ConsensusMeta,
        delayed_bankhash: Hash,
    ) -> Self {
        Self {
            version: CONSENSUS_PAYLOAD_VERSION,
            slot,
            leader_id,
            aggregate,
            consensus_meta,
            delayed_bankhash,
            leader_signature: Signature::default(),
        }
    }

    /// Get the data to be signed.
    pub fn get_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.version);
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(self.leader_id.as_ref());
        data.extend_from_slice(&self.aggregate.to_bytes());
        data.extend_from_slice(&self.consensus_meta.to_bytes());
        data.extend_from_slice(self.delayed_bankhash.as_ref());
        data
    }

    /// Sign the payload.
    pub fn sign(&mut self, keypair: &Keypair) {
        let data = self.get_signing_data();
        self.leader_signature = keypair.sign_message(&data);
    }

    /// Verify the leader's signature.
    pub fn verify(&self) -> bool {
        let data = self.get_signing_data();
        self.leader_signature
            .verify(self.leader_id.as_ref(), &data)
    }

    /// Compute the block ID (hash of canonical payload).
    pub fn block_id(&self) -> Hash {
        let data = self.get_signing_data();
        solana_sha256_hasher::hash(&data)
    }

    /// Serialize the complete payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = self.get_signing_data();
        data.extend_from_slice(self.leader_signature.as_ref());
        data
    }

    /// Get the proposer ID for shreds (always 0xFF for consensus).
    pub fn proposer_id(&self) -> u8 {
        CONSENSUS_PAYLOAD_PROPOSER_ID
    }
}

/// Builds consensus payloads for broadcast.
pub struct ConsensusPayloadBuilder {
    /// The leader's keypair.
    keypair: Keypair,
}

impl ConsensusPayloadBuilder {
    /// Create a new payload builder.
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Build and sign a consensus payload.
    pub fn build(
        &self,
        slot: u64,
        aggregate: SlotAggregate,
        consensus_meta: ConsensusMeta,
        delayed_bankhash: Hash,
    ) -> ConsensusPayload {
        let mut payload = ConsensusPayload::new(
            slot,
            self.keypair.pubkey(),
            aggregate,
            consensus_meta,
            delayed_bankhash,
        );
        payload.sign(&self.keypair);
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    #[test]
    fn test_slot_aggregate() {
        let mut aggregate = SlotAggregate::new();

        aggregate.add_proposer(ProposerAggregation {
            proposer_id: 2,
            merkle_root: make_test_hash(2),
            relay_count: 150,
            attesting_stake: 1000,
        });

        aggregate.add_proposer(ProposerAggregation {
            proposer_id: 0,
            merkle_root: make_test_hash(0),
            relay_count: 180,
            attesting_stake: 1500,
        });

        aggregate.sort();

        assert_eq!(aggregate.proposer_aggregations.len(), 2);
        assert_eq!(aggregate.proposer_aggregations[0].proposer_id, 0);
        assert_eq!(aggregate.proposer_aggregations[1].proposer_id, 2);
        assert_eq!(aggregate.total_attesting_stake, 2500);
    }

    #[test]
    fn test_consensus_payload_signing() {
        let keypair = Keypair::new();
        let builder = ConsensusPayloadBuilder::new(keypair);

        let mut aggregate = SlotAggregate::new();
        aggregate.add_proposer(ProposerAggregation {
            proposer_id: 1,
            merkle_root: make_test_hash(1),
            relay_count: 150,
            attesting_stake: 1000,
        });

        let consensus_meta = ConsensusMeta::new(1234567890, make_test_hash(99), 100);
        let payload = builder.build(500, aggregate, consensus_meta, make_test_hash(50));

        assert!(payload.verify());
        assert_eq!(payload.slot, 500);
        assert_eq!(payload.proposer_id(), CONSENSUS_PAYLOAD_PROPOSER_ID);
    }

    #[test]
    fn test_block_id() {
        let keypair = Keypair::new();
        let builder = ConsensusPayloadBuilder::new(keypair);

        let aggregate = SlotAggregate::new();
        let consensus_meta = ConsensusMeta::new(0, Hash::default(), 0);
        let payload = builder.build(100, aggregate, consensus_meta, Hash::default());

        let block_id = payload.block_id();
        assert_ne!(block_id, Hash::default());

        // Same inputs should produce same block_id
        let builder2 = ConsensusPayloadBuilder::new(Keypair::new());
        let aggregate2 = SlotAggregate::new();
        let consensus_meta2 = ConsensusMeta::new(0, Hash::default(), 0);
        let payload2 = builder2.build(100, aggregate2, consensus_meta2, Hash::default());

        // Different leader = different signing data = different block_id
        assert_ne!(payload.block_id(), payload2.block_id());
    }
}
