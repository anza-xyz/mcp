//! MCP Proposer Shred Distribution
//!
//! This module implements proposer functionality for distributing shreds to relays:
//! - Create shred batch with merkle commitments
//! - Generate merkle witnesses for each relay
//! - Sign and distribute shreds via unicast to relays
//!
//! # Message Format
//!
//! Each shred is sent to relays with the format:
//! (slot, proposer_id, commitment, shred, witness, proposer_sig)
//!
//! - slot: The slot number
//! - proposer_id: This proposer's ID (0-15)
//! - commitment: Merkle root of the shred batch
//! - shred: The actual shred data
//! - witness: Merkle proof for this shred's position
//! - proposer_sig: Signature over (slot, proposer_id, commitment)

use {
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    solana_signer::Signer,
    std::net::SocketAddr,
};

// Re-export MCP constants from canonical source (ledger/src/mcp.rs)
pub use solana_ledger::mcp::{NUM_PROPOSERS, NUM_RELAYS};

/// A shred ready for distribution to relays.
#[derive(Debug, Clone)]
pub struct ProposerShred {
    /// The slot this shred belongs to.
    pub slot: u64,
    /// This proposer's ID.
    pub proposer_id: u8,
    /// The shred index within this proposer's batch.
    pub shred_index: u32,
    /// The raw shred data.
    pub data: Vec<u8>,
}

/// A complete shred batch from a proposer with merkle commitment.
#[derive(Debug)]
pub struct ProposerShredBatch {
    /// The slot this batch is for.
    pub slot: u64,
    /// This proposer's ID.
    pub proposer_id: u8,
    /// The merkle root (commitment) of all shreds in the batch.
    pub commitment: Hash,
    /// Individual shreds with their merkle witnesses.
    pub shreds: Vec<ShredWithWitness>,
}

/// A shred paired with its merkle witness.
#[derive(Debug, Clone)]
pub struct ShredWithWitness {
    /// The shred index.
    pub index: u32,
    /// The raw shred data.
    pub data: Vec<u8>,
    /// The merkle proof for this shred.
    pub witness: Vec<u8>,
}

/// Wire message for distributing a shred to a relay.
#[derive(Debug, Clone)]
pub struct RelayShredMessage {
    /// The slot this shred belongs to.
    pub slot: u64,
    /// The proposer's ID.
    pub proposer_id: u8,
    /// The shred index within the FEC block.
    pub shred_index: u32,
    /// The merkle root commitment.
    pub commitment: Hash,
    /// The raw shred data.
    pub shred_data: Vec<u8>,
    /// The merkle witness for this shred.
    pub witness: Vec<u8>,
    /// The proposer's signature over (slot, proposer_id, shred_index, commitment).
    pub proposer_signature: Signature,
}

impl RelayShredMessage {
    /// Get the data that was signed by the proposer.
    ///
    /// The signature binds to (slot, proposer_id, shred_index, commitment) to prevent
    /// replay of signatures across different shreds.
    pub fn get_signing_data(slot: u64, proposer_id: u8, shred_index: u32, commitment: &Hash) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 1 + 4 + 32);
        data.extend_from_slice(&slot.to_le_bytes());
        data.push(proposer_id);
        data.extend_from_slice(&shred_index.to_le_bytes());
        data.extend_from_slice(commitment.as_ref());
        data
    }

    /// Serialize the message for network transmission.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // slot (8 bytes)
        buffer.extend_from_slice(&self.slot.to_le_bytes());

        // proposer_id (1 byte)
        buffer.push(self.proposer_id);

        // shred_index (4 bytes) - NEW
        buffer.extend_from_slice(&self.shred_index.to_le_bytes());

        // commitment (32 bytes)
        buffer.extend_from_slice(self.commitment.as_ref());

        // shred_data_len (4 bytes) + shred_data
        buffer.extend_from_slice(&(self.shred_data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&self.shred_data);

        // witness_len (2 bytes) + witness
        buffer.extend_from_slice(&(self.witness.len() as u16).to_le_bytes());
        buffer.extend_from_slice(&self.witness);

        // proposer_signature (64 bytes)
        buffer.extend_from_slice(self.proposer_signature.as_ref());

        buffer
    }

    /// Deserialize a message from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        // Minimum size: slot(8) + proposer_id(1) + shred_index(4) + commitment(32) + shred_data_len(4) + witness_len(2) + sig(64)
        if data.len() < 8 + 1 + 4 + 32 + 4 + 2 + 64 {
            return None;
        }

        let mut offset = 0;

        // slot
        let slot = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        // proposer_id
        let proposer_id = data[offset];
        offset += 1;

        // shred_index - NEW
        let shred_index = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        // commitment
        let commitment = Hash::from(<[u8; 32]>::try_from(&data[offset..offset + 32]).ok()?);
        offset += 32;

        // shred_data_len + shred_data
        let shred_data_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;
        if data.len() < offset + shred_data_len {
            return None;
        }
        let shred_data = data[offset..offset + shred_data_len].to_vec();
        offset += shred_data_len;

        // witness_len + witness
        if data.len() < offset + 2 {
            return None;
        }
        let witness_len = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
        offset += 2;
        if data.len() < offset + witness_len {
            return None;
        }
        let witness = data[offset..offset + witness_len].to_vec();
        offset += witness_len;

        // proposer_signature
        if data.len() < offset + 64 {
            return None;
        }
        let sig_bytes: [u8; 64] = data[offset..offset + 64].try_into().ok()?;
        let proposer_signature = Signature::from(sig_bytes);

        Some(Self {
            slot,
            proposer_id,
            shred_index,
            commitment,
            shred_data,
            witness,
            proposer_signature,
        })
    }

    /// Verify the proposer's signature.
    pub fn verify_signature(&self, proposer_pubkey: &Pubkey) -> bool {
        let signing_data = Self::get_signing_data(
            self.slot,
            self.proposer_id,
            self.shred_index,
            &self.commitment,
        );
        self.proposer_signature.verify(proposer_pubkey.as_ref(), &signing_data)
    }
}

/// Proposer shred distributor.
///
/// Handles creating shred batches and distributing them to relays.
pub struct ProposerDistributor {
    /// This proposer's ID.
    proposer_id: u8,
    /// This proposer's keypair for signing.
    keypair: Keypair,
}

impl ProposerDistributor {
    /// Create a new proposer distributor.
    pub fn new(proposer_id: u8, keypair: Keypair) -> Self {
        Self {
            proposer_id,
            keypair,
        }
    }

    /// Get this proposer's ID.
    pub fn proposer_id(&self) -> u8 {
        self.proposer_id
    }

    /// Get this proposer's pubkey.
    pub fn pubkey(&self) -> Pubkey {
        self.keypair.pubkey()
    }

    /// Create messages for distributing a shred batch to relays.
    ///
    /// Returns a vector of (relay_index, message) pairs.
    pub fn prepare_distribution(
        &self,
        batch: &ProposerShredBatch,
    ) -> Vec<(u16, RelayShredMessage)> {
        // Create a message for each shred, with per-shred signature binding
        batch
            .shreds
            .iter()
            .enumerate()
            .map(|(_idx, shred)| {
                let shred_index = shred.index;
                let relay_index = (shred_index as u16) % NUM_RELAYS;

                // Sign each shred individually to bind the signature to this specific shred
                let signing_data = RelayShredMessage::get_signing_data(
                    batch.slot,
                    batch.proposer_id,
                    shred_index,
                    &batch.commitment,
                );
                let signature = self.keypair.sign_message(&signing_data);

                let message = RelayShredMessage {
                    slot: batch.slot,
                    proposer_id: batch.proposer_id,
                    shred_index,
                    commitment: batch.commitment,
                    shred_data: shred.data.clone(),
                    witness: shred.witness.clone(),
                    proposer_signature: signature,
                };
                (relay_index, message)
            })
            .collect()
    }

    /// Create a signed relay shred message.
    pub fn create_message(
        &self,
        slot: u64,
        shred_index: u32,
        commitment: Hash,
        shred_data: Vec<u8>,
        witness: Vec<u8>,
    ) -> RelayShredMessage {
        let signing_data =
            RelayShredMessage::get_signing_data(slot, self.proposer_id, shred_index, &commitment);
        let signature = self.keypair.sign_message(&signing_data);

        RelayShredMessage {
            slot,
            proposer_id: self.proposer_id,
            shred_index,
            commitment,
            shred_data,
            witness,
            proposer_signature: signature,
        }
    }
}

/// Target information for a relay.
#[derive(Debug, Clone)]
pub struct RelayTarget {
    /// The relay's index in the schedule.
    pub relay_index: u16,
    /// The relay's pubkey.
    pub pubkey: Pubkey,
    /// The relay's network address for shred reception.
    pub addr: SocketAddr,
}

/// Distribution plan for sending shreds to relays.
#[derive(Debug)]
pub struct DistributionPlan {
    /// Messages to send, paired with target relay info.
    pub messages: Vec<(RelayTarget, RelayShredMessage)>,
}

impl DistributionPlan {
    /// Create a new distribution plan.
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    /// Add a message to the plan.
    pub fn add(&mut self, target: RelayTarget, message: RelayShredMessage) {
        self.messages.push((target, message));
    }

    /// Get the number of messages in the plan.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Check if the plan is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

impl Default for DistributionPlan {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    #[test]
    fn test_relay_shred_message_serialization() {
        let msg = RelayShredMessage {
            slot: 12345,
            proposer_id: 5,
            shred_index: 42,
            commitment: make_test_hash(42),
            shred_data: vec![1, 2, 3, 4, 5],
            witness: vec![10, 20, 30],
            proposer_signature: Signature::from([0xAB; 64]),
        };

        let serialized = msg.serialize();
        let deserialized = RelayShredMessage::deserialize(&serialized).unwrap();

        assert_eq!(msg.slot, deserialized.slot);
        assert_eq!(msg.proposer_id, deserialized.proposer_id);
        assert_eq!(msg.shred_index, deserialized.shred_index);
        assert_eq!(msg.commitment, deserialized.commitment);
        assert_eq!(msg.shred_data, deserialized.shred_data);
        assert_eq!(msg.witness, deserialized.witness);
        assert_eq!(msg.proposer_signature, deserialized.proposer_signature);
    }

    #[test]
    fn test_proposer_distributor() {
        let keypair = Keypair::new();
        let distributor = ProposerDistributor::new(3, keypair);

        assert_eq!(distributor.proposer_id(), 3);

        let message = distributor.create_message(
            100,
            7, // shred_index
            make_test_hash(1),
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        assert_eq!(message.slot, 100);
        assert_eq!(message.proposer_id, 3);
        assert_eq!(message.shred_index, 7);
        assert_eq!(message.shred_data, vec![1, 2, 3]);
        assert_eq!(message.witness, vec![4, 5, 6]);
    }

    #[test]
    fn test_distribution_plan() {
        let mut plan = DistributionPlan::new();
        assert!(plan.is_empty());

        let target = RelayTarget {
            relay_index: 0,
            pubkey: Pubkey::new_unique(),
            addr: "127.0.0.1:8000".parse().unwrap(),
        };

        let msg = RelayShredMessage {
            slot: 100,
            proposer_id: 1,
            shred_index: 0,
            commitment: make_test_hash(1),
            shred_data: vec![1],
            witness: vec![2],
            proposer_signature: Signature::default(),
        };

        plan.add(target, msg);
        assert_eq!(plan.len(), 1);
        assert!(!plan.is_empty());
    }

    #[test]
    fn test_signing_data() {
        let slot = 12345u64;
        let proposer_id = 5u8;
        let shred_index = 99u32;
        let commitment = make_test_hash(42);

        let data = RelayShredMessage::get_signing_data(slot, proposer_id, shred_index, &commitment);

        // Should be 8 + 1 + 4 + 32 = 45 bytes
        assert_eq!(data.len(), 45);

        // Verify slot bytes
        assert_eq!(&data[0..8], &slot.to_le_bytes());

        // Verify proposer_id
        assert_eq!(data[8], proposer_id);

        // Verify shred_index
        assert_eq!(&data[9..13], &shred_index.to_le_bytes());

        // Verify commitment
        assert_eq!(&data[13..45], commitment.as_ref());
    }
}
