//! MCP Attestation Service
//!
//! This module implements relay attestation submission and consensus leader
//! aggregation for MCP:
//!
//! # Relay Side (MCP-11)
//! - Build RelayAttestation v1 at relay deadline
//! - Sign and submit attestation to consensus leader
//!
//! # Consensus Leader Side (MCP-12)
//! - Receive and verify relay attestations
//! - Aggregate attestations, dropping equivocations
//! - Compute block_id = hash(canonical_aggregate)
//! - Persist AggregateAttestation

use {
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    solana_signer::Signer,
    std::collections::{HashMap, HashSet},
};

// Re-export MCP constants from canonical source (ledger/src/mcp.rs)
pub use solana_ledger::mcp::{NUM_PROPOSERS, NUM_RELAYS};

/// Attestation threshold as percentage (60%).
/// Note: This matches ATTESTATION_THRESHOLD in ledger/src/mcp.rs
pub const ATTESTATION_THRESHOLD_PERCENT: u8 = 60;

// ============================================================================
// Relay Attestation (from MCP-10, used here)
// ============================================================================

/// A single entry in a relay attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttestationEntry {
    /// The proposer ID (0-15).
    pub proposer_id: u8,
    /// The merkle root of the proposer's shred batch.
    pub merkle_root: Hash,
}

impl AttestationEntry {
    /// Create a new attestation entry.
    pub const fn new(proposer_id: u8, merkle_root: Hash) -> Self {
        Self {
            proposer_id,
            merkle_root,
        }
    }
}

/// Wire message for submitting attestation to consensus leader.
#[derive(Debug, Clone)]
pub struct AttestationMessage {
    /// Wire format version.
    pub version: u8,
    /// The slot this attestation is for.
    pub slot: u64,
    /// The relay's ID.
    pub relay_id: u16,
    /// Attestation entries, sorted by proposer_id.
    pub entries: Vec<AttestationEntry>,
    /// The relay's signature.
    pub relay_signature: Signature,
}

impl AttestationMessage {
    /// Current wire format version.
    pub const VERSION: u8 = 1;

    /// Create a new attestation message.
    pub fn new(slot: u64, relay_id: u16, mut entries: Vec<AttestationEntry>) -> Self {
        entries.sort();
        Self {
            version: Self::VERSION,
            slot,
            relay_id,
            entries,
            relay_signature: Signature::default(),
        }
    }

    /// Get the data to be signed.
    pub fn get_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.version);
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(&self.relay_id.to_le_bytes());
        data.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for entry in &self.entries {
            data.push(entry.proposer_id);
            data.extend_from_slice(entry.merkle_root.as_ref());
        }
        data
    }

    /// Sign the attestation with the relay's keypair.
    pub fn sign(&mut self, keypair: &Keypair) {
        let data = self.get_signing_data();
        self.relay_signature = keypair.sign_message(&data);
    }

    /// Verify the relay's signature.
    pub fn verify(&self, relay_pubkey: &Pubkey) -> bool {
        let data = self.get_signing_data();
        self.relay_signature.verify(relay_pubkey.as_ref(), &data)
    }

    /// Serialize the message for network transmission.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.push(self.version);
        buffer.extend_from_slice(&self.slot.to_le_bytes());
        buffer.extend_from_slice(&self.relay_id.to_le_bytes());
        buffer.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());

        for entry in &self.entries {
            buffer.push(entry.proposer_id);
            buffer.extend_from_slice(entry.merkle_root.as_ref());
        }

        buffer.extend_from_slice(self.relay_signature.as_ref());
        buffer
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 1 + 8 + 2 + 2 + 64 {
            return None;
        }

        let mut offset = 0;

        let version = data[offset];
        offset += 1;

        let slot = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let relay_id = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
        offset += 2;

        let entries_len = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
        offset += 2;

        if data.len() < offset + entries_len * 33 + 64 {
            return None;
        }

        let mut entries = Vec::with_capacity(entries_len);
        for _ in 0..entries_len {
            let proposer_id = data[offset];
            offset += 1;
            let merkle_root = Hash::from(<[u8; 32]>::try_from(&data[offset..offset + 32]).ok()?);
            offset += 32;
            entries.push(AttestationEntry::new(proposer_id, merkle_root));
        }

        let sig_bytes: [u8; 64] = data[offset..offset + 64].try_into().ok()?;
        let relay_signature = Signature::from(sig_bytes);

        Some(Self {
            version,
            slot,
            relay_id,
            entries,
            relay_signature,
        })
    }
}

// ============================================================================
// Relay Attestation Builder (MCP-11)
// ============================================================================

/// Builds relay attestations from received shreds.
pub struct RelayAttestationBuilder {
    /// This relay's ID.
    relay_id: u16,
    /// This relay's keypair.
    keypair: Keypair,
}

impl RelayAttestationBuilder {
    /// Create a new attestation builder.
    pub fn new(relay_id: u16, keypair: Keypair) -> Self {
        Self { relay_id, keypair }
    }

    /// Build and sign an attestation for the given slot.
    ///
    /// `commitments` maps proposer_id to merkle_root for all proposers
    /// whose shreds were received and verified.
    pub fn build_attestation(
        &self,
        slot: u64,
        commitments: &HashMap<u8, Hash>,
    ) -> AttestationMessage {
        let entries: Vec<_> = commitments
            .iter()
            .map(|(&proposer_id, &merkle_root)| AttestationEntry::new(proposer_id, merkle_root))
            .collect();

        let mut attestation = AttestationMessage::new(slot, self.relay_id, entries);
        attestation.sign(&self.keypair);
        attestation
    }

    /// Get this relay's pubkey.
    pub fn pubkey(&self) -> Pubkey {
        self.keypair.pubkey()
    }
}

// ============================================================================
// Aggregated Attestation (MCP-12)
// ============================================================================

/// An entry in the aggregated attestation.
#[derive(Debug, Clone)]
pub struct AggregatedProposerEntry {
    /// The proposer ID.
    pub proposer_id: u8,
    /// The merkle root for this proposer.
    pub merkle_root: Hash,
    /// Relay IDs that attested to this (proposer_id, merkle_root) pair.
    pub relay_ids: Vec<u16>,
    /// Total stake of attesting relays.
    pub attesting_stake: u64,
}

/// Aggregated attestations from all relays for a slot.
#[derive(Debug, Clone)]
pub struct AggregateAttestation {
    /// The slot this aggregate is for.
    pub slot: u64,
    /// Aggregated entries per proposer.
    pub entries: Vec<AggregatedProposerEntry>,
    /// The canonical block ID: hash of the aggregate.
    pub block_id: Hash,
}

impl AggregateAttestation {
    /// Serialize for hashing to compute block_id.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());

        for entry in &self.entries {
            data.push(entry.proposer_id);
            data.extend_from_slice(entry.merkle_root.as_ref());
            data.extend_from_slice(&(entry.relay_ids.len() as u16).to_le_bytes());
            for &relay_id in &entry.relay_ids {
                data.extend_from_slice(&relay_id.to_le_bytes());
            }
            data.extend_from_slice(&entry.attesting_stake.to_le_bytes());
        }

        data
    }

    /// Compute the block_id from the canonical aggregate.
    pub fn compute_block_id(&mut self) {
        let bytes = self.canonical_bytes();
        self.block_id = solana_sha256_hasher::hash(&bytes);
    }
}

// ============================================================================
// Consensus Leader Attestation Aggregator (MCP-12)
// ============================================================================

/// Detects equivocations (relay attesting to different merkle roots for same proposer).
#[derive(Debug, Clone)]
pub struct Equivocation {
    /// The relay that equivocated.
    pub relay_id: u16,
    /// The proposer involved.
    pub proposer_id: u8,
    /// First merkle root seen.
    pub merkle_root_1: Hash,
    /// Second (conflicting) merkle root seen.
    pub merkle_root_2: Hash,
}

/// Aggregates relay attestations for a slot.
pub struct AttestationAggregator {
    /// The slot being aggregated.
    slot: u64,
    /// Maps relay_id to their verified attestation.
    relay_attestations: HashMap<u16, AttestationMessage>,
    /// Maps relay_id to their stake.
    relay_stakes: HashMap<u16, u64>,
    /// Maps relay_id to their pubkey for signature verification.
    relay_pubkeys: HashMap<u16, Pubkey>,
    /// Total stake of all relays.
    total_stake: u64,
    /// Detected equivocations.
    equivocations: Vec<Equivocation>,
    /// Relay IDs that have been dropped due to equivocation.
    dropped_relays: HashSet<u16>,
}

impl AttestationAggregator {
    /// Create a new aggregator for a slot.
    ///
    /// # Arguments
    ///
    /// * `slot` - The slot being aggregated
    /// * `relay_stakes` - Maps relay_id to their stake
    /// * `relay_pubkeys` - Maps relay_id to their pubkey for signature verification
    pub fn new(
        slot: u64,
        relay_stakes: HashMap<u16, u64>,
        relay_pubkeys: HashMap<u16, Pubkey>,
    ) -> Self {
        let total_stake = relay_stakes.values().sum();
        Self {
            slot,
            relay_attestations: HashMap::new(),
            relay_stakes,
            relay_pubkeys,
            total_stake,
            equivocations: Vec::new(),
            dropped_relays: HashSet::new(),
        }
    }

    /// Add an attestation from a relay after verifying its signature.
    ///
    /// Returns any equivocation detected. Returns None if:
    /// - Slot doesn't match
    /// - Relay pubkey is unknown
    /// - Signature verification fails
    pub fn add_attestation(
        &mut self,
        attestation: AttestationMessage,
    ) -> Option<Equivocation> {
        if attestation.slot != self.slot {
            return None; // Wrong slot
        }

        let relay_id = attestation.relay_id;

        // Per spec: verify relay signature before processing
        let relay_pubkey = match self.relay_pubkeys.get(&relay_id) {
            Some(pubkey) => pubkey,
            None => return None, // Unknown relay
        };

        if !attestation.verify(relay_pubkey) {
            return None; // Invalid signature
        }

        // Check for equivocation with previous attestation
        if let Some(prev) = self.relay_attestations.get(&relay_id) {
            for entry in &attestation.entries {
                if let Some(prev_entry) = prev
                    .entries
                    .iter()
                    .find(|e| e.proposer_id == entry.proposer_id)
                {
                    if prev_entry.merkle_root != entry.merkle_root {
                        let equivocation = Equivocation {
                            relay_id,
                            proposer_id: entry.proposer_id,
                            merkle_root_1: prev_entry.merkle_root,
                            merkle_root_2: entry.merkle_root,
                        };
                        self.equivocations.push(equivocation.clone());
                        self.dropped_relays.insert(relay_id);
                        return Some(equivocation);
                    }
                }
            }
        }

        self.relay_attestations.insert(relay_id, attestation);
        None
    }

    /// Build the aggregate attestation.
    pub fn build_aggregate(&self) -> AggregateAttestation {
        // Collect all (proposer_id, merkle_root) -> relay_ids
        let mut proposer_votes: HashMap<(u8, Hash), Vec<u16>> = HashMap::new();

        for (&relay_id, attestation) in &self.relay_attestations {
            if self.dropped_relays.contains(&relay_id) {
                continue; // Skip equivocating relays
            }

            for entry in &attestation.entries {
                proposer_votes
                    .entry((entry.proposer_id, entry.merkle_root))
                    .or_default()
                    .push(relay_id);
            }
        }

        // For each proposer, pick the merkle root with most stake
        let mut proposer_entries: HashMap<u8, AggregatedProposerEntry> = HashMap::new();

        for ((proposer_id, merkle_root), relay_ids) in proposer_votes {
            let stake: u64 = relay_ids
                .iter()
                .filter_map(|id| self.relay_stakes.get(id))
                .sum();

            let entry = proposer_entries.entry(proposer_id).or_insert_with(|| {
                AggregatedProposerEntry {
                    proposer_id,
                    merkle_root,
                    relay_ids: Vec::new(),
                    attesting_stake: 0,
                }
            });

            // Keep the merkle root with higher stake
            if stake > entry.attesting_stake {
                entry.merkle_root = merkle_root;
                entry.relay_ids = relay_ids;
                entry.attesting_stake = stake;
            }
        }

        let mut entries: Vec<_> = proposer_entries.into_values().collect();
        entries.sort_by_key(|e| e.proposer_id);

        let mut aggregate = AggregateAttestation {
            slot: self.slot,
            entries,
            block_id: Hash::default(),
        };
        aggregate.compute_block_id();
        aggregate
    }

    /// Check if we have enough attestations to proceed.
    ///
    /// Returns true if attesting stake meets threshold.
    pub fn has_threshold(&self) -> bool {
        let attesting_stake: u64 = self
            .relay_attestations
            .keys()
            .filter(|id| !self.dropped_relays.contains(id))
            .filter_map(|id| self.relay_stakes.get(id))
            .sum();

        let threshold = (self.total_stake * ATTESTATION_THRESHOLD_PERCENT as u64) / 100;
        attesting_stake >= threshold
    }

    /// Get the number of attestations received.
    pub fn attestation_count(&self) -> usize {
        self.relay_attestations.len() - self.dropped_relays.len()
    }

    /// Get detected equivocations.
    pub fn equivocations(&self) -> &[Equivocation] {
        &self.equivocations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    #[test]
    fn test_attestation_message_serialization() {
        let entries = vec![
            AttestationEntry::new(1, make_test_hash(1)),
            AttestationEntry::new(5, make_test_hash(5)),
        ];

        let mut msg = AttestationMessage::new(100, 42, entries);
        let keypair = Keypair::new();
        msg.sign(&keypair);

        let serialized = msg.serialize();
        let deserialized = AttestationMessage::deserialize(&serialized).unwrap();

        assert_eq!(msg.slot, deserialized.slot);
        assert_eq!(msg.relay_id, deserialized.relay_id);
        assert_eq!(msg.entries.len(), deserialized.entries.len());
        assert!(deserialized.verify(&keypair.pubkey()));
    }

    #[test]
    fn test_relay_attestation_builder() {
        let keypair = Keypair::new();
        let builder = RelayAttestationBuilder::new(10, keypair.insecure_clone());

        let mut commitments = HashMap::new();
        commitments.insert(1u8, make_test_hash(1));
        commitments.insert(5u8, make_test_hash(5));

        let attestation = builder.build_attestation(100, &commitments);

        assert_eq!(attestation.slot, 100);
        assert_eq!(attestation.relay_id, 10);
        assert_eq!(attestation.entries.len(), 2);
        assert!(attestation.verify(&builder.pubkey()));
    }

    #[test]
    fn test_attestation_aggregator() {
        // Create keypairs for each relay first
        let keypairs: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();

        let mut stakes = HashMap::new();
        let mut pubkeys = HashMap::new();
        for (relay_id, keypair) in keypairs.iter().enumerate() {
            stakes.insert(relay_id as u16, 100);
            pubkeys.insert(relay_id as u16, keypair.pubkey());
        }

        let mut aggregator = AttestationAggregator::new(100, stakes, pubkeys);

        // Add attestations from three relays
        for (relay_id, keypair) in keypairs.iter().enumerate() {
            let entries = vec![
                AttestationEntry::new(1, make_test_hash(1)),
                AttestationEntry::new(2, make_test_hash(2)),
            ];
            let mut msg = AttestationMessage::new(100, relay_id as u16, entries);
            msg.sign(keypair);
            aggregator.add_attestation(msg);
        }

        assert_eq!(aggregator.attestation_count(), 3);
        assert!(aggregator.has_threshold()); // 100% > 60%

        let aggregate = aggregator.build_aggregate();
        assert_eq!(aggregate.slot, 100);
        assert_eq!(aggregate.entries.len(), 2);
        assert_ne!(aggregate.block_id, Hash::default());
    }

    #[test]
    fn test_equivocation_detection() {
        let keypair = Keypair::new();

        let mut stakes = HashMap::new();
        stakes.insert(0u16, 100);

        let mut pubkeys = HashMap::new();
        pubkeys.insert(0u16, keypair.pubkey());

        let mut aggregator = AttestationAggregator::new(100, stakes, pubkeys);

        // First attestation
        let entries1 = vec![AttestationEntry::new(1, make_test_hash(1))];
        let mut msg1 = AttestationMessage::new(100, 0, entries1);
        msg1.sign(&keypair);
        assert!(aggregator.add_attestation(msg1).is_none());

        // Second attestation with different merkle root - equivocation!
        let entries2 = vec![AttestationEntry::new(1, make_test_hash(99))];
        let mut msg2 = AttestationMessage::new(100, 0, entries2);
        msg2.sign(&keypair);
        assert!(aggregator.add_attestation(msg2).is_some());

        assert_eq!(aggregator.equivocations().len(), 1);
        assert_eq!(aggregator.attestation_count(), 0); // Relay was dropped
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let keypair = Keypair::new();
        let wrong_keypair = Keypair::new();

        let mut stakes = HashMap::new();
        stakes.insert(0u16, 100);

        let mut pubkeys = HashMap::new();
        pubkeys.insert(0u16, keypair.pubkey()); // Register correct pubkey

        let mut aggregator = AttestationAggregator::new(100, stakes, pubkeys);

        // Create attestation signed with wrong key
        let entries = vec![AttestationEntry::new(1, make_test_hash(1))];
        let mut msg = AttestationMessage::new(100, 0, entries);
        msg.sign(&wrong_keypair); // Sign with wrong key

        // Should be rejected (returns None without adding)
        assert!(aggregator.add_attestation(msg).is_none());
        assert_eq!(aggregator.attestation_count(), 0);
    }

    #[test]
    fn test_unknown_relay_rejected() {
        let keypair = Keypair::new();

        let mut stakes = HashMap::new();
        stakes.insert(0u16, 100);

        let mut pubkeys = HashMap::new();
        // Don't register relay 0's pubkey

        let mut aggregator = AttestationAggregator::new(100, stakes, pubkeys);

        let entries = vec![AttestationEntry::new(1, make_test_hash(1))];
        let mut msg = AttestationMessage::new(100, 0, entries);
        msg.sign(&keypair);

        // Should be rejected (unknown relay)
        assert!(aggregator.add_attestation(msg).is_none());
        assert_eq!(aggregator.attestation_count(), 0);
    }
}
