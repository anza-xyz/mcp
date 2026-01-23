//! MCP Relay Attestation Service
//!
//! This module provides the relay attestation flow for MCP:
//! 1. Relays track received shreds from proposers
//! 2. Once enough shreds are received, relays create attestations
//! 3. Attestations are submitted to the consensus leader
//! 4. The leader aggregates attestations to build the MCP block
//!
//! Per MCP spec:
//! - Each relay attests to the proposers whose shreds it has received and verified
//! - Attestations include the merkle commitment for each proposer
//! - The leader needs attestations from >= 60% of relays to finalize a slot

use {
    crate::mcp_consensus_block::MIN_RELAYS_IN_BLOCK,
    solana_clock::Slot,
    solana_gossip::cluster_info::ClusterInfo,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::{
        leader_schedule_cache::LeaderScheduleCache,
        mcp_attestation::{RelayAttestation, RelayAttestationBuilder},
    },
    solana_runtime::bank_forks::BankForks,
    solana_signer::Signer,
    std::{
        collections::HashMap,
        io,
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicU64, Ordering},
            RwLock,
        },
        time::{Duration, Instant},
    },
};

/// Minimum number of shreds needed from a proposer to attest (per spec: 40 data shreds)
pub const MIN_SHREDS_FOR_ATTESTATION: usize = 40;

/// Timeout for waiting for shreds before creating attestation
pub const ATTESTATION_TIMEOUT: Duration = Duration::from_millis(400);

/// How often to check for attestation readiness
pub const ATTESTATION_CHECK_INTERVAL: Duration = Duration::from_millis(50);

/// Minimum percentage of relays needed for block finalization
pub const MIN_RELAY_PERCENTAGE: f64 = 0.60;

/// Minimum number of relays needed (ceil(0.60 * 200) = 120)
/// Re-exported from mcp_consensus_block for convenience
pub const MIN_RELAYS_FOR_BLOCK: usize = MIN_RELAYS_IN_BLOCK;

/// Tracks shreds received from a single proposer.
#[derive(Debug, Default)]
pub struct ProposerShredTracker {
    /// Merkle commitment (same for all shreds from this proposer)
    pub commitment: Option<Hash>,
    /// Proposer's signature over the commitment (from the shred)
    pub proposer_signature: Option<solana_signature::Signature>,
    /// Indices of received shreds
    pub received_indices: Vec<u32>,
    /// When the first shred was received
    pub first_received: Option<Instant>,
}

impl ProposerShredTracker {
    /// Record a received shred.
    pub fn record_shred(
        &mut self,
        shred_index: u32,
        commitment: Hash,
        proposer_signature: solana_signature::Signature,
    ) {
        if self.commitment.is_none() {
            self.commitment = Some(commitment);
            self.proposer_signature = Some(proposer_signature);
            self.first_received = Some(Instant::now());
        }
        if !self.received_indices.contains(&shred_index) {
            self.received_indices.push(shred_index);
        }
    }

    /// Check if we have enough shreds to attest.
    pub fn can_attest(&self) -> bool {
        self.received_indices.len() >= MIN_SHREDS_FOR_ATTESTATION
    }

    /// Get the number of received shreds.
    pub fn shred_count(&self) -> usize {
        self.received_indices.len()
    }
}

/// Tracks all proposer shreds for a slot.
#[derive(Debug, Default)]
pub struct SlotShredState {
    /// Per-proposer tracking
    pub proposers: HashMap<u32, ProposerShredTracker>,
    /// When tracking started for this slot
    pub started: Option<Instant>,
    /// Whether attestation has been sent
    pub attestation_sent: bool,
}

impl SlotShredState {
    /// Create a new slot state.
    pub fn new() -> Self {
        Self {
            proposers: HashMap::new(),
            started: Some(Instant::now()),
            attestation_sent: false,
        }
    }

    /// Record a received shred.
    pub fn record_shred(
        &mut self,
        proposer_id: u32,
        shred_index: u32,
        commitment: Hash,
        proposer_signature: solana_signature::Signature,
    ) {
        self.proposers
            .entry(proposer_id)
            .or_default()
            .record_shred(shred_index, commitment, proposer_signature);
    }

    /// Get proposers that have enough shreds for attestation.
    /// Returns (proposer_id, commitment, proposer_signature) tuples.
    pub fn attestable_proposers(&self) -> Vec<(u32, Hash, solana_signature::Signature)> {
        self.proposers
            .iter()
            .filter(|(_, tracker)| tracker.can_attest())
            .filter_map(|(id, tracker)| {
                tracker.commitment.and_then(|c| {
                    tracker.proposer_signature.map(|s| (*id, c, s))
                })
            })
            .collect()
    }

    /// Check if we should send attestation (timeout or enough data).
    pub fn should_send_attestation(&self) -> bool {
        if self.attestation_sent {
            return false;
        }

        // Check timeout
        if let Some(started) = self.started {
            if started.elapsed() >= ATTESTATION_TIMEOUT {
                return true;
            }
        }

        // Check if we have attestable proposers
        !self.attestable_proposers().is_empty()
    }
}

/// Message to record a received shred.
#[derive(Debug, Clone)]
pub struct ReceivedShredInfo {
    pub slot: Slot,
    pub proposer_id: u32,
    pub shred_index: u32,
    pub commitment: Hash,
    pub proposer_signature: solana_signature::Signature,
}

/// A signed attestation ready for submission.
#[derive(Debug, Clone)]
pub struct SignedAttestation {
    pub attestation: RelayAttestation,
    pub leader_addr: Option<SocketAddr>,
}

/// Configuration for the relay attestation service.
#[derive(Debug, Clone)]
pub struct RelayAttestationConfig {
    /// This relay's index in the schedule (u32 per spec §7.3)
    pub relay_index: u32,
    /// Maximum slots to track
    pub max_tracked_slots: usize,
}

impl Default for RelayAttestationConfig {
    fn default() -> Self {
        Self {
            relay_index: 0,
            max_tracked_slots: 32,
        }
    }
}

/// Service that manages relay attestation creation and submission.
pub struct RelayAttestationService {
    /// Configuration
    config: RelayAttestationConfig,
    /// Per-slot state
    slot_states: HashMap<Slot, SlotShredState>,
    /// Current slot (for cleanup)
    current_slot: Slot,
    /// Statistics
    stats: RelayAttestationStats,
}

/// Statistics for the relay attestation service.
#[derive(Debug, Default)]
pub struct RelayAttestationStats {
    pub shreds_received: AtomicU64,
    pub attestations_created: AtomicU64,
    pub attestations_sent: AtomicU64,
}

impl RelayAttestationService {
    /// Create a new relay attestation service.
    pub fn new(config: RelayAttestationConfig) -> Self {
        Self {
            config,
            slot_states: HashMap::new(),
            current_slot: 0,
            stats: RelayAttestationStats::default(),
        }
    }

    /// Record a received shred.
    pub fn record_shred(&mut self, info: ReceivedShredInfo) {
        self.stats.shreds_received.fetch_add(1, Ordering::Relaxed);

        // Update current slot if needed
        if info.slot > self.current_slot {
            self.current_slot = info.slot;
            self.cleanup_old_slots();
        }

        // Record the shred
        let state = self
            .slot_states
            .entry(info.slot)
            .or_insert_with(SlotShredState::new);
        state.record_shred(
            info.proposer_id,
            info.shred_index,
            info.commitment,
            info.proposer_signature,
        );
    }

    /// Check if we should create an attestation for any slot.
    /// Returns the slot and attestable proposers (with their signatures) if ready.
    pub fn check_attestation_ready(
        &mut self,
    ) -> Option<(Slot, Vec<(u32, Hash, solana_signature::Signature)>)> {
        for (&slot, state) in &mut self.slot_states {
            if state.should_send_attestation() && !state.attestation_sent {
                let proposers = state.attestable_proposers();
                if !proposers.is_empty() {
                    state.attestation_sent = true;
                    return Some((slot, proposers));
                }
            }
        }
        None
    }

    /// Create a signed attestation.
    pub fn create_attestation(
        &mut self,
        slot: Slot,
        proposers: Vec<(u32, Hash, solana_signature::Signature)>,
        keypair: &Keypair,
    ) -> RelayAttestation {
        let mut builder = RelayAttestationBuilder::new(slot, self.config.relay_index);

        for (proposer_id, commitment, proposer_signature) in proposers {
            builder = builder.add_entry(proposer_id, commitment, proposer_signature);
        }

        let unsigned = builder.build_unsigned();
        let signing_data = unsigned.get_signing_data();
        let signature = keypair.sign_message(&signing_data);

        self.stats.attestations_created.fetch_add(1, Ordering::Relaxed);

        RelayAttestation::new_signed(
            slot,
            self.config.relay_index,
            unsigned.entries,
            signature,
        )
    }

    /// Cleanup old slot states.
    fn cleanup_old_slots(&mut self) {
        let min_slot = self
            .current_slot
            .saturating_sub(self.config.max_tracked_slots as u64);
        self.slot_states.retain(|&slot, _| slot >= min_slot);
    }

    /// Get the current relay index.
    pub fn relay_index(&self) -> u32 {
        self.config.relay_index
    }

    /// Get statistics.
    pub fn stats(&self) -> &RelayAttestationStats {
        &self.stats
    }
}

// ============================================================================
// Attestation Aggregator (for consensus leader)
// ============================================================================

/// Tracks attestations from relays for a slot.
#[derive(Debug, Default)]
pub struct SlotAttestations {
    /// Attestations indexed by relay_index (u32 per spec §7.3)
    pub attestations: HashMap<u32, RelayAttestation>,
    /// Per-proposer attestation counts
    pub proposer_counts: HashMap<u32, usize>,
}

impl SlotAttestations {
    /// Add an attestation from a relay.
    pub fn add_attestation(&mut self, attestation: RelayAttestation) -> bool {
        let relay_index = attestation.relay_index;

        // Check for duplicate
        if self.attestations.contains_key(&relay_index) {
            return false;
        }

        // Update proposer counts
        for entry in &attestation.entries {
            *self.proposer_counts.entry(entry.proposer_index).or_insert(0) += 1;
        }

        self.attestations.insert(relay_index, attestation);
        true
    }

    /// Get the number of unique relays that have attested.
    pub fn relay_count(&self) -> usize {
        self.attestations.len()
    }

    /// Check if we have enough relays for block finalization.
    pub fn has_enough_relays(&self) -> bool {
        self.relay_count() >= MIN_RELAYS_FOR_BLOCK
    }

    /// Get proposers with enough attestations for inclusion.
    /// Per spec: need attestations from >= 40% of relays (80 relays).
    pub fn get_included_proposers(&self) -> Vec<(u32, Hash)> {
        const MIN_ATTESTATIONS_PER_PROPOSER: usize = 80; // ceil(0.40 * 200)

        let mut result = Vec::new();

        for (&proposer_id, &count) in &self.proposer_counts {
            if count >= MIN_ATTESTATIONS_PER_PROPOSER {
                // Get the commitment (should be same from all relays for honest proposer)
                if let Some(commitment) = self.get_proposer_commitment(proposer_id) {
                    result.push((proposer_id, commitment));
                }
            }
        }

        result.sort_by_key(|(id, _)| *id);
        result
    }

    /// Get the commitment for a proposer (from any attestation that includes it).
    fn get_proposer_commitment(&self, proposer_id: u32) -> Option<Hash> {
        for attestation in self.attestations.values() {
            if let Some(root) = attestation.get_commitment(proposer_id) {
                return Some(*root);
            }
        }
        None
    }

    /// Get all attestations for block construction.
    ///
    /// Returns attestations sorted by relay_index for deterministic ordering.
    pub fn get_all_attestations(&self) -> Vec<&RelayAttestation> {
        let mut attestations: Vec<_> = self.attestations.values().collect();
        attestations.sort_by_key(|a| a.relay_index);
        attestations
    }
}

/// Aggregates relay attestations for the consensus leader.
#[derive(Debug, Default)]
pub struct AttestationAggregator {
    /// Per-slot attestation tracking
    slot_attestations: HashMap<Slot, SlotAttestations>,
    /// Maximum slots to track
    max_tracked_slots: usize,
    /// Current slot
    current_slot: Slot,
}

impl AttestationAggregator {
    /// Create a new attestation aggregator.
    pub fn new(max_tracked_slots: usize) -> Self {
        Self {
            slot_attestations: HashMap::new(),
            max_tracked_slots,
            current_slot: 0,
        }
    }

    /// Add an attestation.
    /// Returns true if the attestation was new and added.
    pub fn add_attestation(&mut self, attestation: RelayAttestation) -> bool {
        let slot = attestation.slot;

        // Update current slot
        if slot > self.current_slot {
            self.current_slot = slot;
            self.cleanup_old_slots();
        }

        // Add to slot tracking
        self.slot_attestations
            .entry(slot)
            .or_default()
            .add_attestation(attestation)
    }

    /// Check if a slot has enough attestations for block finalization.
    pub fn can_finalize_slot(&self, slot: Slot) -> bool {
        self.slot_attestations
            .get(&slot)
            .map(|sa| sa.has_enough_relays())
            .unwrap_or(false)
    }

    /// Get the included proposers for a slot.
    pub fn get_included_proposers(&self, slot: Slot) -> Vec<(u32, Hash)> {
        self.slot_attestations
            .get(&slot)
            .map(|sa| sa.get_included_proposers())
            .unwrap_or_default()
    }

    /// Get the number of attestations for a slot.
    pub fn attestation_count(&self, slot: Slot) -> usize {
        self.slot_attestations
            .get(&slot)
            .map(|sa| sa.relay_count())
            .unwrap_or(0)
    }

    /// Get all attestations for a slot for block construction.
    ///
    /// Returns attestations sorted by relay_index for deterministic ordering.
    pub fn get_all_attestations(&self, slot: Slot) -> Vec<&RelayAttestation> {
        self.slot_attestations
            .get(&slot)
            .map(|sa| sa.get_all_attestations())
            .unwrap_or_default()
    }

    /// Cleanup old slots.
    fn cleanup_old_slots(&mut self) {
        let min_slot = self
            .current_slot
            .saturating_sub(self.max_tracked_slots as u64);
        self.slot_attestations.retain(|&slot, _| slot >= min_slot);
    }
}

// ============================================================================
// Attestation Submission
// ============================================================================

/// Submits attestations to the consensus leader via UDP.
pub fn submit_attestation(
    attestation: &RelayAttestation,
    leader_addr: SocketAddr,
    socket: &UdpSocket,
) -> io::Result<()> {
    let mut buffer = Vec::with_capacity(attestation.serialized_size());
    attestation.serialize(&mut buffer)?;
    socket.send_to(&buffer, leader_addr)?;
    Ok(())
}

/// Get the leader's address for attestation submission.
pub fn get_attestation_leader_addr(
    slot: Slot,
    leader_schedule_cache: &LeaderScheduleCache,
    cluster_info: &ClusterInfo,
    bank_forks: &RwLock<BankForks>,
) -> Option<SocketAddr> {
    let bank = bank_forks.read().ok()?.working_bank();
    let leader = leader_schedule_cache.slot_leader_at(slot, Some(&bank))?;

    // Get the leader's contact info
    cluster_info
        .lookup_contact_info(&leader, |ci| ci.tvu(solana_gossip::contact_info::Protocol::UDP))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_ledger::mcp_attestation::AttestationEntry;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    fn make_test_sig(seed: u8) -> solana_signature::Signature {
        solana_signature::Signature::from([seed; 64])
    }

    #[test]
    fn test_proposer_shred_tracker() {
        let mut tracker = ProposerShredTracker::default();

        // Initially can't attest
        assert!(!tracker.can_attest());

        // Add some shreds
        for i in 0..MIN_SHREDS_FOR_ATTESTATION {
            tracker.record_shred(i as u32, make_test_hash(1), make_test_sig(1));
        }

        // Now can attest
        assert!(tracker.can_attest());
        assert_eq!(tracker.shred_count(), MIN_SHREDS_FOR_ATTESTATION);
    }

    #[test]
    fn test_slot_shred_state() {
        let mut state = SlotShredState::new();

        // Record shreds from proposer 0
        for i in 0..MIN_SHREDS_FOR_ATTESTATION {
            state.record_shred(0, i as u32, make_test_hash(0), make_test_sig(0));
        }

        // Record shreds from proposer 1 (not enough)
        for i in 0..10 {
            state.record_shred(1, i as u32, make_test_hash(1), make_test_sig(1));
        }

        // Only proposer 0 should be attestable
        let attestable = state.attestable_proposers();
        assert_eq!(attestable.len(), 1);
        assert_eq!(attestable[0].0, 0);
    }

    #[test]
    fn test_relay_attestation_service() {
        let config = RelayAttestationConfig {
            relay_index: 42,
            max_tracked_slots: 10,
        };
        let mut service = RelayAttestationService::new(config);

        // Record shreds for slot 100, proposer 0
        for i in 0..MIN_SHREDS_FOR_ATTESTATION {
            service.record_shred(ReceivedShredInfo {
                slot: 100,
                proposer_id: 0,
                shred_index: i as u32,
                commitment: make_test_hash(0),
                proposer_signature: make_test_sig(0),
            });
        }

        // Should be ready for attestation
        let ready = service.check_attestation_ready();
        assert!(ready.is_some());

        let (slot, proposers) = ready.unwrap();
        assert_eq!(slot, 100);
        assert_eq!(proposers.len(), 1);
        assert_eq!(proposers[0].0, 0);
    }

    #[test]
    fn test_attestation_aggregator() {
        let mut aggregator = AttestationAggregator::new(10);

        // Add attestations from multiple relays
        for relay_index in 0..MIN_RELAYS_FOR_BLOCK as u32 {
            let attestation = RelayAttestation::new_signed(
                100,
                relay_index,
                vec![
                    AttestationEntry::new(0, make_test_hash(0), make_test_sig(0)),
                    AttestationEntry::new(1, make_test_hash(1), make_test_sig(1)),
                ],
                solana_signature::Signature::default(),
            );
            assert!(aggregator.add_attestation(attestation));
        }

        // Should be able to finalize
        assert!(aggregator.can_finalize_slot(100));
        assert_eq!(aggregator.attestation_count(100), MIN_RELAYS_FOR_BLOCK);

        // Get included proposers
        let included = aggregator.get_included_proposers(100);
        assert_eq!(included.len(), 2);
    }

    #[test]
    fn test_slot_attestations_proposer_threshold() {
        let mut slot_attestations = SlotAttestations::default();

        // Add attestations from 80 relays, all attesting to proposer 0
        for relay_index in 0..80u32 {
            let attestation = RelayAttestation::new_signed(
                100,
                relay_index,
                vec![AttestationEntry::new(0, make_test_hash(0), make_test_sig(0))],
                solana_signature::Signature::default(),
            );
            slot_attestations.add_attestation(attestation);
        }

        // Proposer 0 should be included (80 >= 80)
        let included = slot_attestations.get_included_proposers();
        assert_eq!(included.len(), 1);
        assert_eq!(included[0].0, 0);

        // Add 79 more attestations for proposer 1 (not enough)
        for relay_index in 80..159u32 {
            let attestation = RelayAttestation::new_signed(
                100,
                relay_index,
                vec![AttestationEntry::new(1, make_test_hash(1), make_test_sig(1))],
                solana_signature::Signature::default(),
            );
            slot_attestations.add_attestation(attestation);
        }

        // Proposer 1 should not be included yet
        let included = slot_attestations.get_included_proposers();
        assert_eq!(included.len(), 1);

        // Add one more for proposer 1
        let attestation = RelayAttestation::new_signed(
            100,
            159,
            vec![AttestationEntry::new(1, make_test_hash(1), make_test_sig(1))],
            solana_signature::Signature::default(),
        );
        slot_attestations.add_attestation(attestation);

        // Now proposer 1 should also be included
        let included = slot_attestations.get_included_proposers();
        assert_eq!(included.len(), 2);
    }
}
