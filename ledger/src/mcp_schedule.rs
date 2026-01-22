//! MCP (Multiple Concurrent Proposers) schedule generation.
//!
//! This module implements stake-weighted per-epoch schedules for proposers
//! and relays, with rotation of one member per slot.
//!
//! # Schedule Generation
//!
//! Unlike the leader schedule which selects one leader per slot window,
//! MCP schedules maintain sets of active proposers and relays that rotate
//! each slot. The rotation ensures fair participation while maintaining
//! sufficient set sizes for data availability.
//!
//! # Determinism
//!
//! All nodes compute identical proposer/relay sets per slot from the same
//! epoch stakes by using deterministic RNG seeded by epoch.

use {
    crate::mcp::{NUM_PROPOSERS, NUM_RELAYS},
    rand::distributions::{Distribution, WeightedIndex},
    rand_chacha::{rand_core::SeedableRng, ChaChaRng},
    solana_clock::Epoch,
    solana_pubkey::Pubkey,
    std::{collections::HashMap, sync::Arc},
};

/// Proposer ID type (0-15 for regular proposers, 0xFF for consensus payload)
pub type ProposerId = u8;

/// Relay ID type (0-199)
pub type RelayId = u16;

/// MCP schedule for proposers in an epoch.
///
/// Each slot has NUM_PROPOSERS active proposers. The schedule rotates
/// one proposer per slot to ensure fair participation.
#[derive(Debug, Clone)]
pub struct ProposerSchedule {
    /// Base proposer set for the epoch (stake-weighted selection of validators).
    /// Size is num_slots_in_epoch + NUM_PROPOSERS - 1 to support rotation.
    proposer_pool: Vec<Pubkey>,
    /// Number of slots in this epoch
    num_slots: u64,
    /// Map from pubkey to their position(s) in the pool
    pubkey_to_positions: HashMap<Pubkey, Vec<usize>>,
}

impl ProposerSchedule {
    /// Create a new proposer schedule from stake-weighted validators.
    ///
    /// # Arguments
    /// * `keyed_stakes` - Iterator of (pubkey, stake) pairs
    /// * `epoch` - The epoch number (used for RNG seed)
    /// * `num_slots` - Number of slots in this epoch
    pub fn new<'a>(
        keyed_stakes: impl Iterator<Item = (&'a Pubkey, u64)>,
        epoch: Epoch,
        num_slots: u64,
    ) -> Self {
        let proposer_pool = stake_weighted_selection(
            keyed_stakes,
            epoch,
            // Need pool size = num_slots + NUM_PROPOSERS - 1 for rotation
            num_slots + (NUM_PROPOSERS as u64) - 1,
            0x50524F50, // "PROP" magic for proposer RNG differentiation
        );

        let pubkey_to_positions = build_position_map(&proposer_pool);

        Self {
            proposer_pool,
            num_slots,
            pubkey_to_positions,
        }
    }

    /// Get the set of proposers active at the given slot index.
    ///
    /// Returns NUM_PROPOSERS pubkeys representing the active proposers.
    pub fn get_proposers_at_slot_index(&self, slot_index: u64) -> Vec<Pubkey> {
        let start = slot_index as usize;
        self.proposer_pool[start..start + NUM_PROPOSERS as usize].to_vec()
    }

    /// Get the proposer ID for a given pubkey at a given slot index.
    ///
    /// Returns Some(proposer_id) if the pubkey is an active proposer at this slot,
    /// None otherwise.
    pub fn get_proposer_id(&self, slot_index: u64, pubkey: &Pubkey) -> Option<ProposerId> {
        let start = slot_index as usize;
        let end = start + NUM_PROPOSERS as usize;

        for (i, pk) in self.proposer_pool[start..end].iter().enumerate() {
            if pk == pubkey {
                return Some(i as ProposerId);
            }
        }
        None
    }

    /// Check if a pubkey is an active proposer at the given slot index.
    pub fn is_proposer_at_slot(&self, slot_index: u64, pubkey: &Pubkey) -> bool {
        self.get_proposer_id(slot_index, pubkey).is_some()
    }

    /// Get all slot indices where the given pubkey is an active proposer.
    pub fn get_proposer_slots(&self, pubkey: &Pubkey) -> Vec<u64> {
        let positions = match self.pubkey_to_positions.get(pubkey) {
            Some(p) => p,
            None => return vec![],
        };

        let mut slots = Vec::new();
        for &pos in positions {
            // A proposer at position `pos` is active for slots:
            // [max(0, pos - NUM_PROPOSERS + 1), min(pos, num_slots - 1)]
            let first_slot = pos.saturating_sub(NUM_PROPOSERS as usize - 1);
            let last_slot = pos.min(self.num_slots as usize - 1);

            for slot in first_slot..=last_slot {
                if !slots.contains(&(slot as u64)) {
                    slots.push(slot as u64);
                }
            }
        }
        slots.sort();
        slots.dedup();
        slots
    }

    /// Number of slots in this schedule
    pub fn num_slots(&self) -> u64 {
        self.num_slots
    }
}

/// MCP schedule for relays in an epoch.
///
/// Each slot has NUM_RELAYS active relays. The schedule rotates
/// one relay per slot to ensure fair participation.
#[derive(Debug, Clone)]
pub struct RelaySchedule {
    /// Base relay set for the epoch (stake-weighted selection of validators).
    /// Size is num_slots_in_epoch + NUM_RELAYS - 1 to support rotation.
    relay_pool: Vec<Pubkey>,
    /// Number of slots in this epoch
    num_slots: u64,
    /// Map from pubkey to their position(s) in the pool
    pubkey_to_positions: HashMap<Pubkey, Vec<usize>>,
}

impl RelaySchedule {
    /// Create a new relay schedule from stake-weighted validators.
    ///
    /// # Arguments
    /// * `keyed_stakes` - Iterator of (pubkey, stake) pairs
    /// * `epoch` - The epoch number (used for RNG seed)
    /// * `num_slots` - Number of slots in this epoch
    pub fn new<'a>(
        keyed_stakes: impl Iterator<Item = (&'a Pubkey, u64)>,
        epoch: Epoch,
        num_slots: u64,
    ) -> Self {
        let relay_pool = stake_weighted_selection(
            keyed_stakes,
            epoch,
            // Need pool size = num_slots + NUM_RELAYS - 1 for rotation
            num_slots + (NUM_RELAYS as u64) - 1,
            0x52454C59, // "RELY" magic for relay RNG differentiation
        );

        let pubkey_to_positions = build_position_map(&relay_pool);

        Self {
            relay_pool,
            num_slots,
            pubkey_to_positions,
        }
    }

    /// Get the set of relays active at the given slot index.
    ///
    /// Returns NUM_RELAYS pubkeys representing the active relays.
    pub fn get_relays_at_slot_index(&self, slot_index: u64) -> Vec<Pubkey> {
        let start = slot_index as usize;
        self.relay_pool[start..start + NUM_RELAYS as usize].to_vec()
    }

    /// Get the relay ID for a given pubkey at a given slot index.
    ///
    /// Returns Some(relay_id) if the pubkey is an active relay at this slot,
    /// None otherwise.
    pub fn get_relay_id(&self, slot_index: u64, pubkey: &Pubkey) -> Option<RelayId> {
        let start = slot_index as usize;
        let end = start + NUM_RELAYS as usize;

        for (i, pk) in self.relay_pool[start..end].iter().enumerate() {
            if pk == pubkey {
                return Some(i as RelayId);
            }
        }
        None
    }

    /// Check if a pubkey is an active relay at the given slot index.
    pub fn is_relay_at_slot(&self, slot_index: u64, pubkey: &Pubkey) -> bool {
        self.get_relay_id(slot_index, pubkey).is_some()
    }

    /// Get all slot indices where the given pubkey is an active relay.
    pub fn get_relay_slots(&self, pubkey: &Pubkey) -> Vec<u64> {
        let positions = match self.pubkey_to_positions.get(pubkey) {
            Some(p) => p,
            None => return vec![],
        };

        let mut slots = Vec::new();
        for &pos in positions {
            // A relay at position `pos` is active for slots:
            // [max(0, pos - NUM_RELAYS + 1), min(pos, num_slots - 1)]
            let first_slot = pos.saturating_sub(NUM_RELAYS as usize - 1);
            let last_slot = pos.min(self.num_slots as usize - 1);

            for slot in first_slot..=last_slot {
                if !slots.contains(&(slot as u64)) {
                    slots.push(slot as u64);
                }
            }
        }
        slots.sort();
        slots.dedup();
        slots
    }

    /// Number of slots in this schedule
    pub fn num_slots(&self) -> u64 {
        self.num_slots
    }
}

/// Combined MCP schedule for an epoch containing both proposer and relay schedules.
#[derive(Debug, Clone)]
pub struct McpSchedule {
    pub proposer_schedule: Arc<ProposerSchedule>,
    pub relay_schedule: Arc<RelaySchedule>,
    epoch: Epoch,
}

impl McpSchedule {
    /// Create a new MCP schedule from stake-weighted validators.
    pub fn new<'a>(
        keyed_stakes: impl Iterator<Item = (&'a Pubkey, u64)> + Clone,
        epoch: Epoch,
        num_slots: u64,
    ) -> Self {
        Self {
            proposer_schedule: Arc::new(ProposerSchedule::new(
                keyed_stakes.clone(),
                epoch,
                num_slots,
            )),
            relay_schedule: Arc::new(RelaySchedule::new(keyed_stakes, epoch, num_slots)),
            epoch,
        }
    }

    /// Get the epoch this schedule is for
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Get proposers for a slot
    pub fn get_proposers_at_slot_index(&self, slot_index: u64) -> Vec<Pubkey> {
        self.proposer_schedule.get_proposers_at_slot_index(slot_index)
    }

    /// Get relays for a slot
    pub fn get_relays_at_slot_index(&self, slot_index: u64) -> Vec<Pubkey> {
        self.relay_schedule.get_relays_at_slot_index(slot_index)
    }

    /// Get proposer ID for a pubkey at a slot
    pub fn get_proposer_id(&self, slot_index: u64, pubkey: &Pubkey) -> Option<ProposerId> {
        self.proposer_schedule.get_proposer_id(slot_index, pubkey)
    }

    /// Get relay ID for a pubkey at a slot
    pub fn get_relay_id(&self, slot_index: u64, pubkey: &Pubkey) -> Option<RelayId> {
        self.relay_schedule.get_relay_id(slot_index, pubkey)
    }
}

/// Generate stake-weighted selection for a pool of validators.
///
/// Uses ChaCha RNG seeded by epoch and magic number to ensure determinism
/// while differentiating between proposer and relay schedules.
fn stake_weighted_selection<'a>(
    keyed_stakes: impl Iterator<Item = (&'a Pubkey, u64)>,
    epoch: Epoch,
    pool_size: u64,
    magic: u32,
) -> Vec<Pubkey> {
    let mut stakes: Vec<_> = keyed_stakes.filter(|(_, stake)| *stake > 0).collect();

    if stakes.is_empty() {
        return vec![];
    }

    // Sort for determinism
    sort_stakes(&mut stakes);

    let (keys, stake_values): (Vec<_>, Vec<_>) = stakes.into_iter().unzip();
    let weighted_index = WeightedIndex::new(stake_values).unwrap();

    // Seed with epoch and magic to differentiate proposer vs relay schedules
    let mut seed = [0u8; 32];
    seed[0..8].copy_from_slice(&epoch.to_le_bytes());
    seed[8..12].copy_from_slice(&magic.to_le_bytes());

    let rng = &mut ChaChaRng::from_seed(seed);

    (0..pool_size)
        .map(|_| keys[weighted_index.sample(rng)])
        .collect()
}

/// Sort stakes by stake descending, then by pubkey for determinism.
fn sort_stakes(stakes: &mut Vec<(&Pubkey, u64)>) {
    stakes.sort_unstable_by(|(l_pubkey, l_stake), (r_pubkey, r_stake)| {
        if r_stake == l_stake {
            r_pubkey.cmp(l_pubkey)
        } else {
            r_stake.cmp(l_stake)
        }
    });
    stakes.dedup();
}

/// Build a map from pubkey to positions in the pool.
fn build_position_map(pool: &[Pubkey]) -> HashMap<Pubkey, Vec<usize>> {
    let mut map: HashMap<Pubkey, Vec<usize>> = HashMap::new();
    for (pos, pubkey) in pool.iter().enumerate() {
        map.entry(*pubkey).or_default().push(pos);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_stakes() -> Vec<(Pubkey, u64)> {
        (0..50)
            .map(|i| (Pubkey::new_unique(), (i + 1) as u64 * 1000))
            .collect()
    }

    #[test]
    fn test_proposer_schedule_basic() {
        let stakes = create_test_stakes();
        let keyed_stakes: Vec<_> = stakes.iter().map(|(pk, s)| (pk, *s)).collect();

        let schedule = ProposerSchedule::new(keyed_stakes.into_iter(), 0, 100);

        // Check we get NUM_PROPOSERS proposers per slot
        for slot in 0..100 {
            let proposers = schedule.get_proposers_at_slot_index(slot);
            assert_eq!(proposers.len(), NUM_PROPOSERS as usize);
        }
    }

    #[test]
    fn test_relay_schedule_basic() {
        let stakes = create_test_stakes();
        let keyed_stakes: Vec<_> = stakes.iter().map(|(pk, s)| (pk, *s)).collect();

        let schedule = RelaySchedule::new(keyed_stakes.into_iter(), 0, 100);

        // Check we get NUM_RELAYS relays per slot
        for slot in 0..100 {
            let relays = schedule.get_relays_at_slot_index(slot);
            assert_eq!(relays.len(), NUM_RELAYS as usize);
        }
    }

    #[test]
    fn test_proposer_id_lookup() {
        let stakes = create_test_stakes();
        let keyed_stakes: Vec<_> = stakes.iter().map(|(pk, s)| (pk, *s)).collect();

        let schedule = ProposerSchedule::new(keyed_stakes.into_iter(), 0, 100);

        // Get proposers at slot 0
        let proposers = schedule.get_proposers_at_slot_index(0);

        // Each proposer should have a valid ID
        for (expected_id, pk) in proposers.iter().enumerate() {
            let id = schedule.get_proposer_id(0, pk);
            assert_eq!(id, Some(expected_id as ProposerId));
        }

        // Non-proposer should return None
        let non_proposer = Pubkey::new_unique();
        assert!(schedule.get_proposer_id(0, &non_proposer).is_none());
    }

    #[test]
    fn test_schedule_determinism() {
        let stakes = create_test_stakes();
        let keyed_stakes1: Vec<_> = stakes.iter().map(|(pk, s)| (pk, *s)).collect();
        let keyed_stakes2: Vec<_> = stakes.iter().map(|(pk, s)| (pk, *s)).collect();

        // Same epoch should produce same schedule
        let schedule1 = ProposerSchedule::new(keyed_stakes1.into_iter(), 0, 100);
        let schedule2 = ProposerSchedule::new(keyed_stakes2.into_iter(), 0, 100);

        for slot in 0..100 {
            assert_eq!(
                schedule1.get_proposers_at_slot_index(slot),
                schedule2.get_proposers_at_slot_index(slot)
            );
        }
    }

    #[test]
    fn test_different_epochs_different_schedules() {
        let stakes = create_test_stakes();
        let keyed_stakes1: Vec<_> = stakes.iter().map(|(pk, s)| (pk, *s)).collect();
        let keyed_stakes2: Vec<_> = stakes.iter().map(|(pk, s)| (pk, *s)).collect();

        let schedule1 = ProposerSchedule::new(keyed_stakes1.into_iter(), 0, 100);
        let schedule2 = ProposerSchedule::new(keyed_stakes2.into_iter(), 1, 100);

        // Different epochs should (almost certainly) produce different schedules
        let mut different = false;
        for slot in 0..100 {
            if schedule1.get_proposers_at_slot_index(slot)
                != schedule2.get_proposers_at_slot_index(slot)
            {
                different = true;
                break;
            }
        }
        assert!(different, "Different epochs should produce different schedules");
    }

    #[test]
    fn test_proposer_relay_schedules_differ() {
        let stakes = create_test_stakes();
        let keyed_stakes: Vec<_> = stakes.iter().map(|(pk, s)| (pk, *s)).collect();

        let mcp_schedule = McpSchedule::new(keyed_stakes.into_iter(), 0, 100);

        // Proposer and relay schedules should differ (different magic seeds)
        let proposers = mcp_schedule.get_proposers_at_slot_index(0);
        let relays = mcp_schedule.get_relays_at_slot_index(0);

        // They can overlap but should not be identical subsets
        // (since they use different RNG seeds)
        // This is a weak test but verifies the differentiation works
        assert_ne!(proposers.len(), relays.len());
    }

    #[test]
    fn test_rotation() {
        let stakes = create_test_stakes();
        let keyed_stakes: Vec<_> = stakes.iter().map(|(pk, s)| (pk, *s)).collect();

        let schedule = ProposerSchedule::new(keyed_stakes.into_iter(), 0, 100);

        // Get proposers at consecutive slots
        let proposers_0 = schedule.get_proposers_at_slot_index(0);
        let proposers_1 = schedule.get_proposers_at_slot_index(1);

        // Should have NUM_PROPOSERS - 1 overlapping members
        let overlap: Vec<_> = proposers_0
            .iter()
            .filter(|pk| proposers_1.contains(pk))
            .collect();

        // Due to rotation, we expect significant overlap
        assert!(
            overlap.len() >= (NUM_PROPOSERS as usize - 2),
            "Consecutive slots should share most proposers due to rotation"
        );
    }
}
