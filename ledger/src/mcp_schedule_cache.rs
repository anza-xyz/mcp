//! MCP schedule cache for caching proposer and relay schedules per epoch.
//!
//! Similar to LeaderScheduleCache, this caches computed MCP schedules
//! to avoid recomputation on every slot lookup.

use {
    crate::mcp_schedule::{McpSchedule, ProposerId, RelayId},
    log::*,
    solana_clock::{Epoch, Slot},
    solana_epoch_schedule::EpochSchedule,
    solana_pubkey::Pubkey,
    solana_runtime::bank::Bank,
    std::{
        collections::{HashMap, VecDeque},
        sync::{Arc, RwLock},
    },
};

type CachedSchedules = (HashMap<Epoch, Arc<McpSchedule>>, VecDeque<Epoch>);
const MAX_SCHEDULES: usize = 10;

/// Cache for MCP proposer and relay schedules.
///
/// Maintains per-epoch schedules and provides efficient lookups for
/// proposer/relay assignments at any slot.
#[derive(Default)]
pub struct McpScheduleCache {
    /// Map from epoch to MCP schedule
    cached_schedules: RwLock<CachedSchedules>,
    /// Epoch schedule for slot->epoch conversions
    epoch_schedule: EpochSchedule,
    /// Maximum epoch we have computed schedules for
    max_epoch: RwLock<Epoch>,
    /// Maximum number of schedules to cache
    max_schedules: usize,
}

impl McpScheduleCache {
    /// Create a new cache from a bank.
    pub fn new_from_bank(bank: &Bank) -> Self {
        Self::new(bank.epoch_schedule().clone(), bank)
    }

    /// Create a new cache with the given epoch schedule.
    pub fn new(epoch_schedule: EpochSchedule, root_bank: &Bank) -> Self {
        let cache = Self {
            cached_schedules: RwLock::new((HashMap::new(), VecDeque::new())),
            epoch_schedule,
            max_epoch: RwLock::new(0),
            max_schedules: MAX_SCHEDULES,
        };

        // Set the root and compute initial schedule
        cache.set_root(root_bank);

        // Compute schedules for all epochs up to the current one
        let leader_schedule_epoch = cache
            .epoch_schedule
            .get_leader_schedule_epoch(root_bank.slot());
        for epoch in 0..leader_schedule_epoch {
            let first_slot_in_epoch = cache.epoch_schedule.get_first_slot_in_epoch(epoch);
            cache.get_mcp_schedule_at_slot(first_slot_in_epoch, Some(root_bank));
        }

        cache
    }

    /// Update the root, potentially computing new schedules.
    pub fn set_root(&self, root_bank: &Bank) {
        let new_max_epoch = self
            .epoch_schedule
            .get_leader_schedule_epoch(root_bank.slot());
        let old_max_epoch = {
            let mut max_epoch = self.max_epoch.write().unwrap();
            let old_max_epoch = *max_epoch;
            *max_epoch = new_max_epoch;
            assert!(new_max_epoch >= old_max_epoch);
            old_max_epoch
        };

        if new_max_epoch > old_max_epoch {
            self.compute_epoch_schedule(new_max_epoch, root_bank);
        }
    }

    /// Get the MCP schedule for a slot.
    pub fn get_mcp_schedule_at_slot(
        &self,
        slot: Slot,
        bank: Option<&Bank>,
    ) -> Option<Arc<McpSchedule>> {
        let epoch = self.epoch_schedule.get_epoch(slot);
        self.get_epoch_schedule(epoch, bank)
    }

    /// Get proposers for a slot.
    pub fn get_proposers_at_slot(
        &self,
        slot: Slot,
        bank: Option<&Bank>,
    ) -> Option<Vec<Pubkey>> {
        let (epoch, slot_index) = self.epoch_schedule.get_epoch_and_slot_index(slot);
        self.get_epoch_schedule(epoch, bank)
            .map(|schedule| schedule.get_proposers_at_slot_index(slot_index))
    }

    /// Get relays for a slot.
    pub fn get_relays_at_slot(&self, slot: Slot, bank: Option<&Bank>) -> Option<Vec<Pubkey>> {
        let (epoch, slot_index) = self.epoch_schedule.get_epoch_and_slot_index(slot);
        self.get_epoch_schedule(epoch, bank)
            .map(|schedule| schedule.get_relays_at_slot_index(slot_index))
    }

    /// Get proposer ID for a pubkey at a slot.
    pub fn get_proposer_id_at_slot(
        &self,
        slot: Slot,
        pubkey: &Pubkey,
        bank: Option<&Bank>,
    ) -> Option<ProposerId> {
        let (epoch, slot_index) = self.epoch_schedule.get_epoch_and_slot_index(slot);
        self.get_epoch_schedule(epoch, bank)
            .and_then(|schedule| schedule.get_proposer_id(slot_index, pubkey))
    }

    /// Get relay ID for a pubkey at a slot.
    pub fn get_relay_id_at_slot(
        &self,
        slot: Slot,
        pubkey: &Pubkey,
        bank: Option<&Bank>,
    ) -> Option<RelayId> {
        let (epoch, slot_index) = self.epoch_schedule.get_epoch_and_slot_index(slot);
        self.get_epoch_schedule(epoch, bank)
            .and_then(|schedule| schedule.get_relay_id(slot_index, pubkey))
    }

    /// Check if a pubkey is a proposer at a slot.
    pub fn is_proposer_at_slot(
        &self,
        slot: Slot,
        pubkey: &Pubkey,
        bank: Option<&Bank>,
    ) -> bool {
        self.get_proposer_id_at_slot(slot, pubkey, bank).is_some()
    }

    /// Check if a pubkey is a relay at a slot.
    pub fn is_relay_at_slot(&self, slot: Slot, pubkey: &Pubkey, bank: Option<&Bank>) -> bool {
        self.get_relay_id_at_slot(slot, pubkey, bank).is_some()
    }

    fn get_epoch_schedule(&self, epoch: Epoch, bank: Option<&Bank>) -> Option<Arc<McpSchedule>> {
        // Try cache first
        if let Some(schedule) = self.cached_schedules.read().unwrap().0.get(&epoch) {
            return Some(Arc::clone(schedule));
        }

        // Compute if we have a bank
        bank.and_then(|bank| self.compute_epoch_schedule(epoch, bank))
    }

    fn compute_epoch_schedule(&self, epoch: Epoch, bank: &Bank) -> Option<Arc<McpSchedule>> {
        let stakes = bank.epoch_staked_nodes(epoch)?;
        let num_slots = bank.get_slots_in_epoch(epoch);

        let schedule = Arc::new(McpSchedule::new(
            stakes.iter().map(|(pk, stake)| (pk, *stake)),
            epoch,
            num_slots,
        ));

        // Cache the schedule
        let mut cache = self.cached_schedules.write().unwrap();

        // Evict old schedules if at capacity
        while cache.1.len() >= self.max_schedules {
            if let Some(old_epoch) = cache.1.pop_front() {
                cache.0.remove(&old_epoch);
            }
        }

        cache.0.insert(epoch, Arc::clone(&schedule));
        cache.1.push_back(epoch);

        debug!(
            "Computed MCP schedule for epoch {} with {} slots",
            epoch, num_slots
        );

        Some(schedule)
    }

    /// Get the epoch schedule.
    pub fn epoch_schedule(&self) -> &EpochSchedule {
        &self.epoch_schedule
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full tests require runtime infrastructure.
    // These are basic sanity checks.

    #[test]
    fn test_cache_constants() {
        assert_eq!(MAX_SCHEDULES, 10);
    }
}
