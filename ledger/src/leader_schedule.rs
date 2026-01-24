use {
    crate::mcp::{NUM_PROPOSERS, NUM_RELAYS},
    rand::distributions::{Distribution, WeightedIndex},
    rand::Rng,
    rand_chacha::{rand_core::SeedableRng, ChaChaRng},
    solana_clock::Epoch,
    solana_pubkey::Pubkey,
    std::{collections::HashMap, convert::identity, ops::Index, sync::Arc},
};

mod identity_keyed;
mod vote_keyed;
pub use {
    identity_keyed::LeaderSchedule as IdentityKeyedLeaderSchedule,
    vote_keyed::LeaderSchedule as VoteKeyedLeaderSchedule,
};


// ============================================================================
// MCP (Multiple Concurrent Proposers) Schedule Types
// ============================================================================

/// Proposer ID type (0-15 for regular proposers, 0xFF for consensus payload)
pub type ProposerId = u8;

/// Relay ID type (0-199)
pub type RelayId = u16;

/// MCP schedule for proposers in an epoch.
///
/// Per MCP spec §3.3: Committee selection uses deterministic stake-weighted rotation.
/// The committee for slot s+1 is derived by rotating the committee for slot s by 1 position
/// and sampling 1 new validator (not already in committee) to fill the vacated position.
#[derive(Debug, Clone)]
pub struct ProposerSchedule {
    /// Pre-computed committees for each slot in the epoch.
    /// Each entry is a Vec of NUM_PROPOSERS pubkeys representing the committee for that slot.
    slot_committees: Vec<Vec<Pubkey>>,
    /// Number of slots in this epoch
    num_slots: u64,
}

impl ProposerSchedule {
    /// Create a new proposer schedule from stake-weighted validators.
    ///
    /// Per spec §3.3: For slot 0, fill committee by weighted sampling without replacement.
    /// For slot s+1: rotate committee by 1, sample new validator from remaining pool.
    pub fn new<'a>(
        keyed_stakes: impl Iterator<Item = (&'a Pubkey, u64)>,
        epoch: Epoch,
        num_slots: u64,
    ) -> Self {
        let validators: Vec<_> = keyed_stakes
            .filter(|(_, stake)| *stake > 0)
            .map(|(pk, stake)| (*pk, stake))
            .collect();

        // Pre-compute all slot committees
        let slot_committees = compute_slot_committees(
            &validators,
            epoch,
            num_slots,
            NUM_PROPOSERS as usize,
            "proposer", // role per spec §3.3.1
        );

        Self {
            slot_committees,
            num_slots,
        }
    }

    /// Get the set of proposers active at the given slot index.
    pub fn get_proposers_at_slot_index(&self, slot_index: u64) -> Vec<Pubkey> {
        let idx = (slot_index % self.num_slots) as usize;
        if idx < self.slot_committees.len() {
            self.slot_committees[idx].clone()
        } else {
            // Fallback: return the last committee (shouldn't happen)
            self.slot_committees.last().cloned().unwrap_or_default()
        }
    }

    /// Get the proposer ID for a given pubkey at a given slot index.
    pub fn get_proposer_id(&self, slot_index: u64, pubkey: &Pubkey) -> Option<ProposerId> {
        let committee = self.get_proposers_at_slot_index(slot_index);
        committee
            .iter()
            .position(|pk| pk == pubkey)
            .map(|pos| pos as ProposerId)
    }

    /// Check if a pubkey is an active proposer at the given slot index.
    pub fn is_proposer_at_slot(&self, slot_index: u64, pubkey: &Pubkey) -> bool {
        self.get_proposer_id(slot_index, pubkey).is_some()
    }

    /// Get all slot indices where the given pubkey is an active proposer.
    pub fn get_proposer_slots(&self, pubkey: &Pubkey) -> Vec<u64> {
        let mut slots = Vec::new();
        for (slot_idx, committee) in self.slot_committees.iter().enumerate() {
            if committee.contains(pubkey) {
                slots.push(slot_idx as u64);
            }
        }
        slots
    }

    /// Number of slots in this schedule
    pub fn num_slots(&self) -> u64 {
        self.num_slots
    }
}

/// MCP schedule for relays in an epoch.
///
/// Per MCP spec §3.3: Committee selection uses deterministic stake-weighted rotation.
/// The committee for slot s+1 is derived by rotating the committee for slot s by 1 position
/// and sampling 1 new validator (not already in committee) to fill the vacated position.
#[derive(Debug, Clone)]
pub struct RelaySchedule {
    /// Pre-computed committees for each slot in the epoch.
    /// Each entry is a Vec of NUM_RELAYS pubkeys representing the committee for that slot.
    slot_committees: Vec<Vec<Pubkey>>,
    /// Number of slots in this epoch
    num_slots: u64,
}

impl RelaySchedule {
    /// Create a new relay schedule from stake-weighted validators.
    ///
    /// Per spec §3.3: For slot 0, fill committee by weighted sampling without replacement.
    /// For slot s+1: rotate committee by 1, sample new validator from remaining pool.
    pub fn new<'a>(
        keyed_stakes: impl Iterator<Item = (&'a Pubkey, u64)>,
        epoch: Epoch,
        num_slots: u64,
    ) -> Self {
        let validators: Vec<_> = keyed_stakes
            .filter(|(_, stake)| *stake > 0)
            .map(|(pk, stake)| (*pk, stake))
            .collect();

        // Pre-compute all slot committees
        let slot_committees = compute_slot_committees(
            &validators,
            epoch,
            num_slots,
            NUM_RELAYS as usize,
            "relay", // role per spec §3.3.1
        );

        Self {
            slot_committees,
            num_slots,
        }
    }

    /// Get the set of relays active at the given slot index.
    pub fn get_relays_at_slot_index(&self, slot_index: u64) -> Vec<Pubkey> {
        let idx = (slot_index % self.num_slots) as usize;
        if idx < self.slot_committees.len() {
            self.slot_committees[idx].clone()
        } else {
            // Fallback: return the last committee (shouldn't happen)
            self.slot_committees.last().cloned().unwrap_or_default()
        }
    }

    /// Get the relay ID for a given pubkey at a given slot index.
    pub fn get_relay_id(&self, slot_index: u64, pubkey: &Pubkey) -> Option<RelayId> {
        let committee = self.get_relays_at_slot_index(slot_index);
        committee
            .iter()
            .position(|pk| pk == pubkey)
            .map(|pos| pos as RelayId)
    }

    /// Check if a pubkey is an active relay at the given slot index.
    pub fn is_relay_at_slot(&self, slot_index: u64, pubkey: &Pubkey) -> bool {
        self.get_relay_id(slot_index, pubkey).is_some()
    }

    /// Get all slot indices where the given pubkey is an active relay.
    pub fn get_relay_slots(&self, pubkey: &Pubkey) -> Vec<u64> {
        let mut slots = Vec::new();
        for (slot_idx, committee) in self.slot_committees.iter().enumerate() {
            if committee.contains(pubkey) {
                slots.push(slot_idx as u64);
            }
        }
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

/// Compute slot committees for all slots in an epoch using per-slot sampling.
///
/// Per MCP spec §3.3:
/// - Epoch initialization (slot 0): fill committee by weighted sampling without replacement
/// - For slot s+1: rotate committee by 1 position, sample 1 new validator to fill vacancy
///
/// The sampling for slot s+1 uses rng_slot seeded with: seed_role || LE64(slot_index)
fn compute_slot_committees(
    validators: &[(Pubkey, u64)],
    epoch: Epoch,
    num_slots: u64,
    committee_size: usize,
    role: &str,
) -> Vec<Vec<Pubkey>> {
    if validators.is_empty() || committee_size == 0 {
        return vec![vec![]; num_slots as usize];
    }

    // Sort validators by stake (descending) for deterministic ordering
    let mut sorted_validators: Vec<_> = validators.to_vec();
    sort_stakes_owned(&mut sorted_validators);

    // Create base seed for this role per spec §3.3.1:
    // seed_role = SHA256("mcp:committee:" || role || LE64(epoch_number))
    use solana_sha256_hasher::hashv;
    let epoch_bytes = epoch.to_le_bytes();
    let base_seed_hash = hashv(&[b"mcp:committee:", role.as_bytes(), &epoch_bytes]);
    let base_seed: [u8; 32] = base_seed_hash.to_bytes();

    let mut slot_committees = Vec::with_capacity(num_slots as usize);

    // Initialize slot 0 committee by weighted sampling without replacement
    let mut rng_slot0 = ChaChaRng::from_seed(compute_slot_seed(&base_seed, 0));
    let initial_committee = sample_initial_committee(&sorted_validators, committee_size, &mut rng_slot0);
    slot_committees.push(initial_committee);

    // Compute committees for slots 1..num_slots
    for slot_idx in 1..num_slots {
        let prev_committee = &slot_committees[(slot_idx - 1) as usize];

        // Rotate: drop first element, shift left
        // committee' = committee[1..] (the dropped element exits)
        let mut new_committee: Vec<Pubkey> = prev_committee.iter().skip(1).cloned().collect();

        // Sample new validator from candidates not in the rotated committee
        let mut rng_slot = ChaChaRng::from_seed(compute_slot_seed(&base_seed, slot_idx));
        let new_member = sample_new_member(&sorted_validators, &new_committee, &mut rng_slot);

        // Append new member at the end
        new_committee.push(new_member);

        slot_committees.push(new_committee);
    }

    slot_committees
}

/// Compute the seed for a specific slot's RNG.
/// seed_slot = SHA256(base_seed || LE64(slot_index))
fn compute_slot_seed(base_seed: &[u8; 32], slot_index: u64) -> [u8; 32] {
    use solana_sha256_hasher::hashv;
    let slot_bytes = slot_index.to_le_bytes();
    let hash = hashv(&[base_seed, &slot_bytes]);
    hash.to_bytes()
}

/// Sample initial committee by weighted sampling without replacement.
fn sample_initial_committee(
    validators: &[(Pubkey, u64)],
    committee_size: usize,
    rng: &mut ChaChaRng,
) -> Vec<Pubkey> {
    let actual_size = committee_size.min(validators.len());
    let mut remaining: Vec<_> = validators.to_vec();
    let mut committee = Vec::with_capacity(actual_size);

    while committee.len() < actual_size && !remaining.is_empty() {
        let picked = weighted_sample_and_remove(&mut remaining, rng);
        committee.push(picked);
    }

    committee
}

/// Sample a new member from validators not already in the committee.
fn sample_new_member(
    validators: &[(Pubkey, u64)],
    current_committee: &[Pubkey],
    rng: &mut ChaChaRng,
) -> Pubkey {
    // Build candidate set: all validators not in current committee
    let candidates: Vec<_> = validators
        .iter()
        .filter(|(pk, _)| !current_committee.contains(pk))
        .cloned()
        .collect();

    if candidates.is_empty() {
        // Fallback: if all validators are in committee, sample from all
        // This shouldn't happen if committee_size < validators.len()
        let mut all = validators.to_vec();
        return weighted_sample_and_remove(&mut all, rng);
    }

    let mut candidates_mut = candidates;
    weighted_sample_and_remove(&mut candidates_mut, rng)
}

/// Weighted sample one validator and remove from the list.
fn weighted_sample_and_remove(validators: &mut Vec<(Pubkey, u64)>, rng: &mut ChaChaRng) -> Pubkey {
    if validators.is_empty() {
        return Pubkey::default();
    }

    if validators.len() == 1 {
        return validators.remove(0).0;
    }

    let total_stake: u64 = validators.iter().map(|(_, s)| s).sum();
    if total_stake == 0 {
        // All zero stake, pick randomly
        let idx = rng.gen_range(0..validators.len());
        return validators.remove(idx).0;
    }

    let target = rng.gen_range(0..total_stake);
    let mut cumulative = 0u64;
    let mut selected_idx = 0;

    for (i, (_, stake)) in validators.iter().enumerate() {
        cumulative += stake;
        if cumulative > target {
            selected_idx = i;
            break;
        }
    }

    validators.remove(selected_idx).0
}

/// Sort validators by (stake descending, pubkey ascending) for deterministic ordering.
fn sort_stakes_owned(stakes: &mut [(Pubkey, u64)]) {
    stakes.sort_by(|(pk_a, stake_a), (pk_b, stake_b)| {
        stake_b.cmp(stake_a).then_with(|| pk_a.cmp(pk_b))
    });
}

// ============================================================================
// Leader Schedule Types
// ============================================================================

// Used for testing
#[derive(Clone, Debug)]
pub struct FixedSchedule {
    pub leader_schedule: Arc<LeaderSchedule>,
}

/// Stake-weighted leader schedule for one epoch.
pub type LeaderSchedule = Box<dyn LeaderScheduleVariant>;

pub trait LeaderScheduleVariant:
    std::fmt::Debug + Send + Sync + Index<u64, Output = Pubkey>
{
    fn get_slot_leaders(&self) -> &[Pubkey];
    fn get_leader_slots_map(&self) -> &HashMap<Pubkey, Arc<Vec<usize>>>;

    /// Get the vote account address for the given epoch slot index. This is
    /// guaranteed to be Some if the leader schedule is keyed by vote account
    fn get_vote_key_at_slot_index(&self, _epoch_slot_index: usize) -> Option<&Pubkey> {
        None
    }

    fn get_leader_upcoming_slots(
        &self,
        pubkey: &Pubkey,
        offset: usize, // Starting index.
    ) -> Box<dyn Iterator<Item = usize>> {
        let index = self
            .get_leader_slots_map()
            .get(pubkey)
            .cloned()
            .unwrap_or_default();
        let num_slots = self.num_slots();
        let size = index.len();
        #[allow(clippy::reversed_empty_ranges)]
        let range = if index.is_empty() {
            1..=0 // Intentionally empty range of type RangeInclusive.
        } else {
            let offset = index
                .binary_search(&(offset % num_slots))
                .unwrap_or_else(identity)
                + offset / num_slots * size;
            offset..=usize::MAX
        };
        // The modular arithmetic here and above replicate Index implementation
        // for LeaderSchedule, where the schedule keeps repeating endlessly.
        // The '%' returns where in a cycle we are and the '/' returns how many
        // times the schedule is repeated.
        Box::new(range.map(move |k| index[k % size] + k / size * num_slots))
    }

    fn num_slots(&self) -> usize {
        self.get_slot_leaders().len()
    }
}

// Note: passing in zero keyed stakes will cause a panic.
fn stake_weighted_slot_leaders(
    mut keyed_stakes: Vec<(&Pubkey, u64)>,
    epoch: Epoch,
    len: u64,
    repeat: u64,
) -> Vec<Pubkey> {
    sort_stakes(&mut keyed_stakes);
    let (keys, stakes): (Vec<_>, Vec<_>) = keyed_stakes.into_iter().unzip();
    let weighted_index = WeightedIndex::new(stakes).unwrap();
    let mut seed = [0u8; 32];
    seed[0..8].copy_from_slice(&epoch.to_le_bytes());
    let rng = &mut ChaChaRng::from_seed(seed);
    let mut current_slot_leader = Pubkey::default();
    (0..len)
        .map(|i| {
            if i % repeat == 0 {
                current_slot_leader = keys[weighted_index.sample(rng)];
            }
            current_slot_leader
        })
        .collect()
}

fn sort_stakes(stakes: &mut Vec<(&Pubkey, u64)>) {
    // Sort first by stake. If stakes are the same, sort by pubkey to ensure a
    // deterministic result.
    // Note: Use unstable sort, because we dedup right after to remove the equal elements.
    stakes.sort_unstable_by(|(l_pubkey, l_stake), (r_pubkey, r_stake)| {
        if r_stake == l_stake {
            r_pubkey.cmp(l_pubkey)
        } else {
            r_stake.cmp(l_stake)
        }
    });

    // Now that it's sorted, we can do an O(n) dedup.
    stakes.dedup();
}

#[cfg(test)]
mod tests {
    use {super::*, itertools::Itertools, rand::Rng, std::iter::repeat_with};

    #[test]
    fn test_get_leader_upcoming_slots() {
        const NUM_SLOTS: usize = 97;
        let mut rng = rand::thread_rng();
        let pubkeys: Vec<_> = repeat_with(Pubkey::new_unique).take(4).collect();
        let schedule: Vec<_> = repeat_with(|| pubkeys[rng.gen_range(0..3)])
            .take(19)
            .collect();
        let schedule = IdentityKeyedLeaderSchedule::new_from_schedule(schedule);
        let leaders = (0..NUM_SLOTS)
            .map(|i| (schedule[i as u64], i))
            .into_group_map();
        for pubkey in &pubkeys {
            let index = leaders.get(pubkey).cloned().unwrap_or_default();
            for offset in 0..NUM_SLOTS {
                let schedule: Vec<_> = schedule
                    .get_leader_upcoming_slots(pubkey, offset)
                    .take_while(|s| *s < NUM_SLOTS)
                    .collect();
                let index: Vec<_> = index.iter().copied().skip_while(|s| *s < offset).collect();
                assert_eq!(schedule, index);
            }
        }
    }

    #[test]
    fn test_sort_stakes_basic() {
        let pubkey0 = solana_pubkey::new_rand();
        let pubkey1 = solana_pubkey::new_rand();
        let mut stakes = vec![(&pubkey0, 1), (&pubkey1, 2)];
        sort_stakes(&mut stakes);
        assert_eq!(stakes, vec![(&pubkey1, 2), (&pubkey0, 1)]);
    }

    #[test]
    fn test_sort_stakes_with_dup() {
        let pubkey0 = solana_pubkey::new_rand();
        let pubkey1 = solana_pubkey::new_rand();
        let mut stakes = vec![(&pubkey0, 1), (&pubkey1, 2), (&pubkey0, 1)];
        sort_stakes(&mut stakes);
        assert_eq!(stakes, vec![(&pubkey1, 2), (&pubkey0, 1)]);
    }

    #[test]
    fn test_sort_stakes_with_equal_stakes() {
        let pubkey0 = Pubkey::default();
        let pubkey1 = solana_pubkey::new_rand();
        let mut stakes = vec![(&pubkey0, 1), (&pubkey1, 1)];
        sort_stakes(&mut stakes);
        assert_eq!(stakes, vec![(&pubkey1, 1), (&pubkey0, 1)]);
    }
}
