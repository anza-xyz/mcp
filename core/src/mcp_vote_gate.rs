use {
    solana_ledger::mcp,
    std::collections::{BTreeMap, BTreeSet, HashMap},
    thiserror::Error,
};

pub type Commitment = [u8; 32];

pub const REQUIRED_ATTESTATIONS: usize = mcp::REQUIRED_ATTESTATIONS;
pub const REQUIRED_INCLUSIONS: usize = mcp::REQUIRED_INCLUSIONS;
pub const REQUIRED_RECONSTRUCTION: usize = mcp::REQUIRED_RECONSTRUCTION;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayProposerEntry {
    pub proposer_index: u32,
    pub commitment: Commitment,
    pub proposer_signature_valid: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAttestationObservation {
    pub relay_index: u32,
    pub relay_signature_valid: bool,
    pub entries: Vec<RelayProposerEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteGateInput {
    pub leader_signature_valid: bool,
    pub leader_index_matches: bool,
    pub delayed_bankhash_available: bool,
    pub delayed_bankhash_matches: bool,
    pub aggregate: Vec<RelayAttestationObservation>,
    pub proposer_indices: Vec<u32>,
    // Count of locally available shreds already filtered to match included commitment.
    pub local_valid_shreds: HashMap<u32, usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum VoteGateRejection {
    #[error("invalid leader signature")]
    InvalidLeaderSignature,
    #[error("leader index mismatch")]
    LeaderIndexMismatch,
    #[error("delayed bankhash is not yet available")]
    DelayedBankhashUnavailable,
    #[error("delayed bankhash mismatch")]
    DelayedBankhashMismatch,
    #[error("insufficient relay attestations: got {actual}, need {required}")]
    InsufficientRelayAttestations { actual: usize, required: usize },
    #[error("no proposers passed inclusion and equivocation checks")]
    NoIncludedProposers,
    #[error(
        "insufficient local shreds for proposer {proposer_index}: got {actual}, need {required}"
    )]
    InsufficientLocalShreds {
        proposer_index: u32,
        actual: usize,
        required: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VoteGateDecision {
    Vote {
        included_proposers: BTreeMap<u32, Commitment>,
    },
    Reject(VoteGateRejection),
}

pub fn evaluate_vote_gate(input: &VoteGateInput) -> VoteGateDecision {
    if !input.leader_signature_valid {
        return VoteGateDecision::Reject(VoteGateRejection::InvalidLeaderSignature);
    }
    if !input.leader_index_matches {
        return VoteGateDecision::Reject(VoteGateRejection::LeaderIndexMismatch);
    }
    if !input.delayed_bankhash_available {
        return VoteGateDecision::Reject(VoteGateRejection::DelayedBankhashUnavailable);
    }
    if !input.delayed_bankhash_matches {
        return VoteGateDecision::Reject(VoteGateRejection::DelayedBankhashMismatch);
    }

    let valid_relays: Vec<&RelayAttestationObservation> = input
        .aggregate
        .iter()
        .filter(|relay| relay.relay_signature_valid)
        .filter(|relay| {
            relay
                .entries
                .iter()
                .any(|entry| entry.proposer_signature_valid)
        })
        .collect();
    let valid_relay_count = valid_relays
        .iter()
        .map(|relay| relay.relay_index)
        .collect::<BTreeSet<_>>()
        .len();
    if valid_relay_count < REQUIRED_ATTESTATIONS {
        return VoteGateDecision::Reject(VoteGateRejection::InsufficientRelayAttestations {
            actual: valid_relay_count,
            required: REQUIRED_ATTESTATIONS,
        });
    }

    let mut included_proposers = BTreeMap::new();
    for proposer_index in &input.proposer_indices {
        let mut commitment_to_relays: BTreeMap<Commitment, BTreeSet<u32>> = BTreeMap::new();
        for relay in &valid_relays {
            for entry in &relay.entries {
                if entry.proposer_index == *proposer_index && entry.proposer_signature_valid {
                    commitment_to_relays
                        .entry(entry.commitment)
                        .or_default()
                        .insert(relay.relay_index);
                }
            }
        }

        // Multiple commitments imply equivocation and exclusion.
        if commitment_to_relays.len() != 1 {
            continue;
        }

        let (commitment, relays) = commitment_to_relays.first_key_value().unwrap();
        if relays.len() >= REQUIRED_INCLUSIONS {
            included_proposers.insert(*proposer_index, *commitment);
        }
    }

    for proposer_index in included_proposers.keys() {
        let local = input
            .local_valid_shreds
            .get(proposer_index)
            .copied()
            .unwrap_or(0);
        if local < REQUIRED_RECONSTRUCTION {
            return VoteGateDecision::Reject(VoteGateRejection::InsufficientLocalShreds {
                proposer_index: *proposer_index,
                actual: local,
                required: REQUIRED_RECONSTRUCTION,
            });
        }
    }
    if included_proposers.is_empty() {
        return VoteGateDecision::Reject(VoteGateRejection::NoIncludedProposers);
    }

    VoteGateDecision::Vote { included_proposers }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(
        relay_index: u32,
        relay_signature_valid: bool,
        entries: Vec<(u32, Commitment, bool)>,
    ) -> RelayAttestationObservation {
        RelayAttestationObservation {
            relay_index,
            relay_signature_valid,
            entries: entries
                .into_iter()
                .map(
                    |(proposer_index, commitment, proposer_signature_valid)| RelayProposerEntry {
                        proposer_index,
                        commitment,
                        proposer_signature_valid,
                    },
                )
                .collect(),
        }
    }

    fn base_input(aggregate: Vec<RelayAttestationObservation>) -> VoteGateInput {
        VoteGateInput {
            leader_signature_valid: true,
            leader_index_matches: true,
            delayed_bankhash_available: true,
            delayed_bankhash_matches: true,
            aggregate,
            proposer_indices: vec![0, 1],
            local_valid_shreds: HashMap::new(),
        }
    }

    #[test]
    fn test_rejects_when_delayed_bankhash_unavailable() {
        let mut input = base_input(Vec::new());
        input.delayed_bankhash_available = false;
        assert_eq!(
            evaluate_vote_gate(&input),
            VoteGateDecision::Reject(VoteGateRejection::DelayedBankhashUnavailable)
        );
    }

    #[test]
    fn test_rejects_when_delayed_bankhash_mismatches() {
        let mut input = base_input(Vec::new());
        input.delayed_bankhash_matches = false;
        assert_eq!(
            evaluate_vote_gate(&input),
            VoteGateDecision::Reject(VoteGateRejection::DelayedBankhashMismatch)
        );
    }

    #[test]
    fn test_rejects_on_invalid_leader_signature_or_index() {
        let mut input = base_input(Vec::new());
        input.leader_signature_valid = false;
        assert_eq!(
            evaluate_vote_gate(&input),
            VoteGateDecision::Reject(VoteGateRejection::InvalidLeaderSignature)
        );

        let mut input = base_input(Vec::new());
        input.leader_index_matches = false;
        assert_eq!(
            evaluate_vote_gate(&input),
            VoteGateDecision::Reject(VoteGateRejection::LeaderIndexMismatch)
        );
    }

    #[test]
    fn test_rejects_when_global_threshold_not_met() {
        let commitment = [7u8; 32];
        let aggregate = (0..(REQUIRED_ATTESTATIONS - 1))
            .map(|i| relay(i as u32, true, vec![(0, commitment, true)]))
            .collect();
        let mut input = base_input(aggregate);
        input.local_valid_shreds.insert(0, REQUIRED_RECONSTRUCTION);
        assert_eq!(
            evaluate_vote_gate(&input),
            VoteGateDecision::Reject(VoteGateRejection::InsufficientRelayAttestations {
                actual: REQUIRED_ATTESTATIONS - 1,
                required: REQUIRED_ATTESTATIONS,
            })
        );
    }

    #[test]
    fn test_votes_when_thresholds_and_local_reconstruction_hold() {
        let commitment = [9u8; 32];
        let aggregate = (0..REQUIRED_ATTESTATIONS)
            .map(|i| relay(i as u32, true, vec![(0, commitment, true)]))
            .collect();
        let mut input = base_input(aggregate);
        input.local_valid_shreds.insert(0, REQUIRED_RECONSTRUCTION);

        assert_eq!(
            evaluate_vote_gate(&input),
            VoteGateDecision::Vote {
                included_proposers: BTreeMap::from([(0, commitment)]),
            }
        );
    }

    #[test]
    fn test_rejects_when_included_proposer_has_insufficient_local_shreds() {
        let commitment = [3u8; 32];
        let aggregate = (0..REQUIRED_ATTESTATIONS)
            .map(|i| relay(i as u32, true, vec![(0, commitment, true)]))
            .collect();
        let mut input = base_input(aggregate);
        input
            .local_valid_shreds
            .insert(0, REQUIRED_RECONSTRUCTION - 1);

        assert_eq!(
            evaluate_vote_gate(&input),
            VoteGateDecision::Reject(VoteGateRejection::InsufficientLocalShreds {
                proposer_index: 0,
                actual: REQUIRED_RECONSTRUCTION - 1,
                required: REQUIRED_RECONSTRUCTION,
            })
        );
    }

    #[test]
    fn test_equivocating_proposer_is_excluded() {
        let commitment_a = [1u8; 32];
        let commitment_b = [2u8; 32];
        let aggregate = (0..REQUIRED_ATTESTATIONS)
            .map(|i| {
                if i < REQUIRED_INCLUSIONS {
                    relay(i as u32, true, vec![(0, commitment_a, true)])
                } else {
                    relay(i as u32, true, vec![(0, commitment_b, true)])
                }
            })
            .collect();
        let input = base_input(aggregate);

        assert_eq!(
            evaluate_vote_gate(&input),
            VoteGateDecision::Reject(VoteGateRejection::NoIncludedProposers)
        );
    }

    #[test]
    fn test_duplicate_relay_indices_do_not_double_count_threshold() {
        let commitment = [4u8; 32];
        let aggregate = (0..REQUIRED_ATTESTATIONS)
            .map(|i| relay(i as u32, true, vec![(0, commitment, true)]))
            .chain((0..REQUIRED_ATTESTATIONS).map(|i| {
                // Duplicate relay indices should not increase global relay count.
                relay(i as u32, true, vec![(0, commitment, true)])
            }))
            .collect();
        let mut input = base_input(aggregate);
        input.local_valid_shreds.insert(0, REQUIRED_RECONSTRUCTION);

        assert_eq!(
            evaluate_vote_gate(&input),
            VoteGateDecision::Vote {
                included_proposers: BTreeMap::from([(0, commitment)]),
            }
        );
    }

    #[test]
    fn test_relays_without_any_valid_proposer_entries_do_not_count() {
        let commitment = [8u8; 32];
        let aggregate = (0..REQUIRED_ATTESTATIONS)
            .map(|i| relay(i as u32, true, vec![(0, commitment, false)]))
            .collect();
        let input = base_input(aggregate);

        assert_eq!(
            evaluate_vote_gate(&input),
            VoteGateDecision::Reject(VoteGateRejection::InsufficientRelayAttestations {
                actual: 0,
                required: REQUIRED_ATTESTATIONS,
            })
        );
    }

    #[test]
    fn test_inclusion_threshold_boundary_requires_at_least_80_relays() {
        let target_commitment = [5u8; 32];
        let filler_commitment = [6u8; 32];

        let mut input_79 = base_input(
            (0..REQUIRED_ATTESTATIONS)
                .map(|i| {
                    let mut entries = vec![(1, filler_commitment, true)];
                    if i < REQUIRED_INCLUSIONS - 1 {
                        entries.push((0, target_commitment, true));
                    }
                    relay(i as u32, true, entries)
                })
                .collect(),
        );
        input_79.proposer_indices = vec![0];
        input_79
            .local_valid_shreds
            .insert(0, REQUIRED_RECONSTRUCTION);
        assert_eq!(
            evaluate_vote_gate(&input_79),
            VoteGateDecision::Reject(VoteGateRejection::NoIncludedProposers)
        );

        let mut input_80 = base_input(
            (0..REQUIRED_ATTESTATIONS)
                .map(|i| {
                    let mut entries = vec![(1, filler_commitment, true)];
                    if i < REQUIRED_INCLUSIONS {
                        entries.push((0, target_commitment, true));
                    }
                    relay(i as u32, true, entries)
                })
                .collect(),
        );
        input_80.proposer_indices = vec![0];
        input_80
            .local_valid_shreds
            .insert(0, REQUIRED_RECONSTRUCTION);
        assert_eq!(
            evaluate_vote_gate(&input_80),
            VoteGateDecision::Vote {
                included_proposers: BTreeMap::from([(0, target_commitment)]),
            }
        );
    }
}
