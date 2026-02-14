use {
    crate::mcp,
    solana_clock::Slot,
    solana_hash::{Hash, HASH_BYTES},
    solana_pubkey::Pubkey,
    solana_signature::{Signature, SIGNATURE_BYTES},
    solana_signer::Signer,
    std::collections::{BTreeMap, BTreeSet},
};

pub const AGGREGATE_ATTESTATION_V1: u8 = 1;
const HEADER_LEN: usize = 1 + 8 + 4 + 2;
const RELAY_ENTRY_HEADER_LEN: usize = 4 + 1;
const PROPOSER_ENTRY_LEN: usize = 4 + HASH_BYTES + SIGNATURE_BYTES;
const MAX_AGGREGATE_PROTOCOL_BYTES: usize = HEADER_LEN
    + mcp::NUM_RELAYS
        * (RELAY_ENTRY_HEADER_LEN + mcp::NUM_PROPOSERS * PROPOSER_ENTRY_LEN + SIGNATURE_BYTES);
const MAX_AGGREGATE_WIRE_BYTES: usize =
    if MAX_AGGREGATE_PROTOCOL_BYTES < mcp::MAX_QUIC_CONTROL_PAYLOAD_BYTES {
        MAX_AGGREGATE_PROTOCOL_BYTES
    } else {
        mcp::MAX_QUIC_CONTROL_PAYLOAD_BYTES
    };

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateProposerEntry {
    pub proposer_index: u32,
    pub commitment: Hash,
    pub proposer_signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateRelayEntry {
    pub relay_index: u32,
    pub entries: Vec<AggregateProposerEntry>,
    pub relay_signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateAttestation {
    pub version: u8,
    pub slot: Slot,
    pub leader_index: u32,
    pub relay_entries: Vec<AggregateRelayEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilteredRelayEntry {
    pub relay_index: u32,
    pub entries: Vec<AggregateProposerEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilteredAggregateAttestation {
    pub slot: Slot,
    pub leader_index: u32,
    pub relay_entries: Vec<FilteredRelayEntry>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AggregateAttestationError {
    #[error("unknown aggregate attestation version: {0}")]
    UnknownVersion(u8),
    #[error("too many relay entries: {0}")]
    TooManyRelayEntries(usize),
    #[error("relay index out of range: {0}")]
    RelayIndexOutOfRange(u32),
    #[error("too many proposer entries for relay {relay_index}: {entries_len}")]
    TooManyProposerEntries {
        relay_index: u32,
        entries_len: usize,
    },
    #[error("proposer index out of range: {0}")]
    ProposerIndexOutOfRange(u32),
    #[error("leader index out of range: {0}")]
    LeaderIndexOutOfRange(u32),
    #[error("relay entries must be strictly sorted by relay_index")]
    RelayEntriesNotStrictlySorted,
    #[error("proposer entries must be strictly sorted by proposer_index")]
    ProposerEntriesNotStrictlySorted,
    #[error("aggregate attestation is truncated")]
    Truncated,
    #[error("aggregate attestation has trailing bytes")]
    TrailingBytes,
    #[error("aggregate attestation exceeds protocol maximum: {actual} > {max}")]
    WireBytesTooLarge { actual: usize, max: usize },
}

impl AggregateAttestation {
    pub fn new_canonical(
        slot: Slot,
        leader_index: u32,
        mut relay_entries: Vec<AggregateRelayEntry>,
    ) -> Result<Self, AggregateAttestationError> {
        ensure_leader_index_in_range(leader_index)?;
        if relay_entries.len() > mcp::NUM_RELAYS {
            return Err(AggregateAttestationError::TooManyRelayEntries(
                relay_entries.len(),
            ));
        }

        relay_entries.sort_unstable_by_key(|entry| entry.relay_index);
        for relay_entry in &mut relay_entries {
            ensure_relay_index_in_range(relay_entry.relay_index)?;
            if relay_entry.entries.len() > mcp::NUM_PROPOSERS {
                return Err(AggregateAttestationError::TooManyProposerEntries {
                    relay_index: relay_entry.relay_index,
                    entries_len: relay_entry.entries.len(),
                });
            }
            ensure_proposer_indices_in_range(&relay_entry.entries)?;
            relay_entry
                .entries
                .sort_unstable_by_key(|entry| entry.proposer_index);
            ensure_proposer_entries_strictly_sorted(&relay_entry.entries)?;
        }
        ensure_relay_entries_strictly_sorted(&relay_entries)?;

        Ok(Self {
            version: AGGREGATE_ATTESTATION_V1,
            slot,
            leader_index,
            relay_entries,
        })
    }

    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, AggregateAttestationError> {
        self.validate_for_serialize()?;

        let mut out = Vec::with_capacity(
            HEADER_LEN
                + self
                    .relay_entries
                    .iter()
                    .map(|entry| {
                        RELAY_ENTRY_HEADER_LEN
                            + entry.entries.len() * PROPOSER_ENTRY_LEN
                            + SIGNATURE_BYTES
                    })
                    .sum::<usize>(),
        );

        out.push(self.version);
        out.extend_from_slice(&self.slot.to_le_bytes());
        out.extend_from_slice(&self.leader_index.to_le_bytes());
        out.extend_from_slice(&(self.relay_entries.len() as u16).to_le_bytes());

        for relay_entry in &self.relay_entries {
            append_relay_entry_bytes(
                &mut out,
                relay_entry.relay_index,
                &relay_entry.entries,
                &relay_entry.relay_signature,
            )?;
        }
        if out.len() > MAX_AGGREGATE_WIRE_BYTES {
            return Err(AggregateAttestationError::WireBytesTooLarge {
                actual: out.len(),
                max: MAX_AGGREGATE_WIRE_BYTES,
            });
        }

        Ok(out)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, AggregateAttestationError> {
        if bytes.len() > MAX_AGGREGATE_WIRE_BYTES {
            return Err(AggregateAttestationError::WireBytesTooLarge {
                actual: bytes.len(),
                max: MAX_AGGREGATE_WIRE_BYTES,
            });
        }
        if bytes.len() < HEADER_LEN {
            return Err(AggregateAttestationError::Truncated);
        }

        let mut cursor = 0usize;
        let version = read_u8(bytes, &mut cursor)?;
        if version != AGGREGATE_ATTESTATION_V1 {
            return Err(AggregateAttestationError::UnknownVersion(version));
        }

        let slot = read_u64_le(bytes, &mut cursor)?;
        let leader_index = read_u32_le(bytes, &mut cursor)?;
        ensure_leader_index_in_range(leader_index)?;
        let relays_len = read_u16_le(bytes, &mut cursor)? as usize;
        if relays_len > mcp::NUM_RELAYS {
            return Err(AggregateAttestationError::TooManyRelayEntries(relays_len));
        }

        let mut relay_entries = Vec::with_capacity(relays_len);
        for _ in 0..relays_len {
            let relay_index = read_u32_le(bytes, &mut cursor)?;
            ensure_relay_index_in_range(relay_index)?;
            let entries_len = read_u8(bytes, &mut cursor)? as usize;
            if entries_len > mcp::NUM_PROPOSERS {
                return Err(AggregateAttestationError::TooManyProposerEntries {
                    relay_index,
                    entries_len,
                });
            }

            let mut entries = Vec::with_capacity(entries_len);
            for _ in 0..entries_len {
                let proposer_index = read_u32_le(bytes, &mut cursor)?;
                if proposer_index as usize >= mcp::NUM_PROPOSERS {
                    return Err(AggregateAttestationError::ProposerIndexOutOfRange(
                        proposer_index,
                    ));
                }
                let commitment =
                    Hash::new_from_array(read_array::<HASH_BYTES>(bytes, &mut cursor)?);
                let proposer_signature =
                    Signature::from(read_array::<SIGNATURE_BYTES>(bytes, &mut cursor)?);
                entries.push(AggregateProposerEntry {
                    proposer_index,
                    commitment,
                    proposer_signature,
                });
            }

            let relay_signature =
                Signature::from(read_array::<SIGNATURE_BYTES>(bytes, &mut cursor)?);
            relay_entries.push(AggregateRelayEntry {
                relay_index,
                entries,
                relay_signature,
            });
        }

        if cursor != bytes.len() {
            return Err(AggregateAttestationError::TrailingBytes);
        }

        ensure_relay_entries_strictly_sorted(&relay_entries)?;
        for relay_entry in &relay_entries {
            ensure_proposer_entries_strictly_sorted(&relay_entry.entries)?;
        }

        Ok(Self {
            version,
            slot,
            leader_index,
            relay_entries,
        })
    }

    pub fn filtered_valid_entries<FRelay, FProposer>(
        &self,
        mut relay_pubkey_for_index: FRelay,
        mut proposer_pubkey_for_index: FProposer,
    ) -> Vec<FilteredRelayEntry>
    where
        FRelay: FnMut(u32) -> Option<Pubkey>,
        FProposer: FnMut(u32) -> Option<Pubkey>,
    {
        self.relay_entries
            .iter()
            .filter_map(|relay_entry| {
                let relay_pubkey = relay_pubkey_for_index(relay_entry.relay_index)?;
                if !relay_entry.verify_relay_signature(self.version, self.slot, &relay_pubkey) {
                    return None;
                }
                let entries: Vec<AggregateProposerEntry> = relay_entry
                    .entries
                    .iter()
                    .filter(|entry| {
                        proposer_pubkey_for_index(entry.proposer_index).is_some_and(
                            |proposer_pubkey| {
                                entry
                                    .proposer_signature
                                    .verify(proposer_pubkey.as_ref(), entry.commitment.as_ref())
                            },
                        )
                    })
                    .cloned()
                    .collect();
                if entries.is_empty() {
                    // Empty entries should not count toward relay attestation thresholds.
                    return None;
                }
                Some(FilteredRelayEntry {
                    relay_index: relay_entry.relay_index,
                    entries,
                })
            })
            .collect()
    }

    /// Returns a canonical aggregate where:
    /// - relay/proposer signatures are verified and invalid entries are removed
    /// - equivocating proposers (multiple commitments) are removed from all relays
    pub fn canonical_filtered<FRelay, FProposer>(
        &self,
        relay_pubkey_for_index: FRelay,
        proposer_pubkey_for_index: FProposer,
    ) -> Result<FilteredAggregateAttestation, AggregateAttestationError>
    where
        FRelay: FnMut(u32) -> Option<Pubkey>,
        FProposer: FnMut(u32) -> Option<Pubkey>,
    {
        let mut relay_entries =
            self.filtered_valid_entries(relay_pubkey_for_index, proposer_pubkey_for_index);
        let equivocating_proposers = collect_equivocating_proposers(&relay_entries);
        for relay_entry in &mut relay_entries {
            relay_entry
                .entries
                .retain(|entry| !equivocating_proposers.contains(&entry.proposer_index));
        }
        // Relays with no remaining valid proposer entries must not count toward
        // downstream threshold checks.
        relay_entries.retain(|relay_entry| !relay_entry.entries.is_empty());

        Ok(FilteredAggregateAttestation {
            slot: self.slot,
            leader_index: self.leader_index,
            relay_entries,
        })
    }

    fn validate_for_serialize(&self) -> Result<(), AggregateAttestationError> {
        ensure_leader_index_in_range(self.leader_index)?;
        if self.relay_entries.len() > mcp::NUM_RELAYS {
            return Err(AggregateAttestationError::TooManyRelayEntries(
                self.relay_entries.len(),
            ));
        }
        ensure_relay_entries_strictly_sorted(&self.relay_entries)?;
        for relay_entry in &self.relay_entries {
            ensure_relay_index_in_range(relay_entry.relay_index)?;
            if relay_entry.entries.len() > mcp::NUM_PROPOSERS {
                return Err(AggregateAttestationError::TooManyProposerEntries {
                    relay_index: relay_entry.relay_index,
                    entries_len: relay_entry.entries.len(),
                });
            }
            ensure_proposer_indices_in_range(&relay_entry.entries)?;
            ensure_proposer_entries_strictly_sorted(&relay_entry.entries)?;
        }
        Ok(())
    }
}

impl AggregateRelayEntry {
    pub fn sign<T: Signer>(
        &mut self,
        version: u8,
        slot: Slot,
        signer: &T,
    ) -> Result<(), AggregateAttestationError> {
        let signing_bytes = relay_signing_bytes(version, slot, self.relay_index, &self.entries)?;
        self.relay_signature = signer.sign_message(&signing_bytes);
        Ok(())
    }

    pub fn verify_relay_signature(&self, version: u8, slot: Slot, relay_pubkey: &Pubkey) -> bool {
        relay_signing_bytes(version, slot, self.relay_index, &self.entries)
            .map(|signing_bytes| {
                self.relay_signature
                    .verify(relay_pubkey.as_ref(), &signing_bytes)
            })
            .unwrap_or(false)
    }
}

fn relay_signing_bytes(
    version: u8,
    slot: Slot,
    relay_index: u32,
    entries: &[AggregateProposerEntry],
) -> Result<Vec<u8>, AggregateAttestationError> {
    // Relay signatures follow RelayAttestation v1 signing bytes:
    // version || slot || relay_index || entries_len || entries.
    // `leader_index` is intentionally excluded because relay attestations are
    // defined as leader-agnostic for the same slot.
    ensure_relay_index_in_range(relay_index)?;
    if entries.len() > mcp::NUM_PROPOSERS {
        return Err(AggregateAttestationError::TooManyProposerEntries {
            relay_index,
            entries_len: entries.len(),
        });
    }
    ensure_proposer_indices_in_range(entries)?;
    let mut out = Vec::with_capacity(1 + 8 + 4 + 1 + entries.len() * PROPOSER_ENTRY_LEN);
    out.push(version);
    out.extend_from_slice(&slot.to_le_bytes());
    out.extend_from_slice(&relay_index.to_le_bytes());
    out.push(entries.len() as u8);
    for entry in entries {
        out.extend_from_slice(&entry.proposer_index.to_le_bytes());
        out.extend_from_slice(entry.commitment.as_ref());
        out.extend_from_slice(entry.proposer_signature.as_ref());
    }
    Ok(out)
}

fn append_relay_entry_bytes(
    out: &mut Vec<u8>,
    relay_index: u32,
    entries: &[AggregateProposerEntry],
    relay_signature: &Signature,
) -> Result<(), AggregateAttestationError> {
    ensure_relay_index_in_range(relay_index)?;
    if entries.len() > mcp::NUM_PROPOSERS {
        return Err(AggregateAttestationError::TooManyProposerEntries {
            relay_index,
            entries_len: entries.len(),
        });
    }
    ensure_proposer_indices_in_range(entries)?;
    out.extend_from_slice(&relay_index.to_le_bytes());
    out.push(
        entries
            .len()
            .try_into()
            .expect("entries length is bounded by NUM_PROPOSERS"),
    );
    for entry in entries {
        out.extend_from_slice(&entry.proposer_index.to_le_bytes());
        out.extend_from_slice(entry.commitment.as_ref());
        out.extend_from_slice(entry.proposer_signature.as_ref());
    }
    out.extend_from_slice(relay_signature.as_ref());
    Ok(())
}

fn ensure_relay_entries_strictly_sorted(
    relay_entries: &[AggregateRelayEntry],
) -> Result<(), AggregateAttestationError> {
    if relay_entries
        .windows(2)
        .all(|window| window[0].relay_index < window[1].relay_index)
    {
        return Ok(());
    }
    Err(AggregateAttestationError::RelayEntriesNotStrictlySorted)
}

fn ensure_proposer_entries_strictly_sorted(
    entries: &[AggregateProposerEntry],
) -> Result<(), AggregateAttestationError> {
    if entries
        .windows(2)
        .all(|window| window[0].proposer_index < window[1].proposer_index)
    {
        return Ok(());
    }
    Err(AggregateAttestationError::ProposerEntriesNotStrictlySorted)
}

fn ensure_relay_index_in_range(relay_index: u32) -> Result<(), AggregateAttestationError> {
    if relay_index as usize >= mcp::NUM_RELAYS {
        return Err(AggregateAttestationError::RelayIndexOutOfRange(relay_index));
    }
    Ok(())
}

fn ensure_proposer_indices_in_range(
    entries: &[AggregateProposerEntry],
) -> Result<(), AggregateAttestationError> {
    for entry in entries {
        if entry.proposer_index as usize >= mcp::NUM_PROPOSERS {
            return Err(AggregateAttestationError::ProposerIndexOutOfRange(
                entry.proposer_index,
            ));
        }
    }
    Ok(())
}

fn ensure_leader_index_in_range(leader_index: u32) -> Result<(), AggregateAttestationError> {
    if leader_index as usize >= mcp::NUM_PROPOSERS {
        return Err(AggregateAttestationError::LeaderIndexOutOfRange(
            leader_index,
        ));
    }
    Ok(())
}

fn collect_equivocating_proposers(relay_entries: &[FilteredRelayEntry]) -> BTreeSet<u32> {
    let mut proposer_commitments = BTreeMap::new();
    let mut equivocating_proposers = BTreeSet::new();

    for relay_entry in relay_entries {
        for entry in &relay_entry.entries {
            if let Some(existing_commitment) = proposer_commitments.get(&entry.proposer_index) {
                if existing_commitment != &entry.commitment {
                    equivocating_proposers.insert(entry.proposer_index);
                }
            } else {
                proposer_commitments.insert(entry.proposer_index, entry.commitment);
            }
        }
    }

    equivocating_proposers
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, AggregateAttestationError> {
    let Some(end) = cursor.checked_add(1) else {
        return Err(AggregateAttestationError::Truncated);
    };
    if end > bytes.len() {
        return Err(AggregateAttestationError::Truncated);
    }
    let value = bytes[*cursor];
    *cursor = end;
    Ok(value)
}

fn read_u16_le(bytes: &[u8], cursor: &mut usize) -> Result<u16, AggregateAttestationError> {
    Ok(u16::from_le_bytes(read_array::<2>(bytes, cursor)?))
}

fn read_u32_le(bytes: &[u8], cursor: &mut usize) -> Result<u32, AggregateAttestationError> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, cursor)?))
}

fn read_u64_le(bytes: &[u8], cursor: &mut usize) -> Result<u64, AggregateAttestationError> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, cursor)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], AggregateAttestationError> {
    let Some(end) = cursor.checked_add(N) else {
        return Err(AggregateAttestationError::Truncated);
    };
    if end > bytes.len() {
        return Err(AggregateAttestationError::Truncated);
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
    fn test_roundtrip_and_signature_filtering() {
        let relay0 = Keypair::new();
        let relay1 = Keypair::new();
        let proposer0 = Keypair::new();
        let proposer1 = Keypair::new();
        let proposer2 = Keypair::new();

        let commitment0 = Hash::new_unique();
        let commitment1 = Hash::new_unique();
        let commitment2 = Hash::new_unique();

        let mut relay_entry0 = AggregateRelayEntry {
            relay_index: 4,
            entries: vec![
                AggregateProposerEntry {
                    proposer_index: 0,
                    commitment: commitment0,
                    proposer_signature: proposer0.sign_message(commitment0.as_ref()),
                },
                AggregateProposerEntry {
                    proposer_index: 2,
                    commitment: commitment2,
                    proposer_signature: proposer2.sign_message(commitment2.as_ref()),
                },
            ],
            relay_signature: Signature::default(),
        };
        relay_entry0
            .sign(AGGREGATE_ATTESTATION_V1, 55, &relay0)
            .unwrap();

        // Valid relay signature, but one invalid proposer signature in entries.
        let mut relay_entry1 = AggregateRelayEntry {
            relay_index: 9,
            entries: vec![AggregateProposerEntry {
                proposer_index: 1,
                commitment: commitment1,
                proposer_signature: proposer2.sign_message(commitment1.as_ref()),
            }],
            relay_signature: Signature::default(),
        };
        relay_entry1
            .sign(AGGREGATE_ATTESTATION_V1, 55, &relay1)
            .unwrap();

        let aggregate =
            AggregateAttestation::new_canonical(55, 3, vec![relay_entry1, relay_entry0]).unwrap();
        let bytes = aggregate.to_wire_bytes().unwrap();
        let decoded = AggregateAttestation::from_wire_bytes(&bytes).unwrap();

        assert_eq!(decoded, aggregate);

        let filtered = decoded.filtered_valid_entries(
            |relay_index| match relay_index {
                4 => Some(relay0.pubkey()),
                9 => Some(relay1.pubkey()),
                _ => None,
            },
            |proposer_index| match proposer_index {
                0 => Some(proposer0.pubkey()),
                1 => Some(proposer1.pubkey()),
                2 => Some(proposer2.pubkey()),
                _ => None,
            },
        );

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].relay_index, 4);
        assert_eq!(filtered[0].entries.len(), 2);
    }

    #[test]
    fn test_invalid_relay_signature_excludes_relay_entry() {
        let relay = Keypair::new();
        let proposer = Keypair::new();
        let commitment = Hash::new_unique();

        let mut relay_entry = AggregateRelayEntry {
            relay_index: 2,
            entries: vec![AggregateProposerEntry {
                proposer_index: 0,
                commitment,
                proposer_signature: proposer.sign_message(commitment.as_ref()),
            }],
            relay_signature: Signature::default(),
        };
        relay_entry
            .sign(AGGREGATE_ATTESTATION_V1, 77, &relay)
            .unwrap();
        relay_entry.relay_signature = Signature::new_unique();

        let aggregate = AggregateAttestation::new_canonical(77, 0, vec![relay_entry]).unwrap();
        let filtered =
            aggregate.filtered_valid_entries(|_| Some(relay.pubkey()), |_| Some(proposer.pubkey()));
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_unsorted_relay_entries_rejected() {
        let bytes = {
            let mut out = Vec::new();
            out.push(AGGREGATE_ATTESTATION_V1);
            out.extend_from_slice(&1u64.to_le_bytes());
            out.extend_from_slice(&2u32.to_le_bytes());
            out.extend_from_slice(&2u16.to_le_bytes());

            out.extend_from_slice(&10u32.to_le_bytes());
            out.push(0);
            out.extend_from_slice(Signature::new_unique().as_ref());

            out.extend_from_slice(&5u32.to_le_bytes());
            out.push(0);
            out.extend_from_slice(Signature::new_unique().as_ref());
            out
        };

        assert_eq!(
            AggregateAttestation::from_wire_bytes(&bytes).unwrap_err(),
            AggregateAttestationError::RelayEntriesNotStrictlySorted,
        );
    }

    #[test]
    fn test_unsorted_proposer_entries_rejected() {
        let relay = Keypair::new();
        let proposer = Keypair::new();
        let commitment = Hash::new_unique();

        let mut relay_entry_bytes = Vec::new();
        relay_entry_bytes.extend_from_slice(&7u32.to_le_bytes());
        relay_entry_bytes.push(2);

        relay_entry_bytes.extend_from_slice(&4u32.to_le_bytes());
        relay_entry_bytes.extend_from_slice(commitment.as_ref());
        relay_entry_bytes.extend_from_slice(proposer.sign_message(commitment.as_ref()).as_ref());

        relay_entry_bytes.extend_from_slice(&3u32.to_le_bytes());
        relay_entry_bytes.extend_from_slice(commitment.as_ref());
        relay_entry_bytes.extend_from_slice(proposer.sign_message(commitment.as_ref()).as_ref());

        let relay_signing = {
            let mut bytes = vec![AGGREGATE_ATTESTATION_V1];
            bytes.extend_from_slice(&9u64.to_le_bytes());
            bytes.extend_from_slice(&7u32.to_le_bytes());
            bytes.push(2);
            bytes.extend_from_slice(&relay_entry_bytes[5..]);
            bytes
        };
        relay_entry_bytes.extend_from_slice(relay.sign_message(&relay_signing).as_ref());

        let mut aggregate = vec![AGGREGATE_ATTESTATION_V1];
        aggregate.extend_from_slice(&9u64.to_le_bytes());
        aggregate.extend_from_slice(&1u32.to_le_bytes());
        aggregate.extend_from_slice(&1u16.to_le_bytes());
        aggregate.extend_from_slice(&relay_entry_bytes);

        assert_eq!(
            AggregateAttestation::from_wire_bytes(&aggregate).unwrap_err(),
            AggregateAttestationError::ProposerEntriesNotStrictlySorted,
        );
    }

    #[test]
    fn test_unknown_version_rejected() {
        let bytes = vec![99u8; HEADER_LEN];
        assert_eq!(
            AggregateAttestation::from_wire_bytes(&bytes).unwrap_err(),
            AggregateAttestationError::UnknownVersion(99)
        );
    }

    #[test]
    fn test_deterministic_bytes_for_same_map() {
        let relay = Keypair::new();
        let proposer = Keypair::new();
        let commitment = Hash::new_unique();

        let proposer_entry = AggregateProposerEntry {
            proposer_index: 1,
            commitment,
            proposer_signature: proposer.sign_message(commitment.as_ref()),
        };
        let mut relay_entry_a = AggregateRelayEntry {
            relay_index: 2,
            entries: vec![proposer_entry.clone()],
            relay_signature: Signature::default(),
        };
        relay_entry_a
            .sign(AGGREGATE_ATTESTATION_V1, 4, &relay)
            .unwrap();

        let mut relay_entry_b = AggregateRelayEntry {
            relay_index: 2,
            entries: vec![proposer_entry],
            relay_signature: Signature::default(),
        };
        relay_entry_b
            .sign(AGGREGATE_ATTESTATION_V1, 4, &relay)
            .unwrap();

        let a = AggregateAttestation::new_canonical(4, 0, vec![relay_entry_a]).unwrap();
        let b = AggregateAttestation::new_canonical(4, 0, vec![relay_entry_b]).unwrap();
        assert_eq!(a.to_wire_bytes().unwrap(), b.to_wire_bytes().unwrap());
    }

    #[test]
    fn test_canonical_filtered_drops_only_equivocating_proposer_entries() {
        let relay0 = Keypair::new();
        let relay1 = Keypair::new();
        let proposer0 = Keypair::new();
        let proposer1 = Keypair::new();

        let proposer0_commitment_a = Hash::new_unique();
        let proposer0_commitment_b = Hash::new_unique();
        let proposer1_commitment = Hash::new_unique();

        let mut relay_entry0 = AggregateRelayEntry {
            relay_index: 2,
            entries: vec![
                AggregateProposerEntry {
                    proposer_index: 0,
                    commitment: proposer0_commitment_a,
                    proposer_signature: proposer0.sign_message(proposer0_commitment_a.as_ref()),
                },
                AggregateProposerEntry {
                    proposer_index: 1,
                    commitment: proposer1_commitment,
                    proposer_signature: proposer1.sign_message(proposer1_commitment.as_ref()),
                },
            ],
            relay_signature: Signature::default(),
        };
        relay_entry0
            .sign(AGGREGATE_ATTESTATION_V1, 42, &relay0)
            .unwrap();

        let mut relay_entry1 = AggregateRelayEntry {
            relay_index: 9,
            entries: vec![
                AggregateProposerEntry {
                    proposer_index: 0,
                    commitment: proposer0_commitment_b,
                    proposer_signature: proposer0.sign_message(proposer0_commitment_b.as_ref()),
                },
                AggregateProposerEntry {
                    proposer_index: 1,
                    commitment: proposer1_commitment,
                    proposer_signature: proposer1.sign_message(proposer1_commitment.as_ref()),
                },
            ],
            relay_signature: Signature::default(),
        };
        relay_entry1
            .sign(AGGREGATE_ATTESTATION_V1, 42, &relay1)
            .unwrap();

        let aggregate =
            AggregateAttestation::new_canonical(42, 4, vec![relay_entry1, relay_entry0]).unwrap();
        let filtered = aggregate
            .canonical_filtered(
                |relay_index| match relay_index {
                    2 => Some(relay0.pubkey()),
                    9 => Some(relay1.pubkey()),
                    _ => None,
                },
                |proposer_index| match proposer_index {
                    0 => Some(proposer0.pubkey()),
                    1 => Some(proposer1.pubkey()),
                    _ => None,
                },
            )
            .unwrap();

        assert_eq!(filtered.relay_entries.len(), 2);
        assert_eq!(filtered.relay_entries[0].relay_index, 2);
        assert_eq!(filtered.relay_entries[0].entries.len(), 1);
        assert_eq!(filtered.relay_entries[0].entries[0].proposer_index, 1);
        assert_eq!(
            filtered.relay_entries[0].entries[0].commitment,
            proposer1_commitment
        );
        assert_eq!(filtered.relay_entries[1].relay_index, 9);
        assert_eq!(filtered.relay_entries[1].entries.len(), 1);
        assert_eq!(filtered.relay_entries[1].entries[0].proposer_index, 1);
        assert_eq!(
            filtered.relay_entries[1].entries[0].commitment,
            proposer1_commitment
        );
    }

    #[test]
    fn test_canonical_filtered_drops_relays_that_become_empty_after_equivocation_filtering() {
        let relay0 = Keypair::new();
        let relay1 = Keypair::new();
        let proposer0 = Keypair::new();

        let proposer0_commitment_a = Hash::new_unique();
        let proposer0_commitment_b = Hash::new_unique();

        let mut relay_entry0 = AggregateRelayEntry {
            relay_index: 1,
            entries: vec![AggregateProposerEntry {
                proposer_index: 0,
                commitment: proposer0_commitment_a,
                proposer_signature: proposer0.sign_message(proposer0_commitment_a.as_ref()),
            }],
            relay_signature: Signature::default(),
        };
        relay_entry0
            .sign(AGGREGATE_ATTESTATION_V1, 91, &relay0)
            .unwrap();

        let mut relay_entry1 = AggregateRelayEntry {
            relay_index: 2,
            entries: vec![AggregateProposerEntry {
                proposer_index: 0,
                commitment: proposer0_commitment_b,
                proposer_signature: proposer0.sign_message(proposer0_commitment_b.as_ref()),
            }],
            relay_signature: Signature::default(),
        };
        relay_entry1
            .sign(AGGREGATE_ATTESTATION_V1, 91, &relay1)
            .unwrap();

        let aggregate =
            AggregateAttestation::new_canonical(91, 3, vec![relay_entry1, relay_entry0]).unwrap();
        let filtered = aggregate
            .canonical_filtered(
                |relay_index| match relay_index {
                    1 => Some(relay0.pubkey()),
                    2 => Some(relay1.pubkey()),
                    _ => None,
                },
                |proposer_index| match proposer_index {
                    0 => Some(proposer0.pubkey()),
                    _ => None,
                },
            )
            .unwrap();

        assert!(filtered.relay_entries.is_empty());
    }

    #[test]
    fn test_from_wire_bytes_rejects_too_many_relays() {
        let mut bytes = Vec::new();
        bytes.push(AGGREGATE_ATTESTATION_V1);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&((mcp::NUM_RELAYS + 1) as u16).to_le_bytes());

        assert_eq!(
            AggregateAttestation::from_wire_bytes(&bytes).unwrap_err(),
            AggregateAttestationError::TooManyRelayEntries(mcp::NUM_RELAYS + 1)
        );
    }

    #[test]
    fn test_from_wire_bytes_rejects_oversized_wire() {
        let bytes = vec![0u8; MAX_AGGREGATE_WIRE_BYTES + 1];
        assert_eq!(
            AggregateAttestation::from_wire_bytes(&bytes).unwrap_err(),
            AggregateAttestationError::WireBytesTooLarge {
                actual: MAX_AGGREGATE_WIRE_BYTES + 1,
                max: MAX_AGGREGATE_WIRE_BYTES,
            }
        );
    }

    #[test]
    fn test_sign_rejects_too_many_proposer_entries() {
        let relay = Keypair::new();
        let proposer = Keypair::new();
        let commitment = Hash::new_unique();
        let entries = (0..=mcp::NUM_PROPOSERS as u32)
            .map(|proposer_index| AggregateProposerEntry {
                proposer_index,
                commitment,
                proposer_signature: proposer.sign_message(commitment.as_ref()),
            })
            .collect();
        let mut relay_entry = AggregateRelayEntry {
            relay_index: 0,
            entries,
            relay_signature: Signature::default(),
        };

        let err = relay_entry
            .sign(AGGREGATE_ATTESTATION_V1, 1, &relay)
            .unwrap_err();
        assert_eq!(
            err,
            AggregateAttestationError::TooManyProposerEntries {
                relay_index: 0,
                entries_len: mcp::NUM_PROPOSERS + 1,
            }
        );
    }

    #[test]
    fn test_max_wire_fits_quic_control_payload_bound() {
        assert!(MAX_AGGREGATE_WIRE_BYTES <= mcp::MAX_QUIC_CONTROL_PAYLOAD_BYTES);
    }

    #[test]
    fn test_new_canonical_rejects_out_of_range_relay_index() {
        let relay = AggregateRelayEntry {
            relay_index: mcp::NUM_RELAYS as u32,
            entries: vec![],
            relay_signature: Signature::default(),
        };
        assert_eq!(
            AggregateAttestation::new_canonical(1, 0, vec![relay]).unwrap_err(),
            AggregateAttestationError::RelayIndexOutOfRange(mcp::NUM_RELAYS as u32),
        );
    }

    #[test]
    fn test_from_wire_rejects_out_of_range_proposer_index() {
        let mut bytes = Vec::new();
        bytes.push(AGGREGATE_ATTESTATION_V1);
        bytes.extend_from_slice(&1u64.to_le_bytes()); // slot
        bytes.extend_from_slice(&0u32.to_le_bytes()); // leader_index
        bytes.extend_from_slice(&1u16.to_le_bytes()); // relay_entries_len
        bytes.extend_from_slice(&0u32.to_le_bytes()); // relay_index
        bytes.push(1); // proposer entries len
        bytes.extend_from_slice(&(mcp::NUM_PROPOSERS as u32).to_le_bytes()); // proposer_index
        bytes.extend_from_slice(Hash::new_unique().as_ref());
        bytes.extend_from_slice(Signature::default().as_ref());
        bytes.extend_from_slice(Signature::default().as_ref());

        assert_eq!(
            AggregateAttestation::from_wire_bytes(&bytes).unwrap_err(),
            AggregateAttestationError::ProposerIndexOutOfRange(mcp::NUM_PROPOSERS as u32),
        );
    }

    #[test]
    fn test_new_canonical_rejects_duplicate_relay_indices() {
        let duplicate_a = AggregateRelayEntry {
            relay_index: 5,
            entries: vec![],
            relay_signature: Signature::default(),
        };
        let duplicate_b = AggregateRelayEntry {
            relay_index: 5,
            entries: vec![],
            relay_signature: Signature::default(),
        };

        assert_eq!(
            AggregateAttestation::new_canonical(1, 0, vec![duplicate_a, duplicate_b]).unwrap_err(),
            AggregateAttestationError::RelayEntriesNotStrictlySorted,
        );
    }

    #[test]
    fn test_roundtrip_empty_aggregate() {
        let aggregate = AggregateAttestation::new_canonical(9, 1, Vec::new()).unwrap();
        let bytes = aggregate.to_wire_bytes().unwrap();
        let decoded = AggregateAttestation::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, aggregate);
        assert!(decoded.relay_entries.is_empty());
    }

    #[test]
    fn test_new_canonical_rejects_out_of_range_leader_index() {
        assert_eq!(
            AggregateAttestation::new_canonical(1, mcp::NUM_PROPOSERS as u32, Vec::new())
                .unwrap_err(),
            AggregateAttestationError::LeaderIndexOutOfRange(mcp::NUM_PROPOSERS as u32),
        );
    }

    #[test]
    fn test_from_wire_rejects_out_of_range_leader_index() {
        let mut bytes = Vec::new();
        bytes.push(AGGREGATE_ATTESTATION_V1);
        bytes.extend_from_slice(&1u64.to_le_bytes()); // slot
        bytes.extend_from_slice(&(mcp::NUM_PROPOSERS as u32).to_le_bytes()); // leader_index
        bytes.extend_from_slice(&0u16.to_le_bytes()); // relay_entries_len

        assert_eq!(
            AggregateAttestation::from_wire_bytes(&bytes).unwrap_err(),
            AggregateAttestationError::LeaderIndexOutOfRange(mcp::NUM_PROPOSERS as u32),
        );
    }
}
