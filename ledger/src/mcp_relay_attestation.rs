use {
    crate::mcp,
    solana_clock::Slot,
    solana_hash::{Hash, HASH_BYTES},
    solana_pubkey::Pubkey,
    solana_signature::{Signature, SIGNATURE_BYTES},
    solana_signer::Signer,
};

pub const RELAY_ATTESTATION_V1: u8 = 1;
const HEADER_LEN: usize = 1 + 8 + 4 + 1;
const ENTRY_LEN: usize = 4 + HASH_BYTES + SIGNATURE_BYTES;
const FOOTER_LEN: usize = SIGNATURE_BYTES;
const MIN_WIRE_LEN: usize = HEADER_LEN + FOOTER_LEN;
const MAX_RELAY_ATTESTATION_ENTRIES: usize = mcp::NUM_PROPOSERS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAttestationEntry {
    pub proposer_index: u32,
    pub commitment: Hash,
    pub proposer_signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAttestation {
    pub version: u8,
    pub slot: Slot,
    pub relay_index: u32,
    pub entries: Vec<RelayAttestationEntry>,
    pub relay_signature: Signature,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RelayAttestationError {
    #[error("unknown relay attestation version: {0}")]
    UnknownVersion(u8),
    #[error("relay attestation entries exceed MCP proposer limit: {0}")]
    TooManyEntries(usize),
    #[error("relay attestation must include at least one proposer entry")]
    EmptyEntries,
    #[error("relay index out of range: {0}")]
    RelayIndexOutOfRange(u32),
    #[error("proposer index out of range: {0}")]
    ProposerIndexOutOfRange(u32),
    #[error("relay attestation entries must be strictly sorted by proposer_index")]
    EntriesNotStrictlySorted,
    #[error("relay attestation is truncated")]
    Truncated,
    #[error("relay attestation has trailing bytes")]
    TrailingBytes,
}

impl RelayAttestation {
    pub fn new_unsigned(
        slot: Slot,
        relay_index: u32,
        mut entries: Vec<RelayAttestationEntry>,
    ) -> Result<Self, RelayAttestationError> {
        ensure_relay_index_in_range(relay_index)?;
        if entries.is_empty() {
            return Err(RelayAttestationError::EmptyEntries);
        }
        if entries.len() > MAX_RELAY_ATTESTATION_ENTRIES {
            return Err(RelayAttestationError::TooManyEntries(entries.len()));
        }
        ensure_proposer_indices_in_range(&entries)?;
        entries.sort_unstable_by_key(|entry| entry.proposer_index);
        ensure_entries_strictly_sorted(&entries)?;
        Ok(Self {
            version: RELAY_ATTESTATION_V1,
            slot,
            relay_index,
            entries,
            relay_signature: Signature::default(),
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, RelayAttestationError> {
        ensure_relay_index_in_range(self.relay_index)?;
        if self.entries.is_empty() {
            return Err(RelayAttestationError::EmptyEntries);
        }
        if self.entries.len() > MAX_RELAY_ATTESTATION_ENTRIES {
            return Err(RelayAttestationError::TooManyEntries(self.entries.len()));
        }
        ensure_proposer_indices_in_range(&self.entries)?;
        ensure_entries_strictly_sorted(&self.entries)?;

        let mut bytes = Vec::with_capacity(HEADER_LEN + self.entries.len() * ENTRY_LEN);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.slot.to_le_bytes());
        bytes.extend_from_slice(&self.relay_index.to_le_bytes());
        let entries_len = u8::try_from(self.entries.len())
            .map_err(|_| RelayAttestationError::TooManyEntries(self.entries.len()))?;
        bytes.push(entries_len);

        for entry in &self.entries {
            bytes.extend_from_slice(&entry.proposer_index.to_le_bytes());
            bytes.extend_from_slice(entry.commitment.as_ref());
            bytes.extend_from_slice(entry.proposer_signature.as_ref());
        }

        Ok(bytes)
    }

    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, RelayAttestationError> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(self.relay_signature.as_ref());
        Ok(bytes)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, RelayAttestationError> {
        if bytes.len() < MIN_WIRE_LEN {
            return Err(RelayAttestationError::Truncated);
        }

        let mut cursor = 0usize;
        let version = read_u8(bytes, &mut cursor)?;
        if version != RELAY_ATTESTATION_V1 {
            return Err(RelayAttestationError::UnknownVersion(version));
        }

        let slot = read_u64_le(bytes, &mut cursor)?;
        let relay_index = read_u32_le(bytes, &mut cursor)?;
        ensure_relay_index_in_range(relay_index)?;
        let entries_len = read_u8(bytes, &mut cursor)? as usize;
        if entries_len == 0 {
            return Err(RelayAttestationError::EmptyEntries);
        }
        if entries_len > MAX_RELAY_ATTESTATION_ENTRIES {
            return Err(RelayAttestationError::TooManyEntries(entries_len));
        }

        let mut entries = Vec::with_capacity(entries_len);
        for _ in 0..entries_len {
            let proposer_index = read_u32_le(bytes, &mut cursor)?;
            if proposer_index as usize >= mcp::NUM_PROPOSERS {
                return Err(RelayAttestationError::ProposerIndexOutOfRange(
                    proposer_index,
                ));
            }
            let commitment = Hash::new_from_array(read_array::<HASH_BYTES>(bytes, &mut cursor)?);
            let proposer_signature =
                Signature::from(read_array::<SIGNATURE_BYTES>(bytes, &mut cursor)?);
            entries.push(RelayAttestationEntry {
                proposer_index,
                commitment,
                proposer_signature,
            });
        }

        let relay_signature = Signature::from(read_array::<SIGNATURE_BYTES>(bytes, &mut cursor)?);
        if cursor != bytes.len() {
            return Err(RelayAttestationError::TrailingBytes);
        }

        ensure_entries_strictly_sorted(&entries)?;

        Ok(Self {
            version,
            slot,
            relay_index,
            entries,
            relay_signature,
        })
    }

    pub fn sign_relay<T: Signer>(&mut self, signer: &T) -> Result<(), RelayAttestationError> {
        let signing_bytes = self.signing_bytes()?;
        self.relay_signature = signer.sign_message(&signing_bytes);
        Ok(())
    }

    pub fn verify_relay_signature(&self, relay_pubkey: &Pubkey) -> bool {
        let Ok(signing_bytes) = self.signing_bytes() else {
            return false;
        };
        self.relay_signature
            .verify(relay_pubkey.as_ref(), &signing_bytes)
    }

    pub fn verify_proposer_signatures<F>(&self, mut proposer_pubkey_for_index: F) -> bool
    where
        F: FnMut(u32) -> Option<Pubkey>,
    {
        self.entries.iter().all(|entry| {
            proposer_pubkey_for_index(entry.proposer_index).is_some_and(|proposer_pubkey| {
                entry
                    .proposer_signature
                    .verify(proposer_pubkey.as_ref(), entry.commitment.as_ref())
            })
        })
    }
}

fn ensure_entries_strictly_sorted(
    entries: &[RelayAttestationEntry],
) -> Result<(), RelayAttestationError> {
    if entries
        .windows(2)
        .all(|window| window[0].proposer_index < window[1].proposer_index)
    {
        return Ok(());
    }
    Err(RelayAttestationError::EntriesNotStrictlySorted)
}

fn ensure_relay_index_in_range(relay_index: u32) -> Result<(), RelayAttestationError> {
    if relay_index as usize >= mcp::NUM_RELAYS {
        return Err(RelayAttestationError::RelayIndexOutOfRange(relay_index));
    }
    Ok(())
}

fn ensure_proposer_indices_in_range(
    entries: &[RelayAttestationEntry],
) -> Result<(), RelayAttestationError> {
    for entry in entries {
        if entry.proposer_index as usize >= mcp::NUM_PROPOSERS {
            return Err(RelayAttestationError::ProposerIndexOutOfRange(
                entry.proposer_index,
            ));
        }
    }
    Ok(())
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, RelayAttestationError> {
    if *cursor + 1 > bytes.len() {
        return Err(RelayAttestationError::Truncated);
    }
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_u32_le(bytes: &[u8], cursor: &mut usize) -> Result<u32, RelayAttestationError> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, cursor)?))
}

fn read_u64_le(bytes: &[u8], cursor: &mut usize) -> Result<u64, RelayAttestationError> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, cursor)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], RelayAttestationError> {
    if *cursor + N > bytes.len() {
        return Err(RelayAttestationError::Truncated);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use {super::*, solana_hash::Hash, solana_keypair::Keypair};

    #[test]
    fn test_roundtrip_wire_bytes() {
        let proposer0 = Keypair::new();
        let proposer1 = Keypair::new();
        let relay = Keypair::new();

        let commitment0 = Hash::new_unique();
        let commitment1 = Hash::new_unique();

        let mut attestation = RelayAttestation::new_unsigned(
            77,
            9,
            vec![
                RelayAttestationEntry {
                    proposer_index: 2,
                    commitment: commitment0,
                    proposer_signature: proposer0.sign_message(commitment0.as_ref()),
                },
                RelayAttestationEntry {
                    proposer_index: 7,
                    commitment: commitment1,
                    proposer_signature: proposer1.sign_message(commitment1.as_ref()),
                },
            ],
        )
        .unwrap();
        attestation.sign_relay(&relay).unwrap();

        let bytes = attestation.to_wire_bytes().unwrap();
        let decoded = RelayAttestation::from_wire_bytes(&bytes).unwrap();

        assert_eq!(decoded, attestation);
        assert!(decoded.verify_relay_signature(&relay.pubkey()));
        assert!(decoded.verify_proposer_signatures(|index| match index {
            2 => Some(proposer0.pubkey()),
            7 => Some(proposer1.pubkey()),
            _ => None,
        }));
    }

    #[test]
    fn test_wire_bytes_are_deterministic_for_same_map() {
        let proposer0 = Keypair::new();
        let proposer1 = Keypair::new();
        let relay = Keypair::new();

        let commitment0 = Hash::new_unique();
        let commitment1 = Hash::new_unique();

        let entry0 = RelayAttestationEntry {
            proposer_index: 1,
            commitment: commitment0,
            proposer_signature: proposer0.sign_message(commitment0.as_ref()),
        };
        let entry1 = RelayAttestationEntry {
            proposer_index: 0,
            commitment: commitment1,
            proposer_signature: proposer1.sign_message(commitment1.as_ref()),
        };

        let mut left =
            RelayAttestation::new_unsigned(5, 11, vec![entry0.clone(), entry1.clone()]).unwrap();
        let mut right = RelayAttestation::new_unsigned(5, 11, vec![entry1, entry0]).unwrap();
        left.sign_relay(&relay).unwrap();
        right.sign_relay(&relay).unwrap();

        assert_eq!(
            left.to_wire_bytes().unwrap(),
            right.to_wire_bytes().unwrap()
        );
    }

    #[test]
    fn test_unknown_version_is_rejected() {
        let bytes = vec![2u8; MIN_WIRE_LEN];
        assert_eq!(
            RelayAttestation::from_wire_bytes(&bytes).unwrap_err(),
            RelayAttestationError::UnknownVersion(2)
        );
    }

    #[test]
    fn test_unsorted_entries_are_rejected() {
        let proposer = Keypair::new();
        let relay = Keypair::new();
        let commitment = Hash::new_unique();

        let mut bytes = vec![RELAY_ATTESTATION_V1];
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.push(2);

        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(commitment.as_ref());
        bytes.extend_from_slice(proposer.sign_message(commitment.as_ref()).as_ref());

        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(commitment.as_ref());
        bytes.extend_from_slice(proposer.sign_message(commitment.as_ref()).as_ref());

        bytes.extend_from_slice(relay.sign_message(&bytes).as_ref());

        assert_eq!(
            RelayAttestation::from_wire_bytes(&bytes).unwrap_err(),
            RelayAttestationError::EntriesNotStrictlySorted,
        );
    }

    #[test]
    fn test_duplicate_entries_are_rejected() {
        let proposer = Keypair::new();
        let relay = Keypair::new();
        let commitment = Hash::new_unique();

        let mut bytes = vec![RELAY_ATTESTATION_V1];
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.push(2);

        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(commitment.as_ref());
        bytes.extend_from_slice(proposer.sign_message(commitment.as_ref()).as_ref());

        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(commitment.as_ref());
        bytes.extend_from_slice(proposer.sign_message(commitment.as_ref()).as_ref());

        bytes.extend_from_slice(relay.sign_message(&bytes).as_ref());

        assert_eq!(
            RelayAttestation::from_wire_bytes(&bytes).unwrap_err(),
            RelayAttestationError::EntriesNotStrictlySorted,
        );
    }

    #[test]
    fn test_relay_signature_verification_fails_when_tampered() {
        let proposer = Keypair::new();
        let relay = Keypair::new();
        let commitment = Hash::new_unique();

        let mut attestation = RelayAttestation::new_unsigned(
            1,
            2,
            vec![RelayAttestationEntry {
                proposer_index: 0,
                commitment,
                proposer_signature: proposer.sign_message(commitment.as_ref()),
            }],
        )
        .unwrap();
        attestation.sign_relay(&relay).unwrap();
        assert!(attestation.verify_relay_signature(&relay.pubkey()));

        attestation.entries[0].proposer_index = 1;
        assert!(!attestation.verify_relay_signature(&relay.pubkey()));
    }

    #[test]
    fn test_trailing_bytes_are_rejected() {
        let proposer = Keypair::new();
        let relay = Keypair::new();
        let commitment = Hash::new_unique();

        let mut attestation = RelayAttestation::new_unsigned(
            4,
            5,
            vec![RelayAttestationEntry {
                proposer_index: 0,
                commitment,
                proposer_signature: proposer.sign_message(commitment.as_ref()),
            }],
        )
        .unwrap();
        attestation.sign_relay(&relay).unwrap();

        let mut bytes = attestation.to_wire_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            RelayAttestation::from_wire_bytes(&bytes).unwrap_err(),
            RelayAttestationError::TrailingBytes,
        );
    }

    #[test]
    fn test_new_unsigned_rejects_too_many_entries() {
        let proposer = Keypair::new();
        let commitment = Hash::new_unique();
        let entries: Vec<_> = (0..=MAX_RELAY_ATTESTATION_ENTRIES as u32)
            .map(|proposer_index| RelayAttestationEntry {
                proposer_index,
                commitment,
                proposer_signature: proposer.sign_message(commitment.as_ref()),
            })
            .collect();
        assert_eq!(
            RelayAttestation::new_unsigned(1, 2, entries).unwrap_err(),
            RelayAttestationError::TooManyEntries(MAX_RELAY_ATTESTATION_ENTRIES + 1)
        );
    }

    #[test]
    fn test_new_unsigned_rejects_empty_entries() {
        assert_eq!(
            RelayAttestation::new_unsigned(1, 2, Vec::new()).unwrap_err(),
            RelayAttestationError::EmptyEntries,
        );
    }

    #[test]
    fn test_from_wire_rejects_too_many_entries() {
        let relay = Keypair::new();
        let proposer = Keypair::new();
        let commitment = Hash::new_unique();

        let mut bytes = vec![RELAY_ATTESTATION_V1];
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.push((MAX_RELAY_ATTESTATION_ENTRIES + 1) as u8);
        for proposer_index in 0..=MAX_RELAY_ATTESTATION_ENTRIES as u32 {
            bytes.extend_from_slice(&proposer_index.to_le_bytes());
            bytes.extend_from_slice(commitment.as_ref());
            bytes.extend_from_slice(proposer.sign_message(commitment.as_ref()).as_ref());
        }
        bytes.extend_from_slice(relay.sign_message(&bytes).as_ref());

        assert_eq!(
            RelayAttestation::from_wire_bytes(&bytes).unwrap_err(),
            RelayAttestationError::TooManyEntries(MAX_RELAY_ATTESTATION_ENTRIES + 1),
        );
    }

    #[test]
    fn test_new_unsigned_rejects_out_of_range_relay_index() {
        let proposer = Keypair::new();
        let commitment = Hash::new_unique();
        let entries = vec![RelayAttestationEntry {
            proposer_index: 0,
            commitment,
            proposer_signature: proposer.sign_message(commitment.as_ref()),
        }];
        assert_eq!(
            RelayAttestation::new_unsigned(1, mcp::NUM_RELAYS as u32, entries).unwrap_err(),
            RelayAttestationError::RelayIndexOutOfRange(mcp::NUM_RELAYS as u32),
        );
    }

    #[test]
    fn test_new_unsigned_accepts_max_valid_relay_index() {
        let proposer = Keypair::new();
        let commitment = Hash::new_unique();
        let entries = vec![RelayAttestationEntry {
            proposer_index: 0,
            commitment,
            proposer_signature: proposer.sign_message(commitment.as_ref()),
        }];

        let attestation =
            RelayAttestation::new_unsigned(1, (mcp::NUM_RELAYS - 1) as u32, entries).unwrap();
        assert_eq!(attestation.relay_index, (mcp::NUM_RELAYS - 1) as u32);
    }

    #[test]
    fn test_from_wire_rejects_out_of_range_relay_index() {
        let relay = Keypair::new();
        let proposer = Keypair::new();
        let commitment = Hash::new_unique();

        let mut bytes = vec![RELAY_ATTESTATION_V1];
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&(mcp::NUM_RELAYS as u32).to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(commitment.as_ref());
        bytes.extend_from_slice(proposer.sign_message(commitment.as_ref()).as_ref());
        bytes.extend_from_slice(relay.sign_message(&bytes).as_ref());

        assert_eq!(
            RelayAttestation::from_wire_bytes(&bytes).unwrap_err(),
            RelayAttestationError::RelayIndexOutOfRange(mcp::NUM_RELAYS as u32),
        );
    }

    #[test]
    fn test_from_wire_rejects_out_of_range_proposer_index() {
        let relay = Keypair::new();
        let proposer = Keypair::new();
        let commitment = Hash::new_unique();

        let mut bytes = vec![RELAY_ATTESTATION_V1];
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&(mcp::NUM_PROPOSERS as u32).to_le_bytes());
        bytes.extend_from_slice(commitment.as_ref());
        bytes.extend_from_slice(proposer.sign_message(commitment.as_ref()).as_ref());
        bytes.extend_from_slice(relay.sign_message(&bytes).as_ref());

        assert_eq!(
            RelayAttestation::from_wire_bytes(&bytes).unwrap_err(),
            RelayAttestationError::ProposerIndexOutOfRange(mcp::NUM_PROPOSERS as u32),
        );
    }

    #[test]
    fn test_from_wire_rejects_empty_entries() {
        let relay = Keypair::new();
        let mut bytes = vec![RELAY_ATTESTATION_V1];
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(relay.sign_message(&bytes).as_ref());

        assert_eq!(
            RelayAttestation::from_wire_bytes(&bytes).unwrap_err(),
            RelayAttestationError::EmptyEntries,
        );
    }

    #[test]
    fn test_verify_proposer_signatures_fails_when_pubkey_lookup_missing() {
        let proposer = Keypair::new();
        let relay = Keypair::new();
        let commitment = Hash::new_unique();
        let mut attestation = RelayAttestation::new_unsigned(
            77,
            9,
            vec![RelayAttestationEntry {
                proposer_index: 2,
                commitment,
                proposer_signature: proposer.sign_message(commitment.as_ref()),
            }],
        )
        .unwrap();
        attestation.sign_relay(&relay).unwrap();
        assert!(!attestation.verify_proposer_signatures(|_| None));
    }

    #[test]
    fn test_from_wire_rejects_truncated_mid_entry() {
        let proposer = Keypair::new();
        let relay = Keypair::new();
        let commitment = Hash::new_unique();

        let mut bytes = vec![RELAY_ATTESTATION_V1];
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(commitment.as_ref());
        bytes.extend_from_slice(proposer.sign_message(commitment.as_ref()).as_ref());
        bytes.extend_from_slice(relay.sign_message(&bytes).as_ref());

        bytes.truncate(HEADER_LEN + ENTRY_LEN - 1);
        assert_eq!(
            RelayAttestation::from_wire_bytes(&bytes).unwrap_err(),
            RelayAttestationError::Truncated,
        );
    }
}
