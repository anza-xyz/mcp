use {
    agave_feature_set as feature_set,
    bytes::Bytes,
    solana_clock::Slot,
    solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol},
    solana_hash::Hash,
    solana_ledger::{
        leader_schedule_cache::LeaderScheduleCache,
        mcp,
        mcp_relay_attestation::{
            RelayAttestation as LedgerRelayAttestation,
            RelayAttestationEntry as LedgerRelayAttestationEntry,
            RelayAttestationError as LedgerRelayAttestationError, RELAY_ATTESTATION_V1,
        },
    },
    solana_metrics::inc_new_counter_error,
    solana_pubkey::Pubkey,
    solana_runtime::bank::Bank,
    solana_signature::{Signature, SIGNATURE_BYTES},
    solana_turbine::cluster_nodes,
    std::{net::SocketAddr, thread::sleep, time::Duration},
    thiserror::Error,
    tokio::sync::mpsc::{error::TrySendError as AsyncTrySendError, Sender as AsyncSender},
};

pub const MCP_CONTROL_MSG_RELAY_ATTESTATION: u8 = 0x01;
pub const RELAY_ATTESTATION_VERSION_V1: u8 = RELAY_ATTESTATION_V1;
pub const MAX_RELAY_ATTESTATION_BYTES: usize =
    1 + 8 + 4 + 1 + (mcp::NUM_PROPOSERS * (4 + 32 + SIGNATURE_BYTES)) + SIGNATURE_BYTES;
pub const MAX_RELAY_ATTESTATION_FRAME_BYTES: usize = 1 + MAX_RELAY_ATTESTATION_BYTES;
const MCP_RELAY_DISPATCH_SEND_RETRY_LIMIT: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAttestationEntry {
    pub proposer_index: u32,
    pub commitment: [u8; 32],
    pub proposer_signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAttestationV1 {
    pub slot: Slot,
    pub relay_index: u32,
    pub entries: Vec<RelayAttestationEntry>,
    pub relay_signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAttestationDispatch {
    pub slot: Slot,
    pub leader_pubkey: Pubkey,
    pub frame: Vec<u8>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RelaySubmitError {
    #[error("relay attestation payload is too short")]
    PayloadTooShort,
    #[error("invalid relay attestation version: {0}")]
    InvalidVersion(u8),
    #[error("relay attestation payload has trailing bytes")]
    TrailingBytes,
    #[error("relay attestation entries must be sorted and unique by proposer_index")]
    UnsortedOrDuplicateEntries,
    #[error("relay attestation entries must be non-empty")]
    EmptyEntries,
    #[error("relay attestation contains too many entries: {actual} > {max}")]
    TooManyEntries { actual: usize, max: usize },
    #[error("relay index out of range: {0}")]
    RelayIndexOutOfRange(u32),
    #[error("relay attestation proposer_index out of range: {0}")]
    ProposerIndexOutOfRange(u32),
    #[error("unknown MCP control message type: {0:#x}")]
    UnknownMessageType(u8),
    #[error("missing leader for slot {0}")]
    MissingLeader(Slot),
    #[error("missing QUIC TVU address for leader {0}")]
    MissingLeaderAddress(Pubkey),
    #[error("MCP protocol v1 is not active for slot {slot}")]
    FeatureNotActive { slot: Slot },
    #[error("relay attestation frame too large: {actual} > {max}")]
    FrameTooLarge { actual: usize, max: usize },
    #[error("relay attestation send queue is full")]
    SendChannelFull,
    #[error("relay attestation send queue is closed")]
    SendChannelClosed,
}

impl RelayAttestationV1 {
    fn validate_relay_index(relay_index: u32) -> Result<(), RelaySubmitError> {
        if relay_index as usize >= mcp::NUM_RELAYS {
            return Err(RelaySubmitError::RelayIndexOutOfRange(relay_index));
        }
        Ok(())
    }

    fn validate_entries(entries: &[RelayAttestationEntry]) -> Result<(), RelaySubmitError> {
        if entries.is_empty() {
            return Err(RelaySubmitError::EmptyEntries);
        }
        if entries.len() > mcp::NUM_PROPOSERS {
            return Err(RelaySubmitError::TooManyEntries {
                actual: entries.len(),
                max: mcp::NUM_PROPOSERS,
            });
        }
        let mut prev_index = None;
        for entry in entries {
            if entry.proposer_index as usize >= mcp::NUM_PROPOSERS {
                return Err(RelaySubmitError::ProposerIndexOutOfRange(
                    entry.proposer_index,
                ));
            }
            if prev_index.is_some_and(|prev| entry.proposer_index <= prev) {
                return Err(RelaySubmitError::UnsortedOrDuplicateEntries);
            }
            prev_index = Some(entry.proposer_index);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, RelaySubmitError> {
        self.as_ledger()?.signing_bytes().map_err(map_ledger_error)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RelaySubmitError> {
        self.as_ledger()?.to_wire_bytes().map_err(map_ledger_error)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RelaySubmitError> {
        let attestation =
            LedgerRelayAttestation::from_wire_bytes(bytes).map_err(map_ledger_error)?;
        let out = Self::from_ledger(attestation);
        Self::validate_relay_index(out.relay_index)?;
        Self::validate_entries(&out.entries)?;
        Ok(out)
    }

    pub fn verify_relay_signature(&self, relay_pubkey: &Pubkey) -> bool {
        self.as_ledger()
            .map(|attestation| attestation.verify_relay_signature(relay_pubkey))
            .unwrap_or(false)
    }

    pub fn valid_entries<F>(&self, mut proposer_pubkey_for_index: F) -> Vec<RelayAttestationEntry>
    where
        F: FnMut(u32) -> Option<Pubkey>,
    {
        self.entries
            .iter()
            .filter(|entry| {
                proposer_pubkey_for_index(entry.proposer_index).is_some_and(|pubkey| {
                    entry
                        .proposer_signature
                        .verify(pubkey.as_ref(), &entry.commitment)
                })
            })
            .cloned()
            .collect()
    }

    fn as_ledger(&self) -> Result<LedgerRelayAttestation, RelaySubmitError> {
        Self::validate_relay_index(self.relay_index)?;
        Self::validate_entries(&self.entries)?;
        Ok(LedgerRelayAttestation {
            version: RELAY_ATTESTATION_VERSION_V1,
            slot: self.slot,
            relay_index: self.relay_index,
            entries: self
                .entries
                .iter()
                .map(|entry| LedgerRelayAttestationEntry {
                    proposer_index: entry.proposer_index,
                    commitment: Hash::new_from_array(entry.commitment),
                    proposer_signature: entry.proposer_signature,
                })
                .collect(),
            relay_signature: self.relay_signature,
        })
    }

    fn from_ledger(attestation: LedgerRelayAttestation) -> Self {
        Self {
            slot: attestation.slot,
            relay_index: attestation.relay_index,
            entries: attestation
                .entries
                .into_iter()
                .map(|entry| RelayAttestationEntry {
                    proposer_index: entry.proposer_index,
                    commitment: entry.commitment.to_bytes(),
                    proposer_signature: entry.proposer_signature,
                })
                .collect(),
            relay_signature: attestation.relay_signature,
        }
    }
}

fn map_ledger_error(err: LedgerRelayAttestationError) -> RelaySubmitError {
    match err {
        LedgerRelayAttestationError::UnknownVersion(version) => {
            RelaySubmitError::InvalidVersion(version)
        }
        LedgerRelayAttestationError::TooManyEntries(actual) => RelaySubmitError::TooManyEntries {
            actual,
            max: mcp::NUM_PROPOSERS,
        },
        LedgerRelayAttestationError::EmptyEntries => RelaySubmitError::EmptyEntries,
        LedgerRelayAttestationError::RelayIndexOutOfRange(relay_index) => {
            RelaySubmitError::RelayIndexOutOfRange(relay_index)
        }
        LedgerRelayAttestationError::ProposerIndexOutOfRange(proposer_index) => {
            RelaySubmitError::ProposerIndexOutOfRange(proposer_index)
        }
        LedgerRelayAttestationError::EntriesNotStrictlySorted => {
            RelaySubmitError::UnsortedOrDuplicateEntries
        }
        LedgerRelayAttestationError::Truncated => RelaySubmitError::PayloadTooShort,
        LedgerRelayAttestationError::TrailingBytes => RelaySubmitError::TrailingBytes,
    }
}

pub fn encode_relay_attestation_frame(
    attestation_bytes: &[u8],
) -> Result<Vec<u8>, RelaySubmitError> {
    let frame_len = 1 + attestation_bytes.len();
    if frame_len > MAX_RELAY_ATTESTATION_FRAME_BYTES {
        return Err(RelaySubmitError::FrameTooLarge {
            actual: frame_len,
            max: MAX_RELAY_ATTESTATION_FRAME_BYTES,
        });
    }
    let mut frame = Vec::with_capacity(1 + attestation_bytes.len());
    frame.push(MCP_CONTROL_MSG_RELAY_ATTESTATION);
    frame.extend_from_slice(attestation_bytes);
    Ok(frame)
}

pub fn decode_relay_attestation_frame(frame: &[u8]) -> Result<&[u8], RelaySubmitError> {
    if frame.is_empty() {
        return Err(RelaySubmitError::PayloadTooShort);
    }
    if frame.len() > MAX_RELAY_ATTESTATION_FRAME_BYTES {
        return Err(RelaySubmitError::FrameTooLarge {
            actual: frame.len(),
            max: MAX_RELAY_ATTESTATION_FRAME_BYTES,
        });
    }
    if frame[0] != MCP_CONTROL_MSG_RELAY_ATTESTATION {
        return Err(RelaySubmitError::UnknownMessageType(frame[0]));
    }
    Ok(&frame[1..])
}

pub fn build_relay_attestation_dispatch<F>(
    attestation: &RelayAttestationV1,
    mut leader_for_slot: F,
) -> Result<RelayAttestationDispatch, RelaySubmitError>
where
    F: FnMut(Slot) -> Option<Pubkey>,
{
    let leader_pubkey = leader_for_slot(attestation.slot)
        .ok_or(RelaySubmitError::MissingLeader(attestation.slot))?;
    Ok(RelayAttestationDispatch {
        slot: attestation.slot,
        leader_pubkey,
        frame: encode_relay_attestation_frame(&attestation.to_bytes()?)?,
    })
}

pub fn dispatch_relay_attestation_to_slot_leader(
    attestation: &RelayAttestationV1,
    leader_schedule_cache: &LeaderScheduleCache,
    root_bank: &Bank,
    cluster_info: &ClusterInfo,
    quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
) -> Result<RelayAttestationDispatch, RelaySubmitError> {
    if !cluster_nodes::check_feature_activation(
        &feature_set::mcp_protocol_v1::id(),
        attestation.slot,
        root_bank,
    ) {
        return Err(RelaySubmitError::FeatureNotActive {
            slot: attestation.slot,
        });
    }

    let dispatch = build_relay_attestation_dispatch(attestation, |slot| {
        leader_schedule_cache
            .slot_leader_at(slot, Some(root_bank))
            .or_else(|| leader_schedule_cache.slot_leader_at(slot, None))
    })?;

    let leader_addr = cluster_info
        .lookup_contact_info(&dispatch.leader_pubkey, |node| node.tvu(Protocol::QUIC))
        .flatten()
        .ok_or(RelaySubmitError::MissingLeaderAddress(
            dispatch.leader_pubkey,
        ))?;
    let payload = Bytes::copy_from_slice(&dispatch.frame);
    match try_send_dispatch_frame_with_retry(quic_endpoint_sender, leader_addr, payload) {
        Ok(()) => {}
        Err(AsyncTrySendError::Full(_)) => return Err(RelaySubmitError::SendChannelFull),
        Err(AsyncTrySendError::Closed(_)) => return Err(RelaySubmitError::SendChannelClosed),
    }

    Ok(dispatch)
}

fn try_send_dispatch_frame_with_retry(
    quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
    leader_addr: SocketAddr,
    payload: Bytes,
) -> Result<(), AsyncTrySendError<(SocketAddr, Bytes)>> {
    let mut send_item = (leader_addr, payload);
    for attempt in 0..=MCP_RELAY_DISPATCH_SEND_RETRY_LIMIT {
        match quic_endpoint_sender.try_send(send_item) {
            Ok(()) => return Ok(()),
            Err(AsyncTrySendError::Closed(returned)) => {
                inc_new_counter_error!("mcp-relay-attestation-dispatch-dropped-closed", 1, 1);
                return Err(AsyncTrySendError::Closed(returned));
            }
            Err(AsyncTrySendError::Full(returned)) => {
                if attempt == MCP_RELAY_DISPATCH_SEND_RETRY_LIMIT {
                    inc_new_counter_error!("mcp-relay-attestation-dispatch-dropped-full", 1, 1);
                    return Err(AsyncTrySendError::Full(returned));
                }
                send_item = returned;
                let backoff_micros = 50u64.saturating_mul((attempt + 1) as u64);
                sleep(Duration::from_micros(backoff_micros));
            }
        }
    }
    unreachable!("retry loop must return");
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
        solana_keypair::Keypair,
        solana_ledger::{
            genesis_utils::create_genesis_config, leader_schedule_cache::LeaderScheduleCache,
        },
        solana_runtime::bank::Bank,
        solana_signer::Signer,
        solana_streamer::socket::SocketAddrSpace,
        std::{collections::HashMap, net::SocketAddr, sync::Arc},
    };

    fn signed_entry(
        proposer_index: u32,
        commitment: [u8; 32],
        proposer: &Keypair,
    ) -> RelayAttestationEntry {
        RelayAttestationEntry {
            proposer_index,
            commitment,
            proposer_signature: proposer.sign_message(&commitment),
        }
    }

    fn signed_attestation(
        slot: Slot,
        relay_index: u32,
        entries: Vec<RelayAttestationEntry>,
        relay: &Keypair,
    ) -> RelayAttestationV1 {
        let mut attestation = RelayAttestationV1 {
            slot,
            relay_index,
            entries,
            relay_signature: Signature::default(),
        };
        let signature = relay.sign_message(&attestation.signing_bytes().unwrap());
        attestation.relay_signature = signature;
        attestation
    }

    #[test]
    fn test_attestation_roundtrip_and_signature_checks() {
        let relay = Keypair::new();
        let proposer_a = Keypair::new();
        let proposer_b = Keypair::new();
        let commitment_a = [11u8; 32];
        let commitment_b = [22u8; 32];
        let attestation = signed_attestation(
            77,
            9,
            vec![
                signed_entry(3, commitment_a, &proposer_a),
                signed_entry(8, commitment_b, &proposer_b),
            ],
            &relay,
        );

        let bytes = attestation.to_bytes().unwrap();
        let decoded = RelayAttestationV1::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, attestation);
        assert!(decoded.verify_relay_signature(&relay.pubkey()));

        let proposer_map =
            HashMap::from([(3u32, proposer_a.pubkey()), (8u32, proposer_b.pubkey())]);
        let valid_entries = decoded.valid_entries(|index| proposer_map.get(&index).copied());
        assert_eq!(valid_entries.len(), 2);
        assert_eq!(valid_entries[0].proposer_index, 3);
        assert_eq!(valid_entries[1].proposer_index, 8);
    }

    #[test]
    fn test_unsorted_entries_rejected() {
        let relay = Keypair::new();
        let proposer_a = Keypair::new();
        let proposer_b = Keypair::new();
        let slot: Slot = 1;
        let relay_index: u32 = 2;
        let entries = vec![
            signed_entry(9, [1u8; 32], &proposer_a),
            signed_entry(4, [2u8; 32], &proposer_b),
        ];
        let mut bytes = Vec::new();
        bytes.push(RELAY_ATTESTATION_VERSION_V1);
        bytes.extend_from_slice(&slot.to_le_bytes());
        bytes.extend_from_slice(&relay_index.to_le_bytes());
        bytes.push(entries.len() as u8);
        for entry in &entries {
            bytes.extend_from_slice(&entry.proposer_index.to_le_bytes());
            bytes.extend_from_slice(&entry.commitment);
            bytes.extend_from_slice(entry.proposer_signature.as_ref());
        }
        bytes.extend_from_slice(relay.sign_message(b"placeholder").as_ref());

        let err = RelayAttestationV1::from_bytes(&bytes).unwrap_err();
        assert_eq!(err, RelaySubmitError::UnsortedOrDuplicateEntries);
    }

    #[test]
    fn test_empty_entries_rejected() {
        let attestation = RelayAttestationV1 {
            slot: 1,
            relay_index: 2,
            entries: vec![],
            relay_signature: Signature::default(),
        };
        assert_eq!(
            attestation.signing_bytes().unwrap_err(),
            RelaySubmitError::EmptyEntries
        );
    }

    #[test]
    fn test_too_many_entries_rejected() {
        let proposer = Keypair::new();
        let relay = Keypair::new();
        let entries: Vec<_> = (0..=mcp::NUM_PROPOSERS as u32)
            .map(|index| signed_entry(index, [index as u8; 32], &proposer))
            .collect();
        let attestation = RelayAttestationV1 {
            slot: 9,
            relay_index: 1,
            entries,
            relay_signature: relay.sign_message(b"placeholder"),
        };
        assert_eq!(
            attestation.signing_bytes().unwrap_err(),
            RelaySubmitError::TooManyEntries {
                actual: mcp::NUM_PROPOSERS + 1,
                max: mcp::NUM_PROPOSERS,
            }
        );
    }

    #[test]
    fn test_relay_index_out_of_range_rejected() {
        let proposer = Keypair::new();
        let relay = Keypair::new();
        let attestation = RelayAttestationV1 {
            slot: 9,
            relay_index: mcp::NUM_RELAYS as u32,
            entries: vec![signed_entry(1, [1u8; 32], &proposer)],
            relay_signature: relay.sign_message(b"placeholder"),
        };
        assert_eq!(
            attestation.signing_bytes().unwrap_err(),
            RelaySubmitError::RelayIndexOutOfRange(mcp::NUM_RELAYS as u32),
        );
    }

    #[test]
    fn test_truncated_payload_rejected() {
        let relay = Keypair::new();
        let proposer = Keypair::new();
        let attestation =
            signed_attestation(55, 12, vec![signed_entry(1, [5u8; 32], &proposer)], &relay);
        let mut bytes = attestation.to_bytes().unwrap();
        bytes.pop();
        let err = RelayAttestationV1::from_bytes(&bytes).unwrap_err();
        assert_eq!(err, RelaySubmitError::PayloadTooShort);
    }

    #[test]
    fn test_dispatch_frame_roundtrip() {
        let relay = Keypair::new();
        let proposer = Keypair::new();
        let attestation =
            signed_attestation(55, 12, vec![signed_entry(1, [5u8; 32], &proposer)], &relay);
        let leader = Pubkey::new_unique();

        let dispatch = build_relay_attestation_dispatch(&attestation, |slot| {
            if slot == 55 {
                Some(leader)
            } else {
                None
            }
        })
        .unwrap();

        assert_eq!(dispatch.slot, 55);
        assert_eq!(dispatch.leader_pubkey, leader);
        let payload = decode_relay_attestation_frame(&dispatch.frame).unwrap();
        let decoded = RelayAttestationV1::from_bytes(payload).unwrap();
        assert_eq!(decoded, attestation);
    }

    #[test]
    fn test_unknown_frame_type_rejected() {
        let err = decode_relay_attestation_frame(&[0x02, 0x00]).unwrap_err();
        assert_eq!(err, RelaySubmitError::UnknownMessageType(0x02));
    }

    #[test]
    fn test_try_send_dispatch_frame_with_retry_succeeds_when_channel_has_capacity() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let leader_addr = SocketAddr::from(([127, 0, 0, 1], 12345));
        let payload = Bytes::from_static(b"frame");

        assert!(try_send_dispatch_frame_with_retry(&sender, leader_addr, payload.clone()).is_ok());

        let (received_addr, received_payload) = receiver.try_recv().unwrap();
        assert_eq!(received_addr, leader_addr);
        assert_eq!(received_payload, payload);
    }

    #[test]
    fn test_try_send_dispatch_frame_with_retry_rejects_full_channel_immediately() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        sender
            .try_send((
                SocketAddr::from(([127, 0, 0, 1], 12345)),
                Bytes::from_static(b"x"),
            ))
            .unwrap();

        let err = try_send_dispatch_frame_with_retry(
            &sender,
            SocketAddr::from(([127, 0, 0, 1], 12346)),
            Bytes::from_static(b"y"),
        )
        .unwrap_err();
        assert!(matches!(err, AsyncTrySendError::Full(_)));

        // Ensure the initial payload remains queued when the queue is full.
        let (addr, payload) = receiver.try_recv().unwrap();
        assert_eq!(addr, SocketAddr::from(([127, 0, 0, 1], 12345)));
        assert_eq!(payload, Bytes::from_static(b"x"));
    }

    #[test]
    fn test_try_send_dispatch_frame_with_retry_rejects_closed_channel() {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(receiver);

        let err = try_send_dispatch_frame_with_retry(
            &sender,
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            Bytes::from_static(b"frame"),
        )
        .unwrap_err();
        assert!(matches!(err, AsyncTrySendError::Closed(_)));
    }

    #[test]
    fn test_dispatch_relay_attestation_to_slot_leader_sends_quic_frame() {
        let relay = Arc::new(Keypair::new());
        let proposer = Keypair::new();
        let genesis_config = create_genesis_config(10_000).genesis_config;
        let mut root_bank = Bank::new_for_tests(&genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let leader_pubkey = leader_schedule_cache
            .slot_leader_at(slot, Some(&root_bank))
            .unwrap();
        let leader_info = ContactInfo::new_localhost(&leader_pubkey, 0);
        let relay_info = ContactInfo::new_localhost(&relay.pubkey(), 0);
        let cluster_info = ClusterInfo::new(relay_info, relay, SocketAddrSpace::Unspecified);
        cluster_info.insert_info(leader_info.clone());

        let attestation = signed_attestation(
            slot,
            12,
            vec![signed_entry(1, [7u8; 32], &proposer)],
            &Keypair::new(),
        );
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

        let dispatch = dispatch_relay_attestation_to_slot_leader(
            &attestation,
            &leader_schedule_cache,
            &root_bank,
            &cluster_info,
            &sender,
        )
        .unwrap();

        let expected_addr = leader_info.tvu(Protocol::QUIC).unwrap();
        let (addr, frame) = receiver.try_recv().unwrap();
        assert_eq!(addr, expected_addr);
        assert_eq!(frame, Bytes::from(dispatch.frame.clone()));
    }

    #[test]
    fn test_dispatch_relay_attestation_to_slot_leader_requires_feature_gate() {
        let relay = Arc::new(Keypair::new());
        let genesis_config = create_genesis_config(10_000).genesis_config;
        let mut root_bank = Bank::new_for_tests(&genesis_config);
        root_bank.deactivate_feature(&feature_set::mcp_protocol_v1::id());
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let cluster_info = ClusterInfo::new(
            ContactInfo::new_localhost(&relay.pubkey(), 0),
            relay,
            SocketAddrSpace::Unspecified,
        );
        let proposer = Keypair::new();
        let attestation = signed_attestation(
            0,
            0,
            vec![signed_entry(0, [1u8; 32], &proposer)],
            &Keypair::new(),
        );
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);

        let err = dispatch_relay_attestation_to_slot_leader(
            &attestation,
            &leader_schedule_cache,
            &root_bank,
            &cluster_info,
            &sender,
        )
        .unwrap_err();
        assert_eq!(err, RelaySubmitError::FeatureNotActive { slot: 0 });
    }

    #[test]
    fn test_dispatch_relay_attestation_to_slot_leader_rejects_full_queue() {
        let relay = Arc::new(Keypair::new());
        let proposer = Keypair::new();
        let genesis_config = create_genesis_config(10_000).genesis_config;
        let mut root_bank = Bank::new_for_tests(&genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let leader_pubkey = leader_schedule_cache
            .slot_leader_at(slot, Some(&root_bank))
            .unwrap();
        let leader_info = ContactInfo::new_localhost(&leader_pubkey, 0);
        let relay_info = ContactInfo::new_localhost(&relay.pubkey(), 0);
        let cluster_info = ClusterInfo::new(relay_info, relay, SocketAddrSpace::Unspecified);
        cluster_info.insert_info(leader_info);

        let attestation = signed_attestation(
            slot,
            12,
            vec![signed_entry(1, [7u8; 32], &proposer)],
            &Keypair::new(),
        );
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        sender
            .try_send((
                SocketAddr::from(([127, 0, 0, 1], 12345)),
                Bytes::from_static(b"x"),
            ))
            .unwrap();
        assert!(receiver.try_recv().is_ok());
        sender
            .try_send((
                SocketAddr::from(([127, 0, 0, 1], 12345)),
                Bytes::from_static(b"y"),
            ))
            .unwrap();

        let err = dispatch_relay_attestation_to_slot_leader(
            &attestation,
            &leader_schedule_cache,
            &root_bank,
            &cluster_info,
            &sender,
        )
        .unwrap_err();
        assert_eq!(err, RelaySubmitError::SendChannelFull);
    }
}
