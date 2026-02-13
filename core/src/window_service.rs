//! `window_service` handles the data plane incoming shreds, storing them in
//!   blockstore and retransmitting where required
//!

use {
    crate::{
        completed_data_sets_service::CompletedDataSetsSender,
        mcp_relay::{McpRelayOutcome, McpRelayProcessor, McpShredMessage},
        mcp_relay_submit::{
            decode_relay_attestation_frame, dispatch_relay_attestation_to_slot_leader,
            RelayAttestationEntry, RelayAttestationV1, MCP_CONTROL_MSG_RELAY_ATTESTATION,
        },
        mcp_replay::{self, McpConsensusBlockStore},
        mcp_vote_gate::{self, VoteGateDecision},
        repair::repair_service::{
            OutstandingShredRepairs, RepairInfo, RepairService, RepairServiceChannels,
        },
        result::{Error, Result},
    },
    agave_feature_set as feature_set,
    bytes::Bytes,
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender, TrySendError},
    rayon::{prelude::*, ThreadPool},
    solana_clock::{Slot, DEFAULT_MS_PER_SLOT},
    solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol},
    solana_hash::{Hash, HASH_BYTES},
    solana_keypair::Keypair,
    solana_ledger::{
        blockstore::{
            Blockstore, BlockstoreInsertionMetrics, McpPutStatus, PossibleDuplicateShred,
        },
        blockstore_meta::BlockLocation,
        leader_schedule_cache::LeaderScheduleCache,
        mcp,
        mcp_aggregate_attestation::{
            AggregateAttestation, AggregateProposerEntry, AggregateRelayEntry,
        },
        mcp_consensus_block::ConsensusBlock,
        shred::{self, ReedSolomonCache, Shred},
    },
    solana_measure::measure::Measure,
    solana_metrics::inc_new_counter_error,
    solana_pubkey::Pubkey,
    solana_rayon_threadlimit::get_thread_count,
    solana_runtime::bank_forks::BankForks,
    solana_signature::Signature,
    solana_signer::Signer,
    solana_streamer::evicting_sender::EvictingSender,
    solana_streamer::streamer::ChannelSend,
    solana_turbine::cluster_nodes,
    solana_votor_messages::migration::MigrationStatus,
    std::{
        borrow::Cow,
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
    tokio::sync::mpsc::{error::TrySendError as AsyncTrySendError, Sender as AsyncSender},
};

type DuplicateSlotSender = Sender<Slot>;
pub(crate) type DuplicateSlotReceiver = Receiver<Slot>;
const MCP_CONTROL_MSG_CONSENSUS_BLOCK: u8 = 0x02;
const MCP_CONTROL_SEND_RETRY_LIMIT: usize = 3;

fn relay_indices_for_pubkey(relays: &[Pubkey], local_pubkey: &Pubkey) -> Vec<u32> {
    relays
        .iter()
        .enumerate()
        .filter_map(|(index, pubkey)| {
            if pubkey == local_pubkey {
                u32::try_from(index).ok()
            } else {
                None
            }
        })
        .collect()
}

fn try_send_mcp_control_frame(
    quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
    remote_addr: SocketAddr,
    payload: Bytes,
) -> bool {
    let mut send_item = (remote_addr, payload);
    for attempt in 0..=MCP_CONTROL_SEND_RETRY_LIMIT {
        match quic_endpoint_sender.try_send(send_item) {
            Ok(()) => return true,
            Err(AsyncTrySendError::Closed(_)) => return false,
            Err(AsyncTrySendError::Full(returned)) => {
                if attempt == MCP_CONTROL_SEND_RETRY_LIMIT {
                    return false;
                }
                send_item = returned;
                let backoff_micros = 50u64.saturating_mul((attempt + 1) as u64);
                std::thread::sleep(Duration::from_micros(backoff_micros));
            }
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn maybe_finalize_and_broadcast_mcp_consensus_block(
    slot: Slot,
    local_pubkey: &Pubkey,
    cluster_info: &ClusterInfo,
    blockstore: &Blockstore,
    bank_forks: &RwLock<BankForks>,
    leader_schedule_cache: &LeaderScheduleCache,
    mcp_consensus_blocks: Option<&McpConsensusBlockStore>,
    turbine_quic_endpoint_sender: Option<&AsyncSender<(SocketAddr, Bytes)>>,
) -> bool {
    let log_skip = |reason: &str| {
        trace!(
            "MCP consensus finalize skipped for slot {}: {}",
            slot,
            reason
        );
    };
    let Some(consensus_blocks) = mcp_consensus_blocks else {
        log_skip("consensus block cache unavailable");
        return false;
    };
    match consensus_blocks.read() {
        Ok(blocks) => {
            if blocks.contains_key(&slot) {
                log_skip("consensus block already cached");
                return false;
            }
        }
        Err(err) => {
            warn!(
                "failed to read MCP consensus block cache at slot {} due to poisoned lock: {}",
                slot, err
            );
            return false;
        }
    }

    let delayed_slot = slot.saturating_sub(1);
    let (root_bank, root_slot, working_bank, mut delayed_bankhash) = {
        let bank_forks = bank_forks.read().unwrap();
        let root_bank = bank_forks.root_bank();
        if !cluster_nodes::check_feature_activation(
            &feature_set::mcp_protocol_v1::id(),
            slot,
            &root_bank,
        ) {
            log_skip("feature not active at slot");
            return false;
        }

        let delayed_bankhash = bank_forks.get(delayed_slot).map(|bank| bank.hash());
        let working_bank = bank_forks.get(slot).unwrap_or_else(|| root_bank.clone());
        (root_bank, bank_forks.root(), working_bank, delayed_bankhash)
    };
    if delayed_bankhash.is_none() {
        delayed_bankhash = blockstore.get_bank_hash(delayed_slot);
    }
    let Some(delayed_bankhash) = delayed_bankhash else {
        // Vote-gate requires delayed bankhash; do not publish partial consensus state.
        log_skip("missing delayed bankhash");
        return true;
    };

    // Carry an authoritative block_id sidecar. Retry finalization until it is available.
    let consensus_meta = working_bank
        .block_id()
        .or_else(|| {
            blockstore
                .check_last_fec_set_and_get_block_id(
                    slot,
                    working_bank.hash(),
                    true,
                    &working_bank.feature_set,
                )
                .ok()
                .flatten()
        })
        .map(|block_id| block_id.to_bytes().to_vec());
    let Some(consensus_meta) = consensus_meta else {
        log_skip("missing authoritative block_id");
        return true;
    };

    let proposer_schedule = leader_schedule_cache
        .proposers_at_slot(slot, Some(&working_bank))
        .or_else(|| leader_schedule_cache.proposers_at_slot(slot, Some(&root_bank)))
        .or_else(|| leader_schedule_cache.proposers_at_slot(slot, None))
        .unwrap_or_default();
    if proposer_schedule.is_empty() {
        log_skip("proposer schedule unavailable");
        return true;
    }
    let relay_schedule = leader_schedule_cache
        .relays_at_slot(slot, Some(&working_bank))
        .or_else(|| leader_schedule_cache.relays_at_slot(slot, Some(&root_bank)))
        .or_else(|| leader_schedule_cache.relays_at_slot(slot, None))
        .unwrap_or_default();
    if relay_schedule.len() < mcp::NUM_RELAYS {
        log_skip("relay schedule unavailable");
        return true;
    }

    let leader_indices: Vec<u32> = proposer_schedule
        .iter()
        .enumerate()
        .filter_map(|(index, pubkey)| {
            if pubkey == local_pubkey {
                u32::try_from(index).ok()
            } else {
                None
            }
        })
        .collect();
    if leader_indices.is_empty() {
        log_skip("local node is not a leader for slot");
        return false;
    }

    let mut relay_entries = Vec::new();
    for (relay_index, relay_pubkey) in relay_schedule.iter().enumerate() {
        let Some(relay_index_u32) = u32::try_from(relay_index).ok() else {
            continue;
        };
        let Ok(Some(attestation_bytes)) =
            blockstore.get_mcp_relay_attestation(slot, relay_index_u32)
        else {
            continue;
        };
        let Ok(attestation) = RelayAttestationV1::from_bytes(&attestation_bytes) else {
            continue;
        };
        if attestation.slot != slot || attestation.relay_index != relay_index_u32 {
            continue;
        }
        if !attestation.verify_relay_signature(relay_pubkey) {
            continue;
        }

        if attestation
            .valid_entries(|proposer_index| proposer_schedule.get(proposer_index as usize).copied())
            .is_empty()
        {
            continue;
        }
        let entries: Vec<AggregateProposerEntry> = attestation
            .entries
            .iter()
            .map(|entry| AggregateProposerEntry {
                proposer_index: entry.proposer_index,
                commitment: Hash::new_from_array(entry.commitment),
                proposer_signature: entry.proposer_signature,
            })
            .collect();
        relay_entries.push(AggregateRelayEntry {
            relay_index: relay_index_u32,
            entries,
            relay_signature: attestation.relay_signature,
        });
    }

    if relay_entries.len() < mcp::REQUIRED_ATTESTATIONS {
        log_skip("insufficient relay attestations");
        return true;
    }

    let identity_keypair = cluster_info.keypair();
    for leader_index in leader_indices {
        let Ok(aggregate) =
            AggregateAttestation::new_canonical(slot, leader_index, relay_entries.clone())
        else {
            trace!(
                "MCP consensus finalize skipped for slot {} leader_index {}: aggregate canonicalization failed",
                slot, leader_index
            );
            continue;
        };
        let Ok(aggregate_bytes) = aggregate.to_wire_bytes() else {
            trace!(
                "MCP consensus finalize skipped for slot {} leader_index {}: aggregate serialization failed",
                slot, leader_index
            );
            continue;
        };
        let Ok(mut consensus_block) = ConsensusBlock::new_unsigned(
            slot,
            leader_index,
            aggregate_bytes,
            consensus_meta.clone(),
            delayed_bankhash,
        ) else {
            trace!(
                "MCP consensus finalize skipped for slot {} leader_index {}: consensus block build failed",
                slot, leader_index
            );
            continue;
        };
        if consensus_block
            .sign_leader(identity_keypair.as_ref())
            .is_err()
        {
            trace!(
                "MCP consensus finalize skipped for slot {} leader_index {}: leader signature failed",
                slot, leader_index
            );
            continue;
        }
        let Ok(consensus_bytes) = consensus_block.to_wire_bytes() else {
            trace!(
                "MCP consensus finalize skipped for slot {} leader_index {}: consensus serialization failed",
                slot, leader_index
            );
            continue;
        };

        let inserted = match consensus_blocks.write() {
            Ok(mut blocks) => {
                let min_slot = root_slot.saturating_sub(mcp::CONSENSUS_BLOCK_RETENTION_SLOTS);
                blocks.retain(|tracked_slot, _| *tracked_slot >= min_slot);
                if let Some(existing) = blocks.get(&slot) {
                    if existing != &consensus_bytes {
                        warn!(
                            "MCP consensus block conflict at slot {} (keeping first valid block)",
                            slot
                        );
                    }
                    false
                } else {
                    blocks.insert(slot, consensus_bytes.clone());
                    true
                }
            }
            Err(err) => {
                warn!(
                    "failed to cache locally finalized MCP consensus block for slot {}: {}",
                    slot, err
                );
                false
            }
        };
        if !inserted {
            return false;
        }
        debug!(
            "cached local MCP consensus block for slot {} with {} relay attestations",
            slot,
            relay_entries.len()
        );
        maybe_persist_execution_output_from_consensus(
            slot,
            &working_bank,
            bank_forks,
            blockstore,
            leader_schedule_cache,
            consensus_blocks,
        );

        if let Some(sender) = turbine_quic_endpoint_sender {
            let mut frame = Vec::with_capacity(1 + consensus_bytes.len());
            frame.push(MCP_CONTROL_MSG_CONSENSUS_BLOCK);
            frame.extend_from_slice(&consensus_bytes);
            let frame = Bytes::from(frame);
            for peer_addr in cluster_info
                .tvu_peers(|node| node.tvu(Protocol::QUIC))
                .into_iter()
                .flatten()
            {
                if !try_send_mcp_control_frame(sender, peer_addr, frame.clone()) {
                    inc_new_counter_error!("mcp-consensus-block-send-dropped", 1, 1);
                }
            }
        }
        return false;
    }
    false
}

fn maybe_persist_execution_output_from_consensus(
    slot: Slot,
    bank: &solana_runtime::bank::Bank,
    bank_forks: &RwLock<BankForks>,
    blockstore: &Blockstore,
    leader_schedule_cache: &LeaderScheduleCache,
    consensus_blocks: &McpConsensusBlockStore,
) {
    let vote_gate_inputs = RwLock::new(HashMap::new());
    mcp_replay::refresh_vote_gate_input(
        slot,
        bank,
        bank_forks,
        blockstore,
        leader_schedule_cache,
        consensus_blocks,
        &vote_gate_inputs,
    );
    let decision = match vote_gate_inputs.read() {
        Ok(inputs) => inputs.get(&slot).map(mcp_vote_gate::evaluate_vote_gate),
        Err(err) => {
            warn!(
                "failed to evaluate MCP vote gate input at slot {} due to poisoned lock: {}",
                slot, err
            );
            None
        }
    };
    let Some(VoteGateDecision::Vote { included_proposers }) = decision else {
        return;
    };

    let included_proposers = RwLock::new(HashMap::from([(slot, included_proposers)]));
    mcp_replay::maybe_persist_reconstructed_execution_output(
        slot,
        bank,
        bank_forks,
        blockstore,
        leader_schedule_cache,
        &included_proposers,
    );
}

#[derive(Default)]
struct WindowServiceMetrics {
    run_insert_count: u64,
    num_repairs: AtomicUsize,
    num_shreds_received: usize,
    handle_packets_elapsed_us: u64,
    shred_receiver_elapsed_us: u64,
    num_errors: u64,
    num_errors_blockstore: u64,
    num_errors_cross_beam_recv_timeout: u64,
    num_errors_other: u64,
    num_errors_try_crossbeam_send: u64,
}

impl WindowServiceMetrics {
    fn report_metrics(&self, metric_name: &'static str) {
        datapoint_info!(
            metric_name,
            (
                "handle_packets_elapsed_us",
                self.handle_packets_elapsed_us,
                i64
            ),
            ("run_insert_count", self.run_insert_count as i64, i64),
            ("num_repairs", self.num_repairs.load(Ordering::Relaxed), i64),
            ("num_shreds_received", self.num_shreds_received, i64),
            (
                "shred_receiver_elapsed_us",
                self.shred_receiver_elapsed_us as i64,
                i64
            ),
            ("num_errors", self.num_errors, i64),
            ("num_errors_blockstore", self.num_errors_blockstore, i64),
            ("num_errors_other", self.num_errors_other, i64),
            (
                "num_errors_try_crossbeam_send",
                self.num_errors_try_crossbeam_send,
                i64
            ),
            (
                "num_errors_cross_beam_recv_timeout",
                self.num_errors_cross_beam_recv_timeout,
                i64
            ),
        );
    }

    fn record_error(&mut self, err: &Error) {
        self.num_errors += 1;
        match err {
            Error::TrySend => self.num_errors_try_crossbeam_send += 1,
            Error::RecvTimeout(_) => self.num_errors_cross_beam_recv_timeout += 1,
            Error::Blockstore(err) => {
                self.num_errors_blockstore += 1;
                error!("blockstore error: {err}");
            }
            _ => self.num_errors_other += 1,
        }
    }
}

fn run_check_duplicate(
    cluster_info: &ClusterInfo,
    blockstore: &Blockstore,
    shred_receiver: &Receiver<PossibleDuplicateShred>,
    duplicate_slots_sender: &DuplicateSlotSender,
    bank_forks: &RwLock<BankForks>,
    migration_status: &MigrationStatus,
) -> Result<()> {
    let mut root_bank = bank_forks.read().unwrap().root_bank();
    let mut last_updated = Instant::now();
    let check_duplicate = |shred: PossibleDuplicateShred| -> Result<()> {
        if last_updated.elapsed().as_millis() as u64 > DEFAULT_MS_PER_SLOT {
            // Grabs bank forks lock once a slot
            last_updated = Instant::now();
            root_bank = bank_forks.read().unwrap().root_bank();
        }
        let shred_slot = shred.slot();
        let chained_merkle_conflict_duplicate_proofs = cluster_nodes::check_feature_activation(
            &feature_set::chained_merkle_conflict_duplicate_proofs::id(),
            shred_slot,
            &root_bank,
        );
        let (shred1, shred2) = match shred {
            PossibleDuplicateShred::LastIndexConflict(shred, conflict)
            | PossibleDuplicateShred::ErasureConflict(shred, conflict)
            | PossibleDuplicateShred::MerkleRootConflict(shred, conflict) => (shred, conflict),
            PossibleDuplicateShred::ChainedMerkleRootConflict(shred, conflict) => {
                if chained_merkle_conflict_duplicate_proofs {
                    // Although this proof can be immediately stored on detection, we wait until
                    // here in order to check the feature flag, as storage in blockstore can
                    // preclude the detection of other duplicate proofs in this slot
                    if blockstore.has_duplicate_shreds_in_slot(shred_slot) {
                        return Ok(());
                    }
                    blockstore.store_duplicate_slot(
                        shred_slot,
                        conflict.clone(),
                        shred.clone().into_payload(),
                    )?;
                    (shred, conflict)
                } else {
                    return Ok(());
                }
            }
            PossibleDuplicateShred::Exists(shred) => {
                // Unlike the other cases we have to wait until here to decide to handle the duplicate and store
                // in blockstore. This is because the duplicate could have been part of the same insert batch,
                // so we wait until the batch has been written.
                if blockstore.has_duplicate_shreds_in_slot(shred_slot) {
                    return Ok(()); // A duplicate is already recorded
                }
                let Some(existing_shred_payload) = blockstore.is_shred_duplicate(&shred) else {
                    return Ok(()); // Not a duplicate
                };
                blockstore.store_duplicate_slot(
                    shred_slot,
                    existing_shred_payload.clone(),
                    shred.clone().into_payload(),
                )?;
                (shred, shred::Payload::from(existing_shred_payload))
            }
        };

        if migration_status.is_alpenglow_enabled() {
            // In alpenglow we store the duplicate block proofs for the purposes of slashing,
            // but we do not need to gossip or take any action on them.
            return Ok(());
        }

        // Propagate duplicate proof through gossip
        cluster_info.push_duplicate_shred(&shred1, &shred2)?;
        // Notify duplicate consensus state machine
        duplicate_slots_sender.send(shred_slot)?;

        Ok(())
    };
    const RECV_TIMEOUT: Duration = Duration::from_millis(200);
    std::iter::once(shred_receiver.recv_timeout(RECV_TIMEOUT)?)
        .chain(shred_receiver.try_iter())
        .try_for_each(check_duplicate)
}

#[allow(clippy::too_many_arguments)]
fn run_insert<F>(
    thread_pool: &ThreadPool,
    verified_receiver: &Receiver<Vec<(shred::Payload, /*is_repaired:*/ bool, BlockLocation)>>,
    blockstore: &Blockstore,
    bank_forks: &RwLock<BankForks>,
    local_pubkey: &Pubkey,
    leader_schedule_cache: &LeaderScheduleCache,
    handle_duplicate: F,
    metrics: &mut BlockstoreInsertionMetrics,
    ws_metrics: &mut WindowServiceMetrics,
    completed_data_sets_sender: Option<&CompletedDataSetsSender>,
    retransmit_sender: &EvictingSender<Vec<shred::Payload>>,
    reed_solomon_cache: &ReedSolomonCache,
    accept_repairs_only: bool,
    relay_signer: &Keypair,
    mcp_relay_processor: &mut McpRelayProcessor,
    mcp_relay_attestation_sender: Option<&Sender<RelayAttestationV1>>,
    pending_mcp_attestation_entries: &mut HashMap<Slot, BTreeMap<u32, RelayAttestationEntry>>,
    emitted_mcp_attestation_slots: &mut HashSet<Slot>,
    suppressed_mcp_attestation_proposers: &mut HashMap<Slot, HashSet<u32>>,
) -> Result<()>
where
    F: Fn(PossibleDuplicateShred),
{
    const RECV_TIMEOUT: Duration = Duration::from_millis(200);
    const MCP_ATTESTATION_STATE_RETENTION_SLOTS: Slot = 1024;
    let mut shred_receiver_elapsed = Measure::start("shred_receiver_elapsed");
    let mut shreds = verified_receiver.recv_timeout(RECV_TIMEOUT)?;
    shreds.extend(verified_receiver.try_iter().flatten());
    shred_receiver_elapsed.stop();
    ws_metrics.shred_receiver_elapsed_us += shred_receiver_elapsed.as_us();
    ws_metrics.run_insert_count += 1;
    let (mut root_bank, mut working_bank) = {
        let bank_forks = bank_forks.read().unwrap();
        (bank_forks.root_bank(), bank_forks.working_bank())
    };
    let mut last_bank_refresh = Instant::now();
    let mut mcp_retransmit_batch = Vec::new();
    let mut mcp_shred_count = 0usize;
    let mut legacy_shreds = Vec::with_capacity(shreds.len());
    let mut proposer_pubkeys_cache: HashMap<Slot, Vec<Pubkey>> = HashMap::new();
    let min_retained_slot = root_bank
        .slot()
        .saturating_sub(MCP_ATTESTATION_STATE_RETENTION_SLOTS);
    pending_mcp_attestation_entries.retain(|slot, _| *slot >= min_retained_slot);
    emitted_mcp_attestation_slots.retain(|slot| *slot >= min_retained_slot);
    suppressed_mcp_attestation_proposers.retain(|slot, _| *slot >= min_retained_slot);

    for (shred, repair, block_location) in shreds {
        if accept_repairs_only && !repair {
            continue;
        }
        if repair {
            ws_metrics.num_repairs.fetch_add(1, Ordering::Relaxed);
        }

        let Ok(mcp_shred) = McpShredMessage::from_bytes(&shred) else {
            legacy_shreds.push((shred, repair, block_location));
            continue;
        };

        if !cluster_nodes::check_feature_activation(
            &feature_set::mcp_protocol_v1::id(),
            mcp_shred.slot,
            &root_bank,
        ) {
            legacy_shreds.push((shred, repair, block_location));
            continue;
        }

        if last_bank_refresh.elapsed().as_millis() as u64 > DEFAULT_MS_PER_SLOT {
            last_bank_refresh = Instant::now();
            let bank_forks = bank_forks.read().unwrap();
            root_bank = bank_forks.root_bank();
            working_bank = bank_forks.working_bank();
            mcp_relay_processor.prune_below_slot(root_bank.slot());
            proposer_pubkeys_cache.clear();
        }

        let proposer_pubkeys = proposer_pubkeys_cache
            .entry(mcp_shred.slot)
            .or_insert_with(|| {
                leader_schedule_cache
                    .proposers_at_slot(mcp_shred.slot, Some(&working_bank))
                    .or_else(|| {
                        leader_schedule_cache.proposers_at_slot(mcp_shred.slot, Some(&root_bank))
                    })
                    .or_else(|| leader_schedule_cache.proposers_at_slot(mcp_shred.slot, None))
                    .unwrap_or_default()
            });
        let Some(proposer_pubkey) = proposer_pubkeys
            .get(mcp_shred.proposer_index as usize)
            .copied()
        else {
            inc_new_counter_error!("mcp-shred-drop-missing-proposer-pubkey", 1, 1);
            debug!(
                "dropping MCP shred for slot {} proposer {}: proposer pubkey missing in schedule",
                mcp_shred.slot, mcp_shred.proposer_index
            );
            continue;
        };
        let proposer_index = mcp_shred.proposer_index;
        let attestation_entry = RelayAttestationEntry {
            proposer_index,
            commitment: mcp_shred.commitment,
            proposer_signature: mcp_shred.proposer_signature,
        };

        match mcp_relay_processor.process_shred(&shred, &proposer_pubkey) {
            McpRelayOutcome::StoredAndBroadcast {
                slot,
                proposer_index,
                shred_index,
                payload,
            } => {
                match blockstore.put_mcp_shred_data(slot, proposer_index, shred_index, &payload)? {
                    McpPutStatus::Inserted => {
                        mcp_shred_count += 1;
                        mcp_retransmit_batch.push(payload.into());
                    }
                    McpPutStatus::Duplicate => {
                        mcp_shred_count += 1;
                    }
                    McpPutStatus::Conflict(marker) => {
                        mcp_shred_count += 1;
                        warn!(
                            "MCP shred conflict at ({slot}, {proposer_index}, {shred_index}); \
                         existing={}, incoming={}",
                            marker.existing_hash, marker.incoming_hash,
                        );
                        // Persisted conflict means we observed equivocation for this proposer/slot.
                        // Suppress attestation generation even if relay in-memory state was reset.
                        suppressed_mcp_attestation_proposers
                            .entry(slot)
                            .or_default()
                            .insert(proposer_index);
                        if let Some(entries) = pending_mcp_attestation_entries.get_mut(&slot) {
                            entries.remove(&proposer_index);
                        }
                    }
                }
                if !emitted_mcp_attestation_slots.contains(&slot) {
                    let proposer_suppressed = suppressed_mcp_attestation_proposers
                        .get(&slot)
                        .is_some_and(|suppressed| suppressed.contains(&proposer_index));
                    if proposer_suppressed {
                        continue;
                    }
                    pending_mcp_attestation_entries
                        .entry(slot)
                        .or_default()
                        .entry(proposer_index)
                        .or_insert(attestation_entry);
                }
            }
            McpRelayOutcome::Duplicate => {
                mcp_shred_count += 1;
            }
            McpRelayOutcome::Dropped(reason) => {
                inc_new_counter_error!("mcp-shred-drop-invalid", 1, 1);
                // Once bytes are classified as MCP under an active slot, invalid MCP
                // shreds are dropped and never fed into the legacy shred path.
                debug!(
                    "dropping invalid MCP shred for slot {} proposer {} shred {}: {:?}",
                    mcp_shred.slot, mcp_shred.proposer_index, mcp_shred.shred_index, reason
                );
                if reason == crate::mcp_relay::McpDropReason::ConflictingShred {
                    mcp_shred_count += 1;
                    suppressed_mcp_attestation_proposers
                        .entry(mcp_shred.slot)
                        .or_default()
                        .insert(mcp_shred.proposer_index);
                    if let Some(entries) = pending_mcp_attestation_entries.get_mut(&mcp_shred.slot)
                    {
                        entries.remove(&mcp_shred.proposer_index);
                    }
                }
            }
        }
    }

    if let Some(attestation_sender) = mcp_relay_attestation_sender {
        let mut finalized_slots = Vec::new();
        for (slot, entries_by_proposer) in pending_mcp_attestation_entries.iter() {
            let slot = *slot;
            if emitted_mcp_attestation_slots.contains(&slot) {
                finalized_slots.push(slot);
                continue;
            }
            // Emit once per slot after we have full proposer coverage, or after
            // the slot has aged by one working-bank step so late shreds can coalesce.
            let should_emit = entries_by_proposer.len() >= mcp::NUM_PROPOSERS
                || slot.saturating_add(1) < working_bank.slot();
            if !should_emit {
                continue;
            }

            let relay_indices = leader_schedule_cache
                .relays_at_slot(slot, Some(&working_bank))
                .or_else(|| leader_schedule_cache.relays_at_slot(slot, Some(&root_bank)))
                .or_else(|| leader_schedule_cache.relays_at_slot(slot, None))
                .map(|relays| relay_indices_for_pubkey(&relays, local_pubkey))
                .unwrap_or_default();
            if relay_indices.is_empty() {
                continue;
            }

            let entries: Vec<RelayAttestationEntry> =
                entries_by_proposer.values().cloned().collect();
            if entries.is_empty() {
                continue;
            }

            for relay_index in relay_indices {
                let mut attestation = RelayAttestationV1 {
                    slot,
                    relay_index,
                    entries: entries.clone(),
                    relay_signature: Signature::default(),
                };
                let Ok(signing_bytes) = attestation.signing_bytes() else {
                    continue;
                };
                attestation.relay_signature = relay_signer.sign_message(&signing_bytes);

                // Record locally generated attestation as soon as it is finalized.
                if let Ok(attestation_bytes) = attestation.to_bytes() {
                    match blockstore.put_mcp_relay_attestation(
                        slot,
                        relay_index,
                        &attestation_bytes,
                    ) {
                        Ok(McpPutStatus::Conflict(marker)) => {
                            warn!(
                                "local MCP relay attestation conflict at ({slot}, {relay_index}); \
                             existing={}, incoming={}",
                                marker.existing_hash, marker.incoming_hash,
                            );
                        }
                        Ok(_) => {}
                        Err(err) => {
                            debug!(
                                "failed to store local MCP relay attestation for slot {} relay {}: {}",
                                slot, relay_index, err
                            );
                        }
                    }
                }

                match attestation_sender.try_send(attestation) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        inc_new_counter_error!("mcp-relay-attestation-send-dropped-full", 1, 1);
                        debug!(
                            "dropping MCP relay attestation for slot {} relay {}: channel full",
                            slot, relay_index
                        );
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        inc_new_counter_error!(
                            "mcp-relay-attestation-send-dropped-disconnected",
                            1,
                            1
                        );
                        debug!(
                            "dropping MCP relay attestation for slot {} relay {}: channel disconnected",
                            slot, relay_index
                        );
                    }
                }
            }
            emitted_mcp_attestation_slots.insert(slot);
            finalized_slots.push(slot);
        }
        for slot in finalized_slots {
            pending_mcp_attestation_entries.remove(&slot);
        }
    }

    let handle_shred = |(shred, repair, block_location): (shred::Payload, bool, BlockLocation)| {
        let shred = Shred::new_from_serialized_shred(shred).ok()?;
        Some((Cow::Owned(shred), repair, block_location))
    };
    let now = Instant::now();
    let shreds: Vec<_> = thread_pool.install(|| {
        legacy_shreds
            .into_par_iter()
            .with_min_len(32)
            .filter_map(handle_shred)
            .collect()
    });
    ws_metrics.handle_packets_elapsed_us += now.elapsed().as_micros() as u64;
    ws_metrics.num_shreds_received += shreds.len() + mcp_shred_count;

    if !mcp_retransmit_batch.is_empty() {
        retransmit_sender.send(mcp_retransmit_batch)?;
    }

    if shreds.is_empty() {
        return Ok(());
    }

    let completed_data_sets = blockstore.insert_shreds_at_location_handle_duplicate(
        shreds,
        Some(leader_schedule_cache),
        false, // is_trusted
        retransmit_sender,
        &handle_duplicate,
        reed_solomon_cache,
        metrics,
    )?;

    if let Some(sender) = completed_data_sets_sender {
        sender.try_send(completed_data_sets)?;
    }

    Ok(())
}

fn ingest_mcp_control_message(
    sender_pubkey: Pubkey,
    remote_address: SocketAddr,
    frame: &[u8],
    blockstore: &Blockstore,
    bank_forks: &RwLock<BankForks>,
    leader_schedule_cache: &LeaderScheduleCache,
    mcp_consensus_blocks: Option<&McpConsensusBlockStore>,
) -> Option<Slot> {
    let Some(message_type) = frame.first().copied() else {
        return None;
    };

    match message_type {
        MCP_CONTROL_MSG_RELAY_ATTESTATION => {
            let Ok(payload) = decode_relay_attestation_frame(frame) else {
                return None;
            };
            let Ok(attestation) = RelayAttestationV1::from_bytes(payload) else {
                return None;
            };

            let root_bank = bank_forks.read().unwrap().root_bank();
            if !cluster_nodes::check_feature_activation(
                &feature_set::mcp_protocol_v1::id(),
                attestation.slot,
                &root_bank,
            ) {
                return None;
            }

            let relay_pubkey = leader_schedule_cache
                .relays_at_slot(attestation.slot, Some(&root_bank))
                .or_else(|| leader_schedule_cache.relays_at_slot(attestation.slot, None))
                .and_then(|relays| relays.get(attestation.relay_index as usize).copied());
            let Some(relay_pubkey) = relay_pubkey else {
                return None;
            };
            if sender_pubkey != relay_pubkey {
                debug!(
                    "dropping MCP relay attestation for slot {} relay {} from {} (claimed {}, expected {})",
                    attestation.slot,
                    attestation.relay_index,
                    remote_address,
                    sender_pubkey,
                    relay_pubkey,
                );
                return None;
            }
            if !attestation.verify_relay_signature(&relay_pubkey) {
                return None;
            }

            match blockstore.put_mcp_relay_attestation(
                attestation.slot,
                attestation.relay_index,
                payload,
            ) {
                Ok(McpPutStatus::Conflict(marker)) => {
                    warn!(
                        "MCP relay attestation conflict at ({}, {}); existing={}, incoming={}",
                        attestation.slot,
                        attestation.relay_index,
                        marker.existing_hash,
                        marker.incoming_hash,
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    debug!(
                        "failed to store MCP relay attestation for slot {} relay {}: {}",
                        attestation.slot, attestation.relay_index, err
                    );
                    return None;
                }
            }
            Some(attestation.slot)
        }
        MCP_CONTROL_MSG_CONSENSUS_BLOCK => {
            let payload = &frame[1..];
            let Ok(consensus_block) = ConsensusBlock::from_wire_bytes(payload) else {
                return None;
            };

            let root_bank = bank_forks.read().unwrap().root_bank();
            if !cluster_nodes::check_feature_activation(
                &feature_set::mcp_protocol_v1::id(),
                consensus_block.slot,
                &root_bank,
            ) {
                return None;
            }

            let leader_pubkey = leader_schedule_cache
                .proposers_at_slot(consensus_block.slot, Some(&root_bank))
                .or_else(|| leader_schedule_cache.proposers_at_slot(consensus_block.slot, None))
                .and_then(|proposers| {
                    proposers
                        .get(consensus_block.leader_index as usize)
                        .copied()
                });
            let Some(leader_pubkey) = leader_pubkey else {
                return None;
            };
            if sender_pubkey != leader_pubkey {
                debug!(
                    "dropping MCP ConsensusBlock for slot {} from {} (claimed {}, expected {})",
                    consensus_block.slot, remote_address, sender_pubkey, leader_pubkey
                );
                return None;
            }
            if !consensus_block.verify_leader_signature(&leader_pubkey) {
                return None;
            }
            if consensus_block.consensus_meta.len() != HASH_BYTES {
                debug!(
                    "dropping MCP ConsensusBlock for slot {} from {} due to invalid consensus_meta length {}",
                    consensus_block.slot,
                    remote_address,
                    consensus_block.consensus_meta.len(),
                );
                return None;
            }

            if let Some(consensus_blocks) = mcp_consensus_blocks {
                let root_slot = root_bank.slot();
                match consensus_blocks.write() {
                    Ok(mut consensus_blocks) => {
                        let min_slot =
                            root_slot.saturating_sub(mcp::CONSENSUS_BLOCK_RETENTION_SLOTS);
                        consensus_blocks.retain(|slot, _| *slot >= min_slot);
                        if let Some(existing) = consensus_blocks.get(&consensus_block.slot) {
                            if existing != payload {
                                warn!(
                                    "MCP consensus block conflict at slot {} (keeping first valid block)",
                                    consensus_block.slot
                                );
                            }
                        } else {
                            consensus_blocks.insert(consensus_block.slot, payload.to_vec());
                        }
                    }
                    Err(err) => {
                        warn!(
                            "failed to ingest MCP consensus block for slot {} due to poisoned lock: {}",
                            consensus_block.slot, err
                        );
                    }
                }
            }
            None
        }
        _ => None,
    }
}

pub struct WindowServiceChannels {
    pub verified_receiver: Receiver<Vec<(shred::Payload, /*is_repaired:*/ bool, BlockLocation)>>,
    pub retransmit_sender: EvictingSender<Vec<shred::Payload>>,
    pub completed_data_sets_sender: Option<CompletedDataSetsSender>,
    pub duplicate_slots_sender: DuplicateSlotSender,
    pub repair_service_channels: RepairServiceChannels,
    pub mcp_relay_attestation_sender: Option<Sender<RelayAttestationV1>>,
    pub mcp_relay_attestation_receiver: Option<Receiver<RelayAttestationV1>>,
    pub mcp_control_message_receiver: Option<Receiver<(Pubkey, SocketAddr, Bytes)>>,
    pub mcp_consensus_blocks: Option<McpConsensusBlockStore>,
    pub turbine_quic_endpoint_sender: Option<AsyncSender<(SocketAddr, Bytes)>>,
}

impl WindowServiceChannels {
    pub fn new(
        verified_receiver: Receiver<Vec<(shred::Payload, /*is_repaired:*/ bool, BlockLocation)>>,
        retransmit_sender: EvictingSender<Vec<shred::Payload>>,
        completed_data_sets_sender: Option<CompletedDataSetsSender>,
        duplicate_slots_sender: DuplicateSlotSender,
        repair_service_channels: RepairServiceChannels,
        mcp_relay_attestation_sender: Option<Sender<RelayAttestationV1>>,
        mcp_relay_attestation_receiver: Option<Receiver<RelayAttestationV1>>,
        mcp_control_message_receiver: Option<Receiver<(Pubkey, SocketAddr, Bytes)>>,
        mcp_consensus_blocks: Option<McpConsensusBlockStore>,
        turbine_quic_endpoint_sender: Option<AsyncSender<(SocketAddr, Bytes)>>,
    ) -> Self {
        Self {
            verified_receiver,
            retransmit_sender,
            completed_data_sets_sender,
            duplicate_slots_sender,
            repair_service_channels,
            mcp_relay_attestation_sender,
            mcp_relay_attestation_receiver,
            mcp_control_message_receiver,
            mcp_consensus_blocks,
            turbine_quic_endpoint_sender,
        }
    }
}

pub(crate) struct WindowService {
    t_insert: JoinHandle<()>,
    t_check_duplicate: JoinHandle<()>,
    repair_service: RepairService,
}

impl WindowService {
    pub(crate) fn new(
        blockstore: Arc<Blockstore>,
        repair_socket: Arc<UdpSocket>,
        ancestor_hashes_socket: Arc<UdpSocket>,
        exit: Arc<AtomicBool>,
        repair_info: RepairInfo,
        window_service_channels: WindowServiceChannels,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        outstanding_repair_requests: Arc<RwLock<OutstandingShredRepairs>>,
        migration_status: Arc<MigrationStatus>,
    ) -> WindowService {
        let cluster_info = repair_info.cluster_info.clone();
        let bank_forks = repair_info.bank_forks.clone();
        let local_pubkey = cluster_info.id();

        // In wen_restart, we discard all shreds from Turbine and keep only those from repair to
        // avoid new shreds make validator OOM before wen_restart is over.
        let accept_repairs_only = repair_info.wen_restart_repair_slots.is_some();

        let WindowServiceChannels {
            verified_receiver,
            retransmit_sender,
            completed_data_sets_sender,
            duplicate_slots_sender,
            repair_service_channels,
            mcp_relay_attestation_sender,
            mcp_relay_attestation_receiver,
            mcp_control_message_receiver,
            mcp_consensus_blocks,
            turbine_quic_endpoint_sender,
        } = window_service_channels;

        let repair_service = RepairService::new(
            blockstore.clone(),
            exit.clone(),
            repair_socket,
            ancestor_hashes_socket,
            repair_info,
            outstanding_repair_requests.clone(),
            repair_service_channels,
            migration_status.clone(),
        );

        let (duplicate_sender, duplicate_receiver) = unbounded();

        let t_check_duplicate = Self::start_check_duplicate_thread(
            cluster_info.clone(),
            exit.clone(),
            blockstore.clone(),
            duplicate_receiver,
            duplicate_slots_sender,
            bank_forks.clone(),
            migration_status,
        );

        let t_insert = Self::start_window_insert_thread(
            exit,
            blockstore,
            bank_forks,
            local_pubkey,
            leader_schedule_cache,
            verified_receiver,
            cluster_info,
            duplicate_sender,
            completed_data_sets_sender,
            retransmit_sender,
            accept_repairs_only,
            mcp_relay_attestation_sender,
            mcp_relay_attestation_receiver,
            mcp_control_message_receiver,
            mcp_consensus_blocks,
            turbine_quic_endpoint_sender,
        );

        WindowService {
            t_insert,
            t_check_duplicate,
            repair_service,
        }
    }

    fn start_check_duplicate_thread(
        cluster_info: Arc<ClusterInfo>,
        exit: Arc<AtomicBool>,
        blockstore: Arc<Blockstore>,
        duplicate_receiver: Receiver<PossibleDuplicateShred>,
        duplicate_slots_sender: DuplicateSlotSender,
        bank_forks: Arc<RwLock<BankForks>>,
        migration_status: Arc<MigrationStatus>,
    ) -> JoinHandle<()> {
        let handle_error = || {
            inc_new_counter_error!("solana-check-duplicate-error", 1, 1);
        };
        Builder::new()
            .name("solWinCheckDup".to_string())
            .spawn(move || {
                while !exit.load(Ordering::Relaxed) {
                    if let Err(e) = run_check_duplicate(
                        &cluster_info,
                        &blockstore,
                        &duplicate_receiver,
                        &duplicate_slots_sender,
                        &bank_forks,
                        &migration_status,
                    ) {
                        if Self::should_exit_on_error(e, &handle_error) {
                            break;
                        }
                    }
                }
            })
            .unwrap()
    }

    fn start_window_insert_thread(
        exit: Arc<AtomicBool>,
        blockstore: Arc<Blockstore>,
        bank_forks: Arc<RwLock<BankForks>>,
        local_pubkey: Pubkey,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        verified_receiver: Receiver<Vec<(shred::Payload, /*is_repaired:*/ bool, BlockLocation)>>,
        cluster_info: Arc<ClusterInfo>,
        check_duplicate_sender: Sender<PossibleDuplicateShred>,
        completed_data_sets_sender: Option<CompletedDataSetsSender>,
        retransmit_sender: EvictingSender<Vec<shred::Payload>>,
        accept_repairs_only: bool,
        mcp_relay_attestation_sender: Option<Sender<RelayAttestationV1>>,
        mcp_relay_attestation_receiver: Option<Receiver<RelayAttestationV1>>,
        mcp_control_message_receiver: Option<Receiver<(Pubkey, SocketAddr, Bytes)>>,
        mcp_consensus_blocks: Option<McpConsensusBlockStore>,
        turbine_quic_endpoint_sender: Option<AsyncSender<(SocketAddr, Bytes)>>,
    ) -> JoinHandle<()> {
        let handle_error = || {
            inc_new_counter_error!("solana-window-insert-error", 1, 1);
        };
        let reed_solomon_cache = ReedSolomonCache::default();
        Builder::new()
            .name("solWinInsert".to_string())
            .spawn(move || {
                let thread_pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(get_thread_count().min(8))
                    // Use the current thread as one of the workers. This reduces overhead when the
                    // pool is used to process a small number of shreds, since they'll be processed
                    // directly on the current thread.
                    .use_current_thread()
                    .thread_name(|i| format!("solWinInsert{i:02}"))
                    .build()
                    .unwrap();
                let handle_duplicate = |possible_duplicate_shred| {
                    let _ = check_duplicate_sender.send(possible_duplicate_shred);
                };
                let mut metrics = BlockstoreInsertionMetrics::default();
                let mut ws_metrics = WindowServiceMetrics::default();
                let mut mcp_relay_processor = McpRelayProcessor::default();
                let mut pending_mcp_attestation_entries: HashMap<
                    Slot,
                    BTreeMap<u32, RelayAttestationEntry>,
                > = HashMap::new();
                let mut emitted_mcp_attestation_slots: HashSet<Slot> = HashSet::new();
                let mut suppressed_mcp_attestation_proposers: HashMap<Slot, HashSet<u32>> =
                    HashMap::new();
                let mut pending_mcp_consensus_slots: HashSet<Slot> = HashSet::new();
                const MCP_PENDING_CONSENSUS_RETENTION_SLOTS: Slot = 1024;
                let mut last_print = Instant::now();
                while !exit.load(Ordering::Relaxed) {
                    let relay_signer = cluster_info.keypair();
                    if let Err(e) = run_insert(
                        &thread_pool,
                        &verified_receiver,
                        &blockstore,
                        &bank_forks,
                        &local_pubkey,
                        &leader_schedule_cache,
                        handle_duplicate,
                        &mut metrics,
                        &mut ws_metrics,
                        completed_data_sets_sender.as_ref(),
                        &retransmit_sender,
                        &reed_solomon_cache,
                        accept_repairs_only,
                        relay_signer.as_ref(),
                        &mut mcp_relay_processor,
                        mcp_relay_attestation_sender.as_ref(),
                        &mut pending_mcp_attestation_entries,
                        &mut emitted_mcp_attestation_slots,
                        &mut suppressed_mcp_attestation_proposers,
                    ) {
                        ws_metrics.record_error(&e);
                        if Self::should_exit_on_error(e, &handle_error) {
                            break;
                        }
                    }
                    let mut candidate_slots = BTreeSet::new();
                    if let Some(receiver) = mcp_control_message_receiver.as_ref() {
                        for (sender_pubkey, remote_address, frame) in receiver.try_iter() {
                            if let Some(slot) = ingest_mcp_control_message(
                                sender_pubkey,
                                remote_address,
                                &frame,
                                &blockstore,
                                &bank_forks,
                                &leader_schedule_cache,
                                mcp_consensus_blocks.as_ref(),
                            ) {
                                candidate_slots.insert(slot);
                            }
                        }
                    }
                    if let (Some(receiver), Some(quic_sender)) = (
                        mcp_relay_attestation_receiver.as_ref(),
                        turbine_quic_endpoint_sender.as_ref(),
                    ) {
                        let root_bank = bank_forks.read().unwrap().root_bank();
                        for attestation in receiver.try_iter() {
                            candidate_slots.insert(attestation.slot);
                            if let Err(err) = dispatch_relay_attestation_to_slot_leader(
                                &attestation,
                                &leader_schedule_cache,
                                &root_bank,
                                &cluster_info,
                                quic_sender,
                            ) {
                                debug!(
                                    "failed to dispatch MCP relay attestation for slot {}: {}",
                                    attestation.slot, err
                                );
                            }
                        }
                    }
                    let root_slot = bank_forks.read().unwrap().root();
                    let min_retained_slot =
                        root_slot.saturating_sub(MCP_PENDING_CONSENSUS_RETENTION_SLOTS);
                    pending_mcp_consensus_slots.retain(|slot| *slot >= min_retained_slot);
                    candidate_slots.extend(pending_mcp_consensus_slots.iter().copied());
                    pending_mcp_consensus_slots.clear();

                    for slot in candidate_slots {
                        let should_retry = maybe_finalize_and_broadcast_mcp_consensus_block(
                            slot,
                            &local_pubkey,
                            &cluster_info,
                            &blockstore,
                            &bank_forks,
                            &leader_schedule_cache,
                            mcp_consensus_blocks.as_ref(),
                            turbine_quic_endpoint_sender.as_ref(),
                        );
                        if should_retry && slot >= min_retained_slot {
                            pending_mcp_consensus_slots.insert(slot);
                        }
                    }

                    if last_print.elapsed().as_secs() > 2 {
                        metrics.report_metrics("blockstore-insert-shreds");
                        metrics = BlockstoreInsertionMetrics::default();
                        ws_metrics.report_metrics("recv-window-insert-shreds");
                        ws_metrics = WindowServiceMetrics::default();
                        last_print = Instant::now();
                    }
                }
            })
            .unwrap()
    }

    fn should_exit_on_error<H>(e: Error, handle_error: &H) -> bool
    where
        H: Fn(),
    {
        match e {
            Error::RecvTimeout(RecvTimeoutError::Disconnected) => true,
            Error::RecvTimeout(RecvTimeoutError::Timeout) => false,
            Error::Send => true,
            _ => {
                handle_error();
                error!("thread {:?} error {:?}", thread::current().name(), e);
                false
            }
        }
    }

    pub(crate) fn join(self) -> thread::Result<()> {
        self.t_insert.join()?;
        self.t_check_duplicate.join()?;
        self.repair_service.join()
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        agave_feature_set as feature_set,
        rand::Rng,
        solana_entry::entry::{create_ticks, Entry},
        solana_gossip::contact_info::ContactInfo,
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_ledger::{
            blockstore::{make_many_slot_entries, Blockstore},
            genesis_utils::{create_genesis_config, create_genesis_config_with_leader},
            get_tmp_ledger_path_auto_delete,
            mcp_aggregate_attestation::AggregateAttestation,
            mcp_consensus_block::ConsensusBlock,
            shred::{ProcessShredsStats, Shredder},
        },
        solana_runtime::bank::Bank,
        solana_signer::Signer,
        solana_streamer::socket::SocketAddrSpace,
        solana_time_utils::timestamp,
        tokio::sync::mpsc,
    };

    fn local_entries_to_shred(
        entries: &[Entry],
        slot: Slot,
        parent: Slot,
        keypair: &Keypair,
    ) -> Vec<Shred> {
        let shredder = Shredder::new(slot, parent, 0, 0).unwrap();
        let (data_shreds, _) = shredder.entries_to_merkle_shreds_for_tests(
            keypair,
            entries,
            true, // is_last_in_slot
            // chained_merkle_root
            Some(Hash::new_from_array(rand::thread_rng().gen())),
            0, // next_shred_index
            0, // next_code_index
            &ReedSolomonCache::default(),
            &mut ProcessShredsStats::default(),
        );
        data_shreds
    }

    #[test]
    fn test_relay_indices_for_pubkey_returns_all_positions() {
        let local = Pubkey::new_unique();
        let relays = vec![
            Pubkey::new_unique(),
            local,
            Pubkey::new_unique(),
            local,
            local,
        ];
        assert_eq!(relay_indices_for_pubkey(&relays, &local), vec![1, 3, 4]);
    }

    #[test]
    fn test_ingest_mcp_consensus_block_stores_valid_leader_frame() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let leader = Keypair::new();
        let mut genesis = create_genesis_config_with_leader(10_000, &leader.pubkey(), 1_000);
        genesis
            .genesis_config
            .accounts
            .remove(&feature_set::mcp_protocol_v1::id());
        let mut root_bank = Bank::new_for_tests(&genesis.genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let bank_forks = BankForks::new_rw_arc(root_bank);
        let root_bank = bank_forks.read().unwrap().root_bank();
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);
        let leader_index = leader_schedule_cache
            .proposers_at_slot(slot, Some(&root_bank))
            .and_then(|proposers| {
                proposers
                    .iter()
                    .position(|pubkey| *pubkey == leader.pubkey())
                    .and_then(|index| u32::try_from(index).ok())
            })
            .expect("leader should appear in MCP proposer schedule");

        let aggregate_bytes = AggregateAttestation::new_canonical(slot, leader_index, vec![])
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        let delayed_bankhash = Hash::new_unique();
        let block_id = Hash::new_unique();
        let mut block = ConsensusBlock::new_unsigned(
            slot,
            leader_index,
            aggregate_bytes,
            block_id.to_bytes().to_vec(),
            delayed_bankhash,
        )
        .unwrap();
        block.sign_leader(&leader).unwrap();
        let payload = block.to_wire_bytes().unwrap();
        let mut frame = Vec::with_capacity(1 + payload.len());
        frame.push(MCP_CONTROL_MSG_CONSENSUS_BLOCK);
        frame.extend_from_slice(&payload);
        let consensus_blocks = Arc::new(RwLock::new(HashMap::new()));

        ingest_mcp_control_message(
            leader.pubkey(),
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            &frame,
            &blockstore,
            &bank_forks,
            &leader_schedule_cache,
            Some(&consensus_blocks),
        );

        assert_eq!(
            consensus_blocks.read().unwrap().get(&slot).cloned(),
            Some(payload),
        );
    }

    #[test]
    fn test_ingest_mcp_consensus_block_rejects_wrong_sender() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let leader = Keypair::new();
        let mut genesis = create_genesis_config_with_leader(10_000, &leader.pubkey(), 1_000);
        genesis
            .genesis_config
            .accounts
            .remove(&feature_set::mcp_protocol_v1::id());
        let mut root_bank = Bank::new_for_tests(&genesis.genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let bank_forks = BankForks::new_rw_arc(root_bank);
        let root_bank = bank_forks.read().unwrap().root_bank();
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);
        let leader_index = leader_schedule_cache
            .proposers_at_slot(slot, Some(&root_bank))
            .and_then(|proposers| {
                proposers
                    .iter()
                    .position(|pubkey| *pubkey == leader.pubkey())
                    .and_then(|index| u32::try_from(index).ok())
            })
            .expect("leader should appear in MCP proposer schedule");

        let aggregate_bytes = AggregateAttestation::new_canonical(slot, leader_index, vec![])
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        let delayed_bankhash = Hash::new_unique();
        let block_id = Hash::new_unique();
        let mut block = ConsensusBlock::new_unsigned(
            slot,
            leader_index,
            aggregate_bytes,
            block_id.to_bytes().to_vec(),
            delayed_bankhash,
        )
        .unwrap();
        block.sign_leader(&leader).unwrap();
        let payload = block.to_wire_bytes().unwrap();
        let mut frame = Vec::with_capacity(1 + payload.len());
        frame.push(MCP_CONTROL_MSG_CONSENSUS_BLOCK);
        frame.extend_from_slice(&payload);
        let consensus_blocks = Arc::new(RwLock::new(HashMap::new()));

        ingest_mcp_control_message(
            Pubkey::new_unique(),
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            &frame,
            &blockstore,
            &bank_forks,
            &leader_schedule_cache,
            Some(&consensus_blocks),
        );

        assert!(consensus_blocks.read().unwrap().is_empty());
    }

    #[test]
    fn test_ingest_mcp_consensus_block_rejects_invalid_consensus_meta_length() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let leader = Keypair::new();
        let mut genesis = create_genesis_config_with_leader(10_000, &leader.pubkey(), 1_000);
        genesis
            .genesis_config
            .accounts
            .remove(&feature_set::mcp_protocol_v1::id());
        let mut root_bank = Bank::new_for_tests(&genesis.genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let bank_forks = BankForks::new_rw_arc(root_bank);
        let root_bank = bank_forks.read().unwrap().root_bank();
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);
        let leader_index = leader_schedule_cache
            .proposers_at_slot(slot, Some(&root_bank))
            .and_then(|proposers| {
                proposers
                    .iter()
                    .position(|pubkey| *pubkey == leader.pubkey())
                    .and_then(|index| u32::try_from(index).ok())
            })
            .expect("leader should appear in MCP proposer schedule");

        let aggregate_bytes = AggregateAttestation::new_canonical(slot, leader_index, vec![])
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        let delayed_bankhash = Hash::new_unique();
        let mut block = ConsensusBlock::new_unsigned(
            slot,
            leader_index,
            aggregate_bytes,
            vec![7u8; HASH_BYTES - 1],
            delayed_bankhash,
        )
        .unwrap();
        block.sign_leader(&leader).unwrap();
        let payload = block.to_wire_bytes().unwrap();
        let mut frame = Vec::with_capacity(1 + payload.len());
        frame.push(MCP_CONTROL_MSG_CONSENSUS_BLOCK);
        frame.extend_from_slice(&payload);
        let consensus_blocks = Arc::new(RwLock::new(HashMap::new()));

        ingest_mcp_control_message(
            leader.pubkey(),
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            &frame,
            &blockstore,
            &bank_forks,
            &leader_schedule_cache,
            Some(&consensus_blocks),
        );

        assert!(consensus_blocks.read().unwrap().is_empty());
    }

    #[test]
    fn test_ingest_mcp_relay_attestation_preserves_signed_entry_list() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let leader = Keypair::new();
        let mut genesis = create_genesis_config_with_leader(10_000, &leader.pubkey(), 1_000);
        genesis
            .genesis_config
            .accounts
            .remove(&feature_set::mcp_protocol_v1::id());
        let mut root_bank = Bank::new_for_tests(&genesis.genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let bank_forks = BankForks::new_rw_arc(root_bank);
        let root_bank = bank_forks.read().unwrap().root_bank();
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);
        let relay_index = leader_schedule_cache
            .relays_at_slot(slot, Some(&root_bank))
            .and_then(|relays| {
                relays
                    .iter()
                    .position(|pubkey| *pubkey == leader.pubkey())
                    .and_then(|index| u32::try_from(index).ok())
            })
            .expect("leader should appear in MCP relay schedule");
        let valid_proposer_index = leader_schedule_cache
            .proposers_at_slot(slot, Some(&root_bank))
            .and_then(|proposers| {
                proposers
                    .iter()
                    .position(|pubkey| *pubkey == leader.pubkey())
                    .and_then(|index| u32::try_from(index).ok())
            })
            .expect("leader should appear in MCP proposer schedule");
        let invalid_proposer_index = if valid_proposer_index == 0 { 1 } else { 0 };
        let valid_commitment = [41u8; 32];
        let invalid_commitment = [99u8; 32];
        let mut entries = vec![
            RelayAttestationEntry {
                proposer_index: valid_proposer_index,
                commitment: valid_commitment,
                proposer_signature: leader.sign_message(&valid_commitment),
            },
            RelayAttestationEntry {
                proposer_index: invalid_proposer_index,
                commitment: invalid_commitment,
                proposer_signature: Signature::default(),
            },
        ];
        entries.sort_unstable_by_key(|entry| entry.proposer_index);
        let mut attestation = RelayAttestationV1 {
            slot,
            relay_index,
            entries,
            relay_signature: Signature::default(),
        };
        let signing_bytes = attestation.signing_bytes().unwrap();
        attestation.relay_signature = leader.sign_message(&signing_bytes);
        let payload = attestation.to_bytes().unwrap();
        let mut frame = Vec::with_capacity(1 + payload.len());
        frame.push(MCP_CONTROL_MSG_RELAY_ATTESTATION);
        frame.extend_from_slice(&payload);

        assert_eq!(
            ingest_mcp_control_message(
                leader.pubkey(),
                SocketAddr::from(([127, 0, 0, 1], 1234)),
                &frame,
                &blockstore,
                &bank_forks,
                &leader_schedule_cache,
                None,
            ),
            Some(slot),
        );

        let stored = blockstore
            .get_mcp_relay_attestation(slot, relay_index)
            .unwrap()
            .expect("stored attestation missing");
        assert_eq!(stored, payload);
        let stored_attestation = RelayAttestationV1::from_bytes(&stored).unwrap();
        assert_eq!(stored_attestation.entries.len(), 2);
        assert!(stored_attestation.verify_relay_signature(&leader.pubkey()));
    }

    #[test]
    fn test_maybe_finalize_consensus_block_from_relay_attestations() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let leader = Arc::new(Keypair::new());
        let mut genesis = create_genesis_config_with_leader(10_000, &leader.pubkey(), 1_000);
        genesis
            .genesis_config
            .accounts
            .remove(&feature_set::mcp_protocol_v1::id());
        let mut root_bank = Bank::new_for_tests(&genesis.genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let bank_forks = BankForks::new_rw_arc(root_bank);
        let root_bank = bank_forks.read().unwrap().root_bank();
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);

        let delayed_bank = Bank::new_from_parent(
            root_bank.clone(),
            &Pubkey::new_unique(),
            slot.saturating_sub(1),
        );
        let delayed_bankhash = delayed_bank.hash();
        let slot_bank = Bank::new_from_parent(root_bank.clone(), &Pubkey::new_unique(), slot);
        slot_bank.set_block_id(Some(Hash::new_unique()));
        {
            let mut bank_forks = bank_forks.write().unwrap();
            bank_forks.insert(delayed_bank);
            bank_forks.insert(slot_bank);
        }

        let proposer_schedule = leader_schedule_cache
            .proposers_at_slot(slot, Some(&root_bank))
            .expect("MCP proposer schedule missing");
        let proposer_index = proposer_schedule
            .iter()
            .position(|pubkey| *pubkey == leader.pubkey())
            .and_then(|index| u32::try_from(index).ok())
            .expect("leader should appear in MCP proposer schedule");
        let relay_schedule = leader_schedule_cache
            .relays_at_slot(slot, Some(&root_bank))
            .expect("MCP relay schedule missing");

        let commitment = [7u8; 32];
        let proposer_signature = leader.sign_message(&commitment);
        let relay_indices: Vec<u32> = relay_schedule
            .iter()
            .enumerate()
            .filter_map(|(relay_index, pubkey)| {
                if *pubkey == leader.pubkey() {
                    u32::try_from(relay_index).ok()
                } else {
                    None
                }
            })
            .take(mcp::REQUIRED_ATTESTATIONS)
            .collect();
        assert_eq!(relay_indices.len(), mcp::REQUIRED_ATTESTATIONS);

        for relay_index in relay_indices {
            let mut attestation = RelayAttestationV1 {
                slot,
                relay_index,
                entries: vec![RelayAttestationEntry {
                    proposer_index,
                    commitment,
                    proposer_signature,
                }],
                relay_signature: Signature::default(),
            };
            let signing_bytes = attestation.signing_bytes().unwrap();
            attestation.relay_signature = leader.sign_message(&signing_bytes);
            blockstore
                .put_mcp_relay_attestation(slot, relay_index, &attestation.to_bytes().unwrap())
                .unwrap();
        }

        let contact_info = ContactInfo::new_localhost(&leader.pubkey(), timestamp());
        let cluster_info =
            ClusterInfo::new(contact_info, leader.clone(), SocketAddrSpace::Unspecified);
        let consensus_blocks = Arc::new(RwLock::new(HashMap::new()));
        let should_retry = maybe_finalize_and_broadcast_mcp_consensus_block(
            slot,
            &leader.pubkey(),
            &cluster_info,
            &blockstore,
            &bank_forks,
            &leader_schedule_cache,
            Some(&consensus_blocks),
            None,
        );
        assert!(!should_retry);

        let block_bytes = consensus_blocks
            .read()
            .unwrap()
            .get(&slot)
            .cloned()
            .expect("consensus block should be finalized");
        let block = ConsensusBlock::from_wire_bytes(&block_bytes).unwrap();
        assert_eq!(block.slot, slot);
        assert_eq!(block.delayed_bankhash, delayed_bankhash);
        assert!(block.verify_leader_signature(&leader.pubkey()));
    }

    #[test]
    fn test_maybe_finalize_consensus_block_keeps_original_relay_signed_entries() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let leader = Arc::new(Keypair::new());
        let mut genesis = create_genesis_config_with_leader(10_000, &leader.pubkey(), 1_000);
        genesis
            .genesis_config
            .accounts
            .remove(&feature_set::mcp_protocol_v1::id());
        let mut root_bank = Bank::new_for_tests(&genesis.genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let bank_forks = BankForks::new_rw_arc(root_bank);
        let root_bank = bank_forks.read().unwrap().root_bank();
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);

        let delayed_bank = Bank::new_from_parent(
            root_bank.clone(),
            &Pubkey::new_unique(),
            slot.saturating_sub(1),
        );
        let delayed_bankhash = delayed_bank.hash();
        let slot_bank = Bank::new_from_parent(root_bank.clone(), &Pubkey::new_unique(), slot);
        slot_bank.set_block_id(Some(Hash::new_unique()));
        {
            let mut bank_forks = bank_forks.write().unwrap();
            bank_forks.insert(delayed_bank);
            bank_forks.insert(slot_bank);
        }

        let proposer_schedule = leader_schedule_cache
            .proposers_at_slot(slot, Some(&root_bank))
            .expect("MCP proposer schedule missing");
        let valid_proposer_index = proposer_schedule
            .iter()
            .position(|pubkey| *pubkey == leader.pubkey())
            .and_then(|index| u32::try_from(index).ok())
            .expect("leader should appear in MCP proposer schedule");
        let invalid_proposer_index = if valid_proposer_index == 0 { 1 } else { 0 };
        let relay_schedule = leader_schedule_cache
            .relays_at_slot(slot, Some(&root_bank))
            .expect("MCP relay schedule missing");

        let valid_commitment = [7u8; 32];
        let invalid_commitment = [8u8; 32];
        let valid_signature = leader.sign_message(&valid_commitment);
        let relay_indices: Vec<u32> = relay_schedule
            .iter()
            .enumerate()
            .filter_map(|(relay_index, pubkey)| {
                if *pubkey == leader.pubkey() {
                    u32::try_from(relay_index).ok()
                } else {
                    None
                }
            })
            .take(mcp::REQUIRED_ATTESTATIONS)
            .collect();
        assert_eq!(relay_indices.len(), mcp::REQUIRED_ATTESTATIONS);

        for relay_index in relay_indices {
            let mut entries = vec![
                RelayAttestationEntry {
                    proposer_index: valid_proposer_index,
                    commitment: valid_commitment,
                    proposer_signature: valid_signature,
                },
                RelayAttestationEntry {
                    proposer_index: invalid_proposer_index,
                    commitment: invalid_commitment,
                    proposer_signature: Signature::default(),
                },
            ];
            entries.sort_unstable_by_key(|entry| entry.proposer_index);
            let mut attestation = RelayAttestationV1 {
                slot,
                relay_index,
                entries,
                relay_signature: Signature::default(),
            };
            let signing_bytes = attestation.signing_bytes().unwrap();
            attestation.relay_signature = leader.sign_message(&signing_bytes);
            blockstore
                .put_mcp_relay_attestation(slot, relay_index, &attestation.to_bytes().unwrap())
                .unwrap();
        }

        let contact_info = ContactInfo::new_localhost(&leader.pubkey(), timestamp());
        let cluster_info =
            ClusterInfo::new(contact_info, leader.clone(), SocketAddrSpace::Unspecified);
        let consensus_blocks = Arc::new(RwLock::new(HashMap::new()));
        let should_retry = maybe_finalize_and_broadcast_mcp_consensus_block(
            slot,
            &leader.pubkey(),
            &cluster_info,
            &blockstore,
            &bank_forks,
            &leader_schedule_cache,
            Some(&consensus_blocks),
            None,
        );
        assert!(!should_retry);

        let block_bytes = consensus_blocks
            .read()
            .unwrap()
            .get(&slot)
            .cloned()
            .expect("consensus block should be finalized");
        let block = ConsensusBlock::from_wire_bytes(&block_bytes).unwrap();
        assert_eq!(block.slot, slot);
        assert_eq!(block.delayed_bankhash, delayed_bankhash);
        let aggregate = AggregateAttestation::from_wire_bytes(&block.aggregate_bytes).unwrap();
        assert_eq!(aggregate.relay_entries.len(), mcp::REQUIRED_ATTESTATIONS);
        for relay_entry in &aggregate.relay_entries {
            assert_eq!(relay_entry.entries.len(), 2);
            let relay_pubkey = relay_schedule
                .get(relay_entry.relay_index as usize)
                .copied()
                .expect("relay index should map to schedule");
            assert!(relay_entry.verify_relay_signature(aggregate.version, slot, &relay_pubkey));
        }
    }

    #[test]
    fn test_maybe_finalize_consensus_block_requires_delayed_bankhash() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let leader = Arc::new(Keypair::new());
        let mut genesis = create_genesis_config_with_leader(10_000, &leader.pubkey(), 1_000);
        genesis
            .genesis_config
            .accounts
            .remove(&feature_set::mcp_protocol_v1::id());
        let mut root_bank = Bank::new_for_tests(&genesis.genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let bank_forks = BankForks::new_rw_arc(root_bank);
        let root_bank = bank_forks.read().unwrap().root_bank();
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);

        let proposer_schedule = leader_schedule_cache
            .proposers_at_slot(slot, Some(&root_bank))
            .expect("MCP proposer schedule missing");
        let proposer_index = proposer_schedule
            .iter()
            .position(|pubkey| *pubkey == leader.pubkey())
            .and_then(|index| u32::try_from(index).ok())
            .expect("leader should appear in MCP proposer schedule");
        let relay_schedule = leader_schedule_cache
            .relays_at_slot(slot, Some(&root_bank))
            .expect("MCP relay schedule missing");

        let commitment = [11u8; 32];
        let proposer_signature = leader.sign_message(&commitment);
        let relay_indices: Vec<u32> = relay_schedule
            .iter()
            .enumerate()
            .filter_map(|(relay_index, pubkey)| {
                if *pubkey == leader.pubkey() {
                    u32::try_from(relay_index).ok()
                } else {
                    None
                }
            })
            .take(mcp::REQUIRED_ATTESTATIONS)
            .collect();
        assert_eq!(relay_indices.len(), mcp::REQUIRED_ATTESTATIONS);

        for relay_index in relay_indices {
            let mut attestation = RelayAttestationV1 {
                slot,
                relay_index,
                entries: vec![RelayAttestationEntry {
                    proposer_index,
                    commitment,
                    proposer_signature,
                }],
                relay_signature: Signature::default(),
            };
            let signing_bytes = attestation.signing_bytes().unwrap();
            attestation.relay_signature = leader.sign_message(&signing_bytes);
            blockstore
                .put_mcp_relay_attestation(slot, relay_index, &attestation.to_bytes().unwrap())
                .unwrap();
        }

        let contact_info = ContactInfo::new_localhost(&leader.pubkey(), timestamp());
        let cluster_info =
            ClusterInfo::new(contact_info, leader.clone(), SocketAddrSpace::Unspecified);
        let consensus_blocks = Arc::new(RwLock::new(HashMap::new()));
        let should_retry = maybe_finalize_and_broadcast_mcp_consensus_block(
            slot,
            &leader.pubkey(),
            &cluster_info,
            &blockstore,
            &bank_forks,
            &leader_schedule_cache,
            Some(&consensus_blocks),
            None,
        );
        assert!(should_retry);

        assert!(consensus_blocks.read().unwrap().is_empty());
    }

    #[test]
    fn test_maybe_finalize_consensus_block_uses_blockstore_delayed_bankhash() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let leader = Arc::new(Keypair::new());
        let mut genesis = create_genesis_config_with_leader(10_000, &leader.pubkey(), 1_000);
        genesis
            .genesis_config
            .accounts
            .remove(&feature_set::mcp_protocol_v1::id());
        let mut root_bank = Bank::new_for_tests(&genesis.genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let bank_forks = BankForks::new_rw_arc(root_bank);
        let root_bank = bank_forks.read().unwrap().root_bank();
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);
        let delayed_slot = slot.saturating_sub(1);
        let delayed_bankhash = Hash::new_unique();
        blockstore.insert_bank_hash(delayed_slot, delayed_bankhash, false);
        let slot_bank = Bank::new_from_parent(root_bank.clone(), &Pubkey::new_unique(), slot);
        slot_bank.set_block_id(Some(Hash::new_unique()));
        bank_forks.write().unwrap().insert(slot_bank);

        let proposer_schedule = leader_schedule_cache
            .proposers_at_slot(slot, Some(&root_bank))
            .expect("MCP proposer schedule missing");
        let proposer_index = proposer_schedule
            .iter()
            .position(|pubkey| *pubkey == leader.pubkey())
            .and_then(|index| u32::try_from(index).ok())
            .expect("leader should appear in MCP proposer schedule");
        let relay_schedule = leader_schedule_cache
            .relays_at_slot(slot, Some(&root_bank))
            .expect("MCP relay schedule missing");

        let commitment = [31u8; 32];
        let proposer_signature = leader.sign_message(&commitment);
        let relay_indices: Vec<u32> = relay_schedule
            .iter()
            .enumerate()
            .filter_map(|(relay_index, pubkey)| {
                if *pubkey == leader.pubkey() {
                    u32::try_from(relay_index).ok()
                } else {
                    None
                }
            })
            .take(mcp::REQUIRED_ATTESTATIONS)
            .collect();
        assert_eq!(relay_indices.len(), mcp::REQUIRED_ATTESTATIONS);

        for relay_index in relay_indices {
            let mut attestation = RelayAttestationV1 {
                slot,
                relay_index,
                entries: vec![RelayAttestationEntry {
                    proposer_index,
                    commitment,
                    proposer_signature,
                }],
                relay_signature: Signature::default(),
            };
            let signing_bytes = attestation.signing_bytes().unwrap();
            attestation.relay_signature = leader.sign_message(&signing_bytes);
            blockstore
                .put_mcp_relay_attestation(slot, relay_index, &attestation.to_bytes().unwrap())
                .unwrap();
        }

        let contact_info = ContactInfo::new_localhost(&leader.pubkey(), timestamp());
        let cluster_info =
            ClusterInfo::new(contact_info, leader.clone(), SocketAddrSpace::Unspecified);
        let consensus_blocks = Arc::new(RwLock::new(HashMap::new()));
        let should_retry = maybe_finalize_and_broadcast_mcp_consensus_block(
            slot,
            &leader.pubkey(),
            &cluster_info,
            &blockstore,
            &bank_forks,
            &leader_schedule_cache,
            Some(&consensus_blocks),
            None,
        );
        assert!(!should_retry);

        let block_bytes = consensus_blocks
            .read()
            .unwrap()
            .get(&slot)
            .cloned()
            .expect("consensus block should be finalized");
        let block = ConsensusBlock::from_wire_bytes(&block_bytes).unwrap();
        assert_eq!(block.delayed_bankhash, delayed_bankhash);
    }

    #[test]
    fn test_maybe_finalize_consensus_block_broadcasts_quic_control_frame() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let leader = Arc::new(Keypair::new());
        let mut genesis = create_genesis_config_with_leader(10_000, &leader.pubkey(), 1_000);
        genesis
            .genesis_config
            .accounts
            .remove(&feature_set::mcp_protocol_v1::id());
        let mut root_bank = Bank::new_for_tests(&genesis.genesis_config);
        root_bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let bank_forks = BankForks::new_rw_arc(root_bank);
        let root_bank = bank_forks.read().unwrap().root_bank();
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let slot = root_bank.epoch_schedule().get_first_slot_in_epoch(1);

        let delayed_bank = Bank::new_from_parent(
            root_bank.clone(),
            &Pubkey::new_unique(),
            slot.saturating_sub(1),
        );
        let slot_bank = Bank::new_from_parent(root_bank.clone(), &Pubkey::new_unique(), slot);
        slot_bank.set_block_id(Some(Hash::new_unique()));
        {
            let mut bank_forks = bank_forks.write().unwrap();
            bank_forks.insert(delayed_bank);
            bank_forks.insert(slot_bank);
        }

        let proposer_schedule = leader_schedule_cache
            .proposers_at_slot(slot, Some(&root_bank))
            .expect("MCP proposer schedule missing");
        let proposer_index = proposer_schedule
            .iter()
            .position(|pubkey| *pubkey == leader.pubkey())
            .and_then(|index| u32::try_from(index).ok())
            .expect("leader should appear in MCP proposer schedule");
        let relay_schedule = leader_schedule_cache
            .relays_at_slot(slot, Some(&root_bank))
            .expect("MCP relay schedule missing");

        let commitment = [23u8; 32];
        let proposer_signature = leader.sign_message(&commitment);
        let relay_indices: Vec<u32> = relay_schedule
            .iter()
            .enumerate()
            .filter_map(|(relay_index, pubkey)| {
                if *pubkey == leader.pubkey() {
                    u32::try_from(relay_index).ok()
                } else {
                    None
                }
            })
            .take(mcp::REQUIRED_ATTESTATIONS)
            .collect();
        assert_eq!(relay_indices.len(), mcp::REQUIRED_ATTESTATIONS);

        for relay_index in relay_indices {
            let mut attestation = RelayAttestationV1 {
                slot,
                relay_index,
                entries: vec![RelayAttestationEntry {
                    proposer_index,
                    commitment,
                    proposer_signature,
                }],
                relay_signature: Signature::default(),
            };
            let signing_bytes = attestation.signing_bytes().unwrap();
            attestation.relay_signature = leader.sign_message(&signing_bytes);
            blockstore
                .put_mcp_relay_attestation(slot, relay_index, &attestation.to_bytes().unwrap())
                .unwrap();
        }

        let local_contact_info = ContactInfo::new_localhost(&leader.pubkey(), timestamp());
        let cluster_info = ClusterInfo::new(
            local_contact_info,
            leader.clone(),
            SocketAddrSpace::Unspecified,
        );
        let peer_pubkey = Pubkey::new_unique();
        let peer_contact_info = ContactInfo::new_localhost(&peer_pubkey, timestamp());
        let expected_peer_tvu_quic = peer_contact_info.tvu(Protocol::QUIC).unwrap();
        cluster_info.insert_info(peer_contact_info);

        let consensus_blocks = Arc::new(RwLock::new(HashMap::new()));
        let (sender, mut receiver) = mpsc::channel(8);
        maybe_finalize_and_broadcast_mcp_consensus_block(
            slot,
            &leader.pubkey(),
            &cluster_info,
            &blockstore,
            &bank_forks,
            &leader_schedule_cache,
            Some(&consensus_blocks),
            Some(&sender),
        );

        let (remote_addr, frame) = receiver.try_recv().unwrap();
        assert_eq!(remote_addr, expected_peer_tvu_quic);
        assert_eq!(
            frame.first().copied(),
            Some(MCP_CONTROL_MSG_CONSENSUS_BLOCK)
        );
        let broadcast_block = ConsensusBlock::from_wire_bytes(&frame[1..]).unwrap();
        assert_eq!(broadcast_block.slot, slot);
    }

    #[test]
    fn test_process_shred() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Arc::new(Blockstore::open(ledger_path.path()).unwrap());
        let num_entries = 10;
        let original_entries = create_ticks(num_entries, 0, Hash::default());
        let mut shreds = local_entries_to_shred(&original_entries, 0, 0, &Keypair::new());
        shreds.reverse();
        blockstore
            .insert_shreds(shreds, None, false)
            .expect("Expect successful processing of shred");

        assert_eq!(blockstore.get_slot_entries(0, 0).unwrap(), original_entries);
    }

    #[test]
    fn test_run_check_duplicate() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let genesis_config = create_genesis_config(10_000).genesis_config;
        let bank_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
        let blockstore = Arc::new(Blockstore::open(ledger_path.path()).unwrap());
        let (sender, receiver) = unbounded();
        let (duplicate_slot_sender, duplicate_slot_receiver) = unbounded();
        let (shreds, _) = make_many_slot_entries(5, 5, 10);
        blockstore
            .insert_shreds(shreds.clone(), None, false)
            .unwrap();
        let duplicate_index = 0;
        let original_shred = shreds[duplicate_index].clone();
        let duplicate_shred = {
            let (mut shreds, _) = make_many_slot_entries(5, 1, 10);
            shreds.swap_remove(duplicate_index)
        };
        assert_eq!(duplicate_shred.slot(), shreds[0].slot());
        let duplicate_shred_slot = duplicate_shred.slot();
        sender
            .send(PossibleDuplicateShred::Exists(duplicate_shred.clone()))
            .unwrap();
        assert!(!blockstore.has_duplicate_shreds_in_slot(duplicate_shred_slot));
        let keypair = Keypair::new();
        let contact_info = ContactInfo::new_localhost(&keypair.pubkey(), timestamp());
        let cluster_info = ClusterInfo::new(
            contact_info,
            Arc::new(keypair),
            SocketAddrSpace::Unspecified,
        );
        run_check_duplicate(
            &cluster_info,
            &blockstore,
            &receiver,
            &duplicate_slot_sender,
            &bank_forks,
            &MigrationStatus::default(),
        )
        .unwrap();

        // Make sure the correct duplicate proof was stored
        let duplicate_proof = blockstore.get_duplicate_slot(duplicate_shred_slot).unwrap();
        assert_eq!(duplicate_proof.shred1, *original_shred.payload());
        assert_eq!(duplicate_proof.shred2, *duplicate_shred.payload());

        // Make sure a duplicate signal was sent
        assert_eq!(
            duplicate_slot_receiver.try_recv().unwrap(),
            duplicate_shred_slot
        );
    }

    #[test]
    fn test_store_duplicate_shreds_same_batch() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Arc::new(Blockstore::open(ledger_path.path()).unwrap());
        let (duplicate_shred_sender, duplicate_shred_receiver) = unbounded();
        let (duplicate_slot_sender, duplicate_slot_receiver) = unbounded();
        let exit = Arc::new(AtomicBool::new(false));
        let keypair = Keypair::new();
        let contact_info = ContactInfo::new_localhost(&keypair.pubkey(), timestamp());
        let cluster_info = Arc::new(ClusterInfo::new(
            contact_info,
            Arc::new(keypair),
            SocketAddrSpace::Unspecified,
        ));
        let genesis_config = create_genesis_config(10_000).genesis_config;
        let bank_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));

        // Start duplicate thread receiving and inserting duplicates
        let t_check_duplicate = WindowService::start_check_duplicate_thread(
            cluster_info,
            exit.clone(),
            blockstore.clone(),
            duplicate_shred_receiver,
            duplicate_slot_sender,
            bank_forks,
            Arc::new(MigrationStatus::default()),
        );

        let handle_duplicate = |shred| {
            let _ = duplicate_shred_sender.send(shred);
        };
        let num_trials = 100;
        let (dummy_retransmit_sender, _) = EvictingSender::new_bounded(0);
        for slot in 0..num_trials {
            let (shreds, _) = make_many_slot_entries(slot, 1, 10);
            let duplicate_index = 0;
            let original_shred = shreds[duplicate_index].clone();
            let duplicate_shred = {
                let (mut shreds, _) = make_many_slot_entries(slot, 1, 10);
                shreds.swap_remove(duplicate_index)
            };
            assert_eq!(duplicate_shred.slot(), slot);
            // Simulate storing both duplicate shreds in the same batch
            let shreds = [&original_shred, &duplicate_shred]
                .into_iter()
                .map(|shred| (Cow::Borrowed(shred), /*is_repaired:*/ false));
            blockstore
                .insert_shreds_handle_duplicate(
                    shreds,
                    None,
                    false, // is_trusted
                    &dummy_retransmit_sender,
                    &handle_duplicate,
                    &ReedSolomonCache::default(),
                    &mut BlockstoreInsertionMetrics::default(),
                )
                .unwrap();

            // Make sure a duplicate signal was sent
            assert_eq!(
                duplicate_slot_receiver
                    .recv_timeout(Duration::from_millis(5_000))
                    .unwrap(),
                slot
            );

            // Make sure the correct duplicate proof was stored
            let duplicate_proof = blockstore.get_duplicate_slot(slot).unwrap();
            assert_eq!(duplicate_proof.shred1, *original_shred.payload());
            assert_eq!(duplicate_proof.shred2, *duplicate_shred.payload());
        }
        exit.store(true, Ordering::Relaxed);
        t_check_duplicate.join().unwrap();
    }
}
