//! `window_service` handles the data plane incoming shreds, storing them in
//!   blockstore and retransmitting where required
//!

use {
    crate::{
        completed_data_sets_service::CompletedDataSetsSender,
        mcp_relay_attestation::{
            ReceivedShredInfo, RelayAttestationConfig, RelayAttestationService,
            // TODO: Wire in for actual attestation submission
            // get_attestation_leader_addr, submit_attestation,
        },
        mcp_replay_reconstruction::{
            reconstruct_proposer_payload, ProposerShreds, ReconstructionResult,
            ShredData, SlotReconstruction,
        },
        repair::repair_service::{
            OutstandingShredRepairs, RepairInfo, RepairService, RepairServiceChannels,
        },
        result::{Error, Result},
    },
    agave_feature_set as feature_set,
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender},
    rayon::{prelude::*, ThreadPool},
    solana_clock::{Slot, DEFAULT_MS_PER_SLOT},
    solana_gossip::cluster_info::ClusterInfo,
    solana_hash::Hash,
    solana_ledger::{
        blockstore::{Blockstore, BlockstoreInsertionMetrics, PossibleDuplicateShred},
        blockstore_meta::BlockLocation,
        leader_schedule_cache::LeaderScheduleCache,
        mcp::fec::MCP_DATA_SHREDS_PER_FEC_BLOCK,
        shred::{self, mcp_shred::{is_mcp_shred_packet, McpShredV1}, ReedSolomonCache, Shred},
    },
    solana_measure::measure::Measure,
    solana_metrics::inc_new_counter_error,
    solana_rayon_threadlimit::get_thread_count,
    solana_runtime::bank_forks::BankForks,
    solana_signature,
    solana_keypair::Keypair,
    solana_streamer::evicting_sender::EvictingSender,
    solana_turbine::cluster_nodes,
    solana_votor_messages::migration::MigrationStatus,
    std::{
        borrow::Cow,
        collections::HashMap,
        net::UdpSocket,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

type DuplicateSlotSender = Sender<Slot>;
pub(crate) type DuplicateSlotReceiver = Receiver<Slot>;

/// MCP reconstruction result ready for replay
pub type McpReconstructionSender = Sender<SlotReconstruction>;
pub type McpReconstructionReceiver = Receiver<SlotReconstruction>;

/// Track MCP shreds per slot for availability checking
#[derive(Default)]
struct McpSlotTracker {
    /// Shred count per (slot, proposer_id)
    shred_counts: HashMap<(Slot, u8), usize>,
    /// Slots that have been reconstructed
    reconstructed_slots: HashMap<Slot, bool>,
}

impl McpSlotTracker {
    /// Record an MCP shred and return true if we should check reconstruction
    fn record_shred(&mut self, slot: Slot, proposer_id: u8) -> bool {
        // Don't track if already reconstructed
        if self.reconstructed_slots.get(&slot).copied().unwrap_or(false) {
            return false;
        }

        let key = (slot, proposer_id);
        let count = self.shred_counts.entry(key).or_insert(0);
        *count += 1;

        // Check if we just hit the K threshold
        *count == MCP_DATA_SHREDS_PER_FEC_BLOCK
    }

    /// Check if a proposer has enough shreds for reconstruction
    fn can_reconstruct(&self, slot: Slot, proposer_id: u8) -> bool {
        self.shred_counts
            .get(&(slot, proposer_id))
            .copied()
            .unwrap_or(0) >= MCP_DATA_SHREDS_PER_FEC_BLOCK
    }

    /// Mark a slot as reconstructed
    fn mark_reconstructed(&mut self, slot: Slot) {
        self.reconstructed_slots.insert(slot, true);
    }

    /// Garbage collect old slots
    #[allow(dead_code)]
    fn gc_old_slots(&mut self, min_slot: Slot) {
        self.shred_counts.retain(|(slot, _), _| *slot >= min_slot);
        self.reconstructed_slots.retain(|slot, _| *slot >= min_slot);
    }
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
    leader_schedule_cache: &LeaderScheduleCache,
    handle_duplicate: F,
    metrics: &mut BlockstoreInsertionMetrics,
    ws_metrics: &mut WindowServiceMetrics,
    completed_data_sets_sender: Option<&CompletedDataSetsSender>,
    retransmit_sender: &EvictingSender<Vec<shred::Payload>>,
    reed_solomon_cache: &ReedSolomonCache,
    accept_repairs_only: bool,
    mcp_tracker: &mut McpSlotTracker,
    mcp_reconstruction_sender: Option<&McpReconstructionSender>,
    relay_attestation_service: &mut RelayAttestationService,
    relay_keypair: Option<&Arc<Keypair>>,
) -> Result<()>
where
    F: Fn(PossibleDuplicateShred),
{
    const RECV_TIMEOUT: Duration = Duration::from_millis(200);
    let mut shred_receiver_elapsed = Measure::start("shred_receiver_elapsed");
    let mut shreds = verified_receiver.recv_timeout(RECV_TIMEOUT)?;
    shreds.extend(verified_receiver.try_iter().flatten());
    shred_receiver_elapsed.stop();
    ws_metrics.shred_receiver_elapsed_us += shred_receiver_elapsed.as_us();
    ws_metrics.run_insert_count += 1;

    // Separate MCP shreds from regular shreds using format validation
    let (mcp_shreds, regular_shreds): (Vec<_>, Vec<_>) = shreds
        .into_iter()
        .partition(|(shred, _, _)| is_mcp_shred_packet(shred));

    // Handle regular shreds
    let handle_shred = |(shred, repair, block_location): (shred::Payload, bool, BlockLocation)| {
        if accept_repairs_only && !repair {
            return None;
        }
        if repair {
            ws_metrics.num_repairs.fetch_add(1, Ordering::Relaxed);
        }
        let shred = Shred::new_from_serialized_shred(shred).ok()?;
        Some((Cow::Owned(shred), repair, block_location))
    };
    let now = Instant::now();
    let shreds: Vec<_> = thread_pool.install(|| {
        regular_shreds
            .into_par_iter()
            .with_min_len(32)
            .filter_map(handle_shred)
            .collect()
    });

    // Handle MCP shreds - store them and track availability
    let mcp_count = mcp_shreds.len();
    let mut slots_to_check: HashMap<Slot, Vec<u8>> = HashMap::new();

    for (shred_data, _repair, _block_location) in mcp_shreds {
        if let Ok(mcp_shred) = McpShredV1::from_bytes(&shred_data) {
            let slot = mcp_shred.slot;
            let proposer_id = mcp_shred.proposer_index as u8;
            let commitment = Hash::new_from_array(mcp_shred.commitment);
            let proposer_signature = solana_signature::Signature::from(mcp_shred.proposer_signature);

            // Store MCP shred in MCP columns
            if let Err(e) = blockstore.put_mcp_data_shred(
                slot,
                proposer_id,
                mcp_shred.shred_index as u64,
                &shred_data,
            ) {
                debug!("Failed to store MCP shred: {}", e);
                continue;
            }

            // Track the shred for relay attestation
            relay_attestation_service.record_shred(ReceivedShredInfo {
                slot,
                proposer_id: proposer_id as u32,
                shred_index: mcp_shred.shred_index,
                commitment,
                proposer_signature,
            });

            // Track the shred and check if we should try reconstruction
            if mcp_tracker.record_shred(slot, proposer_id) {
                // Just hit K threshold for this proposer - may need reconstruction
                slots_to_check.entry(slot).or_default().push(proposer_id);
            }
        }
    }

    // Check if any attestations are ready to send
    if let Some((slot, proposers)) = relay_attestation_service.check_attestation_ready() {
        info!(
            "MCP relay attestation ready for slot {} with {} proposers",
            slot,
            proposers.len()
        );

        // Create and send attestation if we have a keypair
        if let Some(keypair) = relay_keypair {
            let attestation = relay_attestation_service.create_attestation(
                slot,
                proposers,
                keypair,
            );
            info!(
                "MCP: Created attestation for slot {} from relay {} with {} entries",
                slot,
                attestation.relay_index,
                attestation.entries.len()
            );
            // TODO: Send attestation to leader via UDP
            // let leader_addr = get_attestation_leader_addr(leader_schedule_cache, slot);
            // submit_attestation(&attestation, leader_addr, socket);
        }
    }

    // Try reconstruction for slots that may have enough shreds
    if !slots_to_check.is_empty() {
        if let Some(sender) = mcp_reconstruction_sender {
            for (slot, proposers) in slots_to_check {
                // Try to reconstruct this slot
                if let Some(reconstruction) = try_mcp_reconstruction(blockstore, slot, &proposers, mcp_tracker) {
                    if let Err(e) = sender.try_send(reconstruction) {
                        debug!("Failed to send MCP reconstruction: {:?}", e);
                    } else {
                        mcp_tracker.mark_reconstructed(slot);
                        info!("MCP reconstruction sent for slot {}", slot);
                    }
                }
            }
        }
    }

    if mcp_count > 0 {
        trace!("Stored {} MCP shreds", mcp_count);
    }

    ws_metrics.handle_packets_elapsed_us += now.elapsed().as_micros() as u64;
    ws_metrics.num_shreds_received += shreds.len();
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

/// Try to reconstruct MCP payloads from stored shreds.
///
/// This function:
/// 1. Reads MCP shreds from blockstore for each proposer
/// 2. Performs RS decoding to reconstruct payloads
/// 3. Builds the ordered transaction list with de-duplication
fn try_mcp_reconstruction(
    blockstore: &Blockstore,
    slot: Slot,
    _proposers_with_k: &[u8],
    mcp_tracker: &McpSlotTracker,
) -> Option<SlotReconstruction> {
    use solana_ledger::mcp::NUM_PROPOSERS;

    let mut reconstruction = SlotReconstruction::new(slot);
    let mut any_success = false;

    // Try to reconstruct each proposer that has K shreds
    for proposer_id in 0..NUM_PROPOSERS as u8 {
        if !mcp_tracker.can_reconstruct(slot, proposer_id) {
            continue;
        }

        // Read shreds from blockstore for this proposer
        let shreds = match blockstore.get_mcp_data_shreds_for_proposer(slot, proposer_id) {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to read MCP shreds for slot {} proposer {}: {}", slot, proposer_id, e);
                continue;
            }
        };

        if shreds.len() < MCP_DATA_SHREDS_PER_FEC_BLOCK {
            debug!(
                "Not enough MCP shreds for slot {} proposer {}: {} < {}",
                slot, proposer_id, shreds.len(), MCP_DATA_SHREDS_PER_FEC_BLOCK
            );
            continue;
        }

        // Convert shreds to ShredData format for reconstruction
        let mut shred_data: Vec<ShredData> = Vec::with_capacity(shreds.len());
        let mut commitment: Option<Hash> = None;

        for (index, data) in shreds {
            if let Ok(mcp_shred) = McpShredV1::from_bytes(&data) {
                // Get commitment from first shred
                if commitment.is_none() {
                    commitment = Some(Hash::new_from_array(mcp_shred.commitment));
                }

                shred_data.push(ShredData {
                    index: index as u16,
                    is_data: index < MCP_DATA_SHREDS_PER_FEC_BLOCK as u64,
                    data: mcp_shred.shred_data.to_vec(),
                    merkle_proof: mcp_shred.witness.to_vec(),
                });
            }
        }

        let Some(commitment) = commitment else {
            debug!("No commitment found for slot {} proposer {}", slot, proposer_id);
            continue;
        };

        // Create ProposerShreds tracker for reconstruction
        let mut proposer_shreds = ProposerShreds::new(commitment);
        for sd in shred_data {
            proposer_shreds.add_shred(sd);
        }

        // Try reconstruction
        let result = reconstruct_proposer_payload(&proposer_shreds, &commitment);
        if matches!(result, ReconstructionResult::Success(_)) {
            any_success = true;
        }
        reconstruction.add_payload(proposer_id as u32, result);
    }

    if any_success {
        // Build the global ordered transaction list
        reconstruction.build_ordered_transactions();
        info!(
            "MCP reconstruction for slot {}: {} proposers, {} txs",
            slot,
            reconstruction.successful_proposer_count(),
            reconstruction.transaction_count()
        );
        Some(reconstruction)
    } else {
        None
    }
}

pub struct WindowServiceChannels {
    pub verified_receiver: Receiver<Vec<(shred::Payload, /*is_repaired:*/ bool, BlockLocation)>>,
    pub retransmit_sender: EvictingSender<Vec<shred::Payload>>,
    pub completed_data_sets_sender: Option<CompletedDataSetsSender>,
    pub duplicate_slots_sender: DuplicateSlotSender,
    pub repair_service_channels: RepairServiceChannels,
    /// Sender for MCP reconstruction results to feed replay
    pub mcp_reconstruction_sender: Option<McpReconstructionSender>,
    /// Optional keypair for relay attestation signing (only for relay nodes)
    pub relay_keypair: Option<Arc<Keypair>>,
}

impl WindowServiceChannels {
    pub fn new(
        verified_receiver: Receiver<Vec<(shred::Payload, /*is_repaired:*/ bool, BlockLocation)>>,
        retransmit_sender: EvictingSender<Vec<shred::Payload>>,
        completed_data_sets_sender: Option<CompletedDataSetsSender>,
        duplicate_slots_sender: DuplicateSlotSender,
        repair_service_channels: RepairServiceChannels,
    ) -> Self {
        Self {
            verified_receiver,
            retransmit_sender,
            completed_data_sets_sender,
            duplicate_slots_sender,
            repair_service_channels,
            mcp_reconstruction_sender: None,
            relay_keypair: None,
        }
    }

    /// Create channels with MCP reconstruction support
    pub fn with_mcp_reconstruction(
        verified_receiver: Receiver<Vec<(shred::Payload, /*is_repaired:*/ bool, BlockLocation)>>,
        retransmit_sender: EvictingSender<Vec<shred::Payload>>,
        completed_data_sets_sender: Option<CompletedDataSetsSender>,
        duplicate_slots_sender: DuplicateSlotSender,
        repair_service_channels: RepairServiceChannels,
        mcp_reconstruction_sender: McpReconstructionSender,
    ) -> Self {
        Self {
            verified_receiver,
            retransmit_sender,
            completed_data_sets_sender,
            duplicate_slots_sender,
            repair_service_channels,
            mcp_reconstruction_sender: Some(mcp_reconstruction_sender),
            relay_keypair: None,
        }
    }

    /// Set the relay keypair for attestation signing
    pub fn with_relay_keypair(mut self, keypair: Arc<Keypair>) -> Self {
        self.relay_keypair = Some(keypair);
        self
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

        // In wen_restart, we discard all shreds from Turbine and keep only those from repair to
        // avoid new shreds make validator OOM before wen_restart is over.
        let accept_repairs_only = repair_info.wen_restart_repair_slots.is_some();

        let WindowServiceChannels {
            verified_receiver,
            retransmit_sender,
            completed_data_sets_sender,
            duplicate_slots_sender,
            repair_service_channels,
            mcp_reconstruction_sender,
            relay_keypair,
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
            cluster_info,
            exit.clone(),
            blockstore.clone(),
            duplicate_receiver,
            duplicate_slots_sender,
            bank_forks,
            migration_status,
        );

        let t_insert = Self::start_window_insert_thread(
            exit,
            blockstore,
            leader_schedule_cache,
            verified_receiver,
            duplicate_sender,
            completed_data_sets_sender,
            retransmit_sender,
            accept_repairs_only,
            mcp_reconstruction_sender,
            relay_keypair,
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
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        verified_receiver: Receiver<Vec<(shred::Payload, /*is_repaired:*/ bool, BlockLocation)>>,
        check_duplicate_sender: Sender<PossibleDuplicateShred>,
        completed_data_sets_sender: Option<CompletedDataSetsSender>,
        retransmit_sender: EvictingSender<Vec<shred::Payload>>,
        accept_repairs_only: bool,
        mcp_reconstruction_sender: Option<McpReconstructionSender>,
        relay_keypair: Option<Arc<Keypair>>,
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
                let mut mcp_tracker = McpSlotTracker::default();
                // Create relay attestation service with default relay_id (0)
                // TODO: Wire in actual relay_id from schedule
                let mut relay_attestation_service = RelayAttestationService::new(
                    RelayAttestationConfig::default()
                );
                let mut last_print = Instant::now();
                while !exit.load(Ordering::Relaxed) {
                    if let Err(e) = run_insert(
                        &thread_pool,
                        &verified_receiver,
                        &blockstore,
                        &leader_schedule_cache,
                        handle_duplicate,
                        &mut metrics,
                        &mut ws_metrics,
                        completed_data_sets_sender.as_ref(),
                        &retransmit_sender,
                        &reed_solomon_cache,
                        accept_repairs_only,
                        &mut mcp_tracker,
                        mcp_reconstruction_sender.as_ref(),
                        &mut relay_attestation_service,
                        relay_keypair.as_ref(),
                    ) {
                        ws_metrics.record_error(&e);
                        if Self::should_exit_on_error(e, &handle_error) {
                            break;
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
        rand::Rng,
        solana_entry::entry::{create_ticks, Entry},
        solana_gossip::contact_info::ContactInfo,
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_ledger::{
            blockstore::{make_many_slot_entries, Blockstore},
            genesis_utils::create_genesis_config,
            get_tmp_ledger_path_auto_delete,
            shred::{ProcessShredsStats, Shredder},
        },
        solana_runtime::bank::Bank,
        solana_signer::Signer,
        solana_streamer::socket::SocketAddrSpace,
        solana_time_utils::timestamp,
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
