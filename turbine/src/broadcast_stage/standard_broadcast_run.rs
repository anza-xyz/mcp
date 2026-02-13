#![allow(clippy::rc_buffer)]

use {
    super::{
        broadcast_utils::{self, ReceiveResults},
        *,
    },
    crate::{cluster_nodes::ClusterNodesCache, mcp_proposer},
    agave_feature_set as feature_set,
    agave_transaction_view::{
        mcp_transaction::McpTransaction, transaction_view::SanitizedTransactionView,
    },
    crossbeam_channel::Sender,
    solana_entry::block_component::BlockComponent,
    solana_fee_structure::FeeBudgetLimits,
    solana_gossip::contact_info::Protocol,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::{
        blockstore_meta::BlockLocation,
        leader_schedule_cache::LeaderScheduleCache,
        mcp, mcp_ordering,
        shred::{
            ProcessShredsStats, ReedSolomonCache, Shred, ShredType, Shredder,
            MAX_CODE_SHREDS_PER_SLOT, MAX_DATA_SHREDS_PER_SLOT,
        },
    },
    solana_metrics::inc_new_counter_error,
    solana_pubkey::Pubkey,
    solana_runtime::bank::Bank,
    solana_runtime_transaction::{
        runtime_transaction::RuntimeTransaction, transaction_meta::StaticMeta,
    },
    solana_sha256_hasher::hashv,
    solana_time_utils::AtomicInterval,
    solana_transaction::{sanitized::MessageHash, versioned::VersionedTransaction},
    solana_votor::event::VotorEventSender,
    solana_votor_messages::migration::MigrationStatus,
    std::{
        borrow::Cow,
        collections::{HashMap, HashSet},
        sync::RwLock,
    },
    tokio::sync::mpsc::{error::TrySendError as AsyncTrySendError, Sender as AsyncSender},
};

#[derive(Clone)]
pub struct StandardBroadcastRun {
    identity: Pubkey,
    slot: Slot,
    parent: Slot,
    parent_block_id: Hash,
    chained_merkle_root: Hash,
    double_merkle_leaves: Vec<Hash>,
    carryover_entry: Option<WorkingBankEntryMarker>,
    next_shred_index: u32,
    next_code_index: u32,
    // If last_tick_height has reached bank.max_tick_height() for this slot
    // and so the slot is completed and all shreds are already broadcast.
    completed: bool,
    process_shreds_stats: ProcessShredsStats,
    transmit_shreds_stats: Arc<Mutex<SlotBroadcastStats<TransmitShredsStats>>>,
    insert_shreds_stats: Arc<Mutex<SlotBroadcastStats<InsertShredsStats>>>,
    slot_broadcast_start: Instant,
    shred_version: u16,
    last_datapoint_submit: Arc<AtomicInterval>,
    num_batches: usize,
    cluster_nodes_cache: Arc<ClusterNodesCache<BroadcastStage>>,
    reed_solomon_cache: Arc<ReedSolomonCache>,
    migration_status: Arc<MigrationStatus>,
    mcp_dispatch_state: Arc<Mutex<HashMap<Slot, McpSlotDispatchState>>>,
    mcp_leader_schedule_cache: Arc<Mutex<Option<LeaderScheduleCache>>>,
}

#[derive(Debug)]
enum BroadcastError {
    TooManyShreds,
}

#[derive(Clone)]
struct McpPayloadTransaction {
    wire_bytes: Vec<u8>,
    execution_class: mcp_ordering::ExecutionClass,
    ordering_fee: u64,
    signature: [u8; 64],
    fee_payer: Pubkey,
    base_fee: u64,
    target_proposer: Option<u32>,
}

struct McpSlotDispatchState {
    seen_batches: usize,
    expected_batches: Option<usize>,
    proposer_states: HashMap<u32, McpProposerDispatchState>,
}

struct McpProposerDispatchState {
    payload_transactions: Vec<McpPayloadTransaction>,
    payload_len_bytes: usize,
    payer_fee_reservations: HashMap<Pubkey, u64>,
    seen_signatures: HashSet<[u8; 64]>,
}

const MCP_DISPATCH_STATE_MAX_SLOTS: usize = 1024;
const MCP_DISPATCH_STATE_SLOT_RETENTION: Slot = 512;
const MCP_PAYLOAD_COUNT_PREFIX_BYTES: usize = std::mem::size_of::<u32>();
const MCP_PAYLOAD_LEN_PREFIX_BYTES: usize = std::mem::size_of::<u32>();

impl Default for McpSlotDispatchState {
    fn default() -> Self {
        Self {
            seen_batches: 0,
            expected_batches: None,
            proposer_states: HashMap::new(),
        }
    }
}

impl Default for McpProposerDispatchState {
    fn default() -> Self {
        Self {
            payload_transactions: Vec::new(),
            // tx_count prefix is always present in encoded payload.
            payload_len_bytes: MCP_PAYLOAD_COUNT_PREFIX_BYTES,
            payer_fee_reservations: HashMap::new(),
            seen_signatures: HashSet::new(),
        }
    }
}

impl McpSlotDispatchState {
    fn try_push_transaction(
        &mut self,
        proposer_index: u32,
        bank: &Bank,
        transaction: McpPayloadTransaction,
    ) -> bool {
        self.proposer_states
            .entry(proposer_index)
            .or_default()
            .try_push_transaction(bank, transaction)
    }
}

impl McpProposerDispatchState {
    fn try_push_transaction(&mut self, bank: &Bank, transaction: McpPayloadTransaction) -> bool {
        if self.seen_signatures.contains(&transaction.signature) {
            // Per-proposer dedup is by signature only.
            return true;
        }

        let Some(per_proposer_reservation) =
            transaction.base_fee.checked_mul(mcp::NUM_PROPOSERS as u64)
        else {
            inc_new_counter_error!("mcp-proposer-dispatch-fee-reservation-overflow", 1, 1);
            return true;
        };
        let current_reserved = self
            .payer_fee_reservations
            .get(&transaction.fee_payer)
            .copied()
            .unwrap_or_default();
        let Some(next_reserved) = current_reserved.checked_add(per_proposer_reservation) else {
            inc_new_counter_error!("mcp-proposer-dispatch-fee-reservation-overflow", 1, 1);
            return true;
        };
        if bank.get_balance(&transaction.fee_payer) < next_reserved {
            inc_new_counter_error!("mcp-proposer-dispatch-insufficient-funds", 1, 1);
            return true;
        }

        let Some(tx_wire_len) =
            MCP_PAYLOAD_LEN_PREFIX_BYTES.checked_add(transaction.wire_bytes.len())
        else {
            inc_new_counter_error!("mcp-proposer-dispatch-payload-reservation-overflow", 1, 1);
            return false;
        };
        let Some(next_payload_len) = self.payload_len_bytes.checked_add(tx_wire_len) else {
            inc_new_counter_error!("mcp-proposer-dispatch-payload-reservation-overflow", 1, 1);
            return false;
        };
        if next_payload_len > mcp_proposer::MCP_MAX_PAYLOAD_SIZE {
            inc_new_counter_error!("mcp-proposer-dispatch-payload-full", 1, 1);
            return false;
        }

        let signature = transaction.signature;
        let fee_payer = transaction.fee_payer;
        self.payload_transactions.push(transaction);
        self.payload_len_bytes = next_payload_len;
        self.payer_fee_reservations.insert(fee_payer, next_reserved);
        self.seen_signatures.insert(signature);
        true
    }
}

fn encode_mcp_payload(transactions: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    let tx_count = u32::try_from(transactions.len()).ok()?;
    let mut out = Vec::with_capacity(transactions.iter().try_fold(
        MCP_PAYLOAD_COUNT_PREFIX_BYTES,
        |acc, tx| {
            let tx_len_field = MCP_PAYLOAD_LEN_PREFIX_BYTES.checked_add(tx.len())?;
            acc.checked_add(tx_len_field)
        },
    )?);
    out.extend_from_slice(&tx_count.to_le_bytes());
    for tx in transactions {
        let tx_len = u32::try_from(tx.len()).ok()?;
        out.extend_from_slice(&tx_len.to_le_bytes());
        out.extend_from_slice(&tx);
    }
    Some(out)
}

impl StandardBroadcastRun {
    const MCP_DISPATCH_SEND_RETRY_LIMIT: usize = 3;

    fn mcp_payload_transaction_from_entry_tx(
        bank: &Bank,
        transaction: &VersionedTransaction,
    ) -> Option<McpPayloadTransaction> {
        let solana_wire_bytes = bincode::serialize(transaction).ok()?;

        if let Ok(mcp_transaction) = McpTransaction::from_bytes_compat(&solana_wire_bytes) {
            let wire_bytes = mcp_transaction.to_bytes();
            let mut signature = [0u8; 64];
            signature.copy_from_slice(mcp_transaction.signatures.first()?.as_ref());
            let fee_payer = *mcp_transaction.addresses.first()?;
            let signature_fee = u64::try_from(mcp_transaction.signatures.len())
                .ok()?
                .saturating_mul(bank.fee_structure().lamports_per_signature);
            let inclusion_fee = u64::from(mcp_transaction.inclusion_fee().unwrap_or_default());
            let ordering_fee = mcp_transaction.ordering_fee_with_fallback();
            let target_proposer = mcp_transaction.target_proposer();
            let base_fee = signature_fee
                .saturating_add(inclusion_fee)
                .saturating_add(ordering_fee);

            return Some(McpPayloadTransaction {
                wire_bytes,
                execution_class: mcp_ordering::ExecutionClass::Mcp,
                ordering_fee,
                signature,
                fee_payer,
                base_fee,
                target_proposer,
            });
        }

        let view =
            SanitizedTransactionView::try_new_sanitized(solana_wire_bytes.as_slice()).ok()?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(view.signatures().first()?.as_ref());
        let runtime_tx = RuntimeTransaction::<SanitizedTransactionView<_>>::try_from(
            view,
            MessageHash::Compute,
            None,
        )
        .ok()?;
        let ordering_fee = runtime_tx
            .compute_budget_instruction_details()
            .requested_compute_unit_price();
        let prioritization_fee = runtime_tx
            .compute_budget_instruction_details()
            .sanitize_and_convert_to_compute_budget_limits(&bank.feature_set)
            .ok()
            .map(|limits| u64::from(FeeBudgetLimits::from(limits).prioritization_fee))
            .unwrap_or_default();
        let signature_fee = runtime_tx
            .signature_details()
            .total_signatures()
            .saturating_mul(bank.fee_structure().lamports_per_signature);
        let base_fee = signature_fee.saturating_add(prioritization_fee);
        let fee_payer = *transaction.message.static_account_keys().first()?;

        Some(McpPayloadTransaction {
            wire_bytes: solana_wire_bytes,
            execution_class: mcp_ordering::ExecutionClass::Legacy,
            ordering_fee,
            signature,
            fee_payer,
            base_fee,
            target_proposer: None,
        })
    }

    fn order_mcp_payload_transactions(transactions: Vec<McpPayloadTransaction>) -> Vec<Vec<u8>> {
        mcp_ordering::order_batches_mcp_policy(
            vec![(0u32, transactions)],
            |tx| tx.execution_class,
            |tx| tx.ordering_fee,
            |tx| tx.signature,
        )
        .into_iter()
        .map(|tx| tx.wire_bytes)
        .collect()
    }

    pub(super) fn new(
        identity: Pubkey,
        shred_version: u16,
        migration_status: Arc<MigrationStatus>,
    ) -> Self {
        let cluster_nodes_cache = Arc::new(ClusterNodesCache::<BroadcastStage>::new(
            CLUSTER_NODES_CACHE_NUM_EPOCH_CAP,
            CLUSTER_NODES_CACHE_TTL,
        ));
        Self {
            identity,
            slot: Slot::MAX,
            parent: Slot::MAX,
            parent_block_id: Hash::default(),
            chained_merkle_root: Hash::default(),
            double_merkle_leaves: vec![],
            carryover_entry: None,
            next_shred_index: 0,
            next_code_index: 0,
            completed: true,
            process_shreds_stats: ProcessShredsStats::default(),
            transmit_shreds_stats: Arc::default(),
            insert_shreds_stats: Arc::default(),
            slot_broadcast_start: Instant::now(),
            shred_version,
            last_datapoint_submit: Arc::default(),
            num_batches: 0,
            cluster_nodes_cache,
            reed_solomon_cache: Arc::<ReedSolomonCache>::default(),
            migration_status,
            mcp_dispatch_state: Arc::default(),
            mcp_leader_schedule_cache: Arc::default(),
        }
    }

    /// Upon receipt of shreds from a new bank (bank.slot() != self.slot)
    /// reinitialize any necessary state and stats.
    fn reinitialize_state(
        &mut self,
        blockstore: &Blockstore,
        bank: &Bank,
        process_stats: &mut ProcessShredsStats,
    ) {
        debug_assert_ne!(bank.slot(), self.slot);

        let chained_merkle_root = if self.slot == bank.parent_slot() {
            self.chained_merkle_root
        } else {
            broadcast_utils::get_chained_merkle_root_from_parent(
                bank.slot(),
                bank.parent_slot(),
                blockstore,
            )
            .unwrap_or_else(|err: Error| {
                error!("Unknown chained Merkle root: {err:?}");
                process_stats.err_unknown_chained_merkle_root += 1;
                Hash::default()
            })
        };

        let parent_block_id = bank.parent_block_id().unwrap_or_else(|| {
            // Once SIMD-0333 is active, we can just hard unwrap here.
            error!(
                "Parent block id missing for slot {} parent {}",
                bank.slot(),
                bank.parent_slot()
            );
            process_stats.err_unknown_parent_block_id += 1;
            Hash::default()
        });

        self.slot = bank.slot();
        self.parent = bank.parent_slot();
        self.parent_block_id = parent_block_id;
        self.chained_merkle_root = chained_merkle_root;
        self.double_merkle_leaves.clear();
        self.next_shred_index = 0u32;
        self.next_code_index = 0u32;
        self.completed = false;
        self.slot_broadcast_start = Instant::now();
        self.num_batches = 0;

        process_stats.receive_elapsed = 0;
        process_stats.coalesce_elapsed = 0;
    }

    // If the current slot has changed, generates an empty shred indicating
    // last shred in the previous slot, along with coding shreds for the data
    // shreds buffered.
    fn finish_prev_slot(
        &mut self,
        keypair: &Keypair,
        max_ticks_in_slot: u8,
        stats: &mut ProcessShredsStats,
    ) -> Vec<Shred> {
        if self.completed {
            return vec![];
        }
        // Set the reference_tick as if the PoH completed for this slot
        let reference_tick = max_ticks_in_slot;
        let shreds: Vec<_> =
            Shredder::new(self.slot, self.parent, reference_tick, self.shred_version)
                .unwrap()
                .make_merkle_shreds_from_entries(
                    keypair,
                    &[],  // entries
                    true, // is_last_in_slot,
                    Some(self.chained_merkle_root),
                    self.next_shred_index,
                    self.next_code_index,
                    &self.reed_solomon_cache,
                    stats,
                )
                .inspect(|shred| stats.record_shred(shred))
                .collect();
        if let Some(shred) = shreds.iter().max_by_key(|shred| shred.fec_set_index()) {
            self.chained_merkle_root = shred.merkle_root().unwrap();
        }
        self.report_and_reset_stats(/*was_interrupted:*/ true);
        self.completed = true;
        shreds
    }

    #[allow(clippy::too_many_arguments)]
    fn component_to_shreds(
        &mut self,
        keypair: &Keypair,
        component: &BlockComponent,
        reference_tick: u8,
        is_slot_end: bool,
        process_stats: &mut ProcessShredsStats,
        max_data_shreds_per_slot: u32,
        max_code_shreds_per_slot: u32,
    ) -> std::result::Result<Vec<Shred>, BroadcastError> {
        let shreds: Vec<_> =
            Shredder::new(self.slot, self.parent, reference_tick, self.shred_version)
                .unwrap()
                .make_merkle_shreds_from_component(
                    keypair,
                    component,
                    is_slot_end,
                    Some(self.chained_merkle_root),
                    self.next_shred_index,
                    self.next_code_index,
                    &self.reed_solomon_cache,
                    process_stats,
                )
                .inspect(|shred| {
                    process_stats.record_shred(shred);
                    let next_index = match shred.shred_type() {
                        ShredType::Code => &mut self.next_code_index,
                        ShredType::Data => &mut self.next_shred_index,
                    };
                    *next_index = (*next_index).max(shred.index() + 1);
                })
                .collect();

        let fec_set_roots = shreds
            .iter()
            .unique_by(|shred| shred.fec_set_index())
            .sorted_unstable_by_key(|shred| shred.fec_set_index())
            .map(|shred| shred.merkle_root().expect("no more legacy shreds"));
        // If necessary for perf, these leaves could start being joined in the background
        self.double_merkle_leaves.extend(fec_set_roots);

        if let Some(fec_set_root) = self.double_merkle_leaves.last() {
            self.chained_merkle_root = *fec_set_root;
        }
        if self.next_shred_index > max_data_shreds_per_slot {
            return Err(BroadcastError::TooManyShreds);
        }
        if self.next_code_index > max_code_shreds_per_slot {
            return Err(BroadcastError::TooManyShreds);
        }
        Ok(shreds)
    }

    #[cfg(test)]
    fn test_process_receive_results(
        &mut self,
        keypair: &Keypair,
        cluster_info: &ClusterInfo,
        sock: &UdpSocket,
        blockstore: &Blockstore,
        receive_results: ReceiveResults,
        bank_forks: &RwLock<BankForks>,
        quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
    ) -> Result<()> {
        let (bsend, brecv) = unbounded();
        let (ssend, srecv) = unbounded();
        let (cbsend, _cbrecv) = unbounded();
        self.process_receive_results(
            keypair,
            blockstore,
            &ssend,
            &bsend,
            &cbsend,
            receive_results,
            &mut ProcessShredsStats::default(),
        )?;
        // Data and coding shreds are sent in a single batch.
        let _ = self.transmit(
            &srecv,
            cluster_info,
            BroadcastSocket::Udp(sock),
            bank_forks,
            quic_endpoint_sender,
        );
        let _ = self.record(&brecv, blockstore);
        Ok(())
    }

    fn process_receive_results(
        &mut self,
        keypair: &Keypair,
        blockstore: &Blockstore,
        socket_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        blockstore_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        votor_event_sender: &VotorEventSender,
        receive_results: ReceiveResults,
        process_stats: &mut ProcessShredsStats,
    ) -> Result<()> {
        let num_entries = match &receive_results.component {
            BlockComponent::EntryBatch(entries) => entries.len(),
            BlockComponent::BlockMarker(_) => 0,
        };
        let bank = receive_results.bank.clone();
        let last_tick_height = receive_results.last_tick_height;
        inc_new_counter_info!("broadcast_service-entries_received", num_entries);

        let mut to_shreds_time = Measure::start("broadcast_to_shreds");

        let send_header = if self.slot != bank.slot() {
            // Finish previous slot if it was interrupted.
            if !self.completed {
                let shreds =
                    self.finish_prev_slot(keypair, bank.ticks_per_slot() as u8, process_stats);
                debug_assert!(shreds.iter().all(|shred| shred.slot() == self.slot));
                // Broadcast shreds for the interrupted slot.
                let batch_info = Some(BroadcastShredBatchInfo {
                    slot: self.slot,
                    num_expected_batches: Some(self.num_batches + 1),
                    slot_start_ts: self.slot_broadcast_start,
                    was_interrupted: true,
                });
                let shreds = Arc::new(shreds);
                socket_sender.send((shreds.clone(), batch_info.clone()))?;
                blockstore_sender.send((shreds, batch_info))?;
            }
            // If blockstore already has shreds for this slot,
            // it should not recreate the slot:
            // https://github.com/solana-labs/solana/blob/92a0b310c/ledger/src/leader_schedule_cache.rs##L139-L148
            if blockstore
                .meta(bank.slot())
                .unwrap()
                .filter(|slot_meta| slot_meta.received > 0 || slot_meta.consumed > 0)
                .is_some()
            {
                process_stats.num_extant_slots += 1;
                // This is a faulty situation that should not happen.
                // Refrain from generating shreds for the slot.
                return Err(Error::DuplicateSlotBroadcast(bank.slot()));
            }

            // Reinitialize state for this slot.
            self.reinitialize_state(blockstore, &bank, process_stats);

            self.migration_status.is_alpenglow_enabled()
        } else {
            false
        };

        // 2) Convert entries to shreds and coding shreds
        let is_last_in_slot = last_tick_height == bank.max_tick_height();
        // Calculate how many ticks have already occurred in this slot, the
        // possible range of values is [0, bank.ticks_per_slot()]
        let reference_tick = last_tick_height
            .saturating_add(bank.ticks_per_slot())
            .saturating_sub(bank.max_tick_height());

        let mut header_shreds = if send_header {
            let header = produce_block_header(self.parent, self.parent_block_id);
            self.component_to_shreds(
                keypair,
                &BlockComponent::BlockMarker(header),
                reference_tick as u8,
                false,
                process_stats,
                MAX_DATA_SHREDS_PER_SLOT as u32,
                MAX_CODE_SHREDS_PER_SLOT as u32,
            )
            .unwrap()
        } else {
            vec![]
        };

        let component_shreds = self
            .component_to_shreds(
                keypair,
                &receive_results.component,
                reference_tick as u8,
                is_last_in_slot,
                process_stats,
                MAX_DATA_SHREDS_PER_SLOT as u32,
                MAX_CODE_SHREDS_PER_SLOT as u32,
            )
            .unwrap();

        let shreds = if send_header {
            header_shreds.extend_from_slice(&component_shreds);
            header_shreds
        } else {
            component_shreds
        };

        // Insert the first data shred synchronously so that blockstore stores
        // that the leader started this block. This must be done before the
        // blocks are sent out over the wire, so that the slots we have already
        // sent a shred for are skipped (even if the node reboots):
        // https://github.com/solana-labs/solana/blob/92a0b310c/ledger/src/leader_schedule_cache.rs#L139-L148
        // preventing the node from broadcasting duplicate blocks:
        // https://github.com/solana-labs/solana/blob/92a0b310c/turbine/src/broadcast_stage/standard_broadcast_run.rs#L132-L142
        // By contrast Self::insert skips the 1st data shred with index zero:
        // https://github.com/solana-labs/solana/blob/92a0b310c/turbine/src/broadcast_stage/standard_broadcast_run.rs#L367-L373
        if let Some(shred) = shreds.iter().find(|shred| shred.is_data()) {
            if shred.index() == 0 {
                blockstore
                    .insert_cow_shreds(
                        [Cow::Borrowed(shred)],
                        None, // leader_schedule
                        true, // is_trusted
                    )
                    .expect("Failed to insert shreds in blockstore");
            }
        }
        to_shreds_time.stop();

        let mut get_leader_schedule_time = Measure::start("broadcast_get_leader_schedule");
        // Data and coding shreds are sent in a single batch.
        self.num_batches += 1;
        let num_expected_batches = is_last_in_slot.then_some(self.num_batches);
        let batch_info = Some(BroadcastShredBatchInfo {
            slot: bank.slot(),
            num_expected_batches,
            slot_start_ts: self.slot_broadcast_start,
            was_interrupted: false,
        });
        get_leader_schedule_time.stop();

        let mut coding_send_time = Measure::start("broadcast_coding_send");
        self.maybe_record_mcp_payload_batch(
            &bank,
            &receive_results.component,
            num_expected_batches,
        );

        let shreds = Arc::new(shreds);
        debug_assert!(shreds.iter().all(|shred| shred.slot() == bank.slot()));
        socket_sender.send((shreds.clone(), batch_info.clone()))?;
        blockstore_sender.send((shreds, batch_info))?;

        coding_send_time.stop();

        process_stats.shredding_elapsed = to_shreds_time.as_us();
        process_stats.get_leader_schedule_elapsed = get_leader_schedule_time.as_us();
        process_stats.coding_send_elapsed = coding_send_time.as_us();

        self.process_shreds_stats += *process_stats;

        if last_tick_height == bank.max_tick_height() {
            self.report_and_reset_stats(false);
            self.completed = true;

            // Populate the block id and send for voting
            let block_id = if self
                .migration_status
                .should_use_double_merkle_block_id(bank.slot())
            {
                // Block id is the double merkle root
                let fec_set_count = self.double_merkle_leaves.len();
                // Add the final leaf (parent info)
                let parent_info_leaf =
                    hashv(&[&self.parent.to_le_bytes(), self.parent_block_id.as_ref()]);
                self.double_merkle_leaves.push(parent_info_leaf);
                // Future perf improvement, the blockstore insert can happen async
                blockstore.build_and_insert_double_merkle_meta(
                    bank.slot(),
                    BlockLocation::Original,
                    fec_set_count,
                    self.double_merkle_leaves.drain(..).map(Ok),
                )
            } else {
                // The block id is the merkle root of the last FEC set which is now the chained merkle root
                self.chained_merkle_root
            };

            broadcast_utils::set_block_id_and_send(
                &self.migration_status,
                votor_event_sender,
                bank.clone(),
                block_id,
            )?;
        }

        Ok(())
    }

    fn insert(
        &mut self,
        blockstore: &Blockstore,
        shreds: Arc<Vec<Shred>>,
        broadcast_shred_batch_info: Option<BroadcastShredBatchInfo>,
    ) {
        // Insert shreds into blockstore
        let insert_shreds_start = Instant::now();
        // The first data shred is inserted synchronously.
        // https://github.com/solana-labs/solana/blob/92a0b310c/turbine/src/broadcast_stage/standard_broadcast_run.rs#L268-L283
        let offset = shreds
            .first()
            .map(|shred| shred.is_data() && shred.index() == 0)
            .map(usize::from)
            .unwrap_or_default();
        let num_shreds = shreds.len();
        let shreds = shreds.iter().skip(offset).map(Cow::Borrowed);
        blockstore
            .insert_cow_shreds(
                shreds, /*leader_schedule:*/ None, /*is_trusted:*/ true,
            )
            .expect("Failed to insert shreds in blockstore");
        let insert_shreds_elapsed = insert_shreds_start.elapsed();
        let new_insert_shreds_stats = InsertShredsStats {
            insert_shreds_elapsed: insert_shreds_elapsed.as_micros() as u64,
            num_shreds,
        };
        self.update_insertion_metrics(&new_insert_shreds_stats, &broadcast_shred_batch_info);
    }

    fn update_insertion_metrics(
        &mut self,
        new_insertion_shreds_stats: &InsertShredsStats,
        broadcast_shred_batch_info: &Option<BroadcastShredBatchInfo>,
    ) {
        let mut insert_shreds_stats = self.insert_shreds_stats.lock().unwrap();
        insert_shreds_stats.update(new_insertion_shreds_stats, broadcast_shred_batch_info);
    }

    fn broadcast(
        &mut self,
        sock: BroadcastSocket,
        cluster_info: &ClusterInfo,
        shreds: &Arc<Vec<Shred>>,
        broadcast_shred_batch_info: Option<BroadcastShredBatchInfo>,
        bank_forks: &RwLock<BankForks>,
        quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
    ) -> Result<()> {
        trace!("Broadcasting {:?} shreds", shreds.len());
        let mut transmit_stats = TransmitShredsStats::default();
        // Broadcast the shreds
        let mut transmit_time = Measure::start("broadcast_shreds");

        transmit_stats.num_shreds = shreds.len();

        broadcast_shreds(
            sock,
            &shreds,
            &self.cluster_nodes_cache,
            &self.last_datapoint_submit,
            &mut transmit_stats,
            cluster_info,
            bank_forks,
            cluster_info.socket_addr_space(),
            quic_endpoint_sender,
        )?;
        transmit_time.stop();

        transmit_stats.transmit_elapsed = transmit_time.as_us();

        // Process metrics
        self.update_transmit_metrics(&transmit_stats, &broadcast_shred_batch_info);
        Ok(())
    }

    fn update_transmit_metrics(
        &mut self,
        new_transmit_shreds_stats: &TransmitShredsStats,
        broadcast_shred_batch_info: &Option<BroadcastShredBatchInfo>,
    ) {
        let mut transmit_shreds_stats = self.transmit_shreds_stats.lock().unwrap();
        transmit_shreds_stats.update(new_transmit_shreds_stats, broadcast_shred_batch_info);
    }

    fn report_and_reset_stats(&mut self, was_interrupted: bool) {
        let (name, slot_broadcast_time) = if was_interrupted {
            ("broadcast-process-shreds-interrupted-stats", None)
        } else {
            (
                "broadcast-process-shreds-stats",
                Some(self.slot_broadcast_start.elapsed()),
            )
        };

        self.process_shreds_stats.submit(
            name,
            self.slot,
            self.next_shred_index, // num_data_shreds
            self.next_code_index,  // num_coding_shreds
            slot_broadcast_time,
        );
    }

    fn maybe_record_mcp_payload_batch(
        &self,
        bank: &Bank,
        component: &BlockComponent,
        num_expected_batches: Option<usize>,
    ) {
        if !bank
            .feature_set
            .activated_slot(&feature_set::mcp_protocol_v1::id())
            .is_some_and(|activated_slot| bank.slot() >= activated_slot)
        {
            return;
        }

        let proposer_indices = LeaderScheduleCache::new_from_bank(bank).proposer_indices_at_slot(
            bank.slot(),
            &self.identity,
            Some(bank),
        );
        if proposer_indices.is_empty() {
            return;
        }

        let mut state = self.mcp_dispatch_state.lock().unwrap();
        let min_retained_slot = bank
            .slot()
            .saturating_sub(MCP_DISPATCH_STATE_SLOT_RETENTION);
        state.retain(|tracked_slot, _| *tracked_slot >= min_retained_slot);
        if state.len() >= MCP_DISPATCH_STATE_MAX_SLOTS && !state.contains_key(&bank.slot()) {
            if let Some(oldest_slot) = state.keys().min().copied() {
                state.remove(&oldest_slot);
            }
        }
        let slot_state = state.entry(bank.slot()).or_default();
        slot_state.seen_batches = slot_state.seen_batches.saturating_add(1);
        if let Some(expected_batches) = num_expected_batches {
            slot_state.expected_batches = Some(expected_batches);
        }
        let BlockComponent::EntryBatch(entries) = component else {
            return;
        };
        for entry in entries {
            for tx in &entry.transactions {
                let Some(payload_transaction) =
                    Self::mcp_payload_transaction_from_entry_tx(bank, tx)
                else {
                    warn!(
                        "MCP proposer payload metadata extraction failed for slot {}",
                        bank.slot()
                    );
                    continue;
                };
                if let Some(target_proposer) = payload_transaction.target_proposer {
                    if proposer_indices.contains(&target_proposer) {
                        let _ = slot_state.try_push_transaction(
                            target_proposer,
                            bank,
                            payload_transaction,
                        );
                    }
                    continue;
                }

                for proposer_index in proposer_indices.iter().copied() {
                    let _ = slot_state.try_push_transaction(
                        proposer_index,
                        bank,
                        payload_transaction.clone(),
                    );
                }
            }
        }
    }

    fn maybe_dispatch_mcp_shreds(
        &self,
        batch_info: &Option<BroadcastShredBatchInfo>,
        cluster_info: &ClusterInfo,
        bank_forks: &RwLock<BankForks>,
        sock: BroadcastSocket,
        quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
    ) {
        enum McpRelayTarget {
            Quic(SocketAddr),
            Udp(SocketAddr),
        }

        let Some(batch_info) = batch_info else {
            // Retransmit batches have no slot metadata and are not MCP proposer outputs.
            return;
        };
        let slot = batch_info.slot;
        let (feature_active, working_bank, root_bank, root_slot) = {
            let bank_forks = bank_forks.read().unwrap();
            let bank = bank_forks
                .get(slot)
                .unwrap_or_else(|| bank_forks.root_bank());
            let feature_active = bank
                .feature_set
                .activated_slot(&feature_set::mcp_protocol_v1::id())
                .is_some_and(|activated_slot| slot >= activated_slot);
            (
                feature_active,
                bank,
                bank_forks.root_bank(),
                bank_forks.root(),
            )
        };
        if !feature_active {
            return;
        }

        let identity = cluster_info.id();
        let (proposer_indices, relay_schedule) = {
            let mut cache = self.mcp_leader_schedule_cache.lock().unwrap();
            let cache = cache.get_or_insert_with(|| LeaderScheduleCache::new_from_bank(&root_bank));
            cache.set_root(&root_bank);
            (
                cache.proposer_indices_at_slot(slot, &identity, Some(&working_bank)),
                cache.relays_at_slot(slot, Some(&working_bank)),
            )
        };
        if proposer_indices.is_empty() {
            return;
        }

        let maybe_ordered_payloads_by_proposer = {
            let mut state = self.mcp_dispatch_state.lock().unwrap();
            let min_retained_slot = root_slot.saturating_sub(MCP_DISPATCH_STATE_SLOT_RETENTION);
            state.retain(|tracked_slot, _| *tracked_slot >= min_retained_slot);
            let Some(slot_state) = state.get(&slot) else {
                return;
            };
            let is_slot_complete = slot_state
                .expected_batches
                .map(|num_expected_batches| slot_state.seen_batches >= num_expected_batches)
                .unwrap_or(false);
            if is_slot_complete {
                state.remove(&slot).map(|slot_state| {
                    slot_state
                        .proposer_states
                        .into_iter()
                        .map(|(proposer_index, proposer_state)| {
                            (
                                proposer_index,
                                Self::order_mcp_payload_transactions(
                                    proposer_state.payload_transactions,
                                ),
                            )
                        })
                        .collect::<HashMap<_, _>>()
                })
            } else {
                None
            }
        };
        let Some(mut ordered_payloads_by_proposer) = maybe_ordered_payloads_by_proposer else {
            return;
        };

        let relay_schedule = match relay_schedule {
            Some(relays) => relays,
            None => {
                warn!("MCP proposer dispatch skipped for slot {slot}: relay schedule unavailable");
                return;
            }
        };
        if relay_schedule.len() != mcp_proposer::MCP_NUM_RELAYS {
            warn!(
                "MCP proposer dispatch skipped for slot {}: expected {} relay indices, got {}",
                slot,
                mcp_proposer::MCP_NUM_RELAYS,
                relay_schedule.len(),
            );
            return;
        }

        let relay_targets: Vec<_> = relay_schedule
            .into_iter()
            .map(|relay_pubkey| {
                cluster_info
                    .lookup_contact_info(&relay_pubkey, |node| {
                        if relay_pubkey == identity {
                            node.tvu(Protocol::UDP)
                                .map(McpRelayTarget::Udp)
                                .or_else(|| node.tvu(Protocol::QUIC).map(McpRelayTarget::Quic))
                        } else {
                            node.tvu(Protocol::QUIC).map(McpRelayTarget::Quic)
                        }
                    })
                    .flatten()
            })
            .collect();
        let available = relay_targets.iter().filter(|addr| addr.is_some()).count();
        if available == 0 {
            warn!(
                "MCP proposer dispatch skipped for slot {}: none of {} scheduled relays have reachable TVU addresses",
                slot,
                mcp_proposer::MCP_NUM_RELAYS,
            );
            return;
        }
        if available < mcp_proposer::MCP_NUM_RELAYS {
            warn!(
                "MCP proposer dispatch slot {}: {} of {} scheduled relays have reachable TVU addresses",
                slot,
                available,
                mcp_proposer::MCP_NUM_RELAYS,
            );
        }

        let proposer_keypair = {
            let keypair = cluster_info.keypair();
            Arc::clone(&*keypair)
        };
        for proposer_index in proposer_indices {
            let payload_transactions = ordered_payloads_by_proposer
                .remove(&proposer_index)
                .unwrap_or_default();
            let Some(payload_bytes) = encode_mcp_payload(payload_transactions) else {
                warn!(
                    "MCP proposer dispatch skipped for slot {} proposer {}: invalid payload framing",
                    slot, proposer_index
                );
                continue;
            };
            let shred_payloads = match mcp_proposer::encode_payload_to_mcp_shreds(&payload_bytes) {
                Ok(shreds) => shreds,
                Err(err) => {
                    warn!(
                        "MCP proposer dispatch skipped for slot {} proposer {}: {}",
                        slot, proposer_index, err
                    );
                    continue;
                }
            };
            let messages = match mcp_proposer::build_shred_messages(
                slot,
                proposer_index,
                &shred_payloads,
                proposer_keypair.as_ref(),
            ) {
                Ok(messages) => messages,
                Err(err) => {
                    warn!("MCP proposer dispatch skipped for slot {slot}: {err}");
                    continue;
                }
            };
            for (relay_target, message) in relay_targets.iter().zip(messages.iter()) {
                let Some(relay_target) = relay_target else {
                    continue;
                };
                let (send_ok, relay_addr) = match relay_target {
                    McpRelayTarget::Quic(relay_addr) => (
                        Self::try_send_mcp_dispatch_message(
                            quic_endpoint_sender,
                            *relay_addr,
                            Bytes::copy_from_slice(message),
                        ),
                        relay_addr,
                    ),
                    McpRelayTarget::Udp(relay_addr) => (
                        Self::try_send_mcp_dispatch_message_udp(sock, *relay_addr, message),
                        relay_addr,
                    ),
                };
                if !send_ok {
                    inc_new_counter_error!("mcp-proposer-dispatch-send-dropped", 1, 1);
                    warn!(
                        "MCP proposer dispatch dropped send for slot {} to {}",
                        slot, relay_addr
                    );
                }
            }
        }
    }

    fn try_send_mcp_dispatch_message(
        quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
        relay_addr: SocketAddr,
        bytes: Bytes,
    ) -> bool {
        let mut send_item = (relay_addr, bytes);
        for attempt in 0..=Self::MCP_DISPATCH_SEND_RETRY_LIMIT {
            match quic_endpoint_sender.try_send(send_item) {
                Ok(()) => return true,
                Err(AsyncTrySendError::Closed(_)) => return false,
                Err(AsyncTrySendError::Full(returned)) => {
                    if attempt == Self::MCP_DISPATCH_SEND_RETRY_LIMIT {
                        return false;
                    }
                    send_item = returned;
                    let backoff_micros = 50u64.saturating_mul((attempt + 1) as u64);
                    std::thread::sleep(std::time::Duration::from_micros(backoff_micros));
                }
            }
        }
        false
    }

    fn try_send_mcp_dispatch_message_udp(
        sock: BroadcastSocket,
        relay_addr: SocketAddr,
        bytes: &[u8],
    ) -> bool {
        match sock {
            BroadcastSocket::Udp(sock) => sock.send_to(bytes, relay_addr).is_ok(),
            BroadcastSocket::Xdp(_) => false,
        }
    }
}

impl BroadcastRun for StandardBroadcastRun {
    fn run(
        &mut self,
        keypair: &Keypair,
        blockstore: &Blockstore,
        receiver: &Receiver<WorkingBankEntryMarker>,
        socket_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        blockstore_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        votor_event_sender: &VotorEventSender,
    ) -> Result<()> {
        let mut process_stats = ProcessShredsStats::default();
        let receive_results = broadcast_utils::recv_slot_entries(
            receiver,
            &mut self.carryover_entry,
            &mut process_stats,
        )?;
        // TODO: Confirm that last chunk of coding shreds
        // will not be lost or delayed for too long.
        self.process_receive_results(
            keypair,
            blockstore,
            socket_sender,
            blockstore_sender,
            votor_event_sender,
            receive_results,
            &mut process_stats,
        )
    }
    fn transmit(
        &mut self,
        receiver: &TransmitReceiver,
        cluster_info: &ClusterInfo,
        sock: BroadcastSocket,
        bank_forks: &RwLock<BankForks>,
        quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
    ) -> Result<()> {
        let (shreds, batch_info) = receiver.recv()?;
        self.broadcast(
            sock,
            cluster_info,
            &shreds,
            batch_info.clone(),
            bank_forks,
            quic_endpoint_sender,
        )?;
        self.maybe_dispatch_mcp_shreds(
            &batch_info,
            cluster_info,
            bank_forks,
            sock,
            quic_endpoint_sender,
        );
        Ok(())
    }
    fn record(&mut self, receiver: &RecordReceiver, blockstore: &Blockstore) -> Result<()> {
        let (shreds, slot_start_ts) = receiver.recv()?;
        self.insert(blockstore, shreds, slot_start_ts);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        rand::Rng,
        solana_account::{AccountSharedData, WritableAccount},
        solana_entry::entry::create_ticks,
        solana_genesis_config::GenesisConfig,
        solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_ledger::{
            blockstore::{Blockstore, BlockstoreError},
            genesis_utils::{create_genesis_config, create_genesis_config_with_leader},
            get_tmp_ledger_path,
            shred::{max_ticks_per_n_shreds, DATA_SHREDS_PER_FEC_BLOCK},
        },
        solana_net_utils::sockets::bind_to_localhost_unique,
        solana_runtime::bank::Bank,
        solana_signer::Signer,
        solana_streamer::socket::SocketAddrSpace,
        std::{
            ops::Deref,
            sync::Arc,
            time::{Duration, Instant},
        },
        test_case::test_case,
    };

    #[allow(clippy::type_complexity)]
    fn setup_with_mcp_feature(
        num_shreds_per_slot: Slot,
        mcp_feature_active: bool,
    ) -> (
        Arc<Blockstore>,
        GenesisConfig,
        Arc<ClusterInfo>,
        Arc<Bank>,
        Arc<Keypair>,
        UdpSocket,
        Arc<RwLock<BankForks>>,
    ) {
        // Setup
        let ledger_path = get_tmp_ledger_path!();
        let blockstore = Arc::new(
            Blockstore::open(&ledger_path).expect("Expected to be able to open database ledger"),
        );
        let leader_keypair = Arc::new(Keypair::new());
        let leader_pubkey = leader_keypair.pubkey();
        let leader_info = ContactInfo::new_localhost(&leader_pubkey, 0);
        let cluster_info = Arc::new(ClusterInfo::new(
            leader_info,
            leader_keypair.clone(),
            SocketAddrSpace::Unspecified,
        ));
        let socket = bind_to_localhost_unique().expect("should bind");
        let mut genesis_config = create_genesis_config(10_000).genesis_config;
        genesis_config.ticks_per_slot = max_ticks_per_n_shreds(num_shreds_per_slot, None) + 1;

        let mut bank = Bank::new_for_tests(&genesis_config);
        if mcp_feature_active {
            bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        }
        let bank_forks = BankForks::new_rw_arc(bank);
        let bank0 = bank_forks.read().unwrap().root_bank();
        (
            blockstore,
            genesis_config,
            cluster_info,
            bank0,
            leader_keypair,
            socket,
            bank_forks,
        )
    }

    #[allow(clippy::type_complexity)]
    fn setup(
        num_shreds_per_slot: Slot,
    ) -> (
        Arc<Blockstore>,
        GenesisConfig,
        Arc<ClusterInfo>,
        Arc<Bank>,
        Arc<Keypair>,
        UdpSocket,
        Arc<RwLock<BankForks>>,
    ) {
        setup_with_mcp_feature(num_shreds_per_slot, false)
    }

    fn make_payload_tx(
        wire_len: usize,
        signature_byte: u8,
        fee_payer: Pubkey,
        base_fee: u64,
        ordering_fee: u64,
    ) -> McpPayloadTransaction {
        McpPayloadTransaction {
            wire_bytes: vec![signature_byte; wire_len],
            execution_class: mcp_ordering::ExecutionClass::Legacy,
            ordering_fee,
            signature: [signature_byte; 64],
            fee_payer,
            base_fee,
            target_proposer: None,
        }
    }

    #[test]
    fn test_encode_mcp_payload_frames_transactions() {
        let tx0 = vec![1u8, 2, 3];
        let tx1 = vec![4u8, 5];
        let payload = encode_mcp_payload(vec![tx0.clone(), tx1.clone()]).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&(2u32).to_le_bytes());
        expected.extend_from_slice(&(tx0.len() as u32).to_le_bytes());
        expected.extend_from_slice(&tx0);
        expected.extend_from_slice(&(tx1.len() as u32).to_le_bytes());
        expected.extend_from_slice(&tx1);
        assert_eq!(payload, expected);
    }

    #[test]
    fn test_slot_dispatch_state_enforces_payload_bound_with_framing_overhead() {
        let bank = Arc::new(Bank::new_for_tests(
            &create_genesis_config(10_000).genesis_config,
        ));
        let mut state = McpSlotDispatchState::default();
        let max_size_tx = make_payload_tx(
            mcp_proposer::MCP_MAX_PAYLOAD_SIZE,
            1,
            Pubkey::new_unique(),
            0,
            0,
        );
        assert!(!state.try_push_transaction(0, bank.as_ref(), max_size_tx));

        let valid = make_payload_tx(
            mcp_proposer::MCP_MAX_PAYLOAD_SIZE - 8,
            2,
            Pubkey::new_unique(),
            0,
            0,
        );
        assert!(state.try_push_transaction(0, bank.as_ref(), valid));
    }

    #[test]
    fn test_slot_dispatch_state_dedups_by_signature() {
        let bank = Arc::new(Bank::new_for_tests(
            &create_genesis_config(10_000).genesis_config,
        ));
        let mut state = McpSlotDispatchState::default();
        let fee_payer = Pubkey::new_unique();

        let first = make_payload_tx(16, 7, fee_payer, 0, 0);
        assert!(state.try_push_transaction(0, bank.as_ref(), first));
        let duplicate = make_payload_tx(32, 7, fee_payer, 0, 100);
        assert!(state.try_push_transaction(0, bank.as_ref(), duplicate));

        assert_eq!(
            state
                .proposer_states
                .get(&0)
                .unwrap()
                .payload_transactions
                .len(),
            1
        );
    }

    #[test]
    fn test_slot_dispatch_state_requires_num_proposers_fee_reservation() {
        let bank = Arc::new(Bank::new_for_tests(
            &create_genesis_config(10_000).genesis_config,
        ));
        let fee_payer = Pubkey::new_unique();
        let mut account = AccountSharedData::new(0, 0, &Pubkey::default());
        account.set_lamports((mcp::NUM_PROPOSERS as u64).saturating_sub(1));
        bank.store_account(&fee_payer, &account);

        let mut state = McpSlotDispatchState::default();
        let rejected = make_payload_tx(16, 3, fee_payer, 1, 0);
        assert!(state.try_push_transaction(0, bank.as_ref(), rejected));
        assert!(state
            .proposer_states
            .get(&0)
            .map_or(true, |state| state.payload_transactions.is_empty()));

        account.set_lamports(mcp::NUM_PROPOSERS as u64);
        bank.store_account(&fee_payer, &account);
        let accepted = make_payload_tx(16, 4, fee_payer, 1, 0);
        assert!(state.try_push_transaction(0, bank.as_ref(), accepted));
        assert_eq!(
            state
                .proposer_states
                .get(&0)
                .unwrap()
                .payload_transactions
                .len(),
            1
        );
    }

    #[test]
    fn test_slot_dispatch_state_dedups_within_each_proposer_only() {
        let bank = Arc::new(Bank::new_for_tests(
            &create_genesis_config(10_000).genesis_config,
        ));
        let mut state = McpSlotDispatchState::default();
        let fee_payer = Pubkey::new_unique();

        let first = make_payload_tx(16, 7, fee_payer, 0, 0);
        let duplicate = make_payload_tx(32, 7, fee_payer, 0, 0);
        assert!(state.try_push_transaction(0, bank.as_ref(), first.clone()));
        assert!(state.try_push_transaction(0, bank.as_ref(), duplicate));
        assert!(state.try_push_transaction(1, bank.as_ref(), first));

        assert_eq!(
            state
                .proposer_states
                .get(&0)
                .unwrap()
                .payload_transactions
                .len(),
            1
        );
        assert_eq!(
            state
                .proposer_states
                .get(&1)
                .unwrap()
                .payload_transactions
                .len(),
            1
        );
    }

    #[test]
    fn test_order_mcp_payload_transactions_uses_b2_policy() {
        let fee_payer = Pubkey::new_unique();
        let ordered = StandardBroadcastRun::order_mcp_payload_transactions(vec![
            make_payload_tx(1, 9, fee_payer, 0, 1),
            make_payload_tx(1, 1, fee_payer, 0, 7),
            make_payload_tx(1, 2, fee_payer, 0, 7),
        ]);

        // Higher ordering_fee first, then signature bytes ascending for ties.
        assert_eq!(ordered, vec![vec![1u8], vec![2u8], vec![9u8]]);
    }

    #[test]
    fn test_maybe_dispatch_mcp_shreds_removes_complete_slot_payload_state() {
        let leader_keypair = Arc::new(Keypair::new());
        let mut leader_info = ContactInfo::new_localhost(&leader_keypair.pubkey(), 0);
        // Force QUIC-only relay targets so dispatch fanout is observable via
        // the QUIC endpoint channel in this unit test.
        leader_info.remove_tvu();
        let relay_tvu_quic = bind_to_localhost_unique().expect("should bind");
        let relay_tvu_quic_addr = relay_tvu_quic.local_addr().expect("should have local addr");
        drop(relay_tvu_quic);
        leader_info
            .set_tvu(Protocol::QUIC, relay_tvu_quic_addr)
            .expect("should set QUIC TVU address");
        let cluster_info = Arc::new(ClusterInfo::new(
            leader_info,
            leader_keypair.clone(),
            SocketAddrSpace::Unspecified,
        ));
        let mut genesis_config =
            create_genesis_config_with_leader(10_000, &leader_keypair.pubkey(), 1_000)
                .genesis_config;
        genesis_config.ticks_per_slot =
            max_ticks_per_n_shreds(DATA_SHREDS_PER_FEC_BLOCK as u64, None) + 1;
        let mut bank = Bank::new_for_tests(&genesis_config);
        bank.activate_feature(&feature_set::mcp_protocol_v1::id());
        let bank_forks = BankForks::new_rw_arc(bank);
        let bank = bank_forks.read().unwrap().root_bank();
        let (quic_endpoint_sender, mut quic_endpoint_receiver) =
            tokio::sync::mpsc::channel(/*capacity:*/ 4096);
        let dispatch_socket = bind_to_localhost_unique().expect("should bind");

        let standard_broadcast_run = StandardBroadcastRun::new(
            leader_keypair.pubkey(),
            0,
            Arc::new(MigrationStatus::post_migration_status()),
        );
        let mut slot_state = McpSlotDispatchState::default();
        slot_state.seen_batches = 1;
        slot_state.expected_batches = Some(1);
        assert!(slot_state.try_push_transaction(
            0,
            bank.as_ref(),
            make_payload_tx(4, 5, Pubkey::new_unique(), 0, 0),
        ));
        standard_broadcast_run
            .mcp_dispatch_state
            .lock()
            .unwrap()
            .insert(bank.slot(), slot_state);

        let batch_info = Some(BroadcastShredBatchInfo {
            slot: bank.slot(),
            num_expected_batches: Some(1),
            slot_start_ts: Instant::now(),
            was_interrupted: false,
        });
        standard_broadcast_run.maybe_dispatch_mcp_shreds(
            &batch_info,
            &cluster_info,
            &bank_forks,
            BroadcastSocket::Udp(&dispatch_socket),
            &quic_endpoint_sender,
        );

        assert!(standard_broadcast_run
            .mcp_dispatch_state
            .lock()
            .unwrap()
            .get(&bank.slot())
            .is_none());

        let expected_dispatch_count = {
            let cache = LeaderScheduleCache::new_from_bank(bank.as_ref());
            let proposer_indices =
                cache.proposer_indices_at_slot(bank.slot(), &leader_keypair.pubkey(), Some(&bank));
            let relay_schedule = cache
                .relays_at_slot(bank.slot(), Some(&bank))
                .expect("relay schedule should be available when MCP feature is active");
            let quic_targets = relay_schedule
                .iter()
                .filter(|relay_pubkey| **relay_pubkey == leader_keypair.pubkey())
                .count();
            proposer_indices.len() * quic_targets
        };
        assert!(expected_dispatch_count > 0);

        let mut dispatch_count = 0usize;
        while quic_endpoint_receiver.try_recv().is_ok() {
            dispatch_count += 1;
        }
        assert_eq!(dispatch_count, expected_dispatch_count);
    }

    #[test]
    fn test_try_send_mcp_dispatch_message_succeeds_when_channel_has_capacity() {
        let (quic_endpoint_sender, mut quic_endpoint_receiver) =
            tokio::sync::mpsc::channel(/*capacity:*/ 1);
        let relay_addr = "127.0.0.1:1234".parse().unwrap();
        let payload = Bytes::from_static(&[1u8, 2, 3]);

        assert!(StandardBroadcastRun::try_send_mcp_dispatch_message(
            &quic_endpoint_sender,
            relay_addr,
            payload.clone(),
        ));

        let (received_addr, received_payload) = quic_endpoint_receiver.try_recv().unwrap();
        assert_eq!(received_addr, relay_addr);
        assert_eq!(received_payload, payload);
    }

    #[test]
    fn test_try_send_mcp_dispatch_message_retries_then_fails_on_full_channel() {
        let (quic_endpoint_sender, mut quic_endpoint_receiver) =
            tokio::sync::mpsc::channel(/*capacity:*/ 1);
        let first_addr = "127.0.0.1:1234".parse().unwrap();
        let first_payload = Bytes::from_static(&[7u8]);
        quic_endpoint_sender
            .try_send((first_addr, first_payload.clone()))
            .unwrap();

        let second_addr = "127.0.0.1:5678".parse().unwrap();
        let second_payload = Bytes::from_static(&[9u8]);
        assert!(!StandardBroadcastRun::try_send_mcp_dispatch_message(
            &quic_endpoint_sender,
            second_addr,
            second_payload,
        ));

        // The original queued message remains intact when retries are exhausted.
        let (received_addr, received_payload) = quic_endpoint_receiver.try_recv().unwrap();
        assert_eq!(received_addr, first_addr);
        assert_eq!(received_payload, first_payload);
    }

    #[test]
    fn test_try_send_mcp_dispatch_message_fails_when_channel_closed() {
        let (quic_endpoint_sender, quic_endpoint_receiver) = tokio::sync::mpsc::channel(1);
        drop(quic_endpoint_receiver);

        assert!(!StandardBroadcastRun::try_send_mcp_dispatch_message(
            &quic_endpoint_sender,
            "127.0.0.1:1234".parse().unwrap(),
            Bytes::from_static(&[1u8]),
        ));
    }

    #[test_case(MigrationStatus::default(); "pre_migration")]
    #[test_case(MigrationStatus::post_migration_status(); "post_migration")]
    fn test_interrupted_slot_last_shred(migration_status: MigrationStatus) {
        let keypair = Arc::new(Keypair::new());
        let mut run = StandardBroadcastRun::new(keypair.pubkey(), 0, Arc::new(migration_status));
        assert!(run.completed);

        // Set up the slot to be interrupted
        let next_shred_index = 10;
        let slot = 1;
        let parent = 0;
        run.chained_merkle_root = Hash::new_from_array(rand::thread_rng().gen());
        run.next_shred_index = next_shred_index;
        run.next_code_index = 17;
        run.slot = slot;
        run.parent = parent;
        run.completed = false;
        run.slot_broadcast_start = Instant::now();

        // Slot 2 interrupted slot 1
        let shreds = run.finish_prev_slot(
            &keypair,
            0, // max_ticks_in_slot
            &mut ProcessShredsStats::default(),
        );
        assert!(run.completed);
        let shred = shreds
            .first()
            .expect("Expected a shred that signals an interrupt");

        // Validate the shred
        assert_eq!(shred.parent().unwrap(), parent);
        assert_eq!(shred.slot(), slot);
        assert_eq!(shred.index(), next_shred_index);
        assert!(shred.is_data());
        assert!(shred.verify(&keypair.pubkey()));
    }

    #[test_case(MigrationStatus::default(); "pre_migration")]
    #[test_case(MigrationStatus::post_migration_status(); "post_migration")]
    fn test_slot_interrupt(migration_status: MigrationStatus) {
        // Setup
        let num_shreds_per_slot = DATA_SHREDS_PER_FEC_BLOCK as u64;
        let (blockstore, genesis_config, cluster_info, bank0, leader_keypair, socket, bank_forks) =
            setup(num_shreds_per_slot);
        let (quic_endpoint_sender, _quic_endpoint_receiver) =
            tokio::sync::mpsc::channel(/*capacity:*/ 128);

        // Insert 1 less than the number of ticks needed to finish the slot
        let ticks0 = create_ticks(genesis_config.ticks_per_slot - 1, 0, genesis_config.hash());
        let receive_results = ReceiveResults {
            component: BlockComponent::EntryBatch(ticks0.clone()),
            bank: bank0.clone(),
            last_tick_height: (ticks0.len() - 1) as u64,
        };

        let is_alpenglow_enabled = migration_status.is_alpenglow_enabled();
        let block_header_shreds = if is_alpenglow_enabled {
            DATA_SHREDS_PER_FEC_BLOCK as u64
        } else {
            0
        };

        // Step 1: Make an incomplete transmission for slot 0
        let mut standard_broadcast_run =
            StandardBroadcastRun::new(leader_keypair.pubkey(), 0, Arc::new(migration_status));
        standard_broadcast_run
            .test_process_receive_results(
                &leader_keypair,
                &cluster_info,
                &socket,
                &blockstore,
                receive_results,
                &bank_forks,
                &quic_endpoint_sender,
            )
            .unwrap();
        // Since this is a new slot, it includes both header shreds and component shreds
        assert_eq!(
            standard_broadcast_run.next_shred_index as u64,
            num_shreds_per_slot + block_header_shreds
        );
        assert_eq!(standard_broadcast_run.slot, 0);
        assert_eq!(standard_broadcast_run.parent, 0);
        // Make sure the slot is not complete
        assert!(!blockstore.is_full(0));
        // Modify the stats, should reset later
        standard_broadcast_run.process_shreds_stats.receive_elapsed = 10;
        // Broadcast stats should exist, and 1 batch should have been sent,
        // for both data and coding shreds.
        assert_eq!(
            standard_broadcast_run
                .transmit_shreds_stats
                .lock()
                .unwrap()
                .get(standard_broadcast_run.slot)
                .unwrap()
                .num_batches(),
            1
        );
        assert_eq!(
            standard_broadcast_run
                .insert_shreds_stats
                .lock()
                .unwrap()
                .get(standard_broadcast_run.slot)
                .unwrap()
                .num_batches(),
            1
        );
        // Try to fetch ticks from blockstore, nothing should break
        assert_eq!(blockstore.get_slot_entries(0, 0).unwrap(), ticks0);
        // When alpenglow is enabled, include block header shreds
        assert_eq!(
            blockstore
                .get_slot_entries(0, num_shreds_per_slot + block_header_shreds)
                .unwrap(),
            vec![],
        );

        // Step 2: Make a transmission for another bank that interrupts the transmission for
        // slot 0
        let bank2 = Arc::new(Bank::new_from_parent(bank0, &leader_keypair.pubkey(), 2));
        let interrupted_slot = standard_broadcast_run.slot;
        // Interrupting the slot should cause the unfinished_slot and stats to reset
        let num_shreds = 1;
        assert!(num_shreds < num_shreds_per_slot);
        let ticks1 = create_ticks(
            max_ticks_per_n_shreds(num_shreds, None),
            0,
            genesis_config.hash(),
        );
        let receive_results = ReceiveResults {
            component: BlockComponent::EntryBatch(ticks1.clone()),
            bank: bank2,
            last_tick_height: (ticks1.len() - 1) as u64,
        };
        standard_broadcast_run
            .test_process_receive_results(
                &leader_keypair,
                &cluster_info,
                &socket,
                &blockstore,
                receive_results,
                &bank_forks,
                &quic_endpoint_sender,
            )
            .unwrap();

        // The shred index should have reset to 0, which makes it possible for the
        // index < the previous shred index for slot 0
        // Since this is a new slot, it includes both header shreds and component shreds
        assert_eq!(
            standard_broadcast_run.next_shred_index as usize,
            DATA_SHREDS_PER_FEC_BLOCK
                + if is_alpenglow_enabled {
                    DATA_SHREDS_PER_FEC_BLOCK
                } else {
                    0
                }
        );
        assert_eq!(standard_broadcast_run.slot, 2);
        assert_eq!(standard_broadcast_run.parent, 0);

        // Check that the stats were reset as well
        assert_eq!(
            standard_broadcast_run.process_shreds_stats.receive_elapsed,
            0
        );

        // Broadcast stats for interrupted slot should be cleared
        assert!(standard_broadcast_run
            .transmit_shreds_stats
            .lock()
            .unwrap()
            .get(interrupted_slot)
            .is_none());
        assert!(standard_broadcast_run
            .insert_shreds_stats
            .lock()
            .unwrap()
            .get(interrupted_slot)
            .is_none());

        // Try to fetch the incomplete ticks from blockstore; this should error out.
        let actual = blockstore.get_slot_entries(0, 0);
        assert!(actual.is_err());
        assert!(matches!(
            actual.unwrap_err(),
            BlockstoreError::InvalidShredData(_)
        ));

        let actual = blockstore.get_slot_entries(0, num_shreds_per_slot);
        assert!(actual.is_err());
        assert!(matches!(
            actual.unwrap_err(),
            BlockstoreError::InvalidShredData(_)
        ));
    }

    #[test_case(MigrationStatus::default(); "pre_migration")]
    #[test_case(MigrationStatus::post_migration_status(); "post_migration")]
    fn test_buffer_data_shreds(migration_status: MigrationStatus) {
        let num_shreds_per_slot = 2;
        let (blockstore, genesis_config, _cluster_info, bank, leader_keypair, _socket, _bank_forks) =
            setup(num_shreds_per_slot);
        let (bsend, brecv) = unbounded();
        let (ssend, _srecv) = unbounded();
        let (cbsend, _) = unbounded();
        let mut last_tick_height = 0;
        let mut standard_broadcast_run =
            StandardBroadcastRun::new(leader_keypair.pubkey(), 0, Arc::new(migration_status));
        let mut process_ticks = |num_ticks| {
            let ticks = create_ticks(num_ticks, 0, genesis_config.hash());
            last_tick_height += (ticks.len() - 1) as u64;
            let receive_results = ReceiveResults {
                component: BlockComponent::EntryBatch(ticks),
                bank: bank.clone(),
                last_tick_height,
            };
            standard_broadcast_run
                .process_receive_results(
                    &leader_keypair,
                    &blockstore,
                    &ssend,
                    &bsend,
                    &cbsend,
                    receive_results,
                    &mut ProcessShredsStats::default(),
                )
                .unwrap();
        };
        for i in 0..3 {
            process_ticks((i + 1) * 100);
        }
        let mut shreds = Vec::<Shred>::new();
        while let Ok((recv_shreds, _)) = brecv.recv_timeout(Duration::from_secs(1)) {
            shreds.extend(recv_shreds.deref().clone());
        }
        // At least as many coding shreds as data shreds.
        assert!(shreds.len() >= DATA_SHREDS_PER_FEC_BLOCK * 2);
        assert_eq!(
            shreds.iter().filter(|shred| shred.is_data()).count(),
            shreds.len() / 2
        );
        process_ticks(75);
        while let Ok((recv_shreds, _)) = brecv.recv_timeout(Duration::from_secs(1)) {
            shreds.extend(recv_shreds.deref().clone());
        }
        assert!(shreds.len() >= DATA_SHREDS_PER_FEC_BLOCK * 2);
        assert_eq!(
            shreds.iter().filter(|shred| shred.is_data()).count(),
            shreds.len() / 2
        );
    }

    #[test_case(MigrationStatus::default(); "pre_migration")]
    #[test_case(MigrationStatus::post_migration_status(); "post_migration")]
    fn test_slot_finish(migration_status: MigrationStatus) {
        // Setup
        let num_shreds_per_slot = 2;
        let (blockstore, genesis_config, cluster_info, bank0, leader_keypair, socket, bank_forks) =
            setup(num_shreds_per_slot);
        let (quic_endpoint_sender, _quic_endpoint_receiver) =
            tokio::sync::mpsc::channel(/*capacity:*/ 128);

        // Insert complete slot of ticks needed to finish the slot
        let ticks = create_ticks(genesis_config.ticks_per_slot, 0, genesis_config.hash());
        let receive_results = ReceiveResults {
            component: BlockComponent::EntryBatch(ticks.clone()),
            bank: bank0,
            last_tick_height: ticks.len() as u64,
        };

        let mut standard_broadcast_run =
            StandardBroadcastRun::new(leader_keypair.pubkey(), 0, Arc::new(migration_status));
        standard_broadcast_run
            .test_process_receive_results(
                &leader_keypair,
                &cluster_info,
                &socket,
                &blockstore,
                receive_results,
                &bank_forks,
                &quic_endpoint_sender,
            )
            .unwrap();
        assert!(standard_broadcast_run.completed)
    }

    #[test_case(MigrationStatus::default(); "pre_migration")]
    #[test_case(MigrationStatus::post_migration_status(); "post_migration")]
    fn entries_to_shreds_max(migration_status: MigrationStatus) {
        agave_logger::setup();
        let keypair = Keypair::new();
        let mut bs = StandardBroadcastRun::new(keypair.pubkey(), 0, Arc::new(migration_status));
        bs.slot = 1;
        bs.parent = 0;
        let entries = create_ticks(10_000, 1, solana_hash::Hash::default());

        let mut stats = ProcessShredsStats::default();

        let (data, coding) = bs
            .component_to_shreds(
                &keypair,
                &BlockComponent::EntryBatch(entries[0..entries.len() - 2].to_vec()),
                0,
                false,
                &mut stats,
                1000,
                1000,
            )
            .unwrap()
            .into_iter()
            .partition::<Vec<_>, _>(Shred::is_data);
        info!("{} {}", data.len(), coding.len());
        assert!(!data.is_empty());
        assert!(!coding.is_empty());

        let r = bs.component_to_shreds(
            &keypair,
            &BlockComponent::EntryBatch(entries),
            0,
            false,
            &mut stats,
            10,
            10,
        );
        info!("{r:?}");
        assert_matches!(r, Err(BroadcastError::TooManyShreds));
    }
}
