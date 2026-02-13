//! The `shred_fetch_stage` pulls shreds from UDP sockets and sends it to a channel.

use {
    crate::{
        mcp_relay_submit::MCP_CONTROL_MSG_RELAY_ATTESTATION,
        repair::{repair_service::OutstandingShredRepairs, serve_repair::ServeRepair},
    },
    agave_feature_set::FeatureSet,
    bytes::Bytes,
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender, TrySendError},
    itertools::Itertools,
    solana_clock::{Slot, DEFAULT_MS_PER_SLOT},
    solana_epoch_schedule::EpochSchedule,
    solana_gossip::cluster_info::ClusterInfo,
    solana_keypair::Keypair,
    solana_ledger::shred::{
        self, mcp_shred::is_mcp_shred_bytes, should_discard_shred, ShredFetchStats,
    },
    solana_metrics::inc_new_counter_error,
    solana_packet::{Meta, PACKET_DATA_SIZE},
    solana_perf::packet::{
        BytesPacket, BytesPacketBatch, PacketBatch, PacketBatchRecycler, PacketFlags, PacketRef,
    },
    solana_pubkey::Pubkey,
    solana_runtime::bank_forks::BankForks,
    solana_streamer::{
        evicting_sender::EvictingSender,
        streamer::{self, ChannelSend, PacketBatchReceiver, StreamerReceiveStats},
    },
    std::{
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

// When running with very short epochs (e.g. for testing), we want to avoid
// filtering out shreds that we actually need. This value was chosen empirically
// because it's large enough to protect against observed short epoch problems
// while being small enough to keep the overhead small on deduper, blockstore,
// etc.
const MAX_SHRED_DISTANCE_MINIMUM: u64 = 500;
const MCP_CONTROL_MSG_CONSENSUS_BLOCK: u8 = 0x02;

pub(crate) struct ShredFetchStage {
    thread_hdls: Vec<JoinHandle<()>>,
}

/// Ingress limit for the shred fetch channel (in terms of packet _batches_).
///
/// The general case sees shred and repair ingress in the hundreds of packet batches per second.
/// However, in the case of catch-up, we may see upwards of 8k packet batches per second, which would
/// suggest a roughly 16k packet batch limit for ample headroom. We're setting it to 4x that amount
/// to future proof for increases of CU limits (e.g., a future 100k CU limit).
pub(crate) const SHRED_FETCH_CHANNEL_SIZE: usize = 1024 * 64;

#[derive(Clone)]
struct RepairContext {
    repair_socket: Arc<UdpSocket>,
    cluster_info: Arc<ClusterInfo>,
    outstanding_repair_requests: Arc<RwLock<OutstandingShredRepairs>>,
}

impl ShredFetchStage {
    // updates packets received on a channel and sends them on another channel
    fn modify_packets(
        recvr: PacketBatchReceiver,
        recvr_stats: Option<Arc<StreamerReceiveStats>>,
        sendr: EvictingSender<PacketBatch>,
        bank_forks: &RwLock<BankForks>,
        shred_version: u16,
        name: &'static str,
        flags: PacketFlags,
        repair_context: Option<&RepairContext>,
        turbine_disabled: Arc<AtomicBool>,
    ) {
        // Only repair shreds need repair context.
        debug_assert_eq!(
            flags.contains(PacketFlags::REPAIR),
            repair_context.is_some()
        );
        const STATS_SUBMIT_CADENCE: Duration = Duration::from_secs(1);
        let mut last_updated = Instant::now();
        let mut keypair = repair_context.as_ref().copied().map(RepairContext::keypair);
        let (
            mut last_root,
            mut slots_per_epoch,
            mut feature_set,
            mut epoch_schedule,
            mut last_slot,
        ) = {
            let bank_forks_r = bank_forks.read().unwrap();
            let root_bank = bank_forks_r.root_bank();
            (
                root_bank.slot(),
                root_bank.get_slots_in_epoch(root_bank.epoch()),
                root_bank.feature_set.clone(),
                root_bank.epoch_schedule().clone(),
                bank_forks_r.highest_slot(),
            )
        };
        let mut stats = ShredFetchStats::default();

        for mut packet_batch in recvr {
            if last_updated.elapsed().as_millis() as u64 > DEFAULT_MS_PER_SLOT {
                last_updated = Instant::now();
                let root_bank = {
                    let bank_forks_r = bank_forks.read().unwrap();
                    last_slot = bank_forks_r.highest_slot();
                    bank_forks_r.root_bank()
                };
                feature_set = root_bank.feature_set.clone();
                epoch_schedule = root_bank.epoch_schedule().clone();
                last_root = root_bank.slot();
                slots_per_epoch = root_bank.get_slots_in_epoch(root_bank.epoch());
                keypair = repair_context.as_ref().copied().map(RepairContext::keypair);
            }
            stats.shred_count += packet_batch.len();

            if let Some(repair_context) = repair_context {
                debug_assert_eq!(flags, PacketFlags::REPAIR);
                debug_assert!(keypair.is_some());
                if let Some(ref keypair) = keypair {
                    ServeRepair::handle_repair_response_pings(
                        &repair_context.repair_socket,
                        keypair,
                        &mut packet_batch,
                        &mut stats,
                    );
                }
                // Discard packets if repair nonce does not verify.
                let now = solana_time_utils::timestamp();
                let mut outstanding_repair_requests =
                    repair_context.outstanding_repair_requests.write().unwrap();
                packet_batch
                    .iter_mut()
                    .filter(|packet| !packet.meta().discard())
                    .for_each(|mut packet| {
                        // Have to set repair flag here so that the nonce is
                        // taken off the shred's payload.
                        packet.meta_mut().flags |= PacketFlags::REPAIR;
                        if !verify_repair_nonce(
                            packet.as_ref(),
                            now,
                            &mut outstanding_repair_requests,
                        ) {
                            packet.meta_mut().set_discard(true);
                        }
                    });
            }

            // Filter out shreds that are way too far in the future to avoid the
            // overhead of having to hold onto them.
            let max_slot = last_slot + MAX_SHRED_DISTANCE_MINIMUM.max(2 * slots_per_epoch);
            let turbine_disabled = turbine_disabled.load(Ordering::Relaxed);
            for mut packet in packet_batch.iter_mut().filter(|p| !p.meta().discard()) {
                let preserve_mcp_packet =
                    is_active_mcp_shred_packet(packet.as_ref(), &feature_set, &epoch_schedule);
                if turbine_disabled
                    || (!preserve_mcp_packet
                        && should_discard_shred(
                            packet.as_ref(),
                            last_root,
                            max_slot,
                            shred_version,
                            &mut stats,
                        ))
                {
                    packet.meta_mut().set_discard(true);
                } else {
                    packet.meta_mut().flags.insert(flags);
                }
            }
            if stats.maybe_submit(name, STATS_SUBMIT_CADENCE) {
                if let Some(stats) = recvr_stats.as_ref() {
                    stats.report();
                }
            }
            if let Err(send_err) = sendr.try_send(packet_batch) {
                match send_err {
                    crossbeam_channel::TrySendError::Full(v) => {
                        stats.overflow_shreds += v.len();
                    }
                    _ => unreachable!("EvictingSender holds on to both ends of the channel"),
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn packet_modifier(
        receiver_thread_name: &'static str,
        modifier_thread_name: &'static str,
        sockets: Vec<Arc<UdpSocket>>,
        exit: Arc<AtomicBool>,
        sender: EvictingSender<PacketBatch>,
        recycler: PacketBatchRecycler,
        bank_forks: Arc<RwLock<BankForks>>,
        shred_version: u16,
        name: &'static str,
        receiver_name: &'static str,
        flags: PacketFlags,
        repair_context: Option<RepairContext>,
        turbine_disabled: Arc<AtomicBool>,
    ) -> (Vec<JoinHandle<()>>, JoinHandle<()>) {
        let (packet_sender, packet_receiver) =
            EvictingSender::new_bounded(SHRED_FETCH_CHANNEL_SIZE);
        let receiver_stats = Arc::new(StreamerReceiveStats::new(receiver_name));
        let streamers = sockets
            .into_iter()
            .enumerate()
            .map(|(i, socket)| {
                streamer::receiver(
                    format!("{receiver_thread_name}{i:02}"),
                    socket,
                    exit.clone(),
                    packet_sender.clone(),
                    recycler.clone(),
                    receiver_stats.clone(),
                    Some(Duration::from_millis(5)), // coalesce
                    true,                           // use_pinned_memory
                    None,                           // in_vote_only_mode
                    false,                          // is_staked_service
                )
            })
            .collect();
        let modifier_hdl = Builder::new()
            .name(modifier_thread_name.to_string())
            .spawn(move || {
                Self::modify_packets(
                    packet_receiver,
                    Some(receiver_stats),
                    sender,
                    &bank_forks,
                    shred_version,
                    name,
                    flags,
                    repair_context.as_ref(),
                    turbine_disabled,
                )
            })
            .unwrap();
        (streamers, modifier_hdl)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        sockets: Vec<Arc<UdpSocket>>,
        turbine_quic_endpoint_receiver: Receiver<(Pubkey, SocketAddr, Bytes)>,
        mcp_control_message_sender: Option<Sender<(Pubkey, SocketAddr, Bytes)>>,
        repair_response_quic_receiver: Receiver<(Pubkey, SocketAddr, Bytes)>,
        repair_socket: Arc<UdpSocket>,
        sender: EvictingSender<PacketBatch>,
        shred_version: u16,
        bank_forks: Arc<RwLock<BankForks>>,
        cluster_info: Arc<ClusterInfo>,
        outstanding_repair_requests: Arc<RwLock<OutstandingShredRepairs>>,
        turbine_disabled: Arc<AtomicBool>,
        exit: Arc<AtomicBool>,
    ) -> Self {
        let recycler = PacketBatchRecycler::warmed(100, 1024);
        let repair_context = RepairContext {
            repair_socket: repair_socket.clone(),
            cluster_info,
            outstanding_repair_requests,
        };

        let (mut tvu_threads, tvu_filter) = Self::packet_modifier(
            "solRcvrShred",
            "solTvuPktMod",
            sockets,
            exit.clone(),
            sender.clone(),
            recycler.clone(),
            bank_forks.clone(),
            shred_version,
            "shred_fetch",
            "shred_fetch_receiver",
            PacketFlags::empty(),
            None, // repair_context
            turbine_disabled.clone(),
        );

        let (repair_receiver, repair_handler) = Self::packet_modifier(
            "solRcvrShredRep",
            "solTvuRepPktMod",
            vec![repair_socket],
            exit.clone(),
            sender.clone(),
            recycler.clone(),
            bank_forks.clone(),
            shred_version,
            "shred_fetch_repair",
            "shred_fetch_repair_receiver",
            PacketFlags::REPAIR,
            Some(repair_context.clone()),
            turbine_disabled.clone(),
        );

        tvu_threads.extend(repair_receiver);
        tvu_threads.push(tvu_filter);
        tvu_threads.push(repair_handler);
        // Repair shreds fetched over QUIC protocol.
        {
            let (packet_sender, packet_receiver) = unbounded();
            let bank_forks = bank_forks.clone();
            let exit = exit.clone();
            let sender = sender.clone();
            let turbine_disabled = turbine_disabled.clone();
            tvu_threads.extend([
                Builder::new()
                    .name("solTvuRecvRpr".to_string())
                    .spawn(|| {
                        receive_quic_datagrams(
                            repair_response_quic_receiver,
                            PacketFlags::REPAIR,
                            packet_sender,
                            exit,
                            None,
                        )
                    })
                    .unwrap(),
                Builder::new()
                    .name("solTvuFetchRpr".to_string())
                    .spawn(move || {
                        Self::modify_packets(
                            packet_receiver,
                            None,
                            sender,
                            &bank_forks,
                            shred_version,
                            "shred_fetch_repair_quic",
                            PacketFlags::REPAIR,
                            // No ping packets but need to verify repair nonce.
                            Some(&repair_context),
                            turbine_disabled,
                        )
                    })
                    .unwrap(),
            ]);
        }
        // Turbine shreds fetched over QUIC protocol.
        let (packet_sender, packet_receiver) = unbounded();
        tvu_threads.extend([
            Builder::new()
                .name("solTvuRecvQuic".to_string())
                .spawn(|| {
                    receive_quic_datagrams(
                        turbine_quic_endpoint_receiver,
                        PacketFlags::empty(),
                        packet_sender,
                        exit,
                        mcp_control_message_sender,
                    )
                })
                .unwrap(),
            Builder::new()
                .name("solTvuFetchQuic".to_string())
                .spawn(move || {
                    Self::modify_packets(
                        packet_receiver,
                        None,
                        sender,
                        &bank_forks,
                        shred_version,
                        "shred_fetch_quic",
                        PacketFlags::empty(),
                        None, // repair_context
                        turbine_disabled,
                    )
                })
                .unwrap(),
        ]);
        Self {
            thread_hdls: tvu_threads,
        }
    }

    pub(crate) fn join(self) -> thread::Result<()> {
        for thread_hdl in self.thread_hdls {
            thread_hdl.join()?;
        }
        Ok(())
    }
}

impl RepairContext {
    fn keypair(&self) -> Arc<Keypair> {
        self.cluster_info.keypair().clone()
    }
}

// Returns false if repair nonce is invalid and packet should be discarded.
#[must_use]
fn verify_repair_nonce(
    packet: PacketRef,
    now: u64, // solana_time_utils::timestamp()
    outstanding_repair_requests: &mut OutstandingShredRepairs,
) -> bool {
    debug_assert!(packet.meta().flags.contains(PacketFlags::REPAIR));
    let Some((shred, nonce)) = shred::layout::get_shred_and_repair_nonce(packet) else {
        return false;
    };
    match nonce {
        Some(nonce) => outstanding_repair_requests
            .register_response(nonce, shred, now, |_| ())
            .is_some(),
        None if is_mcp_shred_bytes(shred) => outstanding_repair_requests
            .register_response_without_nonce(shred, now, |_| ())
            .is_some(),
        None => false,
    }
}

fn is_active_mcp_shred_packet(
    packet: PacketRef,
    feature_set: &FeatureSet,
    epoch_schedule: &EpochSchedule,
) -> bool {
    let Some(data) = packet.data(..) else {
        return false;
    };
    if !is_mcp_shred_bytes(data) {
        return false;
    }
    let Ok(slot_bytes) =
        <[u8; std::mem::size_of::<Slot>()]>::try_from(&data[..std::mem::size_of::<Slot>()])
    else {
        return false;
    };
    check_feature_activation(
        &agave_feature_set::mcp_protocol_v1::id(),
        Slot::from_le_bytes(slot_bytes),
        feature_set,
        epoch_schedule,
    )
}

pub(crate) fn receive_quic_datagrams(
    quic_datagrams_receiver: Receiver<(Pubkey, SocketAddr, Bytes)>,
    flags: PacketFlags,
    sender: Sender<PacketBatch>,
    exit: Arc<AtomicBool>,
    mcp_control_message_sender: Option<Sender<(Pubkey, SocketAddr, Bytes)>>,
) {
    const RECV_TIMEOUT: Duration = Duration::from_secs(1);
    const PACKET_COALESCE_DURATION: Duration = Duration::from_millis(1);
    while !exit.load(Ordering::Relaxed) {
        let entry = match quic_datagrams_receiver.recv_timeout(RECV_TIMEOUT) {
            Ok(entry) => entry,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let deadline = Instant::now() + PACKET_COALESCE_DURATION;
        let entries = std::iter::once(entry).chain(
            std::iter::repeat_with(|| quic_datagrams_receiver.recv_deadline(deadline).ok())
                .while_some(),
        );
        let packet_batch: BytesPacketBatch = entries
            .filter_map(|(pubkey, addr, bytes)| {
                if matches!(
                    bytes.first().copied(),
                    Some(MCP_CONTROL_MSG_RELAY_ATTESTATION | MCP_CONTROL_MSG_CONSENSUS_BLOCK)
                ) {
                    if let Some(sender) = mcp_control_message_sender.as_ref() {
                        match sender.try_send((pubkey, addr, bytes)) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                inc_new_counter_error!(
                                    "shred_fetch_stage-mcp_control_message_channel_full",
                                    1
                                );
                                return None;
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                inc_new_counter_error!(
                                    "shred_fetch_stage-mcp_control_message_channel_disconnected",
                                    1
                                );
                                return None;
                            }
                        }
                    }
                    return None;
                }

                if bytes.len() > PACKET_DATA_SIZE {
                    return None;
                }

                let meta = Meta {
                    size: bytes.len(),
                    addr: addr.ip(),
                    port: addr.port(),
                    flags,
                };
                Some(BytesPacket::new(bytes, meta))
            })
            .collect();
        if !packet_batch.is_empty() && sender.send(packet_batch.into()).is_err() {
            return; // The receiver end of the channel is disconnected.
        }
    }
}

// Returns true if the feature is effective for the shred slot.
#[must_use]
#[allow(dead_code)]
fn check_feature_activation(
    feature: &Pubkey,
    shred_slot: Slot,
    feature_set: &FeatureSet,
    epoch_schedule: &EpochSchedule,
) -> bool {
    let _ = epoch_schedule;
    match feature_set.activated_slot(feature) {
        None => false,
        Some(feature_slot) => shred_slot >= feature_slot,
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::repair::serve_repair::ShredRepairType,
        crossbeam_channel::unbounded,
        solana_ledger::shred::mcp_shred::{
            McpShred, MCP_SHRED_DATA_BYTES, MCP_SHRED_WIRE_SIZE, MCP_WITNESS_LEN,
        },
        solana_packet::PacketFlags,
        solana_signature::Signature,
        solana_time_utils::timestamp,
        std::thread,
    };

    #[test]
    fn test_receive_quic_datagrams_routes_mcp_control_frames_before_size_drop() {
        let (quic_sender, quic_receiver) = unbounded();
        let (packet_sender, packet_receiver) = unbounded();
        let (mcp_control_sender, mcp_control_receiver) = unbounded();
        let exit = Arc::new(AtomicBool::new(false));
        let exit_clone = exit.clone();

        let receiver_thread = thread::spawn(move || {
            receive_quic_datagrams(
                quic_receiver,
                PacketFlags::empty(),
                packet_sender,
                exit_clone,
                Some(mcp_control_sender),
            );
        });

        let sender_pubkey = Pubkey::new_unique();
        let remote_addr = SocketAddr::from(([127, 0, 0, 1], 3000));

        // Oversized MCP control payload should bypass PACKET_DATA_SIZE filtering.
        let mut oversized_control = vec![0u8; PACKET_DATA_SIZE + 128];
        oversized_control[0] = MCP_CONTROL_MSG_CONSENSUS_BLOCK;
        quic_sender
            .send((
                sender_pubkey,
                remote_addr,
                Bytes::from(oversized_control.clone()),
            ))
            .unwrap();

        // Oversized non-control payload should be dropped.
        let oversized_non_control = vec![9u8; PACKET_DATA_SIZE + 128];
        quic_sender
            .send((
                sender_pubkey,
                remote_addr,
                Bytes::from(oversized_non_control),
            ))
            .unwrap();

        // Small non-control payload should still flow into packet batches.
        let small_payload = vec![7u8; 64];
        quic_sender
            .send((sender_pubkey, remote_addr, Bytes::from(small_payload)))
            .unwrap();

        let (_pubkey, _addr, forwarded_control) = mcp_control_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("expected MCP control frame");
        assert_eq!(forwarded_control.len(), oversized_control.len());
        assert_eq!(
            forwarded_control.first().copied(),
            Some(MCP_CONTROL_MSG_CONSENSUS_BLOCK)
        );

        let batch = packet_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("expected packet batch for non-control datagrams");
        assert_eq!(batch.len(), 1);

        exit.store(true, Ordering::Relaxed);
        drop(quic_sender);
        receiver_thread.join().unwrap();
    }

    #[test]
    fn test_is_active_mcp_shred_packet_obeys_feature_slot_gate() {
        let slot = 500_000u64;
        let witness_len_offset = std::mem::size_of::<Slot>()
            + std::mem::size_of::<u32>()
            + std::mem::size_of::<u32>()
            + 32
            + MCP_SHRED_DATA_BYTES;
        let mut mcp_bytes = vec![0u8; MCP_SHRED_WIRE_SIZE];
        mcp_bytes[..std::mem::size_of::<Slot>()].copy_from_slice(&slot.to_le_bytes());
        mcp_bytes[witness_len_offset] = MCP_WITNESS_LEN as u8;

        let mut packet = solana_perf::packet::Packet::default();
        packet.buffer_mut()[..mcp_bytes.len()].copy_from_slice(&mcp_bytes);
        packet.meta_mut().size = mcp_bytes.len();

        let feature_set = FeatureSet::default();
        let epoch_schedule = EpochSchedule::default();
        assert!(!is_active_mcp_shred_packet(
            PacketRef::Packet(&packet),
            &feature_set,
            &epoch_schedule,
        ));

        let mut feature_set = feature_set;
        feature_set.activate(&agave_feature_set::mcp_protocol_v1::id(), slot + 1);
        assert!(!is_active_mcp_shred_packet(
            PacketRef::Packet(&packet),
            &feature_set,
            &epoch_schedule,
        ));

        feature_set.activate(&agave_feature_set::mcp_protocol_v1::id(), slot);
        assert!(is_active_mcp_shred_packet(
            PacketRef::Packet(&packet),
            &feature_set,
            &epoch_schedule,
        ));
    }

    #[test]
    fn test_verify_repair_nonce_accepts_mcp_shred_without_nonce() {
        let now = timestamp();
        let mut outstanding = OutstandingShredRepairs::default();
        let request = ShredRepairType::McpShred {
            slot: 55,
            proposer_index: 3,
            shred_index: 4,
        };
        outstanding.add_request(request, now);

        let mcp_shred = McpShred {
            slot: 55,
            proposer_index: 3,
            shred_index: 4,
            commitment: [0u8; 32],
            shred_data: [0u8; MCP_SHRED_DATA_BYTES],
            witness: [[0u8; 32]; MCP_WITNESS_LEN],
            proposer_signature: Signature::default(),
        };
        let mcp_bytes = mcp_shred.to_bytes();
        let mut packet = solana_perf::packet::Packet::default();
        packet.buffer_mut()[..mcp_bytes.len()].copy_from_slice(&mcp_bytes);
        packet.meta_mut().size = mcp_bytes.len();
        packet.meta_mut().flags |= PacketFlags::REPAIR;

        assert!(verify_repair_nonce(
            PacketRef::Packet(&packet),
            now,
            &mut outstanding
        ));
    }
}
