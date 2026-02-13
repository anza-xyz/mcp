use {
    crate::mcp_vote_gate::{
        Commitment, RelayAttestationObservation, RelayProposerEntry, VoteGateInput,
    },
    agave_transaction_view::{
        mcp_payload::McpPayloadTransaction, transaction_view::SanitizedTransactionView,
    },
    solana_clock::Slot,
    solana_ledger::{
        blockstore::Blockstore,
        leader_schedule_cache::LeaderScheduleCache,
        mcp,
        mcp_aggregate_attestation::AggregateAttestation,
        mcp_consensus_block::ConsensusBlock,
        mcp_ordering,
        mcp_reconstruction::{
            decode_reconstructed_payload, reconstruct_payload, MCP_RECON_MAX_PAYLOAD_BYTES,
            MCP_RECON_NUM_SHREDS, MCP_RECON_SHRED_BYTES,
        },
        shred::mcp_shred::McpShred,
    },
    solana_metrics::inc_new_counter_error,
    solana_pubkey::Pubkey,
    solana_runtime::{bank::Bank, bank_forks::BankForks},
    solana_runtime_transaction::{
        runtime_transaction::RuntimeTransaction, transaction_meta::StaticMeta,
    },
    solana_transaction::sanitized::MessageHash,
    std::{
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        sync::{Arc, RwLock},
    },
};

pub(crate) type McpConsensusBlockStore = Arc<RwLock<HashMap<Slot, Vec<u8>>>>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReconstructedTransaction {
    execution_class: mcp_ordering::ExecutionClass,
    ordering_fee: u64,
    signature: [u8; 64],
    wire_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrderingMetadataError {
    MissingSignature,
    InvalidLegacyView,
    InvalidLegacyRuntimeTransaction,
}

fn load_proposer_schedule(
    slot: Slot,
    bank: &Bank,
    root_bank: &Bank,
    leader_schedule_cache: &LeaderScheduleCache,
) -> Vec<Pubkey> {
    leader_schedule_cache
        .proposers_at_slot(slot, Some(bank))
        .or_else(|| leader_schedule_cache.proposers_at_slot(slot, Some(root_bank)))
        .or_else(|| leader_schedule_cache.proposers_at_slot(slot, None))
        .unwrap_or_default()
}

fn load_relay_schedule(
    slot: Slot,
    bank: &Bank,
    root_bank: &Bank,
    leader_schedule_cache: &LeaderScheduleCache,
) -> Vec<Pubkey> {
    leader_schedule_cache
        .relays_at_slot(slot, Some(bank))
        .or_else(|| leader_schedule_cache.relays_at_slot(slot, Some(root_bank)))
        .or_else(|| leader_schedule_cache.relays_at_slot(slot, None))
        .unwrap_or_default()
}

fn derive_selected_commitments(
    aggregate: &[RelayAttestationObservation],
) -> HashMap<u32, Commitment> {
    let mut by_proposer: HashMap<u32, HashMap<Commitment, BTreeSet<u32>>> = HashMap::new();
    for relay in aggregate.iter().filter(|relay| relay.relay_signature_valid) {
        for entry in relay
            .entries
            .iter()
            .filter(|entry| entry.proposer_signature_valid)
        {
            by_proposer
                .entry(entry.proposer_index)
                .or_default()
                .entry(entry.commitment)
                .or_default()
                .insert(relay.relay_index);
        }
    }

    by_proposer
        .into_iter()
        .filter_map(|(proposer_index, commitments)| {
            if commitments.len() != 1 {
                return None;
            }
            let (commitment, relays) = commitments.into_iter().next().unwrap();
            if relays.len() < mcp::REQUIRED_INCLUSIONS {
                return None;
            }
            Some((proposer_index, commitment))
        })
        .collect()
}

fn count_local_valid_shreds_for_commitment(
    blockstore: &Blockstore,
    slot: Slot,
    proposer_index: u32,
    proposer_pubkey: &Pubkey,
    commitment: Commitment,
) -> usize {
    (0..mcp::NUM_RELAYS)
        .filter_map(|shred_index| {
            blockstore
                .get_mcp_shred_data(slot, proposer_index, u32::try_from(shred_index).ok()?)
                .ok()
                .flatten()
        })
        .filter_map(|bytes| McpShred::from_bytes(&bytes).ok())
        .filter(|mcp_shred| {
            mcp_shred.commitment == commitment
                && mcp_shred.verify_signature(proposer_pubkey)
                && mcp_shred.verify_witness()
        })
        .count()
}

fn build_vote_gate_input(
    slot: Slot,
    bank: &Bank,
    root_bank: &Bank,
    blockstore: &Blockstore,
    leader_schedule_cache: &LeaderScheduleCache,
    consensus_block: &ConsensusBlock,
    delayed_bankhash_available: bool,
    delayed_bankhash_matches: bool,
) -> Option<VoteGateInput> {
    if consensus_block.slot != slot {
        return None;
    }

    let proposers = load_proposer_schedule(slot, bank, root_bank, leader_schedule_cache);
    if proposers.is_empty() {
        return None;
    }
    let relays = load_relay_schedule(slot, bank, root_bank, leader_schedule_cache);
    if relays.len() < mcp::NUM_RELAYS {
        return None;
    }

    let leader_pubkey = proposers
        .get(consensus_block.leader_index as usize)
        .copied();
    let leader_signature_valid = leader_pubkey
        .as_ref()
        .is_some_and(|leader_pubkey| consensus_block.verify_leader_signature(leader_pubkey));
    let leader_index_matches = leader_pubkey.is_some_and(|leader_pubkey| {
        leader_schedule_cache
            .slot_leader_at(slot, Some(bank))
            .or_else(|| leader_schedule_cache.slot_leader_at(slot, Some(root_bank)))
            .or_else(|| leader_schedule_cache.slot_leader_at(slot, None))
            .is_some_and(|expected_leader| expected_leader == leader_pubkey)
    });

    let aggregate_attestation =
        AggregateAttestation::from_wire_bytes(&consensus_block.aggregate_bytes).ok()?;
    if aggregate_attestation.slot != slot
        || aggregate_attestation.leader_index != consensus_block.leader_index
    {
        return None;
    }

    let aggregate_version = aggregate_attestation.version;
    let aggregate: Vec<RelayAttestationObservation> = aggregate_attestation
        .relay_entries
        .into_iter()
        .map(|relay_entry| {
            let relay_signature_valid =
                relays
                    .get(relay_entry.relay_index as usize)
                    .is_some_and(|relay_pubkey| {
                        relay_entry.verify_relay_signature(aggregate_version, slot, relay_pubkey)
                    });
            RelayAttestationObservation {
                relay_index: relay_entry.relay_index,
                relay_signature_valid,
                entries: relay_entry
                    .entries
                    .into_iter()
                    .map(|entry| RelayProposerEntry {
                        proposer_index: entry.proposer_index,
                        commitment: entry.commitment.to_bytes(),
                        proposer_signature_valid: proposers
                            .get(entry.proposer_index as usize)
                            .is_some_and(|proposer_pubkey| {
                                entry
                                    .proposer_signature
                                    .verify(proposer_pubkey.as_ref(), entry.commitment.as_ref())
                            }),
                    })
                    .collect(),
            }
        })
        .collect();

    let selected_commitments = derive_selected_commitments(&aggregate);
    let local_valid_shreds = selected_commitments
        .into_iter()
        .filter_map(|(proposer_index, commitment)| {
            let proposer_pubkey = proposers.get(proposer_index as usize)?;
            Some((
                proposer_index,
                count_local_valid_shreds_for_commitment(
                    blockstore,
                    slot,
                    proposer_index,
                    proposer_pubkey,
                    commitment,
                ),
            ))
        })
        .collect();

    let proposer_indices = (0..proposers.len())
        .filter_map(|proposer_index| u32::try_from(proposer_index).ok())
        .collect();

    Some(VoteGateInput {
        leader_signature_valid,
        leader_index_matches,
        delayed_bankhash_available,
        delayed_bankhash_matches,
        aggregate,
        proposer_indices,
        local_valid_shreds,
    })
}

pub(crate) fn refresh_vote_gate_input(
    slot: Slot,
    bank: &Bank,
    bank_forks: &RwLock<BankForks>,
    blockstore: &Blockstore,
    leader_schedule_cache: &LeaderScheduleCache,
    mcp_consensus_blocks: &McpConsensusBlockStore,
    mcp_vote_gate_inputs: &RwLock<HashMap<Slot, VoteGateInput>>,
) {
    let delayed_slot = slot.saturating_sub(1);
    let (root_bank, root_slot, mut local_delayed_bankhash) = {
        let bank_forks = bank_forks.read().unwrap();
        (
            bank_forks.root_bank(),
            bank_forks.root(),
            // Until consensus metadata explicitly carries delayed-slot semantics, use the
            // immediately delayed slot as the local availability gate.
            bank_forks.get(delayed_slot).map(|bank| bank.hash()),
        )
    };
    if local_delayed_bankhash.is_none() {
        local_delayed_bankhash = blockstore.get_bank_hash(delayed_slot);
    }

    let consensus_block = {
        let Ok(consensus_blocks) = mcp_consensus_blocks.read() else {
            warn!(
                "failed to read MCP consensus block cache at slot {} due to poisoned lock",
                slot
            );
            return;
        };
        let Some(payload) = consensus_blocks.get(&slot) else {
            return;
        };
        let Ok(consensus_block) = ConsensusBlock::from_wire_bytes(payload) else {
            drop(consensus_blocks);
            match mcp_consensus_blocks.write() {
                Ok(mut consensus_blocks) => {
                    consensus_blocks.remove(&slot);
                }
                Err(err) => {
                    warn!(
                        "failed to prune invalid MCP consensus block at slot {}: {}",
                        slot, err
                    );
                }
            }
            return;
        };
        consensus_block
    };

    let delayed_bankhash_available = local_delayed_bankhash.is_some();
    let delayed_bankhash_matches =
        local_delayed_bankhash.is_some_and(|bankhash| bankhash == consensus_block.delayed_bankhash);

    let Some(vote_gate_input) = build_vote_gate_input(
        slot,
        bank,
        &root_bank,
        blockstore,
        leader_schedule_cache,
        &consensus_block,
        delayed_bankhash_available,
        delayed_bankhash_matches,
    ) else {
        return;
    };

    match mcp_vote_gate_inputs.write() {
        Ok(mut inputs) => {
            let min_slot = root_slot.saturating_sub(mcp::CONSENSUS_BLOCK_RETENTION_SLOTS);
            inputs.retain(|tracked_slot, _| *tracked_slot >= min_slot);
            inputs.insert(slot, vote_gate_input);
        }
        Err(err) => {
            warn!(
                "failed to persist MCP vote gate input at slot {} due to poisoned lock: {}",
                slot, err
            );
            return;
        }
    }

    match mcp_consensus_blocks.write() {
        Ok(mut consensus_blocks) => {
            let min_slot = root_slot.saturating_sub(mcp::CONSENSUS_BLOCK_RETENTION_SLOTS);
            consensus_blocks.retain(|tracked_slot, _| *tracked_slot >= min_slot);
        }
        Err(err) => {
            warn!(
                "failed to prune MCP consensus block cache after slot {} due to poisoned lock: {}",
                slot, err
            );
        }
    }
}

fn ordering_metadata_for_payload_transaction(
    transaction: &McpPayloadTransaction,
) -> Result<(mcp_ordering::ExecutionClass, u64, [u8; 64]), OrderingMetadataError> {
    if let Some(mcp_transaction) = transaction.mcp_transaction.as_ref() {
        let mut signature = [0u8; 64];
        signature.copy_from_slice(
            mcp_transaction
                .signatures
                .first()
                .ok_or(OrderingMetadataError::MissingSignature)?
                .as_ref(),
        );
        let ordering_fee = mcp_transaction.ordering_fee_with_fallback();
        return Ok((mcp_ordering::ExecutionClass::Mcp, ordering_fee, signature));
    }

    let view = SanitizedTransactionView::try_new_sanitized(transaction.wire_bytes.as_slice())
        .map_err(|_| OrderingMetadataError::InvalidLegacyView)?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(
        view.signatures()
            .first()
            .ok_or(OrderingMetadataError::MissingSignature)?
            .as_ref(),
    );
    let runtime_tx = RuntimeTransaction::<SanitizedTransactionView<_>>::try_from(
        view,
        MessageHash::Compute,
        None,
    )
    .map_err(|_| OrderingMetadataError::InvalidLegacyRuntimeTransaction)?;
    let ordering_fee = runtime_tx
        .compute_budget_instruction_details()
        .requested_compute_unit_price();
    Ok((
        mcp_ordering::ExecutionClass::Legacy,
        ordering_fee,
        signature,
    ))
}

fn encode_ordered_execution_output(transactions: &[ReconstructedTransaction]) -> Option<Vec<u8>> {
    let tx_count = u32::try_from(transactions.len()).ok()?;
    let mut out = Vec::with_capacity(transactions.iter().try_fold(4usize, |acc, tx| {
        let tx_len_field = 4usize.checked_add(tx.wire_bytes.len())?;
        acc.checked_add(tx_len_field)
    })?);
    out.extend_from_slice(&tx_count.to_le_bytes());
    for tx in transactions {
        let tx_len = u32::try_from(tx.wire_bytes.len()).ok()?;
        out.extend_from_slice(&tx_len.to_le_bytes());
        out.extend_from_slice(&tx.wire_bytes);
    }
    Some(out)
}

pub(crate) fn maybe_persist_reconstructed_execution_output(
    slot: Slot,
    bank: &Bank,
    bank_forks: &RwLock<BankForks>,
    blockstore: &Blockstore,
    leader_schedule_cache: &LeaderScheduleCache,
    mcp_vote_gate_included_proposers: &RwLock<HashMap<Slot, BTreeMap<u32, Commitment>>>,
) {
    if let Some(existing_output) = blockstore.get_mcp_execution_output(slot).ok().flatten() {
        if !existing_output.is_empty() {
            return;
        }
    }

    let included_proposers = match mcp_vote_gate_included_proposers.read() {
        Ok(included) => included.get(&slot).cloned().unwrap_or_default(),
        Err(err) => {
            warn!(
                "failed to read MCP vote-gate proposer outputs at slot {} due to poisoned lock: {}",
                slot, err
            );
            return;
        }
    };
    if included_proposers.is_empty() {
        debug!(
            "MCP reconstruction skipped for slot {}: no included proposers",
            slot
        );
        return;
    }
    debug!(
        "MCP reconstruction entered for slot {} with {} included proposers",
        slot,
        included_proposers.len()
    );

    let root_bank = match bank_forks.read() {
        Ok(bank_forks) => bank_forks.root_bank(),
        Err(err) => {
            warn!(
                "failed to read bank forks for MCP reconstruction at slot {} due to poisoned lock: {}",
                slot, err
            );
            return;
        }
    };
    let proposers = load_proposer_schedule(slot, bank, &root_bank, leader_schedule_cache);
    if proposers.is_empty() {
        return;
    }

    let mut reconstructed_batches: Vec<(u32, Vec<ReconstructedTransaction>)> = Vec::new();
    let mut reconstructed_any_proposer = false;
    for (proposer_index, commitment) in included_proposers {
        let Some(proposer_pubkey) = proposers.get(proposer_index as usize) else {
            continue;
        };
        let mut shards: Vec<Option<[u8; MCP_RECON_SHRED_BYTES]>> = vec![None; MCP_RECON_NUM_SHREDS];
        for shred_index in 0..mcp::NUM_RELAYS {
            let Some(shred_index_u32) = u32::try_from(shred_index).ok() else {
                continue;
            };
            let Ok(Some(bytes)) =
                blockstore.get_mcp_shred_data(slot, proposer_index, shred_index_u32)
            else {
                continue;
            };
            let Ok(mcp_shred) = McpShred::from_bytes(&bytes) else {
                continue;
            };
            if mcp_shred.slot != slot
                || mcp_shred.proposer_index != proposer_index
                || mcp_shred.commitment != commitment
                || (mcp_shred.shred_index as usize) >= MCP_RECON_NUM_SHREDS
            {
                continue;
            }
            if !mcp_shred.verify_signature(proposer_pubkey) || !mcp_shred.verify_witness() {
                continue;
            }
            shards[mcp_shred.shred_index as usize] = Some(mcp_shred.shred_data);
        }
        let available_shards = shards.iter().flatten().count();

        let Ok(payload) = reconstruct_payload(
            slot,
            proposer_index,
            MCP_RECON_MAX_PAYLOAD_BYTES,
            commitment,
            &mut shards,
        ) else {
            warn!(
                "MCP reconstruction failed for slot {} proposer {}: {} valid shards",
                slot, proposer_index, available_shards
            );
            continue;
        };
        let Ok(decoded_payload) = decode_reconstructed_payload(&payload) else {
            warn!(
                "MCP reconstruction produced undecodable payload for slot {} proposer {}",
                slot, proposer_index
            );
            continue;
        };
        reconstructed_any_proposer = true;

        let mut seen_signatures = HashSet::new();
        let transactions = decoded_payload
            .transactions
            .into_iter()
            .filter_map(|tx| {
                let (execution_class, ordering_fee, signature) =
                    match ordering_metadata_for_payload_transaction(&tx) {
                        Ok(metadata) => metadata,
                        Err(err) => {
                            inc_new_counter_error!("mcp-reconstruction-transaction-metadata-drop", 1);
                            match err {
                                OrderingMetadataError::MissingSignature => inc_new_counter_error!(
                                    "mcp-reconstruction-transaction-metadata-drop-missing-signature",
                                    1
                                ),
                                OrderingMetadataError::InvalidLegacyView => inc_new_counter_error!(
                                    "mcp-reconstruction-transaction-metadata-drop-invalid-legacy-view",
                                    1
                                ),
                                OrderingMetadataError::InvalidLegacyRuntimeTransaction => {
                                    inc_new_counter_error!(
                                        "mcp-reconstruction-transaction-metadata-drop-invalid-legacy-runtime-transaction",
                                        1
                                    )
                                }
                            }
                            return None;
                        }
                    };
                if !seen_signatures.insert(signature) {
                    // Dedup only within a single proposer's payload.
                    inc_new_counter_error!(
                        "mcp-reconstruction-transaction-duplicate-signature-drop",
                        1
                    );
                    return None;
                }
                Some(ReconstructedTransaction {
                    execution_class,
                    ordering_fee,
                    signature,
                    wire_bytes: tx.wire_bytes,
                })
            })
            .collect::<Vec<_>>();
        if transactions.is_empty() {
            continue;
        }
        reconstructed_batches.push((proposer_index, transactions));
    }

    if reconstructed_batches.is_empty() {
        debug!(
            "MCP reconstruction produced no executable batches for slot {} (reconstructed_any_proposer={})",
            slot, reconstructed_any_proposer
        );
        if reconstructed_any_proposer {
            if let Some(encoded_empty_output) = encode_ordered_execution_output(&[]) {
                let _ = blockstore.put_mcp_execution_output(slot, &encoded_empty_output);
            }
        }
        return;
    }

    let ordered_transactions = mcp_ordering::order_batches_mcp_policy(
        reconstructed_batches,
        |tx| tx.execution_class,
        |tx| tx.ordering_fee,
        |tx| tx.signature,
    );
    let Some(encoded_output) = encode_ordered_execution_output(&ordered_transactions) else {
        return;
    };
    if encoded_output.is_empty() {
        return;
    }

    if let Err(err) = blockstore.put_mcp_execution_output(slot, &encoded_output) {
        debug!(
            "failed to persist reconstructed MCP execution output for slot {}: {}",
            slot, err
        );
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::mcp_vote_gate::{RelayAttestationObservation, RelayProposerEntry},
        agave_feature_set as feature_set,
        solana_keypair::Keypair,
        solana_ledger::{
            blockstore::Blockstore, genesis_utils::create_genesis_config_with_leader,
            get_tmp_ledger_path_auto_delete, mcp_aggregate_attestation::AggregateAttestation,
            mcp_erasure::encode_fec_set, shred::mcp_shred::McpShred,
        },
        solana_runtime::bank_forks::BankForks,
        solana_signer::Signer,
    };

    fn relay_with_entry(
        relay_index: u32,
        proposer_index: u32,
        commitment: Commitment,
    ) -> RelayAttestationObservation {
        RelayAttestationObservation {
            relay_index,
            relay_signature_valid: true,
            entries: vec![RelayProposerEntry {
                proposer_index,
                commitment,
                proposer_signature_valid: true,
            }],
        }
    }

    #[test]
    fn test_derive_selected_commitments_requires_unique_commitment() {
        let commitment_a = [1u8; 32];
        let commitment_b = [2u8; 32];
        let aggregate = (0..mcp::REQUIRED_INCLUSIONS)
            .map(|relay_index| relay_with_entry(relay_index as u32, 0, commitment_a))
            .chain((0..mcp::REQUIRED_INCLUSIONS).map(|relay_index| {
                relay_with_entry(
                    (relay_index + mcp::REQUIRED_INCLUSIONS) as u32,
                    0,
                    commitment_b,
                )
            }))
            .collect::<Vec<_>>();

        let selected = derive_selected_commitments(&aggregate);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_derive_selected_commitments_includes_unique_threshold_commitment() {
        let commitment = [7u8; 32];
        let aggregate = (0..mcp::REQUIRED_INCLUSIONS)
            .map(|relay_index| relay_with_entry(relay_index as u32, 3, commitment))
            .collect::<Vec<_>>();

        let selected = derive_selected_commitments(&aggregate);
        assert_eq!(selected.get(&3), Some(&commitment));
    }

    #[test]
    fn test_refresh_vote_gate_input_populates_slot_input_from_consensus_block() {
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

        let slot = 1;
        let bank = bank_forks
            .write()
            .unwrap()
            .insert(Bank::new_from_parent(
                root_bank.clone(),
                &leader.pubkey(),
                slot,
            ))
            .clone_without_scheduler();

        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let leader_index = leader_schedule_cache
            .proposers_at_slot(slot, Some(&bank))
            .and_then(|proposers| {
                proposers
                    .iter()
                    .position(|pubkey| *pubkey == leader.pubkey())
                    .and_then(|index| u32::try_from(index).ok())
            })
            .expect("leader should appear in proposer schedule");

        let aggregate_bytes = AggregateAttestation::new_canonical(slot, leader_index, vec![])
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        let delayed_bankhash = root_bank.hash();
        let mut consensus_block = ConsensusBlock::new_unsigned(
            slot,
            leader_index,
            aggregate_bytes,
            vec![],
            delayed_bankhash,
        )
        .unwrap();
        consensus_block.sign_leader(&leader).unwrap();
        let consensus_bytes = consensus_block.to_wire_bytes().unwrap();

        let mcp_consensus_blocks = Arc::new(RwLock::new(HashMap::new()));
        mcp_consensus_blocks
            .write()
            .unwrap()
            .insert(slot, consensus_bytes);
        let mcp_vote_gate_inputs = RwLock::new(HashMap::new());

        refresh_vote_gate_input(
            slot,
            &bank,
            &bank_forks,
            &blockstore,
            &leader_schedule_cache,
            &mcp_consensus_blocks,
            &mcp_vote_gate_inputs,
        );

        let input = mcp_vote_gate_inputs
            .read()
            .unwrap()
            .get(&slot)
            .cloned()
            .expect("vote-gate input should be populated");
        assert!(input.leader_signature_valid);
        assert!(input.leader_index_matches);
        assert!(input.delayed_bankhash_available);
        assert!(input.delayed_bankhash_matches);
    }

    #[test]
    fn test_maybe_persist_reconstructed_execution_output_marks_empty_output() {
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

        let slot = 1;
        let bank = bank_forks
            .write()
            .unwrap()
            .insert(Bank::new_from_parent(
                root_bank.clone(),
                &leader.pubkey(),
                slot,
            ))
            .clone_without_scheduler();
        let leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        let proposer_index = leader_schedule_cache
            .proposer_indices_at_slot(slot, &leader.pubkey(), Some(&bank))
            .into_iter()
            .next()
            .expect("leader should be a proposer");

        let payload = Vec::new();
        let shreds = encode_fec_set(&payload).unwrap();
        let (commitment, witnesses) = solana_ledger::mcp_merkle::commitment_and_witnesses::<
            { mcp::SHRED_DATA_BYTES },
            { mcp::MCP_WITNESS_LEN },
        >(slot, proposer_index, &shreds)
        .unwrap();
        let proposer_signature = leader.sign_message(&commitment);
        for shred_index in 0..mcp::REQUIRED_RECONSTRUCTION {
            let message = McpShred {
                slot,
                proposer_index,
                shred_index: shred_index as u32,
                commitment,
                shred_data: shreds[shred_index],
                witness: witnesses[shred_index],
                proposer_signature,
            }
            .to_bytes();
            blockstore
                .put_mcp_shred_data(slot, proposer_index, shred_index as u32, &message)
                .unwrap();
        }

        let mcp_vote_gate_included_proposers =
            RwLock::<HashMap<Slot, BTreeMap<u32, Commitment>>>::new(HashMap::new());
        mcp_vote_gate_included_proposers
            .write()
            .unwrap()
            .insert(slot, BTreeMap::from([(proposer_index, commitment)]));

        maybe_persist_reconstructed_execution_output(
            slot,
            &bank,
            &bank_forks,
            &blockstore,
            &leader_schedule_cache,
            &mcp_vote_gate_included_proposers,
        );

        assert_eq!(
            blockstore.get_mcp_execution_output(slot).unwrap(),
            Some(0u32.to_le_bytes().to_vec())
        );
    }
}
