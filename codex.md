# Codex Audit: anza-xyz/mcp implementation worktree
- Local repo root: /home/anatoly/mcp
- Current branch: master
- Upstream: https://github.com/anza-xyz/mcp
- Upstream default branch: master (via `git remote show upstream`)
- Audit mode: assume adversarial/lazy author
<!-- CODEX_LAST_AUDITED: d3f8032859580f9928170d422384f8013e733237 -->
- Last updated: 2026-01-23T03:32:23Z

## Latest Summary (most recent iteration)
- New commits audited this iteration: 6 (no new commits since last audit)
- Audit verdict: MCP implementation is not to spec and is not fully wired into Agave; the pipeline has types but no call sites for proposer/relay/consensus/replay paths.
- Highest risk finding: MCP core pipeline logic (attestation aggregation, voting, replay reconstruction, consensus broadcast) is removed; remaining MCP code is largely unused scaffolding.
- Spec/code divergence: `mcp_spec.md` defines fixed-size shreds, Merkle proof rules, and a new transaction header; none are implemented in SDK/runtime or turbine wire paths.
- Schedule/format mismatches: MCP schedule is fixed-pool rotation without per-slot new sampling; transaction config uses `Pubkey` target and is not parsed in SDK/runtime.
- Test status: not run (no new tests executed).
- Issue coverage snapshot: Issue metadata carried forward from prior codex snapshot; network not used to refresh GitHub issue state.

## Issue Map (Open upstream issues)
- Issue metadata from last cached snapshot; not refreshed in this audit.
- #19: MCP-04 Transaction: update transaction format [Proposer] — status: OPEN — last updated: 2026-01-21T15:45:39Z
  - Evidence of work in this repo: `ledger/src/mcp.rs`
  - Notes: MCP config struct exists but is not wired into SDK/transaction parsing or fee calculation; `target_proposer` uses `Pubkey` while spec defines `u32` proposer_index and a new on-wire layout.
- #18: MCP-16 Replay: reconstruct messages from shreds [Replay] — status: OPEN — last updated: 2026-01-21T15:46:33Z
  - Evidence of work in this repo: none (prior `core/src/mcp_replay.rs` removed)
  - Notes: No RS decoding or Merkle verification in replay stage; no reconstruction pipeline exists.
- #17: MCP-15 Replay: handle empty slots [Replay] — status: OPEN — last updated: 2026-01-21T15:46:32Z
  - Evidence of work in this repo: none
  - Notes: No replay-stage or blockstore integration for empty slots.
- #16: MCP-14 Voting: validate and vote on blocks [-] — status: OPEN — last updated: 2026-01-21T15:46:30Z
  - Evidence of work in this repo: none (prior `core/src/mcp_voting.rs` removed)
  - Notes: No MCP block validation hook in replay/consensus; no `McpVoteV1` production/verification.
- #15: MCP-13 Consensus Leader: broadcast block via turbine [Consensus] — status: OPEN — last updated: 2026-01-21T15:46:28Z
  - Evidence of work in this repo: none
  - Notes: No MCP block payload serialization or turbine broadcast integration.
- #14: MCP-12 Consensus Leader: aggregate relay attestations [Consensus] — status: OPEN — last updated: 2026-01-21T15:46:27Z
  - Evidence of work in this repo: none (prior `core/src/mcp_attestation_service.rs` removed)
  - Notes: No relay attestation aggregation or threshold checks.
- #13: MCP-11 Relay: submit attestations to leader [Relay] — status: OPEN — last updated: 2026-01-21T15:46:26Z
  - Evidence of work in this repo: `ledger/src/mcp_attestation.rs`
  - Notes: Wire format exists but no relay path emits or sends attestations; signature domain strings and entry fields differ from spec.
- #12: MCP-09 Relay: process and verify shreds [Relay] — status: OPEN — last updated: 2026-01-21T15:45:44Z
  - Evidence of work in this repo: `turbine/src/sigverify_shreds.rs`
  - Notes: Relay processor types are not called by sigverify pipeline; Merkle proof verification is absent and witness length is only capped, not enforced to 8 entries.
- #11: MCP-07 Proposer: distribute shreds to relays [Proposer] — status: OPEN — last updated: 2026-01-21T15:45:42Z
  - Evidence of work in this repo: `turbine/src/broadcast_stage.rs`
  - Notes: Proposer distributor types are not used by broadcast stage; relay mapping ignores schedule; wire format uses variable-length fields inconsistent with spec.
- #10: MCP-19 Proposer: Bankless Leader/proposer [Proposer] — status: OPEN — last updated: 2026-01-21T15:46:36Z
  - Evidence of work in this repo: none (prior `core/src/mcp_bankless.rs` removed)
  - Notes: No bankless leader/proposer flow integrated into banking or replay.
- #9: MCP-10 Relay: record attestation [Relay] — status: OPEN — last updated: 2026-01-21T15:46:14Z
  - Evidence of work in this repo: `ledger/src/blockstore/column.rs`, `ledger/src/blockstore_db.rs`
  - Notes: MCP columns exist but are not wired into blockstore read/write paths or window_service ingestion.
- #8: MCP-17 Replay: do an initial pass to deduct fees before applying state transitions [Replay] — status: OPEN — last updated: 2026-01-21T15:46:34Z
  - Evidence of work in this repo: `svm/src/account_loader.rs`
  - Notes: Fee phase structs exist but are not invoked by transaction processor or replay stage.
- #7: MCP-05 Proposer: add proposerID to the shred format [Proposer] — status: OPEN — last updated: 2026-01-21T15:45:40Z
  - Evidence of work in this repo: `ledger/src/shred.rs`, `ledger/src/shred/wire.rs`
  - Notes: MCP spec now defines a separate `McpShredV1` wire format that is not implemented; legacy shreds are not reconciled with MCP shreds.
- #6: MCP-08 Proposer: update fee payer check to Address/test DA fee payer attacks [Proposer] — status: OPEN — last updated: 2026-01-21T15:45:43Z
  - Evidence of work in this repo: `svm/src/account_loader.rs`
  - Notes: Fee payer tracker/validation helpers are unused in processing.
- #5: MCP-02 Setup: Proposer, Relay and Leader schedule [Setup] — status: OPEN — last updated: 2026-01-21T15:45:36Z
  - Evidence of work in this repo: `ledger/src/leader_schedule.rs`, `ledger/src/leader_schedule_cache.rs`, `ledger/src/leader_schedule_utils.rs`
  - Notes: Schedule uses a fixed pool rotated per slot (no per-slot new validator sampling as spec mandates); schedule is not used by turbine/window_service.
- #4: MCP-01 Setup: protocol constants [Setup] — status: OPEN — last updated: 2026-01-21T15:45:35Z
  - Evidence of work in this repo: `ledger/src/mcp.rs`, `ledger/src/shred.rs`, `svm/src/account_loader.rs`
  - Notes: Constants are duplicated across crates and not consumed by runtime logic.
- #3: MCP-06 Proposer: encode and commit [Proposer] — status: OPEN — last updated: 2026-01-21T15:45:41Z
  - Evidence of work in this repo: `ledger/src/mcp.rs`, `ledger/src/shred.rs`
  - Notes: FEC constants exist but no Reed–Solomon encoding or Merkle commitment generation is implemented.
- #2: MCP-03 Setup: Adjust blockstore to handle multiple proposers and execution consensus seperation. [Setup,Replay] — status: OPEN — last updated: 2026-01-21T15:45:38Z
  - Evidence of work in this repo: `ledger/src/blockstore/column.rs`, `ledger/src/blockstore_db.rs`
  - Notes: Blockstore schema changes are unused and diverge from spec’s suggested columns.
- #1: MCP-18 Replay: output ordered transactions [Replay] — status: OPEN — last updated: 2026-01-21T15:46:35Z
  - Evidence of work in this repo: none
  - Notes: No ordering/dedup integration in replay stage.

## Commit-by-commit audit (chronological)
### 938bdaa693 — MCP-01: Add McpConfig with protocol constants
- Claimed intent: Centralize MCP protocol constants and config.
- Suspected upstream issue(s): #4
- Files changed: `ledger/src/mcp.rs`
- What actually changed (brief, concrete): New constants + `McpConfig` container; no usage elsewhere.
- Red flags / potential defects:
  - Constants duplicated later in other crates (core/turbine/svm) instead of using `McpConfig`, causing drift risk.
- Security considerations: None directly; misconfiguration risk if constants diverge.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Thread `McpConfig` through consensus/relay/replay paths and remove duplicate constants.

### bdcf8c135d — MCP-02: Implement proposer and relay schedules
- Claimed intent: Stake-weighted schedule with rotation for proposers/relays.
- Suspected upstream issue(s): #5
- Files changed: `ledger/src/mcp_schedule.rs`, `ledger/src/mcp_schedule_cache.rs`
- What actually changed: Adds schedule generation and caching using `WeightedIndex` sampling.
- Red flags / potential defects:
  - Sampling with replacement allows duplicate validators within a slot (`ledger/src/mcp_schedule.rs:322`), violating “unique proposer_id” assumptions and returning arbitrary first match (`ledger/src/mcp_schedule.rs:89`).
  - Test `test_proposer_relay_schedules_differ` is a no-op (compares lengths 16 vs 200) (`ledger/src/mcp_schedule.rs:392`).
- Security considerations: Duplicate scheduling could be abused to concentrate proposer slots.
- Test impact: Weak/ineffective tests; does not validate uniqueness.
- Verdict (Risk/Confidence/Status): HIGH / MED / Incorrect
- Recommended follow-ups: Use sampling without replacement and add explicit uniqueness tests for each slot.

### 39005c6fe5 — MCP-03: Add blockstore columns for multiple proposers
- Claimed intent: New CFs to support multi-proposer shreds and consensus/execution separation.
- Suspected upstream issue(s): #2
- Files changed: `ledger/src/blockstore/column.rs`, `ledger/src/blockstore_db.rs`, `ledger/src/lib.rs`
- What actually changed: Adds column families and key serialization only.
- Red flags / potential defects:
  - No read/write integration in blockstore paths; schema is unused and acceptance criteria are unmet.
- Security considerations: New CFs can bloat DB without serving functionality.
- Test impact: None.
- Verdict (Risk/Confidence/Status): MED / HIGH / Incomplete
- Recommended follow-ups: Wire new CFs into `blockstore.rs` and window service; add migration/compat notes.

### 3b37551c44 — MCP-05: Add proposer_id to shred common header
- Claimed intent: Add proposer_id to shred header and update offsets.
- Suspected upstream issue(s): #7
- Files changed: `ledger/src/shred.rs`, `ledger/src/shred/merkle.rs`, `ledger/src/shred/wire.rs`
- What actually changed: Header size increased by 1, new proposer_id field; some offsets updated.
- Red flags / potential defects:
  - Offsets still use legacy positions in merkle root calculations (`ledger/src/shred/merkle.rs:200`, `ledger/src/shred/merkle.rs:256`), breaking merkle verification/erasure indexing.
  - `get_reference_tick` reads byte 85 (legacy) while `get_flags` moved to 86 (`ledger/src/shred/wire.rs:203`).
  - `get_proposer_id` returns byte 79 for legacy shreds; that byte belongs to `fec_set_index`, not proposer_id (`ledger/src/shred/wire.rs:109`).
  - `get_common_header_bytes` always slices 84 bytes; legacy shreds used by dedup (`turbine/src/retransmit_stage.rs:212`) will be mis-keyed.
- Security considerations: Consensus-critical parsing inconsistencies can cause signature/merkle verification bypass or false failures.
- Test impact: No tests cover legacy/MCP compatibility or merkle offsets.
- Verdict (Risk/Confidence/Status): CRITICAL / HIGH / Incorrect
- Recommended follow-ups: Update all offsets consistently; add explicit legacy/MCP regression tests; ensure dedup uses correct header length.

### af5949c9e4 — MCP-06: Add MCP FEC rate constants (40 data + 160 coding)
- Claimed intent: Introduce MCP FEC constants and merkle proof size.
- Suspected upstream issue(s): #3
- Files changed: `ledger/src/shred.rs`, `ledger/src/shred/merkle_tree.rs`
- What actually changed: Adds constants only.
- Red flags / potential defects:
  - No integration with shredder/merkle encoding paths; constants are unused.
- Security considerations: None directly; but gives false sense of MCP FEC support.
- Test impact: None.
- Verdict (Risk/Confidence/Status): MED / HIGH / Incomplete
- Recommended follow-ups: Wire constants into shred creation/verification and update proof sizing logic.

### e08adc174b — MCP-04: Add MCP transaction config format with inclusion_fee and ordering_fee
- Claimed intent: Add transaction config and fee helpers.
- Suspected upstream issue(s): #19
- Files changed: `ledger/src/mcp.rs`
- What actually changed: Adds a `transaction` module with config mask serialization and fee helpers.
- Red flags / potential defects:
  - Not integrated into actual transaction/message parsing or `solana_fee::calculate_fee_details` as required by issue acceptance.
  - `target_proposer` is a `Pubkey` rather than a proposer ID (issue text suggests proposer targeting by ID).
- Security considerations: None, but parsing inconsistencies likely if clients implement differently.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / HIGH / Incomplete
- Recommended follow-ups: Implement wire integration in message/transaction crates and clarify `target_proposer` type.

### 5c682d6104 — MCP-10: Add relay attestation wire format and storage
- Claimed intent: Deterministic attestation wire format.
- Suspected upstream issue(s): #9
- Files changed: `ledger/src/lib.rs`, `ledger/src/mcp_attestation.rs`
- What actually changed: New attestation struct + serialization helpers.
- Red flags / potential defects:
  - Core uses a different attestation message format (`core/src/mcp_attestation_service.rs`), risking diverging encodings.
- Security considerations: Format drift can cause signature failures or acceptance mismatches across components.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Consolidate attestation format and reuse this module across core/turbine.

### c081d11574 — MCP-08: Add MCP fee payer validation to prevent DA attacks
- Claimed intent: Prevent fee payer overcommit in multi-proposer scenario.
- Suspected upstream issue(s): #6
- Files changed: `svm/src/mcp_fee_payer.rs`, `svm/src/lib.rs`
- What actually changed: Validator/tracker types, balance checks.
- Red flags / potential defects:
  - `SlotFeePayerTracker::can_commit` caps by spendable balance, not by `NUM_PROPOSERS * fee`, undermining the stated protection model.
  - Not integrated into transaction processing path.
- Security considerations: Under-enforcement enables DA griefing; over-enforcement can reject valid txs.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Align commitment logic with protocol requirement and wire into fee payer validation path.

### 49f680818b — MCP-09: Add relay shred processing and verification
- Claimed intent: Verify proposer shreds and track for attestation.
- Suspected upstream issue(s): #12
- Files changed: `turbine/src/mcp_relay.rs`, `turbine/src/lib.rs`
- What actually changed: New relay processing/verification structs.
- Red flags / potential defects:
  - Merkle proof verification uses `shred_index`, not relay index, while comments imply relay index verification (`turbine/src/mcp_relay.rs:263`). This fails to enforce relay assignment and enables arbitrary relays to claim any shred.
  - No constraints on witness size; could be used for memory/CPU DoS.
- Security considerations: Weak relay assignment checks enable spam and equivocation ambiguity.
- Test impact: Unit tests do not cover merkle proof correctness.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Define proof format explicitly, include relay index in validation, and bound witness size.

### ac77f71f73 — MCP-07: Add proposer shred distribution to relays
- Claimed intent: Proposers distribute shreds with commitments.
- Suspected upstream issue(s): #11
- Files changed: `turbine/src/mcp_proposer.rs`, `turbine/src/lib.rs`
- What actually changed: New distribution structs and serialization.
- Red flags / potential defects:
  - Signature covers only (slot, proposer_id, commitment); no binding to shred index or witness, enabling replay of stale commitments across shreds.
  - Relay selection is `idx % NUM_RELAYS`, with no scheduling tie-in.
- Security considerations: Ambiguous binding between shred and signature; potential replay/mix-up.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Include shred index in signed data and integrate with relay schedule.

### a7414945f4 — MCP-11/MCP-12: relay attestation submission and aggregation
- Claimed intent: Relay attestation submission and leader aggregation with equivocation detection.
- Suspected upstream issue(s): #13, #14
- Files changed: `core/src/mcp_attestation_service.rs`, `core/src/lib.rs`
- What actually changed: New wire format and aggregation logic.
- Red flags / potential defects:
  - `AttestationAggregator::add_attestation` does not verify relay signatures or relay_id validity; assumes caller did (`core/src/mcp_attestation_service.rs:170`).
  - Duplicate wire formats vs `ledger/src/mcp_attestation.rs`.
  - Attestation threshold uses stake of relays that submitted anything, not proposer-specific stake thresholds.
- Security considerations: Aggregator can be fed forged attestations if verification is skipped.
- Test impact: Unit tests only; no negative tests for signature failures.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Enforce signature verification inside aggregator and unify attestation format.

### 7b74e1891d — MCP-17: fee-only replay pass before state transitions
- Claimed intent: Two-phase fee charging with unconditional inclusion fees.
- Suspected upstream issue(s): #8
- Files changed: `svm/src/mcp_fee_replay.rs`, `svm/src/lib.rs`
- What actually changed: Fee phase structs; `execute_fee_phase` deducts all fees.
- Red flags / potential defects:
  - `conditional_fees` vs `unconditional_fees` is defined but unused; fee phase charges all fees regardless, which may contradict intended policy.
  - No integration into replay/execution pipeline.
- Security considerations: Charging policy ambiguity can cause consensus divergence.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Clarify fee policy and integrate with actual transaction processing.

### a9f217887f — MCP-15/16/18: replay components for empty slots, reconstruction, ordering
- Claimed intent: Replay stage structures for empty slots, reconstruction, ordering.
- Suspected upstream issue(s): #17, #18, #1
- Files changed: `core/src/mcp_replay.rs`, `core/src/lib.rs`
- What actually changed: Type definitions and local algorithms; no integration.
- Red flags / potential defects:
  - Reconstruction uses `total_shreds * 20%` without validating erasure coding or commitments.
  - Ordering assumes proposer IDs 0..15 and ignores proposer schedule or target proposer constraints.
- Security considerations: Placeholder logic can lead to mismatched ordering rules across nodes.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Implement real reconstruction and integrate with replay stage pipeline.

### 19c13464f1 — MCP-13/14/19: consensus broadcast, voting, bankless proposer
- Claimed intent: Consensus payload broadcast, block validation/voting, bankless leader.
- Suspected upstream issue(s): #15, #16, #10
- Files changed: `core/src/mcp_bankless.rs`, `core/src/mcp_consensus_broadcast.rs`, `core/src/mcp_voting.rs`, `core/src/lib.rs`
- What actually changed: New wire formats and validation structs.
- Red flags / potential defects:
  - `BlockValidator::compute_block_id` hashes slot + proposer roots, but `ConsensusPayload::block_id` hashes payload data; mismatch can cause vote disagreement (`core/src/mcp_voting.rs:236`).
  - `BanklessBatch::deserialize` trusts `tx_len` and allocates without bounds; potential memory DoS for malformed input (`core/src/mcp_bankless.rs:86`).
  - Signature verification is not enforced in `BanklessRecorder`; `RecordingStatus::InvalidSignature` is never reachable.
  - Constants duplicated (NUM_PROPOSERS/RELAYS and CONSENSUS_PAYLOAD_PROPOSER_ID) across core/ledger, no shared source.
- Security considerations: Divergent block_id computation and unbounded allocations can cause consensus or DoS issues.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): HIGH / MED / Suspicious
- Recommended follow-ups: Unify block_id derivation, add size limits for deserialization, and wire signature checks.

### 2952d2ec84 — Add comprehensive MCP protocol specification
- Claimed intent: Consolidate all MCP issues into a single, unambiguous specification and declare implementation complete.
- Suspected upstream issue(s): References all MCP-01..MCP-19 items implicitly.
- Files changed: `mcp_spec.md`
- What actually changed (brief, concrete): Adds a 624-line specification document describing constants, wire formats, schedules, and role flows.
- Red flags / potential defects:
  - The spec asserts “Implementation Complete” while multiple subsystems are placeholders or unintegrated (see earlier commit audits); this is misleading and risks being used as authoritative guidance (`mcp_spec.md:4`).
  - Schedule generation described as a deterministic stake-weighted shuffle without replacement, but implementation uses `WeightedIndex` sampling with replacement in `ledger/src/mcp_schedule.rs:322`, enabling duplicate validators per slot (`mcp_spec.md:105`).
  - Transaction config layout is shown with fixed offsets (1-8, 9-16, 17-48), but the actual serialization is mask-ordered and variable-length in `ledger/src/mcp.rs`, so offsets depend on which bits are set; spec is ambiguous and incorrect (`mcp_spec.md:247`).
  - Proposer ordering rule uses “arrival time” as a tie-breaker, which is non-deterministic across validators and conflicts with the determinism requirement in Appendix B (`mcp_spec.md:283`, `mcp_spec.md:616`).
  - Block ID derivation references “canonical_aggregate_bytes” but never defines the canonical serialization of `SlotAggregate` or `ConsensusMeta`; the spec is incomplete and not executable (`mcp_spec.md:361`, `mcp_spec.md:514`).
  - Shred distribution to relays is underspecified (no mapping from shred index to relay_id, no rule for which relay receives which shred), making protocol behavior ambiguous (`mcp_spec.md:298`).
  - Fee payer requirements state `NUM_PROPOSERS * total_fee` for all account types but current code does not enforce this; the spec overstates implemented security guarantees (`mcp_spec.md:456`).
- Security considerations: A misleading spec can normalize unsafe or divergent behavior, making consensus bugs harder to detect during review and testing.
- Test impact: Documentation-only change; no tests updated.
- Verdict (Risk/Confidence/Status): MED / HIGH / Suspicious
- Recommended follow-ups: Mark the spec as draft or explicitly align it with current code; reconcile differences (schedules, fee rules, transaction config layout, block_id derivation) and link to tracking issues.

### 939aeba6de — Fix MCP specification accuracy and clarity
- Claimed intent: Correct MCP specification inaccuracies and clarify deterministic rules.
- Suspected upstream issue(s): References all MCP-01..MCP-19 items implicitly.
- Files changed: `mcp_spec.md`
- What actually changed (brief, concrete): Marks spec as draft, clarifies variable-length transaction config, defines canonical block_id serialization, adds relay assignment rule, replaces arrival-time tie-breaker with tx hash, adds unique selection note for schedules.
- Red flags / potential defects:
  - Schedule section now mandates “without replacement” selection and `role_magic` in the seed, but implementation uses `WeightedIndex` sampling with replacement and no role-specific seed (`ledger/src/mcp_schedule.rs:322`), so spec still conflicts with code.
  - Block_id derivation now matches consensus payload serialization, but `core/src/mcp_voting.rs` still computes block_id from a different input; spec/code divergence remains.
  - Relay assignment rule (`shred_index % NUM_RELAYS`) matches current proposer helper, but the spec still omits how this maps to the stake-weighted relay schedule (the rule ignores schedule ordering).
  - “Order by transaction hash” is a new deterministic rule but no code enforces ordering in bankless batch assembly; spec risks becoming aspirational rather than authoritative.
  - “Witness max 8 entries” is stated in the message format, but no limit is enforced in relay parsing, so the spec is not backed by code.
- Security considerations: Spec/code mismatches can lead to inconsistent third-party implementations and hidden consensus failures.
- Test impact: Documentation-only change; no tests updated.
- Verdict (Risk/Confidence/Status): MED / HIGH / Suspicious
- Recommended follow-ups: Align schedule selection and block_id computation across code and spec; document or remove relay assignment if not enforced by schedule; add explicit serialization limits for witnesses or remove the constraint.

### ca7621467a — Fix MCP spec underspecifications and implementation issues
- Claimed intent: Update MCP spec to remove underspecification and align implementations.
- Suspected upstream issue(s): References all MCP-01..MCP-19 items implicitly.
- Files changed: `mcp_spec.md`, `turbine/src/mcp_proposer.rs`, `turbine/src/mcp_relay.rs`, `ledger/src/mcp_schedule.rs`, `ledger/src/mcp_attestation.rs`, `core/src/mcp_voting.rs`, `core/src/mcp_bankless.rs`, `svm/src/mcp_fee_payer.rs`, plus minor constant re-exports and test adjustments.
- What actually changed (brief, concrete):
  - Spec adds batch limits, explicit SHA256 ordering, shred_index signature binding, relay assignment, witness size enforcement, modular indexing schedule details.
  - Proposer/relay messages now include shred_index in signature binding and serialization; relay checks `shred_index % NUM_RELAYS` and uses payload block_id in voting.
  - Schedule generation replaces weighted sampling with replacement by a weighted shuffle without replacement + modular indexing.
  - Bankless batch deserialization adds size/length limits (but with different constants than spec).
- Red flags / potential defects:
  - Spec mandates pool size equals role count (16/200), but code builds the pool from all validators (`ledger/src/mcp_schedule.rs:56-89`), so schedule selection deviates from spec.
  - Spec batch limits are 65,536 tx and 10 MB, but code enforces 10,000 tx and 16 MB; MAX_SHRED_DATA_SIZE (1,228) is not enforced anywhere (`mcp_spec.md:87`, `core/src/mcp_bankless.rs:114`).
  - Spec requires witness_len <= 8 and silent drop on violation; relay code does not enforce witness length or silent drop policy (`mcp_spec.md:326`, `turbine/src/mcp_relay.rs:224`).
  - Transaction ordering by SHA256(serialized_transaction) is specified, but no code performs ordering before serialization or replay (`mcp_spec.md:287`, `core/src/mcp_bankless.rs:96`).
  - Fee payer requirement remains unenforced (`mcp_spec.md:482`, `svm/src/mcp_fee_payer.rs:127`).
  - Commit adds `codex.md` and `codex_audit.sh` into the repo history; these are audit artifacts and unrelated to MCP, potentially accidental or inappropriate for upstream.
- Security considerations: Mismatched limits (batch size, witness) create DoS or consensus risk; schedule mismatch can alter stake-weighted selection; spec-driven implementations will diverge from this code.
- Test impact: New schedule uniqueness tests; no tests for witness limits or tx ordering.
- Verdict (Risk/Confidence/Status): HIGH / HIGH / Suspicious
- Recommended follow-ups: Align schedule pool size to spec, enforce witness length and batch size constants as specified, implement deterministic ordering, and decide whether audit artifacts belong in repo history.

### c5f4a1fabc — Comprehensive MCP spec update from mcp_spec_next.md and codex.md
- Claimed intent: Merge mcp_spec_next.md content into mcp_spec.md and incorporate audit fixes.
- Suspected upstream issue(s): References all MCP-01..MCP-19 items implicitly.
- Files changed: `mcp_spec.md`
- What actually changed (brief, concrete): Adds cryptographic primitives, explicit wire sizing (1225-byte shreds), McpPayloadV1/McpVoteV1 structures, derived thresholds, equivocation rule, de-duplication, and expanded determinism requirements.
- Red flags / potential defects:
  - Wire format now specifies `witness_len` as 1 byte with fixed 1225-byte shreds, but implementation uses 2-byte `witness_len` and variable-length witnesses (`turbine/src/mcp_proposer.rs:109`, `turbine/src/mcp_relay.rs:126`), so code is out of spec.
  - `McpPayloadV1` uses `tx_len: u16` and `tx_count: u16`, while `core/src/mcp_bankless.rs` uses `u32` lengths; this is a breaking serialization mismatch.
  - Spec enforces `MAX_TX_SIZE=4096`, but code caps tx size at 1232 bytes; spec-as-truth makes current limits wrong.
  - Spec requires 256-leaf Merkle tree with zero-padding leaves and 20-byte truncations; current merkle code does not document or implement the 256-leaf padding rule.
  - Spec introduces `McpVoteV1` format and validator registry indices; no code path uses or produces this format.
  - MTU requirement is still underspecified: 1225-byte shreds are asserted without stating the assumed MTU and overhead; `mcp_spec.md` should specify the packet budget explicitly.
- Security considerations: Divergent wire formats guarantee network incompatibility and can create silent consensus splits if some validators follow spec while others follow code.
- Test impact: Documentation-only change; no tests updated.
- Verdict (Risk/Confidence/Status): HIGH / HIGH / Suspicious
- Recommended follow-ups: Pick a single wire layout (witness_len size, tx_len width, packet budget) and update code + tests to match; explicitly define MTU/overhead assumptions in spec.

### fbe9f1e5b4 — Fix MCP implementation issues from codex.md audit
- Claimed intent: Align implementation with spec findings from codex.md.
- Suspected upstream issue(s): #5, #7, #8, #11, #12, #13, #14
- Files changed: `core/src/mcp_attestation_service.rs`, `core/src/mcp_bankless.rs`, `ledger/src/mcp_schedule.rs`, `ledger/src/shred.rs`, `ledger/src/shred/merkle.rs`, `ledger/src/shred/wire.rs`, `svm/src/mcp_fee_payer.rs`, `turbine/src/mcp_relay.rs`, `codex.md`
- What actually changed (brief, concrete): Added witness size enforcement, batch limits, ordering by ordering_fee+hash, fee payer scaling, relay signature verification, and shred header offset fixes in standalone MCP modules.
- Red flags / potential defects:
  - Fixes landed in standalone MCP modules that are later removed (see `efe05fc3cc`), so the corrected behaviors are not present in the current integrated code.
  - No integration into the Agave pipeline; logic remained isolated even after fixes.
- Security considerations: Improvements exist only in removed modules; current runtime paths remain unprotected.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Obsoleted
- Recommended follow-ups: Re-apply the functional fixes in the integrated Agave paths (`broadcast_stage`, `sigverify_shreds`, `account_loader`, `replay_stage`).

### 062618c036 — Update codex.md to reflect fixed audit issues
- Claimed intent: Mark prior audit items as fixed.
- Suspected upstream issue(s): References MCP-01..MCP-19 items implicitly.
- Files changed: `codex.md`
- What actually changed (brief, concrete): Documentation-only update.
- Red flags / potential defects:
  - Marked issues as fixed that were later removed by subsequent refactors.
- Security considerations: None (doc-only).
- Test impact: None.
- Verdict (Risk/Confidence/Status): LOW / HIGH / Doc-only
- Recommended follow-ups: Update audit status to reflect current integrated code paths.

### addb78f334 — Remove standalone MCP modules - integrate into existing Agave
- Claimed intent: Delete standalone MCP scaffolding.
- Suspected upstream issue(s): References MCP-01..MCP-19 items implicitly.
- Files changed: multiple MCP-specific modules removed.
- What actually changed (brief, concrete): Removed MCP modules and MCP blockstore columns entirely.
- Red flags / potential defects:
  - This commit was immediately reverted, so its behavior did not persist.
- Security considerations: None (reverted).
- Test impact: None.
- Verdict (Risk/Confidence/Status): LOW / HIGH / Reverted
- Recommended follow-ups: None; see `efe05fc3cc` for the final integration approach.

### 19d3a4ab6c — Revert "Remove standalone MCP modules - integrate into existing Agave"
- Claimed intent: Restore removed MCP modules.
- Suspected upstream issue(s): References MCP-01..MCP-19 items implicitly.
- Files changed: MCP modules restored.
- What actually changed (brief, concrete): Reintroduced prior MCP code; no functional changes beyond the revert.
- Red flags / potential defects: None (revert).
- Security considerations: None.
- Test impact: None.
- Verdict (Risk/Confidence/Status): LOW / HIGH / Revert
- Recommended follow-ups: None; superseded by `efe05fc3cc`.

### efe05fc3cc — Integrate MCP functionality into existing Agave modules
- Claimed intent: Move MCP logic into Agave’s core modules and delete standalone MCP files.
- Suspected upstream issue(s): #5, #6, #11, #12, #8
- Files changed: `ledger/src/leader_schedule.rs`, `ledger/src/leader_schedule_cache.rs`, `ledger/src/leader_schedule_utils.rs`, `svm/src/account_loader.rs`, `turbine/src/broadcast_stage.rs`, `turbine/src/sigverify_shreds.rs`, plus removal of `core/src/mcp_*` and `turbine/src/mcp_*` modules
- What actually changed (brief, concrete):
  - Added MCP schedule types to leader schedule utilities.
  - Added MCP fee payer and fee-phase types to account loader.
  - Added proposer distribution and relay shred processor types to turbine modules.
  - Removed all MCP consensus, replay, voting, and attestation service modules from `core/`.
- Red flags / potential defects:
  - New MCP types are not referenced by existing pipeline code; no call sites in broadcast/sigverify/replay/banking.
  - Removing `core/src/mcp_*` eliminated the only implementation of MCP voting, replay reconstruction, and consensus payload handling.
  - MCP attestation wire format remains in `ledger/src/mcp_attestation.rs` but no producer/consumer exists.
- Security considerations: MCP is effectively disabled/incomplete; spec compliance cannot be tested or enforced.
- Test impact: No integration tests; new types are unused.
- Verdict (Risk/Confidence/Status): HIGH / HIGH / Incomplete
- Recommended follow-ups: Wire MCP logic into `broadcast_stage`, `sigverify_shreds`, `window_service`, `replay_stage`, and `banking_stage` so these types are exercised.

### d3f8032859 — Replace mcp_spec.md with improved spec (no-encryption version)
- Claimed intent: Define a complete, stable MCP spec without encryption.
- Suspected upstream issue(s): References MCP-01..MCP-19 items implicitly.
- Files changed: `mcp_spec.md`
- What actually changed (brief, concrete): New spec with fixed wire layouts, deterministic ordering, and explicit block/vote formats.
- Red flags / potential defects:
  - Spec defines a new transaction layout with `transaction_config_mask` in the header, but no SDK/runtime integration exists; compatibility with legacy and v0 transactions is unspecified.
  - `McpShredV1` wire layout (1225 bytes, witness_len u8=8) does not match current turbine relay/proposer messages (variable-length, witness_len u16).
  - Relay attestations in spec include proposer signatures per entry; code’s `RelayAttestation` only includes proposer_id + merkle_root.
  - Spec mandates per-slot committee rotation with new validator sampling; leader schedule code uses a fixed pool rotated per slot.
- Security considerations: Spec/code divergence risks incompatible third-party implementations and consensus splits if treated as authoritative.
- Test impact: Documentation-only change; no tests updated.
- Verdict (Risk/Confidence/Status): HIGH / HIGH / Suspicious
- Recommended follow-ups: Define an explicit upgrade/compatibility path for transaction format and shred wire layouts; align schedule and attestation rules with implementation.

## Cross-cutting concerns (delta vs upstream)
- Behavioral changes that span commits:
  - MCP consensus/replay/voting modules were removed; only isolated type definitions remain in ledger/svm/turbine without integration.
  - MCP types were moved into existing files but lack call sites, so the pipeline ignores MCP paths.
  - Constants remain duplicated across crates (`ledger/src/mcp.rs`, `ledger/src/shred.rs`, `svm/src/account_loader.rs`), risking drift.
  - The new spec is detailed but still mismatches wire formats and runtime behavior.
- Agave integration gaps (where implementation should actually live):
  - MCP schedules in `ledger/src/leader_schedule.rs` are not used by `turbine/src/cluster_nodes.rs` or `core/src/window_service.rs`.
  - Proposer distribution types in `turbine/src/broadcast_stage.rs` are not invoked by `broadcast_stage/standard_broadcast_run.rs`.
  - Relay validation types in `turbine/src/sigverify_shreds.rs` are not invoked by the sigverify pipeline or window_service; Merkle proofs are never checked.
  - Fee payer validation and fee-only phase in `svm/src/account_loader.rs` are not called by `svm/src/transaction_processor.rs` or `runtime/src/bank.rs`.
  - Consensus block construction, attestation aggregation, voting, and replay reconstruction have no integration points in `core/src/replay_stage.rs` or `core/src/consensus.rs`.
  - Blockstore MCP columns are not read/written in `ledger/src/blockstore.rs`.
- Current integration status (post-efe05fc3cc):
  - `ledger/src/leader_schedule.rs` contains MCP schedule types but no consumers.
  - `turbine/src/broadcast_stage.rs` defines MCP proposer distribution types but no broadcaster uses them.
  - `turbine/src/sigverify_shreds.rs` defines MCP relay validation types but no packet path calls them.
  - `svm/src/account_loader.rs` defines MCP fee payer and fee-phase types but they are unused.
  - `ledger/src/mcp_attestation.rs` defines wire format without any producer/consumer.
  - `core/src/mcp_*` modules removed; consensus, replay, and voting logic is absent.
## Issue-by-issue integration map (where changes should actually live)
- #1 MCP-18 Replay: output ordered transactions
  - Integrate into `core/src/replay_stage.rs`, `ledger/src/blockstore_processor.rs`, and execution ordering in `runtime/src/bank.rs`.
- #2 MCP-03 Blockstore multi-proposer + consensus/execution separation
  - Wire into `ledger/src/blockstore.rs`, `ledger/src/blockstore_db.rs`, `core/src/window_service.rs`, and `core/src/replay_stage.rs` (consensus payload vs execution output columns).
- #3 MCP-06 Proposer: encode and commit (FEC 40/160)
  - Implement in `ledger/src/shred.rs`, `ledger/src/shred/merkle.rs`, `turbine/src/broadcast_stage/standard_broadcast_run.rs`, and `turbine/src/sigverify_shreds.rs`.
- #4 MCP-01 Protocol constants
  - Centralize in `ledger/src/mcp.rs` but enforce consumption in `core/src/*`, `turbine/src/*`, `svm/src/*`, `runtime/src/*` to remove duplicates.
- #5 MCP-02 Proposer/Relay/Leader schedules
  - Merge into `ledger/src/leader_schedule_utils.rs` and `ledger/src/leader_schedule_cache.rs`, with use in `core/src/window_service.rs` and `turbine/src/cluster_nodes.rs`.
- #6 MCP-08 Fee payer anti-DA
  - Enforce in `svm/src/transaction_processor.rs` and `runtime/src/bank.rs` (not just helper structs).
- #7 MCP-05 Shred format proposer_id
  - Update canonical shred parser/serializer `ledger/src/shred.rs`, `ledger/src/shred/wire.rs`, `ledger/src/shred/merkle.rs`.
- #8 MCP-17 Fee-only replay pass
  - Integrate into `core/src/replay_stage.rs` and `runtime/src/bank.rs` execution pipeline.
- #9 MCP-10 Relay: record attestation
  - Implement storage in `ledger/src/blockstore.rs` and ingestion in `core/src/window_service.rs`.
- #10 MCP-19 Bankless proposer/leader
  - Integrate with `core/src/banking_stage.rs`, `runtime/src/bank.rs`, and vote/consensus hooks in `core/src/replay_stage.rs`.
- #11 MCP-07 Proposer distribute shreds to relays
  - Implement in `turbine/src/broadcast_stage/standard_broadcast_run.rs` and relay intake in `turbine/src/sigverify_shreds.rs`.
- #12 MCP-09 Relay process/verify shreds
  - Hook into `turbine/src/sigverify_shreds.rs` and `core/src/window_service.rs` to enforce per-relay checks.
- #13 MCP-11 Relay submit attestations
  - Wire into `core/src/cluster_info_vote_listener.rs` or a dedicated gossip/TPU path; use shared attestation format in `ledger/src/mcp_attestation.rs`.
- #14 MCP-12 Consensus leader aggregate relay attestations
  - Integrate into `core/src/consensus.rs` or leader block construction in `core/src/replay_stage.rs`.
- #15 MCP-13 Consensus leader broadcast block via turbine
  - Implement in `turbine/src/broadcast_stage/standard_broadcast_run.rs` with payload serialization in `core/src/replay_stage.rs` or `core/src/consensus.rs`.
- #16 MCP-14 Voting validate/vote on blocks
  - Integrate into `core/src/replay_stage.rs` and `core/src/consensus.rs` vote flow.
- #17 MCP-15 Replay handle empty slots
  - Implement in `core/src/replay_stage.rs` and persist to execution output column in `ledger/src/blockstore.rs`.
- #18 MCP-16 Replay reconstruct from shreds
  - Implement in `core/src/replay_stage.rs` using canonical shred/merkle utilities in `ledger/src/shred/*`.
- #19 MCP-04 Transaction format update
  - Implement in `sdk/src/message/*`, `sdk/src/transaction.rs`, `fee/src/*`, and `runtime/src/bank.rs` fee calculation.
- Spec divergence risk:
  - `mcp_spec.md` defines new wire formats and transaction layout that are not implemented in Agave; treat the spec as aspirational until the pipeline is wired.
  - Packet sizing and MTU assumptions are still implicit for integration with existing shred/turbine paths.
- Spec-as-source-of-truth deviations (current):
  - [OPEN] Committee selection: spec requires per-slot rotation with sampling a new validator; `ledger/src/leader_schedule.rs` only rotates a fixed pool.
  - [OPEN] MCP shred wire format: spec defines fixed 1225-byte `McpShredV1` with `witness_len` u8=8; code uses variable-length relay/proposer messages and legacy `Shred` layout.
  - [OPEN] Merkle commitments and RS encoding/decoding are not implemented; no proof verification in relay path.
  - [OPEN] Relay attestations: spec includes proposer signatures per entry and domain-separated signatures; `ledger/src/mcp_attestation.rs` omits proposer_signature and has different signing rules.
  - [OPEN] Transaction layout: spec defines a new header with `transaction_config_mask` and `target_proposer` as u32; no SDK/runtime support exists and code still uses `Pubkey`.
  - [OPEN] Consensus payload/voting/replay: spec defines `McpBlockV1`, `McpVoteV1`, and `computeImpliedBlocks`; no corresponding runtime integration exists.
  - [OPEN] Storage schema: spec suggests `McpShred`/`McpRelayAttestation`/`McpBlock`; code uses different column families and does not store MCP data.
- API compatibility concerns:
  - MCP transaction format changes are not wired into SDK/runtime; external clients would be incompatible with current nodes.
  - Legacy `Shred` format vs `McpShredV1` is unresolved; no versioning/feature gating in the pipeline.
- Dependency changes:
  - No new dependencies; MCP types live in existing crates.
- Performance/regression risks:
  - Missing call sites mean witness limits, batch size limits, and fee checks are not enforced in the real pipeline.
  - Relay/proposer message parsing remains variable-length and unbounded in turbine paths, risking DoS once integrated.

## Commands run + results (this iteration)
- `ls`
  - Result: listed repository root contents.
- `rg --files -g '*issue*' -g '*ISSUE*'`
  - Result: no matching files.
- `sed -n '1,200p' mcp_spec.md`
  - Result: reviewed MCP spec header and constants.
- `sed -n '1,200p' codex_audit.sh`
  - Result: reviewed audit script behavior.
- `rg -n "issue" -S docs mcp_spec.md README.md codex.md`
  - Result: located prior issue snapshot in `codex.md`.
- `sed -n '1,220p' codex.md`
  - Result: reviewed prior audit content.
- `git log --oneline -n 20`
  - Result: identified new commits since last audit.
- `git show --stat fbe9f1e5b4`
  - Result: MCP fixes in standalone modules.
- `git show --stat 062618c036`
  - Result: codex.md update only.
- `git show --stat addb78f334`
  - Result: MCP modules removed (later reverted).
- `git show --stat 19d3a4ab6c`
  - Result: revert of removal.
- `git show --stat efe05fc3cc`
  - Result: MCP types moved into existing modules; core MCP modules removed.
- `git show --stat d3f8032859`
  - Result: replaced `mcp_spec.md`.
- `sed -n '1,220p' ledger/src/mcp.rs`
  - Result: reviewed MCP constants and transaction config types.
- `rg -n "Mcp|mcp" ledger/src/leader_schedule.rs`
  - Result: located MCP schedule integration.
- `sed -n '1,220p' ledger/src/leader_schedule.rs`
  - Result: reviewed MCP schedule logic.
- `rg -n "MCP|Mcp|mcp" turbine/src/broadcast_stage.rs`
  - Result: located MCP proposer types.
- `sed -n '1,260p' turbine/src/broadcast_stage.rs`
  - Result: reviewed proposer relay message layout.
- `rg -n "MCP|mcp|RelayShred" turbine/src/sigverify_shreds.rs`
  - Result: located MCP relay processor types.
- `sed -n '600,900p' turbine/src/sigverify_shreds.rs`
  - Result: reviewed relay shred processing logic.
- `rg -n "McpFee|fee payer|mcp" svm/src/account_loader.rs`
  - Result: located MCP fee payer helpers.
- `sed -n '1,220p' svm/src/account_loader.rs`
  - Result: reviewed MCP fee payer and fee-phase types.
- `rg -n "mcp_attestation" -S core ledger turbine svm`
  - Result: only `ledger/src/mcp_attestation.rs` is present.
- `sed -n '1,220p' ledger/src/mcp_attestation.rs`
  - Result: reviewed relay attestation wire format.
- `rg -n "committee|rotation|schedule" mcp_spec.md`
  - Result: located spec committee rules.
- `sed -n '450,620p' mcp_spec.md`
  - Result: reviewed transaction format and proposer/relay ops.
- `rg -n "Merkle" mcp_spec.md`
  - Result: located Merkle proof spec.
- `sed -n '220,320p' mcp_spec.md`
  - Result: reviewed Merkle and RS encoding spec.
- `sed -n '720,820p' mcp_spec.md`
  - Result: reviewed storage schema and security notes.
- `date -u +\"%Y-%m-%dT%H:%M:%SZ\"`
  - Result: 2026-01-22T21:14:43Z
- `date -u +\"%Y-%m-%dT%H:%M:%SZ\"`
  - Result: 2026-01-23T01:59:11Z
- `date -u +\"%Y-%m-%dT%H:%M:%SZ\"`
  - Result: 2026-01-23T02:47:38Z
- `date -u +\"%Y-%m-%dT%H:%M:%SZ\"`
  - Result: 2026-01-23T03:32:23Z
