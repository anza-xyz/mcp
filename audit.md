# MCP Adversarial Audit — Votor Hardening + Integration Test Expansion (Master)

Date: 2026-02-13
Branch: `master` (commit `965da326b7`)
Perspective: Principal engineer + security researcher, assuming adversarial/lazy developer.
Scope: **Verify claimed V1, NEW-1, and NEW-2 fixes are genuine (not lazy relocations), confirm prior MCP fixes intact, run integration test.**

---

## Executive Summary

Two new commits: (1) `631f9a5606` expands the integration test to verify that every included proposer's payload contains at least one executed transaction (significant test strengthening), (2) `c98afd85e6` hardens votor consensus by replacing 3 panics with soft error handling and adding a 3-level leader lookup fallback.

All prior MCP fixes (H1, H2, M1, M2, N1-N4, N6, N7) remain **intact** — no core MCP files modified. Both follow-up fixes verified **genuine**: (a) parent-ready leader-lookup failure handling now has counters, bounded consecutive-failure exit after 32 misses, and watermark advancement moved after successful lookup, (b) `McpPayload::from_bytes` now bounds `tx_count` before allocation with `remaining / sizeof::<u32>()` pattern matching `blockstore_processor.rs`. Integration test **PASS** (108.64s).

### Verdicts

| Area | Status |
|------|--------|
| Local-cluster e2e test | **PASS** (108.64s) — expanded with proposer execution verification |
| Prior MCP fixes (H1, H2, M1, M2, N1-N4, N6, N7) | **ALL INTACT** — no core MCP files modified |
| Votor `consensus_metrics.rs` hardening | **CORRECT** — stale epoch counter, well tested |
| Votor `consensus_pool_service.rs` leader fallback | **FIXED** — failure counters + bounded consecutive-failure exit |
| Votor `voting_utils.rs` panic removal | **CORRECT** — graceful `NoRankFound` return |
| Votor `parent_ready_tracker.rs` min→max | **CORRECT** — builds on newest certified chain tip |
| Integration test expansion | **CORRECT** — strong end-to-end proposer execution verification |
| Plan conformance | **STRONG** — votor changes outside plan scope |
| New findings | **0 HIGH, 0 MEDIUM, 0 LOW** (net new this pass) |

---

## 1. New Commit Analysis

### Commit `631f9a5606`: Integration Test — Proposer Execution Verification

This commit adds substantial end-to-end verification to `test_local_cluster_mcp_produces_blockstore_artifacts`:

**New helper closures:**
- `first_signature_bytes_from_wire_transaction` — extracts raw `[u8; 64]` from MCP or legacy tx formats. MCP-first order matches production code. **CORRECT.**
- `maybe_refresh_transfer_stream` — rate-limits transfer submissions to 2/sec (was ~16/sec). Initial burst of 32 txns provides sufficient base pool. **CORRECT.**
- `included_commitments_for_consensus_block` — derives included proposer commitments from consensus block's aggregate attestation. Uses `filtered_valid_entries` (builds on existing code) + manual equivocation exclusion (`commitments.len() != 1`). Thresholds match production (≥120 attestations, ≥80 inclusions). **CORRECT.**
- `proposer_payload_transactions_for_commitment` — reconstructs proposer payload from blockstore shreds. Faithful copy of production logic in `mcp_replay.rs:455-557` (same shard initialization, iteration, filtering, verification, reconstruction). **CORRECT.**
- `assign_one_executed_tx_for_proposer` — matches proposer payload transactions to execution output by signature with reference counting. **CORRECT.**

**New verification section (after existing test):**
1. Derives included proposer commitments from the already-observed consensus block
2. Waits for non-empty execution output at the consensus slot (120s timeout)
3. Builds executed signature map from execution output transactions
4. For each included proposer: reconstructs payload from shreds, asserts payload non-empty, asserts at least one payload transaction appears in execution output
5. Asserts all expected proposer pubkeys are covered

**Verdict: Strong test strengthening.** This closes a significant coverage gap — the test now verifies the full pipeline from consensus block attestations through shred reconstruction to transaction execution matching at the per-proposer level.

**Note on `filtered_valid_entries`:** Previously flagged as dead code (NEW-3). The integration test is now a caller, though not a production caller. The function itself remains test-only in terms of production paths. Reclassified from MEDIUM to **LOW** since it has an important test consumer.

### Commit `c98afd85e6`: Votor Consensus Hardening

Four changes to the votor (Alpenglow consensus) crate:

#### 1. `consensus_metrics.rs` — Stale epoch handling (CORRECT)

**Old:** `assert!(epoch >= self.current_epoch)` — panics on stale epoch notification.
**New:** Soft return with `stale_epoch_events` counter.

- Counter initialized to 0 in `new()` ✓
- Counter emitted in `end_of_epoch_reporting` datapoint ✓
- Uses `saturating_add` (no overflow) ✓
- Early return prevents epoch regression ✓
- Counter resets on epoch advance (via `Self::new()`) ✓
- Tests cover both stale and forward-advance paths ✓

**Verdict: Clean implementation. No regression risk.** ConsensusMetrics is a telemetry thread, not a consensus-critical path.

#### 2. `parent_ready_tracker.rs` — `min()` to `max()` (CORRECT)

**Old:** `ss.parents_ready.iter().min()` — builds on oldest eligible parent.
**New:** `ss.parents_ready.iter().max()` — builds on newest certified chain tip.

`Block = (Slot, Hash)` with tuple `Ord` — `max()` selects highest slot. All parents in `parents_ready` are certified (notarized or notarize-fallback), so building on any is consensus-safe. The `max()` selection maximizes chain quality by extending the longest certified chain.

**Test updated:** `Parent(genesis)` → `Parent((10, _))` — correctly reflects selecting slot 10 (the highest parent-ready slot) instead of genesis.

**Verdict: Correct liveness optimization. Consensus safety maintained** because all candidates are already certified.

#### 3. `consensus_pool_service.rs` — Leader lookup fallback chain (FIXED)

**Old:** `slot_leader_at(*highest_parent_ready, Some(&root_bank))` — root bank only, fatal exit on failure.
**New:** `working_bank` → `root_bank` → `None` (cached schedule), warn + return on failure.

The 3-level fallback matches the MCP pattern in `mcp_replay.rs:58-62` (`load_proposer_schedule`). **Correct.**

Follow-up fix validates the concern and closes it:
- leader lookup failures now increment explicit stats counters
- consecutive failures are tracked and bounded with a deterministic exit
- watermark advancement no longer happens before a successful leader lookup

This removes the prior silent-skip failure mode.

#### 4. `voting_utils.rs` — Epoch stakes panic removal (CORRECT)

**Old:** `bank.epoch_stakes_from_slot(vote.slot()).unwrap_or_else(|| panic!(...))` — fatal panic.
**New:** Returns `GenerateVoteTxResult::NoRankFound` (existing transient-error variant).

Additionally, `insert_vote_and_create_bls_message` now prefers `working_bank` (if it has epoch stakes for the vote slot) over `root_bank`. This mirrors the leader lookup fallback pattern.

**Test:** `test_panic_on_future_slot` renamed to `test_future_slot_returns_none`, now asserts `Ok(None)` instead of `#[should_panic]`. **Correct behavioral change.**

**Verdict:** Safe. Missing epoch stakes is genuinely transient (startup, epoch boundaries). `NoRankFound` is an existing handled path. Votes are generated per consensus event, so subsequent attempts succeed once the bank advances.

---

## 2. Prior MCP Fix Regression Check

All 8 core MCP files verified unmodified since `e12d4904f9`:

| File | Modified? | Fix Status |
|------|-----------|------------|
| `core/src/mcp_replay.rs` | **No** | N3, N6 fixes intact |
| `core/src/mcp_vote_gate.rs` | **No** | H1 fix intact (real sig verification) |
| `core/src/repair/repair_service.rs` | **No** | N1 fix intact (multi-shred scan) |
| `core/src/repair/serve_repair.rs` | **No** | N4 fix intact (feature gate) |
| `core/src/window_service.rs` | **No** | N7 fix intact (unified constant) |
| `ledger/src/blockstore_processor.rs` | **No** | H2, N2 fixes intact |
| `ledger/src/mcp.rs` | **No** | Constants intact |
| `turbine/src/broadcast_stage/standard_broadcast_run.rs` | **No** | M1 fix intact |

---

## 3. Votor Remaining Crash Vectors

The hardening commit removed 3 panics but votor still has significant crash surface:

**Production-path panics:**
- `consensus_pool_service.rs:423` — `panic!("Must have a block production parent")` when `block_production_parent` returns `ParentNotReady`
- `consensus_pool.rs:90` — `panic!("Validator stake is zero for pubkey: {vote_key}")` during pool initialization
- `consensus_pool.rs:636` — `panic!("Should not happen while certificate pool is single threaded")`
- `voting_utils.rs:183,194,222,224` — Multiple `panic!()` for BLS keypair/authorization failures
- `vote_history.rs:106-208` — Multiple `assert!(slot >= self.root)` invariant checks

**Production-path unwraps:**
- `root_utils.rs:68,128,130,149,152` — RwLock poison + missing bank hash
- `event_handler.rs:103,611` — Channel send failure, missing block_id
- `staked_validators_cache.rs:73,86` — RwLock poison

These are not new findings from this commit but represent the remaining crash surface in votor.

---

## 4. Updated Finding Status

### Findings from this pass (net new):

| ID | Concern | Severity | Status |
|----|---------|----------|--------|
| V1 | `consensus_pool_service.rs` leader lookup silently skips block production on persistent failure | MEDIUM | **FIXED — VERIFIED GENUINE** — watermark moved after successful lookup (line 406), `consecutive_leader_lookup_failures` counter with `saturating_add`, bounded exit after 32 consecutive misses, stats emitted via `parent_ready_leader_lookup_failed` and `parent_ready_leader_lookup_exit` datapoints |

### Findings from prior passes (unchanged):

| ID | Concern | Severity | Status |
|----|---------|----------|--------|
| NEW-1 | `mcp_payload.rs` missing bounds check on `Vec::with_capacity` | MEDIUM | **FIXED — VERIFIED GENUINE** — `remaining / sizeof::<u32>()` check before allocation, new `TxCountExceedsMax` error variant, test sends `u32::MAX` and asserts rejection |
| NEW-2 | `McpReconstructionState` dead code (~90 lines pub API) | MEDIUM | **FIXED — VERIFIED GENUINE** — stateful helper and attempt enum gated to `#[cfg(test)]`, no longer part of production API surface |
| NEW-3 | `canonical_filtered` / `filtered_valid_entries` dead code | **LOW** (downgraded) | **OPEN** — `filtered_valid_entries` now has integration test caller |
| NEW-4–12 | Dead code items, unreachable arms, test gaps, fallback fragility | LOW | **OPEN** |
| M4 | Weak equivocation evidence (hash-only marker) | — | **OPEN** — non-blocking v1 tradeoff |
| N5 | O(n) nonce-less repair scan | — | **OPEN** — non-blocking performance concern |

### All prior fixes:

| ID | Concern | Status |
|----|---------|--------|
| H1 | Vote gate dead code | **FIXED** — verified intact |
| H2 | Bincode-before-MCP parse | **FIXED** — verified intact |
| M1 | Dispatch `any()` short-circuit | **FIXED** — verified intact |
| M2 | Silent reconstruction drops | **FIXED** — verified intact |
| M3 | Missing nonce test | **DISMISSED** |
| N1 | Single-shred repair rate | **FIXED** — verified intact |
| N2 | tx_count OOM vector | **FIXED** — verified intact |
| N3 | Error variant discarded | **FIXED** — verified intact |
| N4 | No serve-side feature gate | **FIXED** — verified intact |
| N6 | Dedup counter missing | **FIXED** — verified intact |
| N7 | Duplicate retention constant | **FIXED** — verified intact |
| L2 | Lock poison panic | **FIXED** |
| L3 | Missing consistency tests | **FIXED** |

### Follow-up Fix Verification (this pass)

- `votor/src/consensus_pool_service.rs`:
  - parent-ready leader lookup now uses the candidate slot without advancing the watermark first.
  - failure path increments `parent_ready_leader_lookup_failed`.
  - persistent failures trigger bounded exit after 32 consecutive misses and increment `parent_ready_leader_lookup_exit`.
- `votor/src/consensus_pool_service/stats.rs`:
  - added datapoints for `parent_ready_leader_lookup_failed` and `parent_ready_leader_lookup_exit`.
- `transaction-view/src/mcp_payload.rs`:
  - added `tx_count` upper-bound validation from remaining payload bytes before `Vec::with_capacity`.
  - added unit test `test_from_bytes_rejects_unbounded_tx_count`.
- `ledger/src/mcp_reconstruction.rs`:
  - `McpReconstructionState` and `McpReconstructionAttempt` are now `#[cfg(test)]`.
  - removes dead production API while preserving existing reconstruction-state unit tests.

---

## 5. Plan Conformance

The MCP plan (`plan.md`, 728 lines, 7 passes) contains zero mentions of votor. These changes are **outside plan scope** — they are companion hardening of the Alpenglow consensus layer that MCP depends on.

MCP-specific plan conformance remains **STRONG** from the prior audit pass (all 7 passes, acceptance invariants, feature gate, thresholds — all verified conformant).

---

## 6. Dead Code Summary (Updated)

| File | Dead Items | Severity |
|------|-----------|----------|
| `mcp_shredder.rs` | Entire module (4 pub fns) | LOW |
| `mcp_reconstruction.rs` | `McpReconstructionState` + 5 methods | **FIXED** (test-only) |
| `mcp_aggregate_attestation.rs` | `canonical_filtered` | LOW (downgraded — `filtered_valid_entries` now used in integration test) |
| `mcp_erasure.rs` | `commitment_root` | LOW |
| `mcp_ordering.rs` | `order_batches_by_fee_desc` | LOW |
| `mcp_merkle.rs` | `witness_for_leaf` | LOW |
| `mcp_shred.rs` | `is_mcp_shred_packet`, `is_mcp_shred_packet_ref` | LOW |
| `mcp_relay_attestation.rs` | `verify_proposer_signatures` | LOW |

---

## 7. Test Coverage Gaps (Updated)

| Gap | Severity |
|-----|----------|
| No test exercising per-variant error counters in `mcp_replay.rs` | LOW |
| No test for dedup counter `mcp-reconstruction-transaction-duplicate-signature-drop` | LOW |
| No negative test for `build_vote_gate_input` with bad relay/proposer signatures | LOW |
| No test for ambiguous bytes (valid as both MCP and bincode) | LOW |
| No end-to-end banking-stage MCP admission test | LOW |

**Newly covered (no longer gaps):**
- Per-proposer execution output verification — now covered by expanded integration test
- Consensus block → included commitment derivation — now covered by integration test

---

## 8. Integration Test — PASS

```
cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture
```

**Result: PASS** (108.64s, exit code 0). 5-node cluster with MCP activation. Test now verifies: shred+attestation+execution artifacts, consensus block, transaction inclusion, cross-node equality, AND per-proposer payload reconstruction with execution output signature matching.

---

## Current Verdict

- Prior MCP fix regressions: **0** (all 8 core MCP files unmodified)
- New high findings: **0**
- New medium findings: **0**
- Votor hardening: **4 of 4 changes CORRECT**
- Integration test expansion: **CORRECT** — significant coverage improvement
- Architectural gaps: **2** (snapshot catch-up, consensus-block recovery) — unchanged
- Non-blocking tracked items: **2** (M4 hash-only evidence, N5 O(n) scan)
- Plan conformance: **STRONG** (votor changes outside plan scope)
- Feature gate: **PASS**
- Integration test: **PASS** (108.64s)
