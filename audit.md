# MCP Audit — Post-Fix Verification (Master)

Date: 2026-02-12
Branch: `master`
Scope: Re-validated latest `audit.md` concerns against code, implemented minimal-diff fixes on `master`, and re-ran targeted + e2e tests.

## Executive Summary

- Prior high and medium findings from the latest audit pass are now closed in code.
- MCP integration remains end-to-end passing in 5-node local cluster.
- Two non-blocking items remain tracked:
  - hash-only equivocation conflict marker (`McpConflictMarker`)
  - O(n) nonce-less outstanding-request match path for MCP repair responses

## Concern Status

| ID | Concern | Status | Evidence |
|---|---|---|---|
| H1 | Vote-gate signature/equivocation checks dead due to pre-filtering | FIXED | `core/src/mcp_replay.rs:181` builds `VoteGateInput` from raw aggregate entries; relay/proposer signatures verified at `core/src/mcp_replay.rs:189` and `core/src/mcp_replay.rs:200`. |
| H2 | Replay bridge parsed bincode before MCP, losing MCP fee components | FIXED | MCP parse now first at `ledger/src/blockstore_processor.rs:1778`, bincode fallback second at `ledger/src/blockstore_processor.rs:1789`. |
| M1 | Dispatch `any()` short-circuit skipped remaining proposer indices | FIXED | `turbine/src/broadcast_stage/standard_broadcast_run.rs:872` iterates all proposer indices without early return; targeted-proposer path no longer aborts batch at `turbine/src/broadcast_stage/standard_broadcast_run.rs:861`. |
| M2 | Silent reconstruction tx drops | FIXED | Drops now counted with typed cause counters at `core/src/mcp_replay.rs:524`, `core/src/mcp_replay.rs:529`; aggregate drop counter at `core/src/mcp_replay.rs:519`. |
| M3 | Missing nonce fee edge coverage | DISMISSED (already covered) | Existing tests in `runtime/src/bank/tests.rs:1491` and `runtime/src/bank/tests.rs:1535`. |
| M4 | Weak equivocation evidence (hash-only marker) | OPEN (non-blocking v1 tradeoff) | `ledger/src/blockstore.rs:233` intentionally stores deterministic hashes only in `McpConflictMarker`. |
| N1 | MCP repair only requested first missing shred per proposer per scan | FIXED | `core/src/repair/repair_service.rs:706` continues scanning and enqueues multiple missing shreds up to budget. |
| N2 | `tx_count` capacity allocation from untrusted data could OOM | FIXED | Bound check added before allocation at `ledger/src/blockstore_processor.rs:1711`; reject impossible tx_count. |
| N3 | Typed reconstruction metadata error variant discarded | FIXED | Per-variant counters added at `core/src/mcp_replay.rs:524` and `core/src/mcp_replay.rs:529`. |
| N4 | No MCP feature gate on repair serve-side `McpWindowIndex` | FIXED | Serve-side gate added at `core/src/repair/serve_repair.rs:689`; pre-feature requests dropped and counted at `core/src/repair/serve_repair.rs:710`. |
| N6 | No counter for per-proposer duplicate signature drops during reconstruction | FIXED | Counter added at `core/src/mcp_replay.rs:540`. |
| N7 | MCP consensus retention slot constant duplicated in two files | FIXED | Unified via `ledger/src/mcp.rs` (`CONSENSUS_BLOCK_RETENTION_SLOTS`) and consumed in `core/src/mcp_replay.rs:318` and `core/src/window_service.rs:325`. |

## New/Updated Tests

- `core/src/repair/serve_repair.rs`:
  - `test_handle_repair_mcp_window_request_requires_feature_activation`
- `ledger/src/blockstore_processor.rs`:
  - `test_decode_mcp_execution_output_wire_transactions_rejects_unbounded_tx_count`
- `core/src/repair/repair_service.rs` tests updated to validate multi-shred enqueue behavior.

## Validation Runs

All commands succeeded.

- `cargo test -p solana-core test_identify_mcp_repairs_enqueues_missing_shreds -- --nocapture`
- `cargo test -p solana-core test_identify_mcp_repairs_skips_slot_with_final_execution_output -- --nocapture`
- `cargo test -p solana-core test_handle_repair_mcp_window_request_requires_feature_activation -- --nocapture`
- `cargo test -p solana-ledger test_decode_mcp_execution_output_wire_transactions_roundtrip -- --nocapture`
- `cargo test -p solana-ledger test_decode_mcp_execution_output_wire_transactions_rejects_unbounded_tx_count -- --nocapture`
- `cargo test -p solana-core mcp_replay -- --nocapture`
- `cargo test -p solana-core mcp_vote_gate -- --nocapture`
- `cargo test -p solana-turbine test_maybe_dispatch_mcp_shreds_removes_complete_slot_payload_state -- --nocapture`
- `cargo check -p solana-core -p solana-ledger -p solana-turbine`
- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`
  - PASS, 5-node run, finished in 59.49s.

## Current Verdict

- Critical blockers: **0 open**.
- Medium blockers: **0 open**.
- Remaining tracked non-blocking items: **2** (`McpConflictMarker` hash-only evidence, O(n) nonce-less outstanding request scan).
