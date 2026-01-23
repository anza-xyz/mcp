# MCP Audit Snapshot (spec vs code)
- Repo: /home/anatoly/mcp
- Audit time: 2026-01-23T15:02:26Z
- Spec reviewed: `mcp_spec.md` (source of truth)
- GitHub issues: 20 open items (includes PR #21)
- Assumption: lazy implementation; comments are not trusted

## Verdict
- MCP is not implemented to `mcp_spec.md` and is not fully wired into Agave.
- Only partial MCP shred handling runs (size-based detection + signature checks); consensus, replay, and voting are not integrated.
- Multiple MCP formats exist in code and disagree with the spec and each other, creating drift risk.

## Spec Compliance Gaps (with evidence)
- **Proposer signature message**: FIXED - Code now uses `"mcp:commitment:v1" || commitment32` per spec §5.2 (`ledger/src/shred/mcp_shred.rs:285-289`, `ledger/src/mcp_attestation.rs:103-106`).
- **MCP shred generation not spec-compliant**: spec requires RS-encoding a payload then constructing `McpShredV1` (`mcp_spec.md:548-557`), but broadcast code repackages existing legacy shreds and their payloads (`turbine/src/broadcast_stage/standard_broadcast_run.rs:658-699`) with no RS encoding.
- **MCP shred detection**: FIXED - `is_mcp_shred_packet()` now validates both size (1225 bytes) and witness_len field (must be 8) per spec §6.1 (`ledger/src/shred/mcp_shred.rs:399-406`).
- **Merkle proof verification**: FIXED - Code now correctly compares full 32-byte root against commitment per spec §4.4.5 (`ledger/src/mcp_merkle.rs:97-130`).
- **Relay attestation format**: FIXED - All modules now use `proposer_index: u32` consistently (`ledger/src/mcp_attestation.rs:50`, `ledger/src/shred/mcp_shred.rs`, `core/src/mcp_consensus_block.rs`).
- **Consensus payload type mismatch**: spec defines `AggregateAttestationV1` and block hash rules (`mcp_spec.md:418-618`), while code defines `McpBlockV1` in a separate module and does not wire it into consensus (`core/src/mcp_consensus_block.rs:1-80`).
- **Transaction header format**: PARTIALLY FIXED - `McpTransactionConfig` uses correct types (4-byte mask, `target_proposer: u32`) per spec §7.2 (`ledger/src/mcp.rs:219-263`). Remaining: wire parsing into SDK/runtime.
- **McpPayloadV1 not implemented**: spec defines `McpPayloadV1` and `tx_len: u16` (`mcp_spec.md:318-333`); no serialization/parsing exists in replay or banking.

## Wiring Gaps (code exists but not integrated)
- **Window service**: PARTIALLY FIXED - Now validates format via `is_mcp_shred_packet()` and feeds replay via `mcp_reconstruction_sender`. Relay attestation creation wired with keypair.
- **Consensus/voting**: PARTIALLY FIXED - `mcp_consensus_block.rs` imported in replay_stage; `AttestationAggregator` wired; `mcp_block_sender` wired to retransmit_stage.
- **Replay**: PARTIALLY FIXED - `reconstruct_slot()` wired in replay_stage for MCP payload reconstruction; `TwoPhaseProcessor` initialized with ordered transactions.
- **Relay attestations**: PARTIALLY FIXED - `RelayAttestationService` creates signed attestations with keypair; leader `AttestationAggregator` wired. Remaining: UDP send to leader.
- **Fee-only replay**: PARTIALLY FIXED - `TwoPhaseProcessor` initialized with `set_ordered_transactions()`. Remaining: integrate with blockstore_processor execution.

## Duplicate / Drift-Prone Implementations
- MCP attestation format: FIXED - All modules now use consistent u32 field widths.
- MCP storage schema duplicated (`ledger/src/mcp_storage.rs`) but not wired into blockstore; actual CFs live in `ledger/src/blockstore/column.rs`.
- Multiple MCP constants: PARTIALLY FIXED - `MIN_RELAYS_FOR_BLOCK` consolidated; `MCP_NUM_PROPOSERS` still duplicated with TODO.

## Issue-by-Issue Missing Work (latest snapshot)
- #21 PR Spec: spec is present but code does not implement the defined wire formats or pipeline behavior (`mcp_spec.md:361-618`).
- #19 MCP-04 Transaction format: PARTIALLY FIXED - `McpTransactionConfig` has correct types (u32 mask, u32 target_proposer); remaining: SDK/runtime parsing integration.
- #18 MCP-16 Replay reconstruct: PARTIALLY FIXED - `reconstruct_slot()` and RS decoding wired in replay_stage; remaining: full integration with bank execution.
- #17 MCP-15 Empty slots: no replay-stage handling or execution output persistence.
- #16 MCP-14 Voting: FIXED - `compute_implied_blocks_with_verification()` now called with proposer pubkeys from `leader_schedule_cache.get_proposers_at_slot()` in replay_stage (`core/src/replay_stage.rs:2733-2755`).
- #15 MCP-13 Consensus broadcast: MOSTLY FIXED - `mcp_block_sender` wired replay_stage -> retransmit_stage; remaining: actual broadcast logic in retransmit.
- #14 MCP-12 Aggregate attestations: PARTIALLY FIXED - `AttestationAggregator` wired in replay_stage main loop; format consistency now fixed (all u32).
- #13 MCP-11 Relay submit attestations: MOSTLY FIXED - `RelayAttestationService` creates attestations with keypair; remaining: UDP send to leader.
- #12 MCP-09 Relay verify shreds: FIXED - Merkle verification now correctly compares full 32-byte root against commitment.
- #11 MCP-07 Proposer distribute shreds: broadcaster repackages legacy shreds and does not RS-encode payload (`turbine/src/broadcast_stage/standard_broadcast_run.rs:658-699`).
- #10 MCP-19 Bankless proposer/leader: no bankless integration in banking/replay.
- #9 MCP-10 Record attestation: PARTIALLY FIXED - `McpRelayAttestation` column added with put/get methods (`ledger/src/blockstore/column.rs:372-381`, `ledger/src/blockstore.rs:3337-3358`); remaining: wire writes from attestation aggregation path.
- #8 MCP-17 Fee-only replay: PARTIALLY FIXED - `TwoPhaseProcessor` initialized in replay_stage with ordered transactions; remaining: integrate with blockstore_processor execution.
- #7 MCP-05 Proposer ID in shreds: legacy shred header modified, but MCP shreds are separate; no unified path.
- #6 MCP-08 Fee payer check: MCP fee validation is enforced in transaction processor but relies on a config not parsed from transactions (`svm/src/transaction_processor.rs:633-652`, `ledger/src/mcp.rs:216-262`).
- #5 MCP-02 Schedule: algorithm differs from spec's seed derivation (spec uses `SHA256("mcp:committee:"||role||epoch)`, code uses `epoch||magic`) (`mcp_spec.md:155-206`, `ledger/src/leader_schedule.rs:275-314`).
- #4 MCP-01 Constants: PARTIALLY FIXED - `MIN_RELAYS_FOR_BLOCK` consolidated; remaining: move `MCP_NUM_PROPOSERS` to shared crate.
- #3 MCP-06 Encode/commit: RS encoding and Merkle commitment generation absent in proposer path (`mcp_spec.md:548-557`, `turbine/src/broadcast_stage/standard_broadcast_run.rs:658-699`).
- #2 MCP-03 Blockstore: PARTIALLY FIXED - MCP shreds, consensus payload, execution output, and relay attestation columns now exist with put/get methods; remaining: wire writes from pipeline (`ledger/src/blockstore/column.rs:292-381`, `ledger/src/blockstore.rs:3303-3358`).
- #1 MCP-18 Ordered output: FIXED - `build_ordered_transactions()` provides deterministic ordering (proposers 0..15, first occurrence wins); `TwoPhaseProcessor` integration added in replay_stage.rs.

## High-Risk Bugs
- ~~Invalid MCP shreds can be accepted because Merkle proof verification is not spec-correct~~ FIXED - Now compares full 32-byte root.
- ~~Multiple incompatible attestation formats can cause silent consensus splits~~ FIXED - All modules now use u32 for proposer_index.
- ~~MCP transaction header format mismatch will break clients built to spec~~ PARTIALLY FIXED - Types are correct; remaining: SDK/runtime parsing.

## Commands Run
- `curl -sL "https://api.github.com/repos/anza-xyz/mcp/issues?state=open&per_page=100"`
- `python3 - <<'PY' ... PY` (issue list)
- `date -u +"%Y-%m-%dT%H:%M:%SZ"`
- `nl -ba mcp_spec.md | sed -n '310,620p'`
- `nl -ba turbine/src/broadcast_stage/standard_broadcast_run.rs | sed -n '620,700p'`
- `nl -ba turbine/src/sigverify_shreds.rs | sed -n '900,1040p'`
- `nl -ba core/src/window_service.rs | sed -n '200,280p'`
- `nl -ba ledger/src/shred/mcp_shred.rs | sed -n '10,330p'`
- `nl -ba ledger/src/mcp_merkle.rs | sed -n '80,140p'`
- `nl -ba ledger/src/mcp_attestation.rs | sed -n '1,120p'`
- `nl -ba core/src/mcp_consensus_block.rs | sed -n '1,380p'`
- `nl -ba ledger/src/mcp.rs | sed -n '200,320p'`
- `nl -ba ledger/src/leader_schedule.rs | sed -n '260,360p'`
- `nl -ba svm/src/transaction_processor.rs | sed -n '620,700p'`
