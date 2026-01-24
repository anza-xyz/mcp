# MCP Audit Snapshot (spec vs code)
- Repo: /home/anatoly/mcp
- Audit time: 2026-01-23T19:37:05Z
- Spec reviewed: `mcp_spec.md` (latest)
- GitHub issues: 21 open items (includes PR #23 and #21)
- Assumption: lazy implementation; comments are not trusted

## Verdict
- MCP is not fully implemented to `mcp_spec.md` and is not fully wired into Agave.
- Some MCP-specific code paths exist (broadcast + sigverify) but consensus/voting/replay integration is missing.
- **Wire format and merkle proof are now spec-compliant** (shred size=1393, witness hash size=32, relay_index=u32).
- Transaction format still diverges from the spec (missing transaction_config_mask parsing).

## Spec Compliance Gaps (with evidence)
- **[FIXED] Shred wire format mismatch**: Code now uses 1393-byte shreds with 32-byte witness hashes per spec §7.2. SHRED_DATA_BYTES=1024, MERKLE_PROOF_ENTRY_BYTES=32 (`ledger/src/shred/mcp_shred.rs:30-50`).
- **[FIXED] Witness hash size mismatch**: Code now uses full 32-byte hashes per witness entry, matching spec §6 (`ledger/src/mcp_merkle.rs:36-48`).
- **[FIXED] MCP shred detection**: Detection now validates both size (1393 bytes) and witness_len field (8), providing format-driven detection (`ledger/src/shred/mcp_shred.rs:409-416`).
- **Consensus block format mismatch**: spec defines `ConsensusBlock` with aggregate length and consensus meta; code implements `McpBlockV1` with different fields and block hash computation (`mcp_spec.md:391-419`, `core/src/mcp_consensus_block.rs:135-195`).
- **[FIXED] Relay attestation format**: Code now uses `relay_index: u32` per spec §7.3 (`ledger/src/mcp_attestation.rs:133-134`).
- **Proposer signature message mismatch**: spec signs only commitment bytes (`mcp_spec.md:314-315`), code signs commitment only in `McpShredV1` but other components still assume slot/proposer binding in comments and call sites (check `ledger/src/mcp_attestation.rs:99-105`).
- **Transaction header format not integrated**: spec defines `transaction_config_mask` in the transaction header and `target_proposer: u32` (`mcp_spec.md:500-511`), but the SDK/runtime do not parse it; MCP config lives in `ledger/src/mcp.rs` and is not wired to transaction parsing or fee calculation (`ledger/src/mcp.rs:206-320`).
- **McpPayloadV1 format not implemented**: spec defines payload encoding/tx_len u16 and padding (`mcp_spec.md:318-343`), but no serialization or parsing exists in replay or proposer path.
- **Consensus block ID semantics mismatch**: spec states block_id is consensus-defined and not computed from aggregate bytes (`mcp_spec.md:401-404`); code computes block hash from payload bytes (`core/src/mcp_consensus_block.rs:232-244`).

## Wiring Gaps (code exists but not integrated)
- **Broadcast path**: new MCP broadcast path accumulates txs but there is no guarantee the produced shreds match the spec’s variable-length witness and payload format; still no integration into consensus payload flow (`turbine/src/broadcast_stage/standard_broadcast_run.rs:664-699`).
- **Sigverify path**: MCP shreds are verified by size and signature; no integration with consensus/replay to enforce availability thresholds (`turbine/src/sigverify_shreds.rs:905-959`).
- **Window service**: MCP shreds are inserted by length but not used to reconstruct payloads or produce execution output (`core/src/window_service.rs:214-253`).
- **Consensus/voting**: `core/src/mcp_consensus_block.rs` is not invoked from `core/src/consensus.rs` or `core/src/replay_stage.rs`.
- **Replay**: no RS decode or payload reconstruction pipeline; MCP data shreds are stored only (`ledger/src/blockstore.rs:3164-3278`).

## Duplicate / Drift-Prone Implementations
- MCP attestation format appears in `ledger/src/mcp_attestation.rs` and `core/src/mcp_consensus_block.rs` with different framing than the spec.
- MCP wire formats are split between `ledger/src/shred/mcp_shred.rs` and `mcp_spec.md` with conflicting witness sizing rules.
- MCP constants are duplicated across crates without genesis/config binding (`ledger/src/mcp.rs:15-60`, `svm/src/account_loader.rs:47-52`).

## Issue-by-Issue Missing Work (latest snapshot)
- #23/#21 PR Spec: spec-only changes; code not updated to match wire formats or consensus payload definitions.
- #19 MCP-04 Transaction format: no SDK/runtime parsing or fee integration (`ledger/src/mcp.rs:206-320`, `mcp_spec.md:500-511`).
- #18 MCP-16 Replay reconstruct: no RS decoding or replay pipeline (`ledger/src/blockstore.rs:3164-3278`, `core/src/window_service.rs:214-253`).
- #17 MCP-15 Empty slots: no replay-stage handling or execution output persistence.
- #16 MCP-14 Voting: no integration of MCP block validation into vote flow (`core/src/mcp_consensus_block.rs` unused).
- #15 MCP-13 Consensus broadcast: no turbine path broadcasts consensus MCP block (`core/src/mcp_consensus_block.rs` unused).
- #14 MCP-12 Aggregate attestations: aggregation not wired; consensus payload format mismatch (`mcp_spec.md:357-389`, `core/src/mcp_consensus_block.rs:135-195`).
- #13 MCP-11 Relay submit attestations: no relay attestation send path; format mismatch vs spec (`ledger/src/mcp_attestation.rs:6-40`).
- #12 MCP-09 Relay verify shreds: **[FIXED]** witness now uses 32-byte hashes, detection validates format not just size (`ledger/src/shred/mcp_shred.rs:36-44, 409-416`).
- #11 MCP-07 Proposer distribute shreds: broadcaster still does not use spec payload encoding and RS encoding is not clearly implemented (`turbine/src/broadcast_stage/standard_broadcast_run.rs:664-699`).
- #10 MCP-19 Bankless proposer/leader: no integration in banking or replay.
- #9 MCP-10 Record attestation: MCP attestation CFs exist but no write/read paths.
- #8 MCP-17 Fee-only replay: no replay integration; fee-only two-pass not used.
- #7 MCP-05 Proposer ID in shreds: legacy shred header updates are separate from MCP shreds; spec now uses `proposer_index` u32 in MCP shreds.
- #6 MCP-08 Fee payer check: enforcement exists but relies on MCP config not parsed from transactions (`svm/src/transaction_processor.rs:633-652`, `ledger/src/mcp.rs:206-320`).
- #5 MCP-02 Schedule: schedule uses spec seed format but not wired into consensus/replay; integration gaps remain (`ledger/src/leader_schedule.rs:275-317`).
- #4 MCP-01 Constants: duplicated and not derived from genesis/config (`ledger/src/mcp.rs:15-60`).
- #3 MCP-06 Encode/commit: RS encoding and merkle commitments not tied to spec payload format (`mcp_spec.md:548-557`, `turbine/src/broadcast_stage/standard_broadcast_run.rs:664-699`).
- #2 MCP-03 Blockstore: only MCP shreds stored; consensus/execution outputs not persisted.
- #1 MCP-18 Ordered output: no deterministic ordering in replay.

## High-Risk Bugs
- **[FIXED]** ~~Variable-length witness format in spec cannot interoperate with fixed-length MCP shreds in code.~~ Code now uses 32-byte witness hashes matching spec.
- Consensus block ID semantics differ; vote validity could diverge across implementations.
- **[FIXED]** ~~Attestation format mismatch can cause leader/validator incompatibility.~~ Code now uses relay_index: u32 per spec §7.3.

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
