# MCP Audit Snapshot (spec vs code)
- Repo: /home/anatoly/mcp
- Audit time: 2026-01-23T05:05:10Z
- Spec reviewed: `mcp_spec.md` (source of truth)
- GitHub issues: 20 open items (includes PR #21)
- Assumption: lazy implementation; comments are not trusted

## Verdict
- MCP is not implemented to `mcp_spec.md` and not fully wired into Agave.
- Only partial MCP shred handling runs (size-based detection + signature checks); consensus, replay, and voting are not integrated.
- Multiple MCP formats exist in code and disagree with the spec and each other, creating drift risk.

## Spec Compliance Gaps (with evidence)
- **Proposer signature message mismatch**: spec signs commitment only (`mcp_spec.md:346-351`), but code signs `slot || proposer_index || commitment` (`ledger/src/shred/mcp_shred.rs:277-289`, `ledger/src/mcp_attestation.rs:97-105`).
- **MCP shred generation not spec-compliant**: spec requires RS-encoding a payload then constructing `McpShredV1` (`mcp_spec.md:548-557`), but broadcast code repackages existing legacy shreds and their payloads (`turbine/src/broadcast_stage/standard_broadcast_run.rs:658-699`) with no RS encoding.
- **MCP shred detection is size-only**: spec requires versioned format validation (`mcp_spec.md:361-383`), but detection is `len == 1225` (`ledger/src/shred/mcp_shred.rs:393-396`, `core/src/window_service.rs:214-217`, `turbine/src/sigverify_shreds.rs:905-910`).
- **Merkle proof verification is incorrect**: spec requires witness to open the full commitment (`mcp_spec.md:374-381`, `mcp_spec.md:564-575`). Code verifies against only the first 20 bytes of commitment (`ledger/src/mcp_merkle.rs:97-120`) and does not enforce the spec’s root semantics.
- **Relay attestation format mismatch**: spec uses `proposer_index: u32` and includes proposer signatures (`mcp_spec.md:395-416`). Code defines two incompatible formats: `ledger/src/mcp_attestation.rs` uses `proposer_index: u8` (`ledger/src/mcp_attestation.rs:48-55`) while `ledger/src/shred/mcp_shred.rs` uses `u32` (`ledger/src/shred/mcp_shred.rs:423-456`). Consensus block code consumes the `u8` format (`core/src/mcp_consensus_block.rs:18-20`).
- **Consensus payload type mismatch**: spec defines `AggregateAttestationV1` and block hash rules (`mcp_spec.md:418-418+`, `mcp_spec.md:602-618`), while code defines `McpBlockV1` in a separate module and does not wire it into consensus (`core/src/mcp_consensus_block.rs:1-80`).
- **Transaction header format missing**: spec adds `transaction_config_mask` in the header and `target_proposer: u32` (`mcp_spec.md:500-511`), but code defines a separate blob with a 1-byte mask and `target_proposer: Pubkey` (`ledger/src/mcp.rs:216-262`) and does not wire parsing into SDK/runtime.
- **McpPayloadV1 not implemented**: spec defines `McpPayloadV1` and `tx_len: u16` (`mcp_spec.md:318-333`); no serialization/parsing exists in replay or banking.
- **Relay verification rules not enforced**: spec requires witness_len==8 and Merkle verification with relay assignment (`mcp_spec.md:564-576`); code verifies relay assignment but does not enforce `witness_len` or full Merkle validity in the relay path (`turbine/src/sigverify_shreds.rs:929-957`).

## Wiring Gaps (code exists but not integrated)
- **Window service** stores MCP shreds by size only and does not validate availability or feed replay (`core/src/window_service.rs:214-253`).
- **Consensus/voting**: `core/src/mcp_consensus_block.rs` is not referenced by `core/src/consensus.rs` or `core/src/replay_stage.rs`; MCP block/vote logic is unused.
- **Replay**: no code reconstructs MCP payloads from stored MCP shreds; blockstore has MCP shard getters, but no call sites (`ledger/src/blockstore.rs:3164-3278`).
- **Relay attestations**: no relay path builds/sends attestations; no leader path aggregates them (only formats exist).
- **Fee-only replay**: fee phase helpers exist in `svm/src/account_loader.rs`, but replay does not invoke them.

## Duplicate / Drift-Prone Implementations
- MCP attestation format duplicated with different field widths (`ledger/src/mcp_attestation.rs` vs `ledger/src/shred/mcp_shred.rs`).
- MCP storage schema duplicated (`ledger/src/mcp_storage.rs`) but not wired into blockstore; actual CFs live in `ledger/src/blockstore/column.rs`.
- Multiple MCP constants duplicated across crates (`ledger/src/mcp.rs`, `ledger/src/shred.rs`, `svm/src/account_loader.rs`).

## Issue-by-Issue Missing Work (latest snapshot)
- #21 PR Spec: spec is present but code does not implement the defined wire formats or pipeline behavior (`mcp_spec.md:361-618`).
- #19 MCP-04 Transaction format: no SDK/runtime parsing or fee integration; mismatched config layout and `target_proposer` type (`ledger/src/mcp.rs:216-262`, `mcp_spec.md:500-511`).
- #18 MCP-16 Replay reconstruct: no RS decoding or reconstruction pipeline; MCP shreds only stored (`core/src/window_service.rs:214-253`, `ledger/src/blockstore.rs:3164-3278`).
- #17 MCP-15 Empty slots: no replay-stage handling or execution output persistence.
- #16 MCP-14 Voting: MCP block validation/vote logic exists but is unused; implied block computation skips proposer signature checks (`core/src/mcp_consensus_block.rs:333-368`).
- #15 MCP-13 Consensus broadcast: no turbine path broadcasts MCP blocks; only relay-shred distribution exists (`turbine/src/broadcast_stage/standard_broadcast_run.rs:631-700`).
- #14 MCP-12 Aggregate attestations: no aggregation pipeline; attestation formats conflict (`ledger/src/mcp_attestation.rs:48-55`, `ledger/src/shred/mcp_shred.rs:423-456`).
- #13 MCP-11 Relay submit attestations: no relay emission path; attestation formats inconsistent with spec.
- #12 MCP-09 Relay verify shreds: Merkle verification uses truncated root and relay witness_len is not enforced (`ledger/src/mcp_merkle.rs:97-120`, `turbine/src/sigverify_shreds.rs:929-957`).
- #11 MCP-07 Proposer distribute shreds: broadcaster repackages legacy shreds and does not RS-encode payload (`turbine/src/broadcast_stage/standard_broadcast_run.rs:658-699`).
- #10 MCP-19 Bankless proposer/leader: no bankless integration in banking/replay.
- #9 MCP-10 Record attestation: MCP attestation CFs exist but no writes/reads from pipeline.
- #8 MCP-17 Fee-only replay: helper types exist but replay does not use them.
- #7 MCP-05 Proposer ID in shreds: legacy shred header modified, but MCP shreds are separate; no unified path.
- #6 MCP-08 Fee payer check: MCP fee validation is enforced in transaction processor but relies on a config not parsed from transactions (`svm/src/transaction_processor.rs:633-652`, `ledger/src/mcp.rs:216-262`).
- #5 MCP-02 Schedule: algorithm differs from spec’s seed derivation (spec uses `SHA256("mcp:committee:"||role||epoch)`, code uses `epoch||magic`) (`mcp_spec.md:355-407`, `ledger/src/leader_schedule.rs:275-314`).
- #4 MCP-01 Constants: duplicated and not derived from genesis/config (`ledger/src/mcp.rs:15-60`, `svm/src/account_loader.rs:47-52`).
- #3 MCP-06 Encode/commit: RS encoding and Merkle commitment generation absent in proposer path (`mcp_spec.md:548-557`, `turbine/src/broadcast_stage/standard_broadcast_run.rs:658-699`).
- #2 MCP-03 Blockstore: only MCP shreds stored; no MCP block/attestation/output columns used (`core/src/window_service.rs:214-253`, `ledger/src/blockstore.rs:3164-3278`, `ledger/src/mcp_storage.rs:1-41`).
- #1 MCP-18 Ordered output: no deterministic ordering in replay; no integration with execution output.

## High-Risk Bugs
- Invalid MCP shreds can be accepted because Merkle proof verification is not spec-correct (`ledger/src/mcp_merkle.rs:97-120`, `turbine/src/sigverify_shreds.rs:953-957`).
- Multiple incompatible attestation formats can cause silent consensus splits (`ledger/src/mcp_attestation.rs:48-55`, `ledger/src/shred/mcp_shred.rs:423-456`, `core/src/mcp_consensus_block.rs:18-20`).
- MCP transaction header format mismatch will break clients built to spec (`mcp_spec.md:500-511`, `ledger/src/mcp.rs:216-262`).

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
