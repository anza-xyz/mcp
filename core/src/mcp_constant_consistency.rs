#[test]
fn test_mcp_num_proposers_constant_matches_ledger() {
    assert_eq!(
        solana_fee::MCP_NUM_PROPOSERS,
        solana_ledger::mcp::NUM_PROPOSERS
    );
}

#[test]
fn test_mcp_shred_constants_match_ledger_protocol_constants() {
    assert_eq!(
        solana_ledger::shred::mcp_shred::MCP_NUM_PROPOSERS,
        solana_ledger::mcp::NUM_PROPOSERS
    );
    assert_eq!(
        solana_ledger::shred::mcp_shred::MCP_NUM_RELAYS,
        solana_ledger::mcp::NUM_RELAYS
    );
    assert_eq!(
        solana_ledger::shred::mcp_shred::MCP_SHRED_DATA_BYTES,
        solana_ledger::mcp::SHRED_DATA_BYTES
    );
}

#[test]
fn test_mcp_erasure_constants_match_ledger_protocol_constants() {
    assert_eq!(
        solana_ledger::mcp_erasure::MCP_NUM_RELAYS,
        solana_ledger::mcp::NUM_RELAYS
    );
    assert_eq!(
        solana_ledger::mcp_erasure::MCP_SHRED_DATA_BYTES,
        solana_ledger::mcp::SHRED_DATA_BYTES
    );
    assert_eq!(
        solana_ledger::mcp_erasure::MCP_MAX_PAYLOAD_BYTES,
        solana_ledger::mcp::MAX_PROPOSER_PAYLOAD
    );
}

#[test]
fn test_mcp_reconstruction_constants_match_ledger_protocol_constants() {
    assert_eq!(
        solana_ledger::mcp_reconstruction::MCP_RECON_NUM_SHREDS,
        solana_ledger::mcp::NUM_RELAYS
    );
    assert_eq!(
        solana_ledger::mcp_reconstruction::MCP_RECON_SHRED_BYTES,
        solana_ledger::mcp::SHRED_DATA_BYTES
    );
    assert_eq!(
        solana_ledger::mcp_reconstruction::MCP_RECON_MAX_PAYLOAD_BYTES,
        solana_ledger::mcp::MAX_PROPOSER_PAYLOAD
    );
}
