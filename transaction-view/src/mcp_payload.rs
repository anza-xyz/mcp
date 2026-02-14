use crate::{
    mcp_transaction::{McpTransaction, McpTransactionParseError},
    transaction_view::SanitizedTransactionView,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpPayloadTransactionFormat {
    Latest,
    Legacy,
    StandardSolana,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpPayloadTransaction {
    pub format: McpPayloadTransactionFormat,
    pub wire_bytes: Vec<u8>,
    pub mcp_transaction: Option<McpTransaction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpPayload {
    pub transactions: Vec<McpPayloadTransaction>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpPayloadParseError {
    UnexpectedEof,
    LengthOverflow(u32),
    TxCountExceedsMax {
        tx_count: u32,
        max_count: usize,
    },
    TransactionParse {
        tx_index: usize,
        error: McpTransactionParseError,
    },
    TrailingNonZeroPadding,
}

impl McpPayload {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, McpPayloadParseError> {
        let mut offset = 0usize;
        let tx_count_u32 = take_u32(bytes, &mut offset)?;
        let tx_count = usize::try_from(tx_count_u32)
            .map_err(|_| McpPayloadParseError::LengthOverflow(tx_count_u32))?;
        // Each transaction must include at least a 4-byte length prefix.
        let remaining = bytes.len().saturating_sub(offset);
        let max_count = remaining / std::mem::size_of::<u32>();
        if tx_count > max_count {
            return Err(McpPayloadParseError::TxCountExceedsMax {
                tx_count: tx_count_u32,
                max_count,
            });
        }

        let mut transactions = Vec::with_capacity(tx_count);
        for tx_index in 0..tx_count {
            let tx_len_u32 = take_u32(bytes, &mut offset)?;
            let tx_len = usize::try_from(tx_len_u32)
                .map_err(|_| McpPayloadParseError::LengthOverflow(tx_len_u32))?;
            let tx_bytes = take_bytes(bytes, &mut offset, tx_len)?;

            let (format, mcp_transaction) = match McpTransaction::from_bytes_compat(tx_bytes) {
                Ok(transaction) => {
                    let format = if transaction.to_bytes() == tx_bytes {
                        McpPayloadTransactionFormat::Latest
                    } else {
                        McpPayloadTransactionFormat::Legacy
                    };
                    (format, Some(transaction))
                }
                Err(error) => {
                    SanitizedTransactionView::try_new_sanitized(tx_bytes)
                        .map_err(|_| McpPayloadParseError::TransactionParse { tx_index, error })?;
                    (McpPayloadTransactionFormat::StandardSolana, None)
                }
            };

            transactions.push(McpPayloadTransaction {
                format,
                wire_bytes: tx_bytes.to_vec(),
                mcp_transaction,
            });
        }

        if bytes[offset..].iter().any(|byte| *byte != 0) {
            return Err(McpPayloadParseError::TrailingNonZeroPadding);
        }

        Ok(Self { transactions })
    }
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], McpPayloadParseError> {
    let Some(end) = offset.checked_add(len) else {
        return Err(McpPayloadParseError::UnexpectedEof);
    };
    if bytes.len() < end {
        return Err(McpPayloadParseError::UnexpectedEof);
    }
    let out = &bytes[*offset..end];
    *offset = end;
    Ok(out)
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, McpPayloadParseError> {
    Ok(u32::from_le_bytes(
        take_bytes(bytes, offset, 4)?.try_into().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::mcp_transaction::{
            InstructionHeader, InstructionPayload, LegacyHeader, MCP_TX_LATEST_VERSION,
        },
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_pubkey::Pubkey,
        solana_signature::Signature,
        solana_signer::Signer,
        solana_system_interface::instruction as system_instruction,
        solana_transaction::Transaction,
    };

    fn sample_tx() -> McpTransaction {
        McpTransaction {
            version: MCP_TX_LATEST_VERSION,
            legacy_header: LegacyHeader {
                num_required_signatures: 1,
                num_readonly_signed: 0,
                num_readonly_unsigned: 0,
            },
            transaction_config_mask: 0,
            lifetime_specifier: [1u8; 32],
            addresses: vec![Pubkey::new_unique()],
            config_values: vec![],
            instruction_headers: vec![InstructionHeader {
                program_account_index: 0,
                num_instruction_accounts: 1,
                num_instruction_data_bytes: 0,
            }],
            instruction_payloads: vec![InstructionPayload {
                account_indexes: vec![0],
                instruction_data: vec![],
            }],
            signatures: vec![Signature::from([7u8; 64])],
        }
    }

    fn encode_payload(entries: &[Vec<u8>], trailing_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for tx in entries {
            out.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            out.extend_from_slice(tx);
        }
        out.extend_from_slice(trailing_bytes);
        out
    }

    #[test]
    fn test_from_bytes_accepts_latest_and_legacy_entries() {
        let tx = sample_tx();
        let latest = tx.to_bytes();
        let legacy = latest[1..].to_vec();
        let payload = encode_payload(&[latest.clone(), legacy.clone()], &[0, 0, 0]);

        let parsed = McpPayload::from_bytes(&payload).unwrap();
        assert_eq!(parsed.transactions.len(), 2);
        assert_eq!(
            parsed.transactions[0].format,
            McpPayloadTransactionFormat::Latest
        );
        assert_eq!(parsed.transactions[0].wire_bytes, latest);
        assert_eq!(parsed.transactions[0].mcp_transaction, Some(tx.clone()));
        assert_eq!(
            parsed.transactions[1].format,
            McpPayloadTransactionFormat::Legacy
        );
        assert_eq!(parsed.transactions[1].wire_bytes, legacy);
        assert_eq!(parsed.transactions[1].mcp_transaction, Some(tx));
    }

    #[test]
    fn test_from_bytes_accepts_standard_solana_wire_entries() {
        let keypair = Keypair::new();
        let to = Pubkey::new_unique();
        let mut solana_tx = Transaction::new_with_payer(
            &[system_instruction::transfer(&keypair.pubkey(), &to, 1)],
            Some(&keypair.pubkey()),
        );
        solana_tx.sign(&[&keypair], Hash::new_unique());
        let wire = bincode::serialize(&solana_tx).unwrap();
        let payload = encode_payload(&[wire.clone()], &[]);

        let parsed = McpPayload::from_bytes(&payload).unwrap();
        assert_eq!(parsed.transactions.len(), 1);
        assert_eq!(
            parsed.transactions[0].format,
            McpPayloadTransactionFormat::StandardSolana
        );
        assert_eq!(parsed.transactions[0].wire_bytes, wire);
        assert_eq!(parsed.transactions[0].mcp_transaction, None);
    }

    #[test]
    fn test_from_bytes_rejects_non_zero_trailing_padding() {
        let tx = sample_tx().to_bytes();
        let payload = encode_payload(&[tx], &[0, 1]);

        assert_eq!(
            McpPayload::from_bytes(&payload),
            Err(McpPayloadParseError::TrailingNonZeroPadding)
        );
    }

    #[test]
    fn test_from_bytes_rejects_truncated_payload() {
        let tx = sample_tx().to_bytes();
        let mut payload = encode_payload(&[tx], &[]);
        payload.pop();

        assert_eq!(
            McpPayload::from_bytes(&payload),
            Err(McpPayloadParseError::UnexpectedEof)
        );
    }

    #[test]
    fn test_from_bytes_reports_transaction_parse_error_index() {
        let tx = sample_tx().to_bytes();
        let payload = encode_payload(&[tx, vec![1, 2, 3]], &[]);

        assert_eq!(
            McpPayload::from_bytes(&payload),
            Err(McpPayloadParseError::TransactionParse {
                tx_index: 1,
                error: McpTransactionParseError::UnexpectedEof,
            })
        );
    }

    #[test]
    fn test_from_bytes_accepts_empty_payload_with_zero_padding() {
        assert_eq!(
            McpPayload::from_bytes(&[0, 0, 0, 0, 0, 0]),
            Ok(McpPayload {
                transactions: Vec::new(),
            })
        );
    }

    #[test]
    fn test_from_bytes_rejects_unbounded_tx_count() {
        let payload = u32::MAX.to_le_bytes();
        assert_eq!(
            McpPayload::from_bytes(&payload),
            Err(McpPayloadParseError::TxCountExceedsMax {
                tx_count: u32::MAX,
                max_count: 0,
            })
        );
    }
}
