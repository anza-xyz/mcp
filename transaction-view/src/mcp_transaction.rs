use {
    solana_compute_budget_instruction::compute_budget_instruction_details::ComputeBudgetInstructionDetails,
    solana_pubkey::Pubkey, solana_signature::Signature,
    solana_svm_transaction::instruction::SVMInstruction,
};

pub const MCP_TX_LATEST_VERSION: u8 = 1;
pub const MCP_TX_CONFIG_BIT_INCLUSION_FEE: u8 = 0;
pub const MCP_TX_CONFIG_BIT_ORDERING_FEE: u8 = 1;
pub const MCP_TX_CONFIG_BIT_COMPUTE_UNIT_LIMIT: u8 = 2;
pub const MCP_TX_CONFIG_BIT_ACCOUNTS_DATA_SIZE_LIMIT: u8 = 3;
pub const MCP_TX_CONFIG_BIT_HEAP_SIZE: u8 = 4;
pub const MCP_TX_CONFIG_BIT_TARGET_PROPOSER: u8 = 5;
pub const MCP_TX_CONFIG_MASK_ALLOWED: u32 = (1u32 << (MCP_TX_CONFIG_BIT_TARGET_PROPOSER + 1)) - 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstructionHeader {
    pub program_account_index: u8,
    pub num_instruction_accounts: u8,
    pub num_instruction_data_bytes: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstructionPayload {
    pub account_indexes: Vec<u8>,
    pub instruction_data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpTransaction {
    pub version: u8,
    pub legacy_header: LegacyHeader,
    pub transaction_config_mask: u32,
    pub lifetime_specifier: [u8; 32],
    pub addresses: Vec<Pubkey>,
    // Config values ordered by ascending bit index for bits set in
    // transaction_config_mask.
    pub config_values: Vec<u32>,
    pub instruction_headers: Vec<InstructionHeader>,
    pub instruction_payloads: Vec<InstructionPayload>,
    pub signatures: Vec<Signature>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpTransactionParseError {
    UnexpectedEof,
    TrailingBytes,
    InvalidVersion(u8),
    InvalidConfigMask(u32),
    InvalidConfigValuesLen,
    InstructionLengthMismatch,
}

impl McpTransaction {
    pub fn maybe_mcp_wire_prefix(bytes: &[u8]) -> bool {
        if bytes.first() == Some(&MCP_TX_LATEST_VERSION)
            && read_config_mask_at(bytes, 4)
                .is_some_and(|mask| mask & !MCP_TX_CONFIG_MASK_ALLOWED == 0)
        {
            return true;
        }

        read_config_mask_at(bytes, 3).is_some_and(|mask| mask & !MCP_TX_CONFIG_MASK_ALLOWED == 0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, McpTransactionParseError> {
        Self::parse_inner(bytes, true)
    }

    pub fn from_legacy_bytes(bytes: &[u8]) -> Result<Self, McpTransactionParseError> {
        Self::parse_inner(bytes, false)
    }

    pub fn from_bytes_compat(bytes: &[u8]) -> Result<Self, McpTransactionParseError> {
        if bytes.first().copied() != Some(MCP_TX_LATEST_VERSION) {
            return parse_legacy_canonical(bytes);
        }

        let latest = Self::from_bytes(bytes).and_then(|parsed| {
            // Require canonical latest layout to avoid accepting malformed payloads.
            if parsed.to_bytes() == bytes {
                Ok(parsed)
            } else {
                Err(McpTransactionParseError::TrailingBytes)
            }
        });
        if let Ok(parsed) = latest {
            return Ok(parsed);
        }

        // Ambiguous prefix (`0x01`) may still be valid legacy.
        parse_legacy_canonical(bytes)
    }

    fn parse_inner(
        bytes: &[u8],
        has_version_prefix: bool,
    ) -> Result<Self, McpTransactionParseError> {
        let mut offset = 0usize;
        let version = if has_version_prefix {
            let version = take_u8(bytes, &mut offset)?;
            if version != MCP_TX_LATEST_VERSION {
                return Err(McpTransactionParseError::InvalidVersion(version));
            }
            version
        } else {
            MCP_TX_LATEST_VERSION
        };
        let num_required_signatures = take_u8(bytes, &mut offset)?;
        let num_readonly_signed = take_u8(bytes, &mut offset)?;
        let num_readonly_unsigned = take_u8(bytes, &mut offset)?;
        let legacy_header = LegacyHeader {
            num_required_signatures,
            num_readonly_signed,
            num_readonly_unsigned,
        };

        let transaction_config_mask = take_u32(bytes, &mut offset)?;
        if transaction_config_mask & !MCP_TX_CONFIG_MASK_ALLOWED != 0 {
            return Err(McpTransactionParseError::InvalidConfigMask(
                transaction_config_mask,
            ));
        }
        let lifetime_specifier = take_array_32(bytes, &mut offset)?;
        let num_instructions = take_u8(bytes, &mut offset)? as usize;
        let num_addresses = take_u8(bytes, &mut offset)? as usize;

        let mut addresses = Vec::with_capacity(num_addresses);
        for _ in 0..num_addresses {
            addresses.push(Pubkey::new_from_array(take_array_32(bytes, &mut offset)?));
        }

        let config_len = transaction_config_mask.count_ones() as usize;
        let mut config_values = Vec::with_capacity(config_len);
        for _ in 0..config_len {
            config_values.push(take_u32(bytes, &mut offset)?);
        }

        let mut instruction_headers = Vec::with_capacity(num_instructions);
        for _ in 0..num_instructions {
            instruction_headers.push(InstructionHeader {
                program_account_index: take_u8(bytes, &mut offset)?,
                num_instruction_accounts: take_u8(bytes, &mut offset)?,
                num_instruction_data_bytes: take_u16(bytes, &mut offset)?,
            });
        }

        let mut instruction_payloads = Vec::with_capacity(num_instructions);
        for header in &instruction_headers {
            let accounts_len = header.num_instruction_accounts as usize;
            let data_len = header.num_instruction_data_bytes as usize;
            instruction_payloads.push(InstructionPayload {
                account_indexes: take_bytes(bytes, &mut offset, accounts_len)?.to_vec(),
                instruction_data: take_bytes(bytes, &mut offset, data_len)?.to_vec(),
            });
        }
        if instruction_payloads.len() != instruction_headers.len() {
            return Err(McpTransactionParseError::InstructionLengthMismatch);
        }

        let mut signatures = Vec::with_capacity(num_required_signatures as usize);
        for _ in 0..num_required_signatures {
            signatures.push(Signature::from(take_array_64(bytes, &mut offset)?));
        }

        if offset != bytes.len() {
            return Err(McpTransactionParseError::TrailingBytes);
        }

        Ok(Self {
            version,
            legacy_header,
            transaction_config_mask,
            lifetime_specifier,
            addresses,
            config_values,
            instruction_headers,
            instruction_payloads,
            signatures,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Always emit latest format on serialization.
        bytes.push(MCP_TX_LATEST_VERSION);
        bytes.push(self.legacy_header.num_required_signatures);
        bytes.push(self.legacy_header.num_readonly_signed);
        bytes.push(self.legacy_header.num_readonly_unsigned);
        bytes.extend_from_slice(&self.transaction_config_mask.to_le_bytes());
        bytes.extend_from_slice(&self.lifetime_specifier);
        bytes.push(self.instruction_headers.len() as u8);
        bytes.push(self.addresses.len() as u8);
        for address in &self.addresses {
            bytes.extend_from_slice(address.as_ref());
        }
        for value in &self.config_values {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for header in &self.instruction_headers {
            bytes.push(header.program_account_index);
            bytes.push(header.num_instruction_accounts);
            bytes.extend_from_slice(&header.num_instruction_data_bytes.to_le_bytes());
        }
        for payload in &self.instruction_payloads {
            bytes.extend_from_slice(&payload.account_indexes);
            bytes.extend_from_slice(&payload.instruction_data);
        }
        for signature in &self.signatures {
            bytes.extend_from_slice(signature.as_ref());
        }
        bytes
    }

    pub fn config_value(&self, bit: u8) -> Option<u32> {
        if bit >= u32::BITS as u8 {
            return None;
        }
        if self.transaction_config_mask & (1u32 << bit) == 0 {
            return None;
        }
        let lower_bits_mask = (1u64 << bit) - 1;
        let index = ((self.transaction_config_mask as u64) & lower_bits_mask).count_ones() as usize;
        self.config_values.get(index).copied()
    }

    pub fn inclusion_fee(&self) -> Option<u32> {
        self.config_value(MCP_TX_CONFIG_BIT_INCLUSION_FEE)
    }

    pub fn ordering_fee(&self) -> Option<u32> {
        self.config_value(MCP_TX_CONFIG_BIT_ORDERING_FEE)
    }

    pub fn ordering_fee_with_fallback(&self) -> u64 {
        self.ordering_fee().map_or_else(
            || {
                self.compute_budget_instruction_details()
                    .map_or(0, |details| details.requested_compute_unit_price())
            },
            u64::from,
        )
    }

    pub fn target_proposer(&self) -> Option<u32> {
        self.config_value(MCP_TX_CONFIG_BIT_TARGET_PROPOSER)
    }

    fn compute_budget_instruction_details(&self) -> Option<ComputeBudgetInstructionDetails> {
        let addresses = self.addresses.as_slice();
        let instructions = self
            .instruction_headers
            .iter()
            .zip(self.instruction_payloads.iter())
            .filter_map(move |(header, payload)| {
                let program_id = addresses.get(header.program_account_index as usize)?;
                Some((
                    program_id,
                    SVMInstruction {
                        program_id_index: header.program_account_index,
                        accounts: payload.account_indexes.as_slice(),
                        data: payload.instruction_data.as_slice(),
                    },
                ))
            });
        ComputeBudgetInstructionDetails::try_from(instructions).ok()
    }
}

fn parse_legacy_canonical(bytes: &[u8]) -> Result<McpTransaction, McpTransactionParseError> {
    let legacy = McpTransaction::from_legacy_bytes(bytes)?;
    // Require canonical legacy layout to avoid accepting malformed payloads.
    if legacy.to_bytes().get(1..) == Some(bytes) {
        Ok(legacy)
    } else {
        Err(McpTransactionParseError::TrailingBytes)
    }
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], McpTransactionParseError> {
    let Some(end) = offset.checked_add(len) else {
        return Err(McpTransactionParseError::UnexpectedEof);
    };
    if bytes.len() < end {
        return Err(McpTransactionParseError::UnexpectedEof);
    }
    let out = &bytes[*offset..end];
    *offset = end;
    Ok(out)
}

fn take_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, McpTransactionParseError> {
    Ok(take_bytes(bytes, offset, 1)?[0])
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, McpTransactionParseError> {
    Ok(u16::from_le_bytes(
        take_bytes(bytes, offset, 2)?.try_into().unwrap(),
    ))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, McpTransactionParseError> {
    Ok(u32::from_le_bytes(
        take_bytes(bytes, offset, 4)?.try_into().unwrap(),
    ))
}

fn take_array_32(bytes: &[u8], offset: &mut usize) -> Result<[u8; 32], McpTransactionParseError> {
    Ok(take_bytes(bytes, offset, 32)?.try_into().unwrap())
}

fn take_array_64(bytes: &[u8], offset: &mut usize) -> Result<[u8; 64], McpTransactionParseError> {
    Ok(take_bytes(bytes, offset, 64)?.try_into().unwrap())
}

fn read_config_mask_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use {
        super::*, solana_hash::Hash, solana_keypair::Keypair, solana_signer::Signer,
        solana_system_interface::instruction as system_instruction,
        solana_transaction::Transaction,
    };

    fn sample_transaction() -> McpTransaction {
        let transaction_config_mask = (1u32 << MCP_TX_CONFIG_BIT_INCLUSION_FEE)
            | (1u32 << MCP_TX_CONFIG_BIT_ORDERING_FEE)
            | (1u32 << MCP_TX_CONFIG_BIT_TARGET_PROPOSER);
        McpTransaction {
            version: MCP_TX_LATEST_VERSION,
            legacy_header: LegacyHeader {
                num_required_signatures: 2,
                num_readonly_signed: 0,
                num_readonly_unsigned: 1,
            },
            transaction_config_mask,
            lifetime_specifier: [9u8; 32],
            addresses: vec![Pubkey::new_unique(), Pubkey::new_unique()],
            config_values: vec![7, 11, 42], // inclusion_fee, ordering_fee, target_proposer
            instruction_headers: vec![
                InstructionHeader {
                    program_account_index: 1,
                    num_instruction_accounts: 2,
                    num_instruction_data_bytes: 3,
                },
                InstructionHeader {
                    program_account_index: 0,
                    num_instruction_accounts: 1,
                    num_instruction_data_bytes: 0,
                },
            ],
            instruction_payloads: vec![
                InstructionPayload {
                    account_indexes: vec![0, 1],
                    instruction_data: vec![8, 9, 10],
                },
                InstructionPayload {
                    account_indexes: vec![1],
                    instruction_data: vec![],
                },
            ],
            signatures: vec![Signature::from([3u8; 64]), Signature::from([4u8; 64])],
        }
    }

    #[test]
    fn test_roundtrip_and_field_extraction() {
        let tx = sample_transaction();
        let bytes = tx.to_bytes();
        let parsed = McpTransaction::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, tx);
        assert_eq!(parsed.inclusion_fee(), Some(7));
        assert_eq!(parsed.ordering_fee(), Some(11));
        assert_eq!(parsed.ordering_fee_with_fallback(), 11);
        assert_eq!(parsed.target_proposer(), Some(42));
    }

    #[test]
    fn test_ordering_fee_with_fallback_uses_compute_unit_price_when_field_absent() {
        let mut tx = sample_transaction();
        tx.transaction_config_mask =
            (1u32 << MCP_TX_CONFIG_BIT_INCLUSION_FEE) | (1u32 << MCP_TX_CONFIG_BIT_TARGET_PROPOSER);
        tx.config_values = vec![7, 42];
        tx.addresses = vec![solana_sdk_ids::compute_budget::id()];
        tx.instruction_headers = vec![InstructionHeader {
            program_account_index: 0,
            num_instruction_accounts: 0,
            num_instruction_data_bytes: 9,
        }];
        let mut instruction_data = vec![3u8];
        instruction_data.extend_from_slice(&55u64.to_le_bytes());
        tx.instruction_payloads = vec![InstructionPayload {
            account_indexes: vec![],
            instruction_data,
        }];

        assert_eq!(tx.ordering_fee(), None);
        assert_eq!(tx.ordering_fee_with_fallback(), 55);
    }

    #[test]
    fn test_truncated_payload_rejected() {
        let tx = sample_transaction();
        let mut bytes = tx.to_bytes();
        bytes.pop();
        assert_eq!(
            McpTransaction::from_bytes(&bytes),
            Err(McpTransactionParseError::UnexpectedEof)
        );
    }

    #[test]
    fn test_trailing_bytes_rejected() {
        let tx = sample_transaction();
        let mut bytes = tx.to_bytes();
        bytes.push(0);
        assert_eq!(
            McpTransaction::from_bytes(&bytes),
            Err(McpTransactionParseError::TrailingBytes)
        );
    }

    #[test]
    fn test_legacy_parse_is_accepted_and_serialized_as_latest() {
        let tx = sample_transaction();
        let latest = tx.to_bytes();
        // Legacy encoding omits version prefix.
        let legacy = latest[1..].to_vec();

        let parsed = McpTransaction::from_bytes_compat(&legacy).unwrap();
        assert_eq!(parsed.version, MCP_TX_LATEST_VERSION);
        assert_eq!(parsed.inclusion_fee(), Some(7));
        assert_eq!(parsed.ordering_fee(), Some(11));
        assert_eq!(parsed.target_proposer(), Some(42));
        assert_eq!(parsed.to_bytes(), latest);
    }

    #[test]
    fn test_invalid_config_mask_rejected() {
        let tx = sample_transaction();
        let mut bytes = tx.to_bytes();
        // Set an unsupported config bit.
        let mask = (1u32 << 30).to_le_bytes();
        bytes[4..8].copy_from_slice(&mask);
        assert_eq!(
            McpTransaction::from_bytes(&bytes),
            Err(McpTransactionParseError::InvalidConfigMask(1u32 << 30))
        );
    }

    #[test]
    fn test_legacy_with_first_byte_one_prefers_legacy_layout() {
        let mut tx = sample_transaction();
        tx.legacy_header.num_required_signatures = 1;
        tx.signatures.truncate(1);

        let latest = tx.to_bytes();
        let legacy = latest[1..].to_vec();
        let parsed = McpTransaction::from_bytes_compat(&legacy).unwrap();

        assert_eq!(parsed.legacy_header.num_required_signatures, 1);
        assert_eq!(parsed.to_bytes(), latest);
    }

    #[test]
    fn test_unknown_version_rejected() {
        let mut bytes = sample_transaction().to_bytes();
        bytes[0] = MCP_TX_LATEST_VERSION + 1;
        assert_eq!(
            McpTransaction::from_bytes(&bytes),
            Err(McpTransactionParseError::InvalidVersion(
                MCP_TX_LATEST_VERSION + 1
            ))
        );
    }

    #[test]
    fn test_standard_solana_transaction_is_not_mcp() {
        let payer = Keypair::new();
        let recipient = Pubkey::new_unique();
        let mut tx = Transaction::new_with_payer(
            &[system_instruction::transfer(&payer.pubkey(), &recipient, 1)],
            Some(&payer.pubkey()),
        );
        tx.sign(&[&payer], Hash::new_unique());
        let serialized = bincode::serialize(&tx).unwrap();

        assert!(McpTransaction::from_bytes_compat(&serialized).is_err());
    }

    #[test]
    fn test_maybe_mcp_wire_prefix_for_latest_and_legacy() {
        let latest = sample_transaction().to_bytes();
        let legacy = latest[1..].to_vec();
        assert!(McpTransaction::maybe_mcp_wire_prefix(&latest));
        assert!(McpTransaction::maybe_mcp_wire_prefix(&legacy));
    }

    #[test]
    fn test_maybe_mcp_wire_prefix_rejects_standard_solana_transaction() {
        let payer = Keypair::new();
        let recipient = Pubkey::new_unique();
        let mut tx = Transaction::new_with_payer(
            &[system_instruction::transfer(&payer.pubkey(), &recipient, 1)],
            Some(&payer.pubkey()),
        );
        tx.sign(&[&payer], Hash::new_unique());
        let serialized = bincode::serialize(&tx).unwrap();

        assert!(!McpTransaction::maybe_mcp_wire_prefix(&serialized));
    }
}
