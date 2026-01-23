//! MCP Consensus Block Construction and Voting
//!
//! This module implements the MCP block format and voting protocol:
//! - McpBlockV1: The consensus block payload containing relay attestations
//! - McpVoteV1: The compact vote format for MCP-aware consensus
//! - Block construction from aggregated relay attestations
//! - Block validation for voting
//!
//! Per MCP spec:
//! - The consensus leader builds a block from relay attestations
//! - Validators vote on the block_hash
//! - A block is valid if it has >= 120 relay attestations

use {
    solana_clock::Slot,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::mcp_attestation::{
        AttestationEntry, RelayAttestation, ATTESTATION_ENTRY_SIZE,
    },
    solana_signer::Signer,
    std::{
        collections::HashMap,
        io::{self, Read, Write},
    },
};

/// Domain separator for block hash computation
pub const BLOCK_HASH_DOMAIN: &[u8] = b"mcp:block-hash:v1";

/// Domain separator for block signature
pub const BLOCK_SIG_DOMAIN: &[u8] = b"mcp:block-sig:v1";

/// Domain separator for vote signature
pub const VOTE_SIG_DOMAIN: &[u8] = b"mcp:vote:v1";

/// Minimum number of relays required for a valid block
pub const MIN_RELAYS_IN_BLOCK: usize = 120;

/// Minimum percentage of relays attesting to a proposer for inclusion
pub const MIN_PROPOSER_ATTESTATION_PERCENTAGE: f64 = 0.40;

/// Total number of relays
pub const NUM_RELAYS: u16 = 200;

/// Delay slots for bankhash
pub const BANKHASH_DELAY_SLOTS: u64 = 4;

/// McpVoteV1 size in bytes
pub const MCP_VOTE_SIZE: usize = 117;

/// Vote types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VoteType {
    /// Standard vote for the block
    Vote = 0,
    /// Vote to skip/abstain
    Skip = 1,
}

impl From<u8> for VoteType {
    fn from(v: u8) -> Self {
        match v {
            0 => VoteType::Vote,
            1 => VoteType::Skip,
            _ => VoteType::Skip, // Default to skip for unknown types
        }
    }
}

// ============================================================================
// Relay Entry (contained in McpBlockV1)
// ============================================================================

/// A relay entry in the MCP block, containing the relay's attestations.
///
/// Wire format:
/// - relay_index: u32 (4 bytes)
/// - num_attestations: u8 (1 byte)
/// - entries: num_attestations × AttestationEntryV1
/// - relay_signature: [u8; 64]
#[derive(Debug, Clone)]
pub struct RelayEntryV1 {
    pub relay_index: u32,
    pub entries: Vec<AttestationEntry>,
    pub relay_signature: [u8; 64],
}

impl RelayEntryV1 {
    /// Size of this entry when serialized
    pub fn serialized_size(&self) -> usize {
        4 + 1 + (self.entries.len() * ATTESTATION_ENTRY_SIZE) + 64
    }

    /// Serialize to a writer
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.relay_index.to_le_bytes())?;
        writer.write_all(&[self.entries.len() as u8])?;
        for entry in &self.entries {
            entry.serialize(writer)?;
        }
        writer.write_all(&self.relay_signature)?;
        Ok(())
    }

    /// Deserialize from a reader
    pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut relay_index_bytes = [0u8; 4];
        reader.read_exact(&mut relay_index_bytes)?;
        let relay_index = u32::from_le_bytes(relay_index_bytes);

        let mut num_attestations = [0u8; 1];
        reader.read_exact(&mut num_attestations)?;
        let num_attestations = num_attestations[0] as usize;

        let mut entries = Vec::with_capacity(num_attestations);
        for _ in 0..num_attestations {
            entries.push(AttestationEntry::deserialize(reader)?);
        }

        let mut relay_signature = [0u8; 64];
        reader.read_exact(&mut relay_signature)?;

        Ok(Self {
            relay_index,
            entries,
            relay_signature,
        })
    }
}

// ============================================================================
// McpBlockV1
// ============================================================================

/// MCP Block payload for a slot.
///
/// Wire format:
/// - slot: u64 (8 bytes)
/// - leader_index: u32 (4 bytes)
/// - delayed_bankhash: [u8; 32]
/// - num_relays: u16 (2 bytes)
/// - relay_entries: num_relays × RelayEntryV1
/// - leader_signature: [u8; 64]
#[derive(Debug, Clone)]
pub struct McpBlockV1 {
    pub slot: Slot,
    pub leader_index: u32,
    pub delayed_bankhash: Hash,
    pub relay_entries: Vec<RelayEntryV1>,
    pub leader_signature: [u8; 64],
}

impl McpBlockV1 {
    /// Create a new unsigned block (leader_signature set to zeros)
    pub fn new_unsigned(
        slot: Slot,
        leader_index: u32,
        delayed_bankhash: Hash,
        relay_entries: Vec<RelayEntryV1>,
    ) -> Self {
        Self {
            slot,
            leader_index,
            delayed_bankhash,
            relay_entries,
            leader_signature: [0u8; 64],
        }
    }

    /// Size when serialized
    pub fn serialized_size(&self) -> usize {
        let relay_size: usize = self.relay_entries.iter()
            .map(|e| e.serialized_size())
            .sum();
        8 + 4 + 32 + 2 + relay_size + 64
    }

    /// Serialize the block body (without leader_signature) for hashing
    pub fn serialize_body<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.slot.to_le_bytes())?;
        writer.write_all(&self.leader_index.to_le_bytes())?;
        writer.write_all(self.delayed_bankhash.as_ref())?;
        writer.write_all(&(self.relay_entries.len() as u16).to_le_bytes())?;
        for entry in &self.relay_entries {
            entry.serialize(writer)?;
        }
        Ok(())
    }

    /// Serialize the complete block
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.serialize_body(writer)?;
        writer.write_all(&self.leader_signature)?;
        Ok(())
    }

    /// Deserialize from a reader
    pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut slot_bytes = [0u8; 8];
        reader.read_exact(&mut slot_bytes)?;
        let slot = Slot::from_le_bytes(slot_bytes);

        let mut leader_index_bytes = [0u8; 4];
        reader.read_exact(&mut leader_index_bytes)?;
        let leader_index = u32::from_le_bytes(leader_index_bytes);

        let mut delayed_bankhash_bytes = [0u8; 32];
        reader.read_exact(&mut delayed_bankhash_bytes)?;
        let delayed_bankhash = Hash::from(delayed_bankhash_bytes);

        let mut num_relays_bytes = [0u8; 2];
        reader.read_exact(&mut num_relays_bytes)?;
        let num_relays = u16::from_le_bytes(num_relays_bytes) as usize;

        let mut relay_entries = Vec::with_capacity(num_relays);
        for _ in 0..num_relays {
            relay_entries.push(RelayEntryV1::deserialize(reader)?);
        }

        let mut leader_signature = [0u8; 64];
        reader.read_exact(&mut leader_signature)?;

        Ok(Self {
            slot,
            leader_index,
            delayed_bankhash,
            relay_entries,
            leader_signature,
        })
    }

    /// Compute the block hash according to spec:
    /// block_hash = SHA256("mcp:block-hash:v1" || block_body)
    pub fn compute_block_hash(&self) -> Hash {
        use solana_sha256_hasher::Hasher;
        let mut hasher = Hasher::default();
        hasher.hash(BLOCK_HASH_DOMAIN);

        let mut body = Vec::new();
        self.serialize_body(&mut body).expect("serialization to vec cannot fail");
        hasher.hash(&body);

        Hash::new_from_array(hasher.result().to_bytes())
    }

    /// Sign the block and update leader_signature
    pub fn sign(&mut self, keypair: &Keypair) {
        let block_hash = self.compute_block_hash();

        // Construct message: domain || block_hash
        let mut message = Vec::with_capacity(BLOCK_SIG_DOMAIN.len() + 32);
        message.extend_from_slice(BLOCK_SIG_DOMAIN);
        message.extend_from_slice(block_hash.as_ref());

        let signature = keypair.sign_message(&message);
        self.leader_signature.copy_from_slice(signature.as_ref());
    }

    /// Verify the leader signature
    pub fn verify_leader_signature(&self, leader_pubkey: &solana_pubkey::Pubkey) -> bool {
        let block_hash = self.compute_block_hash();

        let mut message = Vec::with_capacity(BLOCK_SIG_DOMAIN.len() + 32);
        message.extend_from_slice(BLOCK_SIG_DOMAIN);
        message.extend_from_slice(block_hash.as_ref());

        let signature = solana_signature::Signature::from(self.leader_signature);
        signature.verify(leader_pubkey.as_ref(), &message)
    }

    /// Check if the block has minimum required relays
    pub fn has_minimum_relays(&self) -> bool {
        self.relay_entries.len() >= MIN_RELAYS_IN_BLOCK
    }

    /// Check if relay entries are properly sorted and unique
    pub fn relays_are_sorted_and_unique(&self) -> bool {
        if self.relay_entries.is_empty() {
            return true;
        }
        for i in 1..self.relay_entries.len() {
            if self.relay_entries[i].relay_index <= self.relay_entries[i - 1].relay_index {
                return false;
            }
        }
        true
    }

    /// Validate block structure (does not verify signatures)
    pub fn validate_structure(&self) -> bool {
        self.has_minimum_relays() && self.relays_are_sorted_and_unique()
    }

    /// Get proposer commitments implied by this block.
    /// Returns a map of proposer_index -> (commitment, attestation_count)
    pub fn get_implied_proposer_commitments(&self) -> HashMap<u8, (Hash, usize)> {
        let mut proposer_votes: HashMap<u8, HashMap<Hash, usize>> = HashMap::new();

        // Count attestations for each (proposer, commitment) pair
        for relay_entry in &self.relay_entries {
            for entry in &relay_entry.entries {
                let proposer_counts = proposer_votes
                    .entry(entry.proposer_index)
                    .or_default();
                *proposer_counts
                    .entry(entry.commitment)
                    .or_default() += 1;
            }
        }

        // For each proposer, find the commitment with the most attestations
        let mut result = HashMap::new();
        let min_attestations = (NUM_RELAYS as f64 * MIN_PROPOSER_ATTESTATION_PERCENTAGE) as usize;

        for (proposer_index, commitment_counts) in proposer_votes {
            // Find the commitment with max attestations
            if let Some((commitment, count)) = commitment_counts
                .into_iter()
                .max_by_key(|(_, count)| *count)
            {
                // Only include if it meets the minimum threshold
                if count >= min_attestations {
                    result.insert(proposer_index, (commitment, count));
                }
            }
        }

        result
    }

    /// Compute implied blocks according to spec §11.2.
    ///
    /// This implements the full `computeImpliedBlocks` algorithm:
    /// 1. Gather all (commitment, proposer_signature) pairs for each proposer
    /// 2. Detect equivocation: if two different commitments exist for a proposer
    ///    with valid signatures, exclude that proposer
    /// 3. Choose the commitment with maximum relay support
    /// 4. Tie-break by lexicographically smallest commitment
    /// 5. Only include if count >= MIN_RELAYS_PER_PROPOSER (80)
    ///
    /// Note: This version does not verify proposer signatures. Use
    /// `compute_implied_blocks_with_verification` for full signature verification.
    ///
    /// Returns: list of (proposer_id, commitment) pairs that are implied
    pub fn compute_implied_blocks(&self) -> Vec<(u8, Hash)> {
        self.compute_implied_blocks_impl(None)
    }

    /// Compute implied blocks with proposer signature verification.
    ///
    /// Same as `compute_implied_blocks` but also verifies that each proposer's
    /// signature over their commitment is valid. Invalid signatures are treated
    /// as if the attestation didn't exist.
    ///
    /// Per spec §11.2: The proposer signature is verified against the signing
    /// message: "mcp:commitment:v1" || LE64(slot) || LE32(proposer_index) || commitment32
    ///
    /// Returns: list of (proposer_id, commitment) pairs that are implied
    pub fn compute_implied_blocks_with_verification(
        &self,
        proposer_pubkeys: &[solana_pubkey::Pubkey],
    ) -> Vec<(u8, Hash)> {
        self.compute_implied_blocks_impl(Some(proposer_pubkeys))
    }

    /// Internal implementation of compute_implied_blocks with optional signature verification.
    fn compute_implied_blocks_impl(
        &self,
        proposer_pubkeys: Option<&[solana_pubkey::Pubkey]>,
    ) -> Vec<(u8, Hash)> {
        // Minimum attestations required per proposer (40% of 200 = 80)
        const MIN_RELAYS_PER_PROPOSER: usize = 80;

        // Track all commitments seen for each proposer, along with valid signatures
        // Map: proposer_id -> commitment -> (count, has_valid_signature)
        let mut proposer_commitments: HashMap<u8, HashMap<Hash, (usize, bool)>> = HashMap::new();

        for relay_entry in &self.relay_entries {
            for entry in &relay_entry.entries {
                let proposer_id = entry.proposer_index;

                // Check signature validity if proposer_pubkeys provided
                let sig_valid = if let Some(pubkeys) = proposer_pubkeys {
                    if (proposer_id as usize) < pubkeys.len() {
                        entry.verify_proposer_signature(
                            &pubkeys[proposer_id as usize],
                            self.slot,
                        )
                    } else {
                        false // Invalid proposer_id
                    }
                } else {
                    true // No verification requested, assume valid
                };

                let entry_data = proposer_commitments
                    .entry(proposer_id)
                    .or_default()
                    .entry(entry.commitment)
                    .or_insert((0, false));

                entry_data.0 += 1;
                if sig_valid {
                    entry_data.1 = true;
                }
            }
        }

        let mut implied_blocks = Vec::new();

        for (proposer_id, commitment_data) in proposer_commitments {
            // Filter to only commitments with valid signatures (if verification was requested)
            let valid_commitments: Vec<(Hash, usize)> = commitment_data
                .into_iter()
                .filter(|(_, (_, has_valid_sig))| *has_valid_sig)
                .map(|(commitment, (count, _))| (commitment, count))
                .collect();

            // Check for equivocation: if there are 2+ different commitments
            // with valid signatures, the proposer is equivocating
            if valid_commitments.len() > 1 {
                // Proposer equivocation detected - exclude this proposer
                continue;
            }

            // Find the commitment with max support, tie-break by lex order
            let mut best: Option<(Hash, usize)> = None;
            for (commitment, count) in valid_commitments {
                match &best {
                    None => best = Some((commitment, count)),
                    Some((best_commitment, best_count)) => {
                        if count > *best_count
                            || (count == *best_count && commitment.as_ref() < best_commitment.as_ref())
                        {
                            best = Some((commitment, count));
                        }
                    }
                }
            }

            // Include if meets threshold
            if let Some((commitment, count)) = best {
                if count >= MIN_RELAYS_PER_PROPOSER {
                    implied_blocks.push((proposer_id, commitment));
                }
            }
        }

        // Sort by proposer_id for deterministic ordering
        implied_blocks.sort_by_key(|(id, _)| *id);
        implied_blocks
    }
}

// ============================================================================
// McpVoteV1
// ============================================================================

/// MCP Vote message (117 bytes fixed).
///
/// Wire format:
/// - slot: u64 (8 bytes)
/// - validator_index: u32 (4 bytes)
/// - block_hash: [u8; 32]
/// - vote_type: u8 (1 byte)
/// - timestamp: i64 (8 bytes)
/// - signature: [u8; 64]
#[derive(Debug, Clone)]
pub struct McpVoteV1 {
    pub slot: Slot,
    pub validator_index: u32,
    pub block_hash: Hash,
    pub vote_type: VoteType,
    pub timestamp: i64,
    pub signature: [u8; 64],
}

impl McpVoteV1 {
    /// Create a new unsigned vote
    pub fn new_unsigned(
        slot: Slot,
        validator_index: u32,
        block_hash: Hash,
        vote_type: VoteType,
        timestamp: i64,
    ) -> Self {
        Self {
            slot,
            validator_index,
            block_hash,
            vote_type,
            timestamp,
            signature: [0u8; 64],
        }
    }

    /// Serialize the vote body (without signature) for signing
    pub fn serialize_body<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.slot.to_le_bytes())?;
        writer.write_all(&self.validator_index.to_le_bytes())?;
        writer.write_all(self.block_hash.as_ref())?;
        writer.write_all(&[self.vote_type as u8])?;
        writer.write_all(&self.timestamp.to_le_bytes())?;
        Ok(())
    }

    /// Serialize the complete vote
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.serialize_body(writer)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }

    /// Deserialize from a reader
    pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut slot_bytes = [0u8; 8];
        reader.read_exact(&mut slot_bytes)?;
        let slot = Slot::from_le_bytes(slot_bytes);

        let mut validator_index_bytes = [0u8; 4];
        reader.read_exact(&mut validator_index_bytes)?;
        let validator_index = u32::from_le_bytes(validator_index_bytes);

        let mut block_hash_bytes = [0u8; 32];
        reader.read_exact(&mut block_hash_bytes)?;
        let block_hash = Hash::from(block_hash_bytes);

        let mut vote_type_byte = [0u8; 1];
        reader.read_exact(&mut vote_type_byte)?;
        let vote_type = VoteType::from(vote_type_byte[0]);

        let mut timestamp_bytes = [0u8; 8];
        reader.read_exact(&mut timestamp_bytes)?;
        let timestamp = i64::from_le_bytes(timestamp_bytes);

        let mut signature = [0u8; 64];
        reader.read_exact(&mut signature)?;

        Ok(Self {
            slot,
            validator_index,
            block_hash,
            vote_type,
            timestamp,
            signature,
        })
    }

    /// Sign the vote and update signature
    pub fn sign(&mut self, keypair: &Keypair) {
        let mut body = Vec::with_capacity(53);
        self.serialize_body(&mut body).expect("serialization to vec cannot fail");

        // Construct message: domain || body
        let mut message = Vec::with_capacity(VOTE_SIG_DOMAIN.len() + body.len());
        message.extend_from_slice(VOTE_SIG_DOMAIN);
        message.extend_from_slice(&body);

        let signature = keypair.sign_message(&message);
        self.signature.copy_from_slice(signature.as_ref());
    }

    /// Verify the vote signature
    pub fn verify_signature(&self, voter_pubkey: &solana_pubkey::Pubkey) -> bool {
        let mut body = Vec::with_capacity(53);
        self.serialize_body(&mut body).expect("serialization to vec cannot fail");

        let mut message = Vec::with_capacity(VOTE_SIG_DOMAIN.len() + body.len());
        message.extend_from_slice(VOTE_SIG_DOMAIN);
        message.extend_from_slice(&body);

        let signature = solana_signature::Signature::from(self.signature);
        signature.verify(voter_pubkey.as_ref(), &message)
    }
}

// ============================================================================
// Block Builder
// ============================================================================

/// Builder for constructing McpBlockV1 from relay attestations.
pub struct McpBlockBuilder {
    slot: Slot,
    leader_index: u32,
    delayed_bankhash: Hash,
    relay_attestations: HashMap<u16, RelayAttestation>,
}

impl McpBlockBuilder {
    /// Create a new block builder
    pub fn new(slot: Slot, leader_index: u32, delayed_bankhash: Hash) -> Self {
        Self {
            slot,
            leader_index,
            delayed_bankhash,
            relay_attestations: HashMap::new(),
        }
    }

    /// Add a relay attestation
    pub fn add_attestation(&mut self, relay_id: u16, attestation: RelayAttestation) {
        // Only keep the first attestation from each relay (equivocation prevention)
        self.relay_attestations.entry(relay_id).or_insert(attestation);
    }

    /// Check if we have enough attestations to build a block
    pub fn can_build(&self) -> bool {
        self.relay_attestations.len() >= MIN_RELAYS_IN_BLOCK
    }

    /// Get the number of attestations collected
    pub fn attestation_count(&self) -> usize {
        self.relay_attestations.len()
    }

    /// Build the unsigned block from collected attestations
    pub fn build_unsigned(self) -> Option<McpBlockV1> {
        if !self.can_build() {
            return None;
        }

        // Convert attestations to relay entries, sorted by relay_index
        let mut relay_entries: Vec<RelayEntryV1> = self.relay_attestations
            .into_iter()
            .map(|(relay_id, attestation)| RelayEntryV1 {
                relay_index: relay_id as u32,
                entries: attestation.entries.clone(),
                relay_signature: attestation.relay_signature.into(),
            })
            .collect();

        relay_entries.sort_by_key(|e| e.relay_index);

        Some(McpBlockV1::new_unsigned(
            self.slot,
            self.leader_index,
            self.delayed_bankhash,
            relay_entries,
        ))
    }

    /// Build and sign the block
    pub fn build(self, keypair: &Keypair) -> Option<McpBlockV1> {
        let mut block = self.build_unsigned()?;
        block.sign(keypair);
        Some(block)
    }
}

// ============================================================================
// Block Validator
// ============================================================================

/// Result of block validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockValidationError {
    /// Not enough relay attestations
    InsufficientRelays { actual: usize, required: usize },
    /// Relay entries not sorted or have duplicates
    RelaysNotSortedOrUnique,
    /// Invalid leader signature
    InvalidLeaderSignature,
    /// Delayed bankhash mismatch
    BankhashMismatch { expected: Hash, actual: Hash },
    /// Wrong leader for slot
    WrongLeader { expected: u32, actual: u32 },
}

/// Validates MCP blocks for voting.
pub struct BlockValidator {
    expected_leader_index: u32,
    expected_delayed_bankhash: Hash,
    leader_pubkey: solana_pubkey::Pubkey,
}

impl BlockValidator {
    /// Create a new block validator
    pub fn new(
        expected_leader_index: u32,
        expected_delayed_bankhash: Hash,
        leader_pubkey: solana_pubkey::Pubkey,
    ) -> Self {
        Self {
            expected_leader_index,
            expected_delayed_bankhash,
            leader_pubkey,
        }
    }

    /// Validate a block for voting
    pub fn validate(&self, block: &McpBlockV1) -> Result<(), BlockValidationError> {
        // Check leader index
        if block.leader_index != self.expected_leader_index {
            return Err(BlockValidationError::WrongLeader {
                expected: self.expected_leader_index,
                actual: block.leader_index,
            });
        }

        // Check delayed bankhash
        if block.delayed_bankhash != self.expected_delayed_bankhash {
            return Err(BlockValidationError::BankhashMismatch {
                expected: self.expected_delayed_bankhash,
                actual: block.delayed_bankhash,
            });
        }

        // Check minimum relays
        if block.relay_entries.len() < MIN_RELAYS_IN_BLOCK {
            return Err(BlockValidationError::InsufficientRelays {
                actual: block.relay_entries.len(),
                required: MIN_RELAYS_IN_BLOCK,
            });
        }

        // Check relay sorting and uniqueness
        if !block.relays_are_sorted_and_unique() {
            return Err(BlockValidationError::RelaysNotSortedOrUnique);
        }

        // Verify leader signature
        if !block.verify_leader_signature(&self.leader_pubkey) {
            return Err(BlockValidationError::InvalidLeaderSignature);
        }

        Ok(())
    }
}

// ============================================================================
// Availability Checker
// ============================================================================

/// Minimum number of shreds needed per proposer to vote (K_DATA_SHREDS = 40)
pub const K_DATA_SHREDS: usize = 40;

/// Result of availability check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvailabilityCheckResult {
    /// All implied proposers have sufficient shreds
    Ready,
    /// Some proposers are missing shreds
    Waiting {
        /// Proposers that don't have enough shreds yet
        missing: Vec<(u8, Hash, usize)>, // (proposer_id, commitment, current_count)
    },
}

/// Trait for checking local shred availability.
///
/// Implementations should track verified shreds and count how many
/// distinct shred_index values exist for a given (slot, proposer, commitment).
pub trait ShredAvailability {
    /// Count the number of distinct verified shreds for this proposer commitment.
    ///
    /// Only shreds with valid Merkle proofs matching the commitment should be counted.
    fn count_verified_shreds(
        &self,
        slot: Slot,
        proposer_id: u8,
        commitment: &Hash,
    ) -> usize;
}

/// Checks if a validator has enough shreds to vote on an MCP block.
///
/// Per spec §11.3: For each implied proposer commitment, the validator must
/// have at least K_DATA_SHREDS (40) distinct shred_index values with valid
/// Merkle proofs before voting.
pub struct AvailabilityChecker<'a, S: ShredAvailability> {
    slot: Slot,
    availability: &'a S,
}

impl<'a, S: ShredAvailability> AvailabilityChecker<'a, S> {
    /// Create a new availability checker
    pub fn new(slot: Slot, availability: &'a S) -> Self {
        Self { slot, availability }
    }

    /// Check if we can vote on this block
    ///
    /// Returns Ready if all implied proposers have >= K_DATA_SHREDS shreds,
    /// otherwise returns Waiting with the list of proposers that need more shreds.
    pub fn check_availability(&self, implied_blocks: &[(u8, Hash)]) -> AvailabilityCheckResult {
        let mut missing = Vec::new();

        for (proposer_id, commitment) in implied_blocks {
            let count = self.availability.count_verified_shreds(
                self.slot,
                *proposer_id,
                commitment,
            );

            if count < K_DATA_SHREDS {
                missing.push((*proposer_id, *commitment, count));
            }
        }

        if missing.is_empty() {
            AvailabilityCheckResult::Ready
        } else {
            AvailabilityCheckResult::Waiting { missing }
        }
    }

    /// Check if a single proposer has enough shreds
    pub fn has_enough_shreds(&self, proposer_id: u8, commitment: &Hash) -> bool {
        self.availability.count_verified_shreds(self.slot, proposer_id, commitment) >= K_DATA_SHREDS
    }
}

/// A simple in-memory implementation of ShredAvailability for testing
#[derive(Debug, Default)]
pub struct InMemoryShredAvailability {
    /// Map of (slot, proposer_id, commitment) -> set of shred indices
    shreds: HashMap<(Slot, u8, Hash), std::collections::HashSet<u16>>,
}

impl InMemoryShredAvailability {
    /// Create a new in-memory availability tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a verified shred
    pub fn record_shred(&mut self, slot: Slot, proposer_id: u8, commitment: Hash, shred_index: u16) {
        self.shreds
            .entry((slot, proposer_id, commitment))
            .or_default()
            .insert(shred_index);
    }
}

impl ShredAvailability for InMemoryShredAvailability {
    fn count_verified_shreds(&self, slot: Slot, proposer_id: u8, commitment: &Hash) -> usize {
        self.shreds
            .get(&(slot, proposer_id, *commitment))
            .map(|s| s.len())
            .unwrap_or(0)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hash(seed: u8) -> Hash {
        Hash::from([seed; 32])
    }

    fn make_test_sig(seed: u8) -> solana_signature::Signature {
        solana_signature::Signature::from([seed; 64])
    }

    fn make_test_attestation_entry(proposer_index: u8, commitment_seed: u8) -> AttestationEntry {
        AttestationEntry::new(
            proposer_index,
            Hash::from([commitment_seed; 32]),
            make_test_sig(commitment_seed),
        )
    }

    fn make_test_relay_entry(relay_index: u32, proposer_entries: Vec<(u8, u8)>) -> RelayEntryV1 {
        let entries = proposer_entries
            .into_iter()
            .map(|(p, c)| make_test_attestation_entry(p, c))
            .collect();
        RelayEntryV1 {
            relay_index,
            entries,
            relay_signature: [0u8; 64],
        }
    }

    #[test]
    fn test_relay_entry_serialization() {
        let entry = make_test_relay_entry(42, vec![(0, 1), (1, 2)]);

        let mut buffer = Vec::new();
        entry.serialize(&mut buffer).unwrap();

        let deserialized = RelayEntryV1::deserialize(&mut buffer.as_slice()).unwrap();

        assert_eq!(deserialized.relay_index, 42);
        assert_eq!(deserialized.entries.len(), 2);
        assert_eq!(deserialized.entries[0].proposer_index, 0);
        assert_eq!(deserialized.entries[1].proposer_index, 1);
    }

    #[test]
    fn test_mcp_block_serialization() {
        let relay_entries = vec![
            make_test_relay_entry(0, vec![(0, 1)]),
            make_test_relay_entry(1, vec![(1, 2)]),
        ];

        let block = McpBlockV1::new_unsigned(
            100,
            5,
            make_test_hash(42),
            relay_entries,
        );

        let mut buffer = Vec::new();
        block.serialize(&mut buffer).unwrap();

        let deserialized = McpBlockV1::deserialize(&mut buffer.as_slice()).unwrap();

        assert_eq!(deserialized.slot, 100);
        assert_eq!(deserialized.leader_index, 5);
        assert_eq!(deserialized.delayed_bankhash, make_test_hash(42));
        assert_eq!(deserialized.relay_entries.len(), 2);
    }

    #[test]
    fn test_block_hash_deterministic() {
        let relay_entries = vec![
            make_test_relay_entry(0, vec![(0, 1)]),
        ];

        let block = McpBlockV1::new_unsigned(
            100,
            5,
            make_test_hash(42),
            relay_entries,
        );

        let hash1 = block.compute_block_hash();
        let hash2 = block.compute_block_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_block_signature() {
        let keypair = Keypair::new();
        let relay_entries = vec![
            make_test_relay_entry(0, vec![(0, 1)]),
        ];

        let mut block = McpBlockV1::new_unsigned(
            100,
            5,
            make_test_hash(42),
            relay_entries,
        );

        block.sign(&keypair);

        assert!(block.verify_leader_signature(&keypair.pubkey()));

        // Verify with wrong pubkey fails
        let wrong_keypair = Keypair::new();
        assert!(!block.verify_leader_signature(&wrong_keypair.pubkey()));
    }

    #[test]
    fn test_vote_serialization() {
        let vote = McpVoteV1::new_unsigned(
            100,
            42,
            make_test_hash(1),
            VoteType::Vote,
            1234567890,
        );

        let mut buffer = Vec::new();
        vote.serialize(&mut buffer).unwrap();

        assert_eq!(buffer.len(), MCP_VOTE_SIZE);

        let deserialized = McpVoteV1::deserialize(&mut buffer.as_slice()).unwrap();

        assert_eq!(deserialized.slot, 100);
        assert_eq!(deserialized.validator_index, 42);
        assert_eq!(deserialized.block_hash, make_test_hash(1));
        assert_eq!(deserialized.vote_type, VoteType::Vote);
        assert_eq!(deserialized.timestamp, 1234567890);
    }

    #[test]
    fn test_vote_signature() {
        let keypair = Keypair::new();
        let mut vote = McpVoteV1::new_unsigned(
            100,
            42,
            make_test_hash(1),
            VoteType::Vote,
            1234567890,
        );

        vote.sign(&keypair);

        assert!(vote.verify_signature(&keypair.pubkey()));
    }

    #[test]
    fn test_block_builder_minimum_relays() {
        let mut builder = McpBlockBuilder::new(100, 5, make_test_hash(42));

        // Not enough attestations
        assert!(!builder.can_build());

        // Add minimum required attestations
        for i in 0..MIN_RELAYS_IN_BLOCK {
            let attestation = RelayAttestation {
                version: 1,
                slot: 100,
                relay_id: i as u16,
                entries: vec![make_test_attestation_entry(0, 1)],
                relay_signature: solana_signature::Signature::default(),
            };
            builder.add_attestation(i as u16, attestation);
        }

        assert!(builder.can_build());

        let block = builder.build_unsigned().unwrap();
        assert!(block.has_minimum_relays());
        assert!(block.relays_are_sorted_and_unique());
    }

    #[test]
    fn test_block_relays_sorted() {
        let relay_entries = vec![
            make_test_relay_entry(0, vec![(0, 1)]),
            make_test_relay_entry(5, vec![(1, 2)]),
            make_test_relay_entry(10, vec![(2, 3)]),
        ];

        let block = McpBlockV1::new_unsigned(100, 5, make_test_hash(42), relay_entries);
        assert!(block.relays_are_sorted_and_unique());

        // Unsorted entries
        let unsorted_entries = vec![
            make_test_relay_entry(5, vec![(0, 1)]),
            make_test_relay_entry(0, vec![(1, 2)]),
        ];

        let unsorted_block = McpBlockV1::new_unsigned(100, 5, make_test_hash(42), unsorted_entries);
        assert!(!unsorted_block.relays_are_sorted_and_unique());
    }

    #[test]
    fn test_implied_proposer_commitments() {
        // Create relay entries where proposer 0 has consistent commitment across 100 relays
        // and proposer 1 has inconsistent commitments
        let mut relay_entries = Vec::new();

        for i in 0..150 {
            let proposer_0_commitment = 1; // Consistent
            let proposer_1_commitment = if i < 50 { 2 } else { 3 }; // Inconsistent

            relay_entries.push(make_test_relay_entry(
                i as u32,
                vec![(0, proposer_0_commitment), (1, proposer_1_commitment)],
            ));
        }

        let block = McpBlockV1::new_unsigned(100, 5, make_test_hash(42), relay_entries);
        let implied = block.get_implied_proposer_commitments();

        // Proposer 0 should be included (150 attestations >= 80 required)
        assert!(implied.contains_key(&0));
        assert_eq!(implied[&0].1, 150);

        // Proposer 1 should also be included (100 attestations for commitment 3 >= 80)
        assert!(implied.contains_key(&1));
        assert_eq!(implied[&1].1, 100); // The larger count
    }

    #[test]
    fn test_block_validator() {
        let keypair = Keypair::new();
        let delayed_bankhash = make_test_hash(42);

        // Build a valid block with enough relays
        let mut builder = McpBlockBuilder::new(100, 5, delayed_bankhash);
        for i in 0..MIN_RELAYS_IN_BLOCK {
            let attestation = RelayAttestation {
                version: 1,
                slot: 100,
                relay_id: i as u16,
                entries: vec![make_test_attestation_entry(0, 1)],
                relay_signature: solana_signature::Signature::default(),
            };
            builder.add_attestation(i as u16, attestation);
        }

        let block = builder.build(&keypair).unwrap();

        let validator = BlockValidator::new(5, delayed_bankhash, keypair.pubkey());
        assert!(validator.validate(&block).is_ok());

        // Wrong leader should fail
        let wrong_leader_validator = BlockValidator::new(6, delayed_bankhash, keypair.pubkey());
        assert!(matches!(
            wrong_leader_validator.validate(&block),
            Err(BlockValidationError::WrongLeader { .. })
        ));

        // Wrong bankhash should fail
        let wrong_bankhash_validator = BlockValidator::new(5, make_test_hash(99), keypair.pubkey());
        assert!(matches!(
            wrong_bankhash_validator.validate(&block),
            Err(BlockValidationError::BankhashMismatch { .. })
        ));
    }

    #[test]
    fn test_compute_implied_blocks_basic() {
        // Create 100 relays attesting to proposer 0 with commitment 1
        let mut relay_entries = Vec::new();
        for i in 0..100 {
            relay_entries.push(make_test_relay_entry(i as u32, vec![(0, 1)]));
        }

        let block = McpBlockV1::new_unsigned(100, 5, make_test_hash(42), relay_entries);
        let implied = block.compute_implied_blocks();

        // Proposer 0 should be included (100 >= 80)
        assert_eq!(implied.len(), 1);
        assert_eq!(implied[0].0, 0);
        assert_eq!(implied[0].1, make_test_hash(1));
    }

    #[test]
    fn test_compute_implied_blocks_equivocation() {
        // Create relays where proposer 0 equivocates (sends different commitments)
        let mut relay_entries = Vec::new();

        // 50 relays attest to commitment 1
        for i in 0..50 {
            relay_entries.push(make_test_relay_entry(i as u32, vec![(0, 1)]));
        }

        // 50 relays attest to commitment 2
        for i in 50..100 {
            relay_entries.push(make_test_relay_entry(i as u32, vec![(0, 2)]));
        }

        let block = McpBlockV1::new_unsigned(100, 5, make_test_hash(42), relay_entries);
        let implied = block.compute_implied_blocks();

        // Proposer 0 should be EXCLUDED due to equivocation
        assert!(implied.is_empty());
    }

    #[test]
    fn test_compute_implied_blocks_below_threshold() {
        // Create 79 relays attesting to proposer 0 (below threshold of 80)
        let mut relay_entries = Vec::new();
        for i in 0..79 {
            relay_entries.push(make_test_relay_entry(i as u32, vec![(0, 1)]));
        }

        let block = McpBlockV1::new_unsigned(100, 5, make_test_hash(42), relay_entries);
        let implied = block.compute_implied_blocks();

        // Proposer 0 should be excluded (79 < 80)
        assert!(implied.is_empty());
    }

    #[test]
    fn test_compute_implied_blocks_multiple_proposers() {
        // Create relays attesting to multiple proposers
        let mut relay_entries = Vec::new();

        for i in 0..100 {
            relay_entries.push(make_test_relay_entry(
                i as u32,
                vec![
                    (0, 1),   // Proposer 0 with commitment 1
                    (2, 3),   // Proposer 2 with commitment 3
                ],
            ));
        }

        let block = McpBlockV1::new_unsigned(100, 5, make_test_hash(42), relay_entries);
        let implied = block.compute_implied_blocks();

        // Both proposers should be included (100 >= 80)
        assert_eq!(implied.len(), 2);
        // Sorted by proposer_id
        assert_eq!(implied[0].0, 0);
        assert_eq!(implied[1].0, 2);
    }

    #[test]
    fn test_availability_checker_ready() {
        let slot = 100;
        let commitment = make_test_hash(1);

        let mut availability = InMemoryShredAvailability::new();

        // Record 40 shreds for proposer 0
        for i in 0..K_DATA_SHREDS {
            availability.record_shred(slot, 0, commitment, i as u16);
        }

        let checker = AvailabilityChecker::new(slot, &availability);
        let implied = vec![(0, commitment)];

        assert_eq!(checker.check_availability(&implied), AvailabilityCheckResult::Ready);
    }

    #[test]
    fn test_availability_checker_waiting() {
        let slot = 100;
        let commitment = make_test_hash(1);

        let mut availability = InMemoryShredAvailability::new();

        // Record only 30 shreds for proposer 0 (below threshold)
        for i in 0..30 {
            availability.record_shred(slot, 0, commitment, i as u16);
        }

        let checker = AvailabilityChecker::new(slot, &availability);
        let implied = vec![(0, commitment)];

        let result = checker.check_availability(&implied);
        match result {
            AvailabilityCheckResult::Waiting { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0].0, 0); // proposer_id
                assert_eq!(missing[0].2, 30); // current count
            }
            _ => panic!("Expected Waiting"),
        }
    }

    #[test]
    fn test_availability_checker_multiple_proposers() {
        let slot = 100;
        let commitment_0 = make_test_hash(1);
        let commitment_1 = make_test_hash(2);

        let mut availability = InMemoryShredAvailability::new();

        // Proposer 0 has enough shreds
        for i in 0..50 {
            availability.record_shred(slot, 0, commitment_0, i as u16);
        }

        // Proposer 1 doesn't have enough
        for i in 0..20 {
            availability.record_shred(slot, 1, commitment_1, i as u16);
        }

        let checker = AvailabilityChecker::new(slot, &availability);
        let implied = vec![(0, commitment_0), (1, commitment_1)];

        let result = checker.check_availability(&implied);
        match result {
            AvailabilityCheckResult::Waiting { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0].0, 1); // Only proposer 1 missing
            }
            _ => panic!("Expected Waiting"),
        }
    }
}
