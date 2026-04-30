//! Shared Zone RPC data types.

use solana_signature::Signature;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneDecryptedUtxoRecord {
    /// Narrow private query projection. Blinding, spend secrets, and extended
    /// payload bytes are intentionally not retained after hash verification.
    pub utxo_hash: [u8; 32],
    pub operation_commitment: [u8; 32],
    pub zone_config_hash: [u8; 32],
    pub owner_pubkey: [u8; 32],
    pub owner_hash: [u8; 32],
    pub token_mint: [u8; 32],
    pub spl_amount: u64,
    pub sol_amount: u64,
    pub data_hash: [u8; 32],
    pub slot: u64,
    pub signature: Signature,
    pub event_index: u32,
    pub output_index: u8,
    pub utxo_tree: [u8; 32],
    pub leaf_index: u64,
    pub tree_sequence: u64,
    pub spent: bool,
}
