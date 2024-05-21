/// Copied from the Light repo. We copy them instead of importing from the Light repo in order to
/// to avoid having to import all of Light's dependencies.
use anchor_lang::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, PartialEq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct OutputCompressedAccountWithPackedContext {
    pub compressed_account: CompressedAccount,
    pub merkle_tree_index: u8,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize, Default, PartialEq)]
pub struct PublicTransactionEvent {
    pub input_compressed_account_hashes: Vec<[u8; 32]>,
    pub output_compressed_account_hashes: Vec<[u8; 32]>,
    pub output_compressed_accounts: Vec<OutputCompressedAccountWithPackedContext>,
    pub output_leaf_indices: Vec<u32>,
    pub relay_fee: Option<u64>,
    pub is_compress: bool,
    pub compression_lamports: Option<u64>,
    pub pubkey_array: Vec<Pubkey>,
    // TODO: remove(data can just be written into a compressed account)
    pub message: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct CompressedAccount {
    pub owner: Pubkey,
    pub lamports: u64,
    pub address: Option<[u8; 32]>,
    pub data: Option<CompressedAccountData>,
}

#[derive(Debug, PartialEq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct CompressedAccountData {
    pub discriminator: [u8; 8],
    pub data: Vec<u8>,
    pub data_hash: [u8; 32],
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct Changelogs {
    pub changelogs: Vec<ChangelogEvent>,
}

/// Event containing the Merkle path of the given
/// [`StateMerkleTree`](light_merkle_tree_program::state::StateMerkleTree)
/// change. Indexers can use this type of events to re-build a non-sparse
/// version of state Merkle tree.
#[derive(BorshDeserialize, BorshSerialize, Debug)]
#[repr(C)]
pub enum ChangelogEvent {
    V1(ChangelogEventV1),
    V2(ChangelogEventV2),
}

/// Node of the Merkle path with an index representing the position in a
/// non-sparse Merkle tree.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
pub struct PathNode {
    pub node: [u8; 32],
    pub index: u32,
}

/// Version 1 of the [`ChangelogEvent`](light_merkle_tree_program::state::ChangelogEvent).
#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct ChangelogEventV1 {
    /// Public key of the tree.
    pub id: [u8; 32],
    // Merkle paths.
    pub paths: Vec<Vec<PathNode>>,
    /// Number of successful operations on the on-chain tree.
    pub seq: u64,
    /// Changelog event index.
    pub index: u32,
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct ChangelogEventV2 {
    /// Public key of the tree.
    pub id: [u8; 32],
    pub leaves: Vec<UpdatedLeaf>,
    /// Number of successful operations on the on-chain tree.
    /// seq corresponds to leaves[0].
    /// seq + 1 corresponds to leaves[1].
    pub seq: u64,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
pub struct UpdatedLeaf {
    pub leaf: [u8; 32],
    pub leaf_index: u64,
}


#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct Nullifier {
    pub nullifiers: Vec<NullifyEvent>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
#[repr(C)]
pub enum NullifyEvent {
    V1(NullifyEventV1),
}

/// Version 1 of the [`NullifyEvent`](account_compression::instructions::nullify_leaves::NullifyEvent).
#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct NullifyEventV1 {
    /// Public key of the tree.
    pub id: [u8; 32],
    /// Leaf index.
    pub index: u64,
}