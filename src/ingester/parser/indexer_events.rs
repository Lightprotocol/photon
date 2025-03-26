/// Copied from the Light repo. We copy them instead of importing from the Light repo in order
/// to avoid having to import all of Light's dependencies.
use anchor_lang::prelude::*;
use light_compressed_account::indexer_event::event::{BatchNullifyContext, NewAddress};

#[derive(Debug, PartialEq, Eq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct OutputCompressedAccountWithPackedContext {
    pub compressed_account: CompressedAccount,
    pub merkle_tree_index: u8,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize, Default, Eq, PartialEq)]
pub struct MerkleTreeSequenceNumberV2 {
    pub tree_pubkey: Pubkey,
    pub queue_pubkey: Pubkey,
    pub tree_type: u64,
    pub seq: u64,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize, Default, Eq, PartialEq)]
pub struct MerkleTreeSequenceNumberV1 {
    pub pubkey: Pubkey,
    pub seq: u64,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize, Eq, PartialEq)]
pub enum MerkleTreeSequenceNumber {
    V1(MerkleTreeSequenceNumberV1),
    V2(MerkleTreeSequenceNumberV2),
}

impl MerkleTreeSequenceNumber {
    pub fn tree_pubkey(&self) -> Pubkey {
        match self {
            MerkleTreeSequenceNumber::V1(x) => x.pubkey,
            MerkleTreeSequenceNumber::V2(x) => x.tree_pubkey,
        }
    }
    pub fn seq(&self) -> u64 {
        match self {
            MerkleTreeSequenceNumber::V1(x) => x.seq,
            MerkleTreeSequenceNumber::V2(x) => x.seq,
        }
    }
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize, Eq, PartialEq)]
pub enum PublicTransactionEvent {
    V1(PublicTransactionEventV1),
    V2(PublicTransactionEventV2),
}

impl PublicTransactionEvent {
    pub fn input_compressed_account_hashes(&self) -> Vec<[u8; 32]> {
        match self {
            PublicTransactionEvent::V1(x) => x.input_compressed_account_hashes.clone(),
            PublicTransactionEvent::V2(x) => x.input_compressed_account_hashes.clone(),
        }
    }

    pub fn output_compressed_account_hashes(&self) -> Vec<[u8; 32]> {
        match self {
            PublicTransactionEvent::V1(x) => x.output_compressed_account_hashes.clone(),
            PublicTransactionEvent::V2(x) => x.output_compressed_account_hashes.clone(),
        }
    }

    pub fn output_compressed_accounts(&self) -> Vec<OutputCompressedAccountWithPackedContext> {
        match self {
            PublicTransactionEvent::V1(x) => x.output_compressed_accounts.clone(),
            PublicTransactionEvent::V2(x) => x.output_compressed_accounts.clone(),
        }
    }

    pub fn pubkey_array(&self) -> Vec<Pubkey> {
        match self {
            PublicTransactionEvent::V1(x) => x.pubkey_array.clone(),
            PublicTransactionEvent::V2(x) => x.pubkey_array.clone(),
        }
    }

    pub fn sequence_numbers(&self) -> Vec<MerkleTreeSequenceNumber> {
        match self {
            PublicTransactionEvent::V1(x) => x
                .sequence_numbers
                .iter()
                .map(|x| MerkleTreeSequenceNumber::V1(x.clone()))
                .collect(),
            PublicTransactionEvent::V2(x) => x
                .sequence_numbers
                .iter()
                .map(|x| MerkleTreeSequenceNumber::V2(x.clone()))
                .collect(),
        }
    }

    pub fn output_leaf_indices(&self) -> Vec<u32> {
        match self {
            PublicTransactionEvent::V1(x) => x.output_leaf_indices.clone(),
            PublicTransactionEvent::V2(x) => x.output_leaf_indices.clone(),
        }
    }
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize, Default, PartialEq, Eq)]
pub struct PublicTransactionEventV1 {
    pub input_compressed_account_hashes: Vec<[u8; 32]>,
    pub output_compressed_account_hashes: Vec<[u8; 32]>,
    pub output_compressed_accounts: Vec<OutputCompressedAccountWithPackedContext>,
    pub output_leaf_indices: Vec<u32>,
    pub sequence_numbers: Vec<MerkleTreeSequenceNumberV1>,
    pub relay_fee: Option<u64>,
    pub is_compress: bool,
    pub compression_lamports: Option<u64>,
    pub pubkey_array: Vec<Pubkey>,
    // TODO: remove(data can just be written into a compressed account)
    pub message: Option<Vec<u8>>,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize, Default, PartialEq, Eq)]
pub struct PublicTransactionEventV2 {
    pub input_compressed_account_hashes: Vec<[u8; 32]>,
    pub output_compressed_account_hashes: Vec<[u8; 32]>,
    pub output_compressed_accounts: Vec<OutputCompressedAccountWithPackedContext>,
    pub output_leaf_indices: Vec<u32>,
    pub sequence_numbers: Vec<MerkleTreeSequenceNumberV2>,
    pub relay_fee: Option<u64>,
    pub is_compress: bool,
    pub compression_lamports: Option<u64>,
    pub pubkey_array: Vec<Pubkey>,
    // TODO: remove(data can just be written into a compressed account)
    pub message: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BatchPublicTransactionEvent {
    pub event: PublicTransactionEventV2,
    pub new_addresses: Vec<NewAddress>,
    pub input_sequence_numbers: Vec<MerkleTreeSequenceNumberV2>,
    pub address_sequence_numbers: Vec<MerkleTreeSequenceNumberV2>,
    pub tx_hash: [u8; 32],
    pub batch_input_accounts: Vec<BatchNullifyContext>,
}

#[derive(Debug, PartialEq, Eq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct CompressedAccount {
    pub owner: Pubkey,
    pub lamports: u64,
    pub address: Option<[u8; 32]>,
    pub data: Option<CompressedAccountData>,
}

#[derive(Debug, PartialEq, Eq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct CompressedAccountData {
    pub discriminator: [u8; 8],
    pub data: Vec<u8>,
    pub data_hash: [u8; 32],
}

/// Event containing the Merkle path of the given
/// [`StateMerkleTree`](light_merkle_tree_program::state::StateMerkleTree)
/// change. Indexers can use this type of events to re-build a non-sparse
/// version of state Merkle tree.
#[derive(AnchorDeserialize, AnchorSerialize, Clone, Eq, PartialEq, Debug)]
#[repr(C)]
pub enum MerkleTreeEvent {
    V1(ChangelogEvent),
    V2(NullifierEvent),
    V3(IndexedMerkleTreeEvent),
    BatchAppend(BatchEvent),
    BatchNullify(BatchEvent),
    BatchAddressAppend(BatchEvent),
}

/// Node of the Merkle path with an index representing the position in a
/// non-sparse Merkle tree.
#[derive(AnchorDeserialize, AnchorSerialize, Clone, Debug, Eq, PartialEq)]
pub struct PathNode {
    pub node: [u8; 32],
    pub index: u32,
}

/// Version 1 of the [`ChangelogEvent`](light_merkle_tree_program::state::ChangelogEvent).
#[derive(AnchorDeserialize, AnchorSerialize, PartialEq, Eq, Clone, Debug)]
pub struct ChangelogEvent {
    /// Public key of the tree.
    pub id: [u8; 32],
    // Merkle paths.
    pub paths: Vec<Vec<PathNode>>,
    /// Number of successful operations on the on-chain tree.
    pub seq: u64,
    /// Changelog event index.
    pub index: u32,
}

#[derive(AnchorSerialize, AnchorDeserialize, PartialEq, Eq, Clone, Debug)]
pub struct NullifierEvent {
    /// Public key of the tree.
    pub id: [u8; 32],
    /// Indices of leaves that were nullified.
    /// Nullified means updated with [0u8;32].
    pub nullified_leaves_indices: Vec<u64>,
    /// Number of successful operations on the on-chain tree.
    /// seq corresponds to leaves[0].
    /// seq + 1 corresponds to leaves[1].
    pub seq: u64,
}

#[derive(Debug, Default, Clone, Copy, AnchorSerialize, AnchorDeserialize, Eq, PartialEq)]
pub struct RawIndexedElement {
    pub value: [u8; 32],
    pub next_index: usize,
    pub next_value: [u8; 32],
    pub index: usize,
}

#[derive(AnchorDeserialize, AnchorSerialize, PartialEq, Eq, Debug, Clone)]
pub struct IndexedMerkleTreeUpdate {
    pub new_low_element: RawIndexedElement,
    /// Leaf hash in new_low_element.index.
    pub new_low_element_hash: [u8; 32],
    pub new_high_element: RawIndexedElement,
    /// Leaf hash in new_high_element.index,
    /// is equivalent with next_index.
    pub new_high_element_hash: [u8; 32],
}

#[derive(AnchorDeserialize, AnchorSerialize, Clone, PartialEq, Eq, Debug)]
pub struct IndexedMerkleTreeEvent {
    /// Public key of the tree.
    pub id: [u8; 32],
    pub updates: Vec<IndexedMerkleTreeUpdate>,
    /// Number of successful operations on the on-chain tree.
    /// seq corresponds to leaves[0].
    /// seq + 1 corresponds to leaves[1].
    pub seq: u64,
}

#[repr(C)]
#[derive(AnchorDeserialize, AnchorSerialize, Debug, PartialEq, Clone, Eq)]
pub struct BatchEvent {
    pub merkle_tree_pubkey: [u8; 32],
    pub batch_index: u64,
    pub zkp_batch_index: u64,
    pub zkp_batch_size: u64,
    pub old_next_index: u64,
    pub new_next_index: u64,
    pub new_root: [u8; 32],
    pub root_index: u32,
    pub sequence_number: u64,
    pub output_queue_pubkey: Option<[u8; 32]>,
}
