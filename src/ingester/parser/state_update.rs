use super::{
    indexer_events::RawIndexedElement, merkle_tree_events_parser::BatchMerkleTreeEvents,
    tree_info::TreeInfo,
};
use crate::common::typedefs::account::AccountWithContext;
use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use borsh::{BorshDeserialize, BorshSerialize};
use jsonrpsee_core::Serialize;
use light_compressed_account::indexer_event::event::{BatchNullifyContext, NewAddress};
use light_compressed_account::TreeType;
use solana_pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::collections::{HashMap, HashSet};
use tracing::error;
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceGap {
    pub tree: Pubkey,
    pub expected_seq: u64,
    pub actual_seq: u64,
}

#[derive(Debug, Clone)]
pub enum SequenceGapError {
    GapDetected(Vec<SequenceGap>),
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct PathNode {
    pub node: [u8; 32],
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrichedPathNode {
    pub node: PathNode,
    pub slot: u64,
    pub tree: [u8; 32],
    pub seq: u64,
    pub level: usize,
    pub tree_depth: usize,
    pub leaf_index: Option<u32>,
}

pub struct PathUpdate {
    pub tree: [u8; 32],
    pub path: Vec<PathNode>,
    pub seq: u64,
}

#[derive(Hash, Eq, Clone, PartialEq, Debug)]
pub struct Transaction {
    pub signature: Signature,
    pub slot: u64,
    pub uses_compression: bool,
    pub error: Option<String>,
}

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub struct AccountTransaction {
    pub hash: Hash,
    pub signature: Signature,
}

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub struct LeafNullification {
    pub tree: Pubkey,
    pub leaf_index: u64,
    pub seq: u64,
    pub signature: Signature,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct IndexedTreeLeafUpdate {
    pub tree: Pubkey,
    pub tree_type: TreeType,
    pub leaf: RawIndexedElement,
    pub hash: [u8; 32],
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AddressQueueUpdate {
    pub tree: SerializablePubkey,
    pub address: [u8; 32],
    pub queue_index: u64,
}

impl From<NewAddress> for AddressQueueUpdate {
    fn from(new_address: NewAddress) -> Self {
        AddressQueueUpdate {
            tree: SerializablePubkey::from(new_address.mt_pubkey),
            address: new_address.address,
            queue_index: new_address.queue_index,
        }
    }
}
// TODO: add rewind for all sequence numbers not just address tree v1
#[derive(Default, Debug, Clone, PartialEq, Eq)]
/// Representation of state update of the compression system that is optimal for simple persistence.
pub struct StateUpdate {
    // v1 and v2 tree accounts
    pub in_accounts: HashSet<Hash>, // covered by leaf nullifications
    // v1 and v2 tree accounts
    pub out_accounts: Vec<AccountWithContext>, // has leaf index, got v2 Merkle trees we need to
    pub account_transactions: HashSet<AccountTransaction>,
    pub transactions: HashSet<Transaction>,
    pub leaf_nullifications: HashSet<LeafNullification>, // Has sequence number
    pub indexed_merkle_tree_updates: HashMap<(Pubkey, u64), IndexedTreeLeafUpdate>, // Has sequence number
    // v2 state and address Merkle tree updates
    pub batch_merkle_tree_events: BatchMerkleTreeEvents, // Has sequence number
    // v2 input accounts that are inserted into the input queue
    pub batch_nullify_context: Vec<BatchNullifyContext>, // Has queue index we need to track this as well the same as sequence number
    pub batch_new_addresses: Vec<AddressQueueUpdate>, // Has queue index we need to track this as well the same as sequence number
}

impl StateUpdate {
    pub fn new() -> Self {
        StateUpdate::default()
    }

    pub fn merge_updates(updates: Vec<StateUpdate>) -> Result<StateUpdate, SequenceGapError> {
        Self::merge_updates_with_slot(updates, None)
    }

    pub fn merge_updates_with_slot(
        updates: Vec<StateUpdate>,
        slot: Option<u64>,
    ) -> Result<StateUpdate, SequenceGapError> {
        let mut merged = StateUpdate::default();
        let mut detected_gaps = Vec::new();

        for update in updates {
            merged.in_accounts.extend(update.in_accounts);
            merged.out_accounts.extend(update.out_accounts);
            merged
                .account_transactions
                .extend(update.account_transactions);
            merged.transactions.extend(update.transactions);
            merged
                .leaf_nullifications
                .extend(update.leaf_nullifications);

            for (key, value) in update.indexed_merkle_tree_updates {
                let (tree, _leaf_index) = key;

                // Check for sequence gaps before merging
                if let Some((expected_seq, actual_seq)) =
                    TreeInfo::check_sequence_gap(&tree, value.seq)
                {
                    error!(
                        "Sequence gap detected for tree {}: expected {}, got {}",
                        tree, expected_seq, actual_seq
                    );
                    detected_gaps.push(SequenceGap {
                        tree,
                        expected_seq,
                        actual_seq,
                    });
                }

                // Update highest sequence numbers for each tree
                if let Some(slot) = slot {
                    for ((tree, _leaf_index), value) in &merged.indexed_merkle_tree_updates {
                        if let Err(e) = TreeInfo::update_highest_seq(tree, value.seq, slot) {
                            error!("Failed to update highest sequence for tree {}: {}", tree, e);
                        }
                    }
                }

                // Insert only if the seq is higher.
                if let Some(existing) = merged.indexed_merkle_tree_updates.get_mut(&key) {
                    if value.seq > existing.seq {
                        *existing = value;
                    }
                } else {
                    merged.indexed_merkle_tree_updates.insert(key, value);
                }
            }

            for (key, events) in update.batch_merkle_tree_events {
                if let Some(existing_events) = merged.batch_merkle_tree_events.get_mut(&key) {
                    existing_events.extend(events);
                } else {
                    merged.batch_merkle_tree_events.insert(key, events);
                }
            }

            merged
                .batch_new_addresses
                .extend(update.batch_new_addresses);
            merged
                .batch_nullify_context
                .extend(update.batch_nullify_context);
        }

        // If gaps were detected, return error
        if !detected_gaps.is_empty() {
            return Err(SequenceGapError::GapDetected(detected_gaps));
        }

        Ok(merged)
    }
}
