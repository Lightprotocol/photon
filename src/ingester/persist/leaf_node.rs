use crate::common::typedefs::account::{Account, AccountWithContext};
use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::dao::generated::state_trees;
use crate::ingester::error::IngesterError;
use crate::ingester::parser::state_update::LeafNullification;
use crate::ingester::persist::persisted_indexed_merkle_tree::{
    format_bytes, ReferenceTree, REFERENCE_TREES,
};
use crate::ingester::persist::persisted_state_tree::{get_proof_nodes, ZERO_BYTES};
use crate::ingester::persist::{compute_parent_hash, get_node_direct_ancestors};
use crate::migration::OnConflict;
use itertools::Itertools;
use log::info;
use sea_orm::{ConnectionTrait, DatabaseTransaction, EntityTrait, QueryTrait, Set, Statement};
use solana_sdk::signature::Signature;

use std::cmp::max;
use std::collections::HashMap;

pub const TREE_HEIGHT_V1: u32 = 26;
pub const STATE_TREE_HEIGHT_V2: u32 = 32;

#[derive(Clone, Debug)]
pub struct LeafNode {
    pub tree: SerializablePubkey,
    pub leaf_index: u32,
    pub hash: Hash,
    pub seq: Option<u32>,
}

impl LeafNode {
    pub fn node_index(&self, tree_height: u32) -> i64 {
        leaf_index_to_node_index(self.leaf_index, tree_height)
    }
}

// leaf_index should be u64 / i64 to avoid overflow
pub fn leaf_index_to_node_index(leaf_index: u32, tree_height: u32) -> i64 {
    2_i64.pow(tree_height - 1) + leaf_index as i64
}

impl From<Account> for LeafNode {
    fn from(account: Account) -> Self {
        Self {
            tree: account.tree,
            leaf_index: account.leaf_index.0 as u32,
            hash: account.hash,
            seq: account.seq.map(|x| x.0 as u32),
        }
    }
}

impl From<AccountWithContext> for LeafNode {
    fn from(account: AccountWithContext) -> Self {
        Self {
            tree: account.account.tree,
            leaf_index: account.account.leaf_index.0 as u32,
            hash: account.account.hash,
            seq: account.account.seq.map(|x| x.0 as u32),
        }
    }
}

impl From<LeafNullification> for LeafNode {
    fn from(leaf_nullification: LeafNullification) -> Self {
        Self {
            tree: SerializablePubkey::from(leaf_nullification.tree),
            leaf_index: leaf_nullification.leaf_index as u32,
            hash: Hash::from(ZERO_BYTES[0]),
            seq: Some(leaf_nullification.seq as u32),
        }
    }
}

pub async fn persist_leaf_nodes(
    txn: &DatabaseTransaction,
    leaf_nodes: Vec<LeafNode>,
    tree_height: u32,
) -> Result<(), IngesterError> {
    persist_leaf_nodes_with_signatures(
        txn,
        leaf_nodes.into_iter().map(|node| (node, None)).collect(),
        tree_height,
    )
    .await
}

pub async fn persist_leaf_nodes_with_signatures(
    txn: &DatabaseTransaction,
    leaf_nodes_with_signatures: Vec<(LeafNode, Option<Signature>)>,
    tree_height: u32,
) -> Result<(), IngesterError> {
    if leaf_nodes_with_signatures.is_empty() {
        return Ok(());
    }

    let mut leaf_nodes_with_signatures = leaf_nodes_with_signatures;
    leaf_nodes_with_signatures.sort_by_key(|(node, _)| node.seq);
    let leaf_nodes: Vec<LeafNode> = leaf_nodes_with_signatures
        .iter()
        .map(|(node, _)| node.clone())
        .collect();

    let leaf_locations = leaf_nodes
        .iter()
        .map(|node| (node.tree.to_bytes_vec(), node.node_index(tree_height)))
        .collect::<Vec<_>>();

    let node_locations_to_models =
        get_proof_nodes(txn, leaf_locations, true, false, Some(tree_height)).await?;
    let mut node_locations_to_hashes_and_seq = node_locations_to_models
        .iter()
        .map(|(key, value)| (key.clone(), (value.hash.clone(), value.seq)))
        .collect::<HashMap<_, _>>();

    let mut models_to_updates = HashMap::new();

    for leaf_node in leaf_nodes.clone() {
        let node_idx = leaf_node.node_index(tree_height);
        let tree = leaf_node.tree;
        let key = (tree.to_bytes_vec(), node_idx);

        let model = state_trees::ActiveModel {
            tree: Set(tree.to_bytes_vec()),
            level: Set(0),
            node_idx: Set(node_idx),
            hash: Set(leaf_node.hash.to_vec()),
            leaf_idx: Set(Some(leaf_node.leaf_index as i64)),
            seq: Set(leaf_node.seq.map(|x| x as i64)),
        };

        let existing_seq = node_locations_to_hashes_and_seq
            .get(&key)
            .map(|x| x.1)
            .unwrap_or(Some(0));

        if let Some(existing_seq) = existing_seq {
            if let Some(leaf_node_seq) = leaf_node.seq {
                if leaf_node_seq >= existing_seq as u32 {
                    models_to_updates.insert(key.clone(), model);
                    node_locations_to_hashes_and_seq
                        .insert(key, (leaf_node.hash.to_vec(), Some(leaf_node_seq as i64)));
                }
            }
        }
    }

    let all_ancestors = leaf_nodes
        .iter()
        .flat_map(|leaf_node| {
            get_node_direct_ancestors(leaf_node.node_index(tree_height))
                .iter()
                .enumerate()
                .map(move |(i, &idx)| (leaf_node.tree.to_bytes_vec(), idx, i))
                .collect::<Vec<(Vec<u8>, i64, usize)>>()
        })
        .sorted_by(|a, b| {
            // Need to sort elements before dedup
            a.0.cmp(&b.0) // Sort by tree
                .then_with(|| a.1.cmp(&b.1)) // Then by node index
        }) // Need to sort elements before dedup
        .dedup()
        .collect::<Vec<(Vec<u8>, i64, usize)>>();

    for (tree, node_index, child_level) in all_ancestors.into_iter().rev() {
        let (left_child_hash, left_child_seq) = node_locations_to_hashes_and_seq
            .get(&(tree.clone(), node_index * 2))
            .cloned()
            .unwrap_or((ZERO_BYTES[child_level].to_vec(), Some(0)));

        let (right_child_hash, right_child_seq) = node_locations_to_hashes_and_seq
            .get(&(tree.clone(), node_index * 2 + 1))
            .cloned()
            .unwrap_or((ZERO_BYTES[child_level].to_vec(), Some(0)));

        let level = child_level + 1;

        let hash = compute_parent_hash(left_child_hash.clone(), right_child_hash.clone())?;

        let seq = max(left_child_seq, right_child_seq);
        let model = state_trees::ActiveModel {
            tree: Set(tree.clone()),
            level: Set(level as i64),
            node_idx: Set(node_index),
            hash: Set(hash.clone()),
            leaf_idx: Set(None),
            seq: Set(seq),
        };

        let key = (tree.clone(), node_index);
        models_to_updates.insert(key.clone(), model);
        node_locations_to_hashes_and_seq.insert(key, (hash, seq));
    }

    // We first build the query and then execute it because SeaORM has a bug where it always throws
    // an error if we do not insert a record in an insert statement. However, in this case, it's
    // expected not to insert anything if the key already exists.
    let mut query = state_trees::Entity::insert_many(models_to_updates.into_values())
        .on_conflict(
            OnConflict::columns([state_trees::Column::Tree, state_trees::Column::NodeIdx])
                .update_columns([state_trees::Column::Hash, state_trees::Column::Seq])
                .to_owned(),
        )
        .build(txn.get_database_backend());
    query.sql = format!("{} WHERE excluded.seq >= state_trees.seq", query.sql);
    txn.execute(query).await.map_err(|e| {
        IngesterError::DatabaseError(format!("Failed to persist path nodes: {}", e))
    })?;

    // validate_reference_trees(txn, &leaf_nodes_with_signatures, tree_height).await?;

    Ok(())
}

async fn validate_reference_trees(
    txn: &DatabaseTransaction,
    leaf_nodes_with_signatures: &[(LeafNode, Option<Signature>)],
    tree_height: u32,
) -> Result<(), IngesterError> {
    // Group leaf nodes by tree
    let mut trees_to_leaves: HashMap<Vec<u8>, Vec<&(LeafNode, Option<Signature>)>> = HashMap::new();
    for leaf_node_with_sig in leaf_nodes_with_signatures {
        trees_to_leaves
            .entry(leaf_node_with_sig.0.tree.to_bytes_vec())
            .or_insert_with(Vec::new)
            .push(leaf_node_with_sig);
    }

    for (tree_bytes, leaves) in trees_to_leaves {
        // Extract signatures first to avoid borrow checker issues
        let signatures: Vec<String> = leaves
            .iter()
            .filter_map(|(_, sig)| sig.as_ref())
            .map(|sig| sig.to_string())
            .collect();

        // Initialize or synchronize reference tree with current database state
        let ref_root = {
            let mut reference_trees = REFERENCE_TREES.lock().map_err(|e| {
                IngesterError::DatabaseError(format!("Failed to lock reference trees: {}", e))
            })?;

            let reference_tree = reference_trees
                .entry(tree_bytes.clone())
                .or_insert_with(|| {
                    ReferenceTree::new_empty(tree_height).unwrap_or_else(|_| {
                        // Fallback to height 32 if unsupported height
                        ReferenceTree::new_empty(32).unwrap()
                    })
                });

            // For indexed merkle trees, we append leaf hashes in order of their leaf_index
            let mut sorted_leaves = leaves;
            sorted_leaves.sort_by_key(|(leaf, _)| leaf.leaf_index);

            log::debug!(
                "Building reference tree for {:?} with {} leaves",
                SerializablePubkey::try_from(tree_bytes.clone()).unwrap_or_default(),
                sorted_leaves.len()
            );

            for (i, (leaf_node, _)) in sorted_leaves.iter().enumerate() {
                let hash_bytes: [u8; 32] = leaf_node.hash.0;
                log::trace!(
                    "Appending leaf {} at index {}: hash={}",
                    i,
                    leaf_node.leaf_index,
                    hex::encode(hash_bytes)
                );
                reference_tree.append(hash_bytes);
            }

            let root = reference_tree.root();
            log::debug!(
                "Reference tree constructed with root: {} (leaf count: {})",
                hex::encode(root),
                reference_tree.leaf_count()
            );
            root
        };

        // Query the database root (node_idx = 1 is the root node)
        let root_query = Statement::from_string(
            txn.get_database_backend(),
            format!(
                "SELECT hash FROM state_trees WHERE tree = {} AND node_idx = 1 ORDER BY seq DESC LIMIT 1",
                format_bytes(tree_bytes.clone(), txn.get_database_backend())
            ),
        );

        let db_root_row = txn.query_one(root_query).await.map_err(|e| {
            IngesterError::DatabaseError(format!("Failed to query database root: {}", e))
        })?;

        if let Some(row) = db_root_row {
            let db_root_bytes: Vec<u8> = row.try_get("", "hash").map_err(|e| {
                IngesterError::DatabaseError(format!(
                    "Failed to get root hash from database: {}",
                    e
                ))
            })?;

            let db_root: [u8; 32] = db_root_bytes.try_into().map_err(|_| {
                IngesterError::DatabaseError("Database root is not 32 bytes".to_string())
            })?;

            if ref_root != db_root {
                let tree_pubkey = SerializablePubkey::try_from(tree_bytes.clone()).unwrap();
                let signatures_str = if signatures.is_empty() {
                    "No signatures available".to_string()
                } else {
                    signatures.join(", ")
                };

                // Serialize reference tree to file before panicking
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let filename = format!(
                    "reference_tree_mismatch_{}_{}.json",
                    hex::encode(&tree_bytes[..8]),
                    timestamp
                );

                log::error!(
                    "CRITICAL: Reference tree root mismatch detected! Tree: {:?}, Reference root: {}, Database root: {}, Leaf count in reference: {}",
                    tree_pubkey,
                    hex::encode(ref_root),
                    hex::encode(db_root),
                    {
                        let trees = REFERENCE_TREES.lock().unwrap();
                        trees.get(&tree_bytes).map(|t| t.leaf_count()).unwrap_or(0)
                    }
                );

                // Access the reference tree again to serialize it
                let serialization_result = {
                    let reference_trees = REFERENCE_TREES.lock().map_err(|e| {
                        IngesterError::DatabaseError(format!(
                            "Failed to lock reference trees: {}",
                            e
                        ))
                    });

                    match reference_trees {
                        Ok(trees) => {
                            if let Some(tree) = trees.get(&tree_bytes) {
                                tree.serialize_to_file(&tree_bytes, &filename)
                            } else {
                                Err(IngesterError::DatabaseError(
                                    "Reference tree not found".to_string(),
                                ))
                            }
                        }
                        Err(e) => Err(e),
                    }
                };

                match serialization_result {
                    Ok(()) => {
                        log::error!(
                            "Reference tree with full leaf data serialized to {}",
                            filename
                        );
                        log::error!(
                            "To reproduce this issue: load the serialized tree from {} and compare with database state",
                            filename
                        );
                        panic!(
                            "Reference tree root mismatch for tree {:?}: ref_root={} db_root={} transaction_signatures=[{}] serialized_to={}",
                            tree_pubkey,
                            hex::encode(ref_root),
                            hex::encode(db_root),
                            signatures_str,
                            filename
                        );
                    }
                    Err(e) => {
                        log::error!("FAILED to serialize reference tree before panic: {}", e);
                        log::error!("Critical debugging data lost due to serialization failure!");
                        panic!(
                            "Reference tree root mismatch for tree {:?}: ref_root={} db_root={} transaction_signatures=[{}] ERROR: failed_to_serialize_debug_data",
                            tree_pubkey,
                            hex::encode(ref_root),
                            hex::encode(db_root),
                            signatures_str
                        );
                    }
                }
            } else {
                log::debug!(
                    "Reference tree validation PASSED for tree {:?}: root={}",
                    SerializablePubkey::try_from(tree_bytes.clone()).unwrap_or_default(),
                    hex::encode(ref_root)
                );
            }
        } else {
            log::debug!(
                "No existing root found in database for tree: {:?} - this may be a new tree",
                SerializablePubkey::try_from(tree_bytes.clone()).unwrap_or_default()
            );
        }
    }

    Ok(())
}
