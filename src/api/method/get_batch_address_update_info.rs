use log::info;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::error::PhotonApiError;
use crate::api::method::get_multiple_new_address_proofs::{
    get_multiple_new_address_proofs_helper, AddressWithTree, MerkleContextWithNewAddressProof,
};
use crate::common::typedefs::context::Context;
use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::dao::generated::indexed_trees;
use crate::dao::generated::indexed_trees::Model;
use crate::ingester::parser::tree_info::TreeInfo;
use crate::ingester::persist::compute_parent_hash;
use crate::ingester::persist::persisted_indexed_merkle_tree::{compute_range_node_hash, format_bytes, get_zeroeth_exclusion_range, HIGHEST_ADDRESS_PLUS_ONE};
use crate::ingester::persist::persisted_state_tree::ZERO_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetBatchAddressUpdateInfoRequest {
    pub tree: Hash,
    pub batch_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AddressQueueIndex {
    pub address: SerializablePubkey,
    pub queue_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetBatchAddressUpdateInfoResponse {
    pub context: Context,
    pub start_index: u64,
    pub addresses: Vec<AddressQueueIndex>,
    pub non_inclusion_proofs: Vec<MerkleContextWithNewAddressProof>,
    pub subtrees: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetBatchAddressUpdateInfoResponseValue {
    pub proof: Vec<Hash>,
    pub root: Hash,
    pub leaf_index: u64,
    pub leaf: Hash,
    pub tree: Hash,
    pub root_seq: u64,
    pub tx_hash: Option<Hash>,
    pub account_hash: Hash,
}

pub async fn get_batch_address_update_info(
    conn: &DatabaseConnection,
    request: GetBatchAddressUpdateInfoRequest,
) -> Result<GetBatchAddressUpdateInfoResponse, PhotonApiError> {
    info!("get_batch_address_update_info: {:?}", request);
    let batch_size = request.batch_size;
    let merkle_tree_pubkey = request.tree;
    let tree_info = TreeInfo::get(&merkle_tree_pubkey.to_base58())
        .ok_or_else(|| PhotonApiError::UnexpectedError("Failed to get tree info".to_string()))?
        .clone();

    let merkle_tree = SerializablePubkey::from(merkle_tree_pubkey.0).to_bytes_vec();

    let context = Context::extract(conn).await?;
    let tx = conn.begin().await?;
    if tx.get_database_backend() == DatabaseBackend::Postgres {
        tx.execute(Statement::from_string(
            tx.get_database_backend(),
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;".to_string(),
        ))
        .await?;
    }

    // 1. Get batch_start_index
    let max_index_stmt = Statement::from_string(
        tx.get_database_backend(),
        format!(
            "SELECT COALESCE(MAX(leaf_index + 1), 1) as max_index FROM indexed_trees WHERE tree = {}",
            format_bytes(merkle_tree.clone(), tx.get_database_backend())
        ),
    );
    let max_index_result = tx.query_one(max_index_stmt).await?;
    let batch_start_index = match max_index_result {
        Some(row) => row.try_get::<i64>("", "max_index")? as usize,
        None => 1,
    };

    // 2. Get queue elements from the address_queues table
    let address_queue_stmt = Statement::from_string(
        tx.get_database_backend(),
        format!(
            "SELECT tree, address, queue_index FROM address_queues
             WHERE tree = {}
             ORDER BY queue_index ASC
             LIMIT {}",
            format_bytes(merkle_tree.clone(), tx.get_database_backend()),
            batch_size
        ),
    );
    let queue_results = tx.query_all(address_queue_stmt).await?;

    // Early exit if no elements in the queue
    if queue_results.is_empty() {
        tx.commit().await?;
        return Ok(GetBatchAddressUpdateInfoResponse {
            context,
            addresses: Vec::new(),
            non_inclusion_proofs: Vec::new(),
            subtrees: Vec::new(),
            start_index: batch_start_index as u64,
        });
    }

    // 3. Build arrays for addresses and addresses with trees.
    let mut addresses = Vec::new();
    let mut addresses_with_trees = Vec::new();
    let serializable_tree = SerializablePubkey::try_from(merkle_tree.clone())?;

    for row in &queue_results {
        let address: Vec<u8> = row.try_get("", "address")?;
        let queue_index: i64 = row.try_get("", "queue_index")?;
        let address_pubkey = SerializablePubkey::try_from(address.clone())?;
        addresses_with_trees.push(AddressWithTree {
            address: address_pubkey,
            tree: serializable_tree,
        });
        addresses.push(AddressQueueIndex {
            address: address_pubkey,
            queue_index: queue_index as u64,
        });
    }

    // 4. Get non-inclusion proofs for each address.
    let non_inclusion_proofs =
        get_multiple_new_address_proofs_helper(&tx, addresses_with_trees).await?;

    // 5. Retrieve indexed tree entries and compute subtrees.
    let mut entries = indexed_trees::Entity::find()
        .filter(indexed_trees::Column::Tree.eq(merkle_tree.clone()))
        .order_by_asc(indexed_trees::Column::LeafIndex)
        .all(&tx)
        .await
        .map_err(|e| PhotonApiError::UnexpectedError(format!("DB error: {}", e)))?;
    if entries.is_empty() {
        let entry = get_zeroeth_exclusion_range(merkle_tree.clone());
        entries.push(entry);
    }
    let subtrees = get_subtrees(merkle_tree, tree_info.height as usize, &entries)?;

    Ok(GetBatchAddressUpdateInfoResponse {
        context,
        start_index: batch_start_index as u64,
        addresses,
        non_inclusion_proofs,
        subtrees,
    })
}

fn get_subtrees(tree: Vec<u8>, tree_height: usize, entries: &[Model]) -> Result<Vec<[u8; 32]>, PhotonApiError> {
    info!("get_subtrees: tree: {:?}, tree_height: {}, entries: {:?}", tree, tree_height, entries);
    let mut entries = Vec::from(entries);
    let mut subtrees = vec![[0u8; 32]; tree_height];
    if entries.is_empty() {
        entries.push(indexed_trees::Model {
            tree: tree.clone(),
            leaf_index: 0,
            value: vec![0; 32],
            next_index: 1,
            next_value: vec![0]
                .into_iter()
                .chain(HIGHEST_ADDRESS_PLUS_ONE.to_bytes_be())
                .collect(),
            seq: Some(0),
        });
        // entries.push(get_top_element(tree));
    }

    // Compute leaf hashes and sort by leaf_index.
    let mut sorted_leaves: Vec<(i64, [u8; 32])> = entries
        .iter()
        .map(|entry| {
            let hash = compute_range_node_hash(entry).map_err(|e| {
                PhotonApiError::UnexpectedError(format!("Failed to compute range node hash: {}", e))
            })?;
            if hash.0.len() != 32 {
                return Err(PhotonApiError::UnexpectedError(
                    "Computed hash is not 32 bytes".to_string(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash.0);
            Ok((entry.leaf_index, arr))
        })
        .collect::<Result<_, _>>()?;
    sorted_leaves.sort_by_key(|(idx, _)| *idx);
    let leaf_level: Vec<[u8; 32]> = sorted_leaves.into_iter().map(|(_, hash)| hash).collect();

    // Build layers upward from the leaves.
    let mut layers: Vec<Vec<[u8; 32]>> = Vec::new();
    layers.push(leaf_level);

    while layers.len() < tree_height {
        let last_layer = layers.last().unwrap();
        if last_layer.is_empty() {
            break;
        }
        let mut next_layer = Vec::new();
        let len = last_layer.len();
        let mut i = 0;
        while i < len {
            if i + 1 < len {
                let parent =
                    compute_parent_hash(last_layer[i].to_vec(), last_layer[i + 1].to_vec())
                        .map_err(|e| {
                            PhotonApiError::UnexpectedError(format!(
                                "Failed to compute parent hash: {}",
                                e
                            ))
                        })?;
                if parent.len() < 32 {
                    return Err(PhotonApiError::UnexpectedError(
                        "Parent hash length is less than 32".to_string(),
                    ));
                }
                let mut parent_arr = [0u8; 32];
                parent_arr.copy_from_slice(&parent[..32]);
                next_layer.push(parent_arr);
            } else {
                // For an unpaired node, use a default zero value (level-specific).
                let default_right = ZERO_BYTES[layers.len() - 1];
                let parent = compute_parent_hash(last_layer[i].to_vec(), default_right.to_vec())
                    .map_err(|e| {
                        PhotonApiError::UnexpectedError(format!(
                            "Failed to compute parent hash: {}",
                            e
                        ))
                    })?;
                if parent.len() < 32 {
                    return Err(PhotonApiError::UnexpectedError(
                        "Parent hash length is less than 32".to_string(),
                    ));
                }
                let mut parent_arr = [0u8; 32];
                parent_arr.copy_from_slice(&parent[..32]);
                next_layer.push(parent_arr);
            }
            i += 2;
        }
        layers.push(next_layer);
    }

    // For each level choose the rightmost left node.
    for (level, layer) in layers.iter().enumerate() {
        if !layer.is_empty() {
            let selected = if layer.len() % 2 == 0 {
                layer[layer.len() - 2]
            } else {
                layer[layer.len() - 1]
            };
            subtrees[level] = selected;
        }
    }

    info!("get_subtrees: subtrees: {:?}", subtrees);
    Ok(subtrees)
}

#[cfg(test)]
mod tests {
    use borsh::BorshSerialize;
    use super::*;
    use crate::ingester::persist::persisted_indexed_merkle_tree::{
        get_top_element, HIGHEST_ADDRESS_PLUS_ONE,
    };
    use light_hasher::Poseidon;
    use light_indexed_merkle_tree::array::IndexedArray;
    use light_indexed_merkle_tree::reference::IndexedMerkleTree;
    use num_bigint::ToBigUint;
    use solana_program::pubkey::Pubkey;

    #[test]
    fn test_empty_subtrees() {
        let tree_height = 4;
        let mut indexing_array = IndexedArray::<Poseidon, usize>::default();
        indexing_array.init().unwrap();
        let mut indexed_tree = IndexedMerkleTree::<Poseidon, usize>::new(tree_height, 0).unwrap();
        indexed_tree.init().unwrap();

        let db_subtrees = get_subtrees(vec![], tree_height, &[]).unwrap();
        assert_eq!(db_subtrees.len(), tree_height);

        let ref_subtrees = indexed_tree.merkle_tree.get_subtrees();
        assert_eq!(ref_subtrees.len(), tree_height);

        println!("db subtrees: {:?}", db_subtrees);
        println!("ref subtrees: {:?}", ref_subtrees);
        //
        // for (i, (ref_subtree, db_subtree)) in ref_subtrees.iter().zip(db_subtrees.iter()).enumerate() {
        //     assert_eq!(ref_subtree, db_subtree, "Subtrees at level {} don't match", i);
        // }
    }
    // assert subtrees equality with reference implementation after appending from 1 up to 1000 addresses.
    #[test]
    fn test_subtrees_dynamic() {
        let tree_height = 4;
        let mut relayer_indexing_array = IndexedArray::<Poseidon, usize>::default();
        relayer_indexing_array.init().unwrap();
        let mut relayer_merkle_tree =
            IndexedMerkleTree::<Poseidon, usize>::new(tree_height, 0).unwrap();
        relayer_merkle_tree.init().unwrap();
        let tree_bytes = Pubkey::new_unique().try_to_vec().unwrap();

        // Prepare db_entries with the zeroeth element and the top element.
        let mut db_entries = Vec::new();
        db_entries.push(indexed_trees::Model {
            tree: tree_bytes.clone(),
            leaf_index: 0,
            value: vec![0; 32],
            next_index: 1,
            next_value: vec![0]
                .into_iter()
                .chain(HIGHEST_ADDRESS_PLUS_ONE.to_bytes_be())
                .collect(),
            seq: Some(0),
        });
        db_entries.push(get_top_element(tree_bytes.clone()));

        // For each appended address from 1 to 1000.
        for count in 1..=4 {
            let address_value = count.to_biguint().unwrap();
            let address_bytes = address_value.to_bytes_be();
            let mut padded_address = vec![0; 32];
            if address_bytes.len() <= 32 {
                let start_idx = 32 - address_bytes.len();
                padded_address[start_idx..].copy_from_slice(&address_bytes);
            } else {
                padded_address.copy_from_slice(&address_bytes[0..32]);
            }

            let new_index = db_entries.len() as i64;
            // Create a new model with a placeholder next pointer.
            let new_entry = indexed_trees::Model {
                tree: tree_bytes.clone(),
                leaf_index: new_index,
                value: padded_address.clone(),
                next_index: 0,
                next_value: vec![0; 32],
                seq: Some(1),
            };

            // Update chain pointers:
            if new_index == 2 {
                // First appended element: update the zeroeth element pointer.
                db_entries[0].next_index = new_index;
                db_entries[0].next_value = padded_address.clone();
            } else {
                // Update the previously appended element.
                if let Some(prev) = db_entries.get_mut((new_index - 1) as usize) {
                    prev.next_index = new_index;
                    prev.next_value = padded_address.clone();
                }
            }
            db_entries.push(new_entry);

            // Append to the reference Merkle tree.
            relayer_merkle_tree
                .append(&address_value, &mut relayer_indexing_array)
                .unwrap();
        }
        // After all appends, update the last appended element to point back to the top element.
        let top_value = db_entries[1].value.clone();
        if let Some(last) = db_entries.last_mut() {
            last.next_index = 1;
            last.next_value = top_value;
        }

        let reference_subtrees = relayer_merkle_tree.merkle_tree.get_subtrees();
        let our_subtrees = get_subtrees(tree_bytes, tree_height, &db_entries).unwrap();

        assert_eq!(
            reference_subtrees.len(),
            our_subtrees.len(),
            "Subtrees arrays should have the same length"
        );
        for (i, (ref_subtree, our_subtree)) in reference_subtrees
            .iter()
            .zip(our_subtrees.iter())
            .enumerate()
        {
            assert_eq!(
                ref_subtree, our_subtree,
                "Subtrees at level {} don't match after adding {} addresses",
                i, 1000
            );
        }
    }
}
