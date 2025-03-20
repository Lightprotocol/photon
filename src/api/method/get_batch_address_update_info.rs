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
use crate::ingester::persist::persisted_indexed_merkle_tree::{compute_range_node_hash_for_subtrees, get_zeroeth_exclusion_range};
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

    // 1. Get batch_start_index (current tree size)
    let max_index_stmt = Statement::from_string(
        tx.get_database_backend(),
        format!(
            "SELECT COALESCE(MAX(leaf_index), 1) as max_index FROM indexed_trees WHERE tree = {}",
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

    // Exit early if no elements in the queue
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

    // 3. Create array of addresses with seq numbers
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

        let address_seq = AddressQueueIndex {
            address: address_pubkey,
            queue_index: queue_index as u64,
        };

        addresses.push(address_seq);
    }

    // 4. Get non-inclusion proofs for each address
    let non_inclusion_proofs =
        get_multiple_new_address_proofs_helper(&tx, addresses_with_trees).await?;

    // 5. Calculate subtrees from the indexed tree
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

    let subtrees = get_subtrees(tree_info.height as usize, &entries)?;

    Ok(GetBatchAddressUpdateInfoResponse {
        context,
        start_index: batch_start_index as u64,
        addresses,
        non_inclusion_proofs,
        subtrees,
    })
}

fn get_subtrees(tree_height: usize, entries: &[Model]) -> Result<Vec<[u8; 32]>, PhotonApiError> {
    let mut subtrees = vec![[0u8; 32]; tree_height];
    if entries.is_empty() {
        return Ok(subtrees);
    }
    // Compute each leaf hash (verify it is 32 bytes) and sort by leaf_index.
    let mut sorted_leaves: Vec<(i64, [u8; 32])> = entries
        .iter()
        .map(|entry| {
            let hash = compute_range_node_hash_for_subtrees(entry)
                .map_err(|e| {
                    PhotonApiError::UnexpectedError(format!("Failed to compute range node hash: {}", e))
                })?;
            if hash.0.len() != 32 {
                return Err(PhotonApiError::UnexpectedError("Computed hash is not 32 bytes".to_string()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash.0);
            Ok((entry.leaf_index, arr))
        })
        .collect::<Result<Vec<_>, _>>()?;
    sorted_leaves.sort_by_key(|(idx, _)| *idx);
    let leaf_level: Vec<[u8; 32]> = sorted_leaves.into_iter().map(|(_, hash)| hash).collect();

    // Build layers from the leaves.
    let mut layers: Vec<Vec<[u8; 32]>> = Vec::new();
    layers.push(leaf_level);

    // Build successive layers until we reach the desired tree height.
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
                let parent = compute_parent_hash(last_layer[i].to_vec(), last_layer[i + 1].to_vec())
                    .map_err(|e| {
                        PhotonApiError::UnexpectedError(format!("Failed to compute parent hash: {}", e))
                    })?;
                if parent.len() < 32 {
                    return Err(PhotonApiError::UnexpectedError("Parent hash length is less than 32".to_string()));
                }
                let mut parent_arr = [0u8; 32];
                parent_arr.copy_from_slice(&parent[..32]);
                next_layer.push(parent_arr);
            } else {
                // // For an unpaired node, simply propagate it.
                // next_layer.push(last_layer[i]);

                println!("Unpaired node: {:?}", last_layer[i]);
                println!("Last layer: {:?}", last_layer);
                println!("layers.len() = {}", layers.len());
                // Instead of simply propagating the unpaired node,
                // compute its parent using a default zero value for the missing right child.
                let default_right =  ZERO_BYTES[layers.len() - 1]; //  vec![0u8; 32];  // You might want to use a level-specific zero if available.
                let parent = compute_parent_hash(last_layer[i].to_vec(), default_right.to_vec())
                    .map_err(|e| {
                        PhotonApiError::UnexpectedError(format!("Failed to compute parent hash: {}", e))
                    })?;
                if parent.len() < 32 {
                    return Err(PhotonApiError::UnexpectedError("Parent hash length is less than 32".to_string()));
                }
                let mut parent_arr = [0u8; 32];
                parent_arr.copy_from_slice(&parent[..32]);
                next_layer.push(parent_arr);
            }
            i += 2;
        }
        layers.push(next_layer);
    }

    // For each level, choose the “rightmost left” node:
    // - if even number of nodes: select element at index len-2,
    // - if odd: select the last element.
    for level in 0..tree_height {
        if let Some(layer) = layers.get(level) {
            if !layer.is_empty() {
                let selected = if layer.len() % 2 == 0 {
                    layer[layer.len() - 2]
                } else {
                    layer[layer.len() - 1]
                };
                subtrees[level] = selected;
            }
        }
    }

    Ok(subtrees)
}



fn format_bytes(bytes: Vec<u8>, database_backend: DatabaseBackend) -> String {
    let hex_bytes = hex::encode(bytes);
    match database_backend {
        DatabaseBackend::Postgres => format!("E'\\\\x{}'", hex_bytes),
        DatabaseBackend::Sqlite => format!("x'{}'", hex_bytes),
        _ => unimplemented!(),
    }
}


#[cfg(test)]
mod tests {
    use light_batched_merkle_tree::constants::DEFAULT_BATCH_ADDRESS_TREE_HEIGHT;
    use light_hasher::Poseidon;
    use light_indexed_merkle_tree::array::IndexedArray;
    use light_indexed_merkle_tree::reference::IndexedMerkleTree;
    use num_bigint::{BigUint, ToBigUint};
    use crate::ingester::persist::persisted_indexed_merkle_tree::{get_top_element, HIGHEST_ADDRESS_PLUS_ONE};
    use super::*;

    #[test]
    fn test_subtrees_2_elements() {
        let tree_height = 40;
        let mut relayer_indexing_array = IndexedArray::<Poseidon, usize>::default();
        relayer_indexing_array.init().unwrap();
        let mut relayer_merkle_tree = IndexedMerkleTree::<Poseidon, usize>::new(tree_height, 0).unwrap();

        relayer_merkle_tree.init().unwrap();
        let root = relayer_merkle_tree.root();
        let root_bn = BigUint::from_bytes_be(&root);
        println!("root {:?}", root_bn);
        println!("indexed mt inited root {:?}", relayer_merkle_tree.root());

        let reference_subtrees: Vec<[u8; 32]> = relayer_merkle_tree.merkle_tree.get_subtrees();
        println!("reference subtrees for empty tree {:?}", reference_subtrees);

        let mut db_entries = vec![];

        let tree_bytes = vec![1, 2, 3, 4, 5]; // Mock tree ID bytes
        // Add the zeroeth element
        let zeroeth_element = indexed_trees::Model {
            tree: tree_bytes.clone(),
            leaf_index: 0,
            value: vec![0; 32],
            next_index: 1,
            next_value: vec![0]
                .into_iter()
                .chain(HIGHEST_ADDRESS_PLUS_ONE.to_bytes_be())
                .collect(),
            seq: Some(0),
        };
        db_entries.push(zeroeth_element);

        let top_element = db_entries.push(get_top_element(tree_bytes.clone()));

        let our_subtrees = get_subtrees(tree_height, &db_entries).unwrap();
        println!("db subtrees for empty tree {:?}", reference_subtrees);

        assert_eq!(reference_subtrees.len(), our_subtrees.len(),
                   "Subtrees arrays should have the same length");

        for i in 0..relayer_merkle_tree.merkle_tree.rightmost_index {
            let element = &relayer_indexing_array.elements[i];
            let leaf = relayer_merkle_tree.merkle_tree.get_leaf(i).unwrap();
            println!("ref element {:?} hash: {:?}", element, leaf);
        }

        // print all leaves from our tree
        for (i, entry) in db_entries.iter().enumerate() {
            println!("our entry {} {:?} hash: {:?}", i, entry, compute_range_node_hash_for_subtrees(entry).unwrap().0);
        }


        let address1_value = 30_u32.to_biguint().unwrap();
        let address1_bytes = address1_value.to_bytes_be();

        let address2_value = 31_u32.to_biguint().unwrap();
        let address2_bytes = address2_value.to_bytes_be();

        let test_address: BigUint = BigUint::from_bytes_be(&[
            171, 159, 63, 33, 62, 94, 156, 27, 61, 216, 203, 164, 91, 229, 110, 16, 230, 124, 129, 133,
            222, 159, 99, 235, 50, 181, 94, 203, 105, 23, 82,
        ]);

        let non_inclusion_proof_0 = relayer_merkle_tree
            .get_non_inclusion_proof(&test_address, &relayer_indexing_array)
            .unwrap();

        // println!("non inclusion proof init {:?}", non_inclusion_proof_0);

        relayer_merkle_tree
            .append(&address1_value, &mut relayer_indexing_array)
            .unwrap();

        relayer_merkle_tree
            .append(&address2_value, &mut relayer_indexing_array)
            .unwrap();

        println!(
            "indexed mt with 2 appends {:?}",
            relayer_merkle_tree.root()
        );
        let root_bn = BigUint::from_bytes_be(&relayer_merkle_tree.root());
        println!("indexed mt with 2 appends {:?}", root_bn);

        let reference_subtrees_with_one = relayer_merkle_tree.merkle_tree.get_subtrees();
        println!("reference subtrees 1 element {:?}", reference_subtrees_with_one);

        let mut padded_address_1 = vec![0; 32];
        if address1_bytes.len() <= 32 {
            let start_idx = 32 - address1_bytes.len();
            padded_address_1[start_idx..].copy_from_slice(&address1_bytes);
        } else {
            padded_address_1.copy_from_slice(&address1_bytes[0..32]);
        }

        let mut padded_address_2 = vec![0; 32];
        if address2_bytes.len() <= 32 {
            let start_idx = 32 - address2_bytes.len();
            padded_address_2[start_idx..].copy_from_slice(&address2_bytes);
        } else {
            padded_address_2.copy_from_slice(&address2_bytes[0..32]);
        }

        let entry_1_value = db_entries.iter()
            .find(|e| e.leaf_index == 1)
            .map(|e| e.value.clone())
            .unwrap_or_else(|| vec![0; 32]);

        let address1_model = indexed_trees::Model {
            tree: tree_bytes.clone(),
            leaf_index: 2,
            value: padded_address_1,
            next_index: 3,
            next_value: padded_address_2.clone(),
            seq: Some(1),
        };

        let address2_model = indexed_trees::Model {
            tree: tree_bytes.clone(),
            leaf_index: 3,
            value: padded_address_2,
            next_index: 1,
            next_value: entry_1_value,
            seq: Some(1),
        };

        db_entries[0].next_index = 2;
        db_entries[0].next_value = address1_model.value.clone();

        // Add new address to entries
        db_entries.push(address1_model);
        db_entries.push(address2_model);

        // Calculate subtrees again with our implementation
        let our_subtrees_with_one = get_subtrees(tree_height, &db_entries).unwrap();
        println!("our subtrees 1 element {:?}", our_subtrees_with_one);

        for i in 0..relayer_merkle_tree.merkle_tree.rightmost_index {
            let element = &relayer_indexing_array.elements[i];
            let leaf = relayer_merkle_tree.merkle_tree.get_leaf(i).unwrap();
            println!("ref element {:?} hash: {:?}", element, leaf);
        }

        // print all leaves from our tree
        for (i, entry) in db_entries.iter().enumerate() {
            println!("our entry {} {:?} hash: {:?}", i, entry, compute_range_node_hash_for_subtrees(entry).unwrap().0);
        }



        // Compare the two implementations with one address
        for (i, (ref_subtree, our_subtree)) in reference_subtrees_with_one.iter().zip(our_subtrees_with_one.iter()).enumerate() {
            assert_eq!(ref_subtree, our_subtree,
                       "Subtrees at level {} don't match after adding one address", i);
        }
    }

    #[test]
    fn test_subtrees_1_element() {
        let tree_height = 40;
        let mut relayer_indexing_array = IndexedArray::<Poseidon, usize>::default();
        relayer_indexing_array.init().unwrap();
        let mut relayer_merkle_tree = IndexedMerkleTree::<Poseidon, usize>::new(tree_height, 0).unwrap();

        relayer_merkle_tree.init().unwrap();
        let root = relayer_merkle_tree.root();
        let root_bn = BigUint::from_bytes_be(&root);
        println!("root {:?}", root_bn);
        println!("indexed mt inited root {:?}", relayer_merkle_tree.root());

        let reference_subtrees: Vec<[u8; 32]> = relayer_merkle_tree.merkle_tree.get_subtrees();
        println!("reference subtrees for empty tree {:?}", reference_subtrees);

        let mut db_entries = vec![];

        let tree_bytes = vec![1, 2, 3, 4, 5]; // Mock tree ID bytes
        // Add the zeroeth element
        let zeroeth_element = indexed_trees::Model {
            tree: tree_bytes.clone(),
            leaf_index: 0,
            value: vec![0; 32],
            next_index: 1,
            next_value: vec![0]
                .into_iter()
                .chain(HIGHEST_ADDRESS_PLUS_ONE.to_bytes_be())
                .collect(),
            seq: Some(0),
        };
        db_entries.push(zeroeth_element);

        let top_element = db_entries.push(get_top_element(tree_bytes.clone()));

        let our_subtrees = get_subtrees(tree_height, &db_entries).unwrap();
        println!("db subtrees for empty tree {:?}", reference_subtrees);

        assert_eq!(reference_subtrees.len(), our_subtrees.len(),
                   "Subtrees arrays should have the same length");

        for i in 0..relayer_merkle_tree.merkle_tree.rightmost_index {
            let element = &relayer_indexing_array.elements[i];
            let leaf = relayer_merkle_tree.merkle_tree.get_leaf(i).unwrap();
            println!("ref element {:?} hash: {:?}", element, leaf);
        }

        // print all leaves from our tree
        for (i, entry) in db_entries.iter().enumerate() {
            println!("our entry {} {:?} hash: {:?}", i, entry, compute_range_node_hash_for_subtrees(entry).unwrap().0);
        }


        let address1_value = 30_u32.to_biguint().unwrap();
        let address1_bytes = address1_value.to_bytes_be();

        let test_address: BigUint = BigUint::from_bytes_be(&[
            171, 159, 63, 33, 62, 94, 156, 27, 61, 216, 203, 164, 91, 229, 110, 16, 230, 124, 129, 133,
            222, 159, 99, 235, 50, 181, 94, 203, 105, 23, 82,
        ]);

        let non_inclusion_proof_0 = relayer_merkle_tree
            .get_non_inclusion_proof(&test_address, &relayer_indexing_array)
            .unwrap();

        // println!("non inclusion proof init {:?}", non_inclusion_proof_0);

        relayer_merkle_tree
            .append(&address1_value, &mut relayer_indexing_array)
            .unwrap();

        println!(
            "indexed mt with 2 appends {:?}",
            relayer_merkle_tree.root()
        );
        let root_bn = BigUint::from_bytes_be(&relayer_merkle_tree.root());
        println!("indexed mt with 2 appends {:?}", root_bn);

        let reference_subtrees_with_one = relayer_merkle_tree.merkle_tree.get_subtrees();
        println!("reference subtrees 1 element {:?}", reference_subtrees_with_one);

        let mut padded_address_1 = vec![0; 32];
        if address1_bytes.len() <= 32 {
            let start_idx = 32 - address1_bytes.len();
            padded_address_1[start_idx..].copy_from_slice(&address1_bytes);
        } else {
            padded_address_1.copy_from_slice(&address1_bytes[0..32]);
        }


        let entry_1_value = db_entries.iter()
            .find(|e| e.leaf_index == 1)
            .map(|e| e.value.clone())
            .unwrap_or_else(|| vec![0; 32]);

        let address1_model = indexed_trees::Model {
            tree: tree_bytes.clone(),
            leaf_index: 2,
            value: padded_address_1,
            next_index: 1,
            next_value: entry_1_value.clone(),
            seq: Some(1),
        };

        db_entries[0].next_index = 2;
        db_entries[0].next_value = address1_model.value.clone();

        // Add new address to entries
        db_entries.push(address1_model);

        // Calculate subtrees again with our implementation
        let our_subtrees_with_one = get_subtrees(tree_height, &db_entries).unwrap();
        println!("our subtrees 1 element {:?}", our_subtrees_with_one);

        for i in 0..relayer_merkle_tree.merkle_tree.rightmost_index {
            let element = &relayer_indexing_array.elements[i];
            let leaf = relayer_merkle_tree.merkle_tree.get_leaf(i).unwrap();
            println!("ref element {:?} hash: {:?}", element, leaf);
        }

        // print all leaves from our tree
        for (i, entry) in db_entries.iter().enumerate() {
            println!("our entry {} {:?} hash: {:?}", i, entry, compute_range_node_hash_for_subtrees(entry).unwrap().0);
        }



        // Compare the two implementations with one address
        for (i, (ref_subtree, our_subtree)) in reference_subtrees_with_one.iter().zip(our_subtrees_with_one.iter()).enumerate() {
            assert_eq!(ref_subtree, our_subtree,
                       "Subtrees at level {} don't match after adding one address", i);
        }
    }

}