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
use crate::ingester::persist::persisted_indexed_merkle_tree::{
    compute_range_node_hash, get_zeroeth_exclusion_range,
};

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

    let subtrees = get_subtrees(tree_info.height as usize, &mut entries)?;

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
    // If we have entries, calculate the subtrees
    if !entries.is_empty() {
        // Build initial layer from leaf hashes
        let mut current_layer: Vec<Vec<u8>> = entries
            .iter()
            .map(|e| {
                compute_range_node_hash(e)
                    .map_err(|e| {
                        PhotonApiError::UnexpectedError(format!(
                            "Failed to compute range node hash: {}",
                            e
                        ))
                    })
                    .map(|h| h.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut level = 0;
        while !current_layer.is_empty() && level < tree_height {
            // Store the rightmost left node at this level
            if current_layer.len() % 2 == 0 && current_layer.len() >= 2 {
                // For even number of nodes, take second-to-last
                subtrees[level].copy_from_slice(&current_layer[current_layer.len() - 2]);
            } else if current_layer.len() % 2 == 1 {
                // For odd number of nodes, take the last one
                subtrees[level].copy_from_slice(&current_layer[current_layer.len() - 1]);
            }

            // Calculate next layer
            let mut next_layer = Vec::new();
            for chunk in current_layer.chunks(2) {
                if chunk.len() == 2 {
                    let parent =
                        compute_parent_hash(chunk[0].clone(), chunk[1].clone()).map_err(|e| {
                            PhotonApiError::UnexpectedError(format!(
                                "Failed to compute parent hash: {}",
                                e
                            ))
                        })?;
                    next_layer.push(parent);
                } else {
                    next_layer.push(chunk[0].clone());
                }
            }

            current_layer = next_layer;
            level += 1;
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
    use super::*;
    use crate::ingester::persist::persisted_indexed_merkle_tree::HIGHEST_ADDRESS_PLUS_ONE;
    use light_batched_merkle_tree::constants::DEFAULT_BATCH_ADDRESS_TREE_HEIGHT;
    use light_hasher::Poseidon;
    use light_indexed_merkle_tree::array::IndexedArray;
    use light_indexed_merkle_tree::reference::IndexedMerkleTree;
    use num_bigint::{BigUint, ToBigUint};

    #[test]
    fn test_subtrees() {
        let mut relayer_indexing_array = IndexedArray::<Poseidon, usize>::default();
        relayer_indexing_array.init().unwrap();
        let mut relayer_merkle_tree = IndexedMerkleTree::<Poseidon, usize>::new(40, 0).unwrap();
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
            next_index: 0,
            next_value: vec![0]
                .into_iter()
                .chain(HIGHEST_ADDRESS_PLUS_ONE.to_bytes_be())
                .collect(),
            seq: Some(0),
        };
        db_entries.push(zeroeth_element);

        let our_subtrees = get_subtrees(DEFAULT_BATCH_ADDRESS_TREE_HEIGHT as usize, &db_entries).unwrap();
        println!("db subtrees for empty tree {:?}", reference_subtrees);

        assert_eq!(reference_subtrees.len(), our_subtrees.len(),
                   "Subtrees arrays should have the same length");

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
            "indexed mt with one append {:?}",
            relayer_merkle_tree.root()
        );
        let root_bn = BigUint::from_bytes_be(&relayer_merkle_tree.root());
        println!("indexed mt with one append {:?}", root_bn);

        let reference_subtrees_with_one = relayer_merkle_tree.merkle_tree.get_subtrees();
        println!("1 subtrees {:?}", reference_subtrees_with_one);

        let mut padded_address = vec![0; 32];
        if address1_bytes.len() <= 32 {
            let start_idx = 32 - address1_bytes.len();
            padded_address[start_idx..].copy_from_slice(&address1_bytes);
        } else {
            padded_address.copy_from_slice(&address1_bytes[0..32]);
        }

        let next_value = vec![0; 32]; // Next value will be zeros for the rightmost address

        let address1_model = indexed_trees::Model {
            tree: tree_bytes.clone(),
            leaf_index: 1,
            value: padded_address,
            next_index: 0,
            next_value,
            seq: Some(0),
        };

        db_entries[0].next_index = 1;
        db_entries[0].next_value = address1_model.value.clone();

        db_entries.push(address1_model);


        let ref_leaf_0 = relayer_merkle_tree.merkle_tree.get_leaf(0).unwrap();
        let ref_leaf_1 = relayer_merkle_tree.merkle_tree.get_leaf(1).unwrap();
        let ref_leaf_2 = relayer_merkle_tree.merkle_tree.get_leaf(2).unwrap();

        println!("ref leaf 0 {:?}", ref_leaf_0);
        println!("ref leaf 1 {:?}", ref_leaf_1);
        println!("ref leaf 2 {:?}", ref_leaf_2);

        let db_leaf_0 = db_entries[0].value.clone();
        let db_leaf_1 = db_entries[1].value.clone();
        println!("db leaf 0 {:?}", db_leaf_0);
        println!("db leaf 1 {:?}", db_leaf_1);

        // Calculate subtrees again with our implementation
        let our_subtrees_with_one = get_subtrees(DEFAULT_BATCH_ADDRESS_TREE_HEIGHT as usize, &db_entries).unwrap();

        // Compare the two implementations with one address
        for (i, (ref_subtree, our_subtree)) in reference_subtrees_with_one.iter().zip(our_subtrees_with_one.iter()).enumerate() {
            assert_eq!(ref_subtree, our_subtree,
                       "Subtrees at level {} don't match after adding one address", i);
        }
    }
}