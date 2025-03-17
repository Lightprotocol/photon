use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait,
    QueryFilter, QueryOrder, Statement, TransactionTrait,
};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::error::PhotonApiError;
use crate::api::method::get_multiple_new_address_proofs::{get_multiple_new_address_proofs_helper, AddressWithTree, MerkleContextWithNewAddressProof};
use crate::common::typedefs::context::Context;
use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::dao::generated::{indexed_trees};
use crate::ingester::parser::tree_info::TreeInfo;
use crate::ingester::persist::{compute_parent_hash};
use crate::ingester::persist::persisted_indexed_merkle_tree::{compute_range_node_hash};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetBatchAddressUpdateInfoRequest {
    pub tree: Hash,
    pub batch_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AddressSeq {
    pub address: SerializablePubkey,
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetBatchAddressUpdateInfoResponse {
    pub context: Context,
    pub start_index: u64,
    pub addresses: Vec<AddressSeq>,
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
    let tree_info = TreeInfo::get(&merkle_tree_pubkey.to_base58()).ok_or_else(|| {
        PhotonApiError::UnexpectedError("Failed to get tree info".to_string())
    })?.clone();

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
            "SELECT COALESCE(MAX(leaf_index), 0) as max_index FROM indexed_trees WHERE tree = {}",
            format_bytes(merkle_tree.clone(), tx.get_database_backend())
        ),
    );
    let max_index_result = tx.query_one(max_index_stmt).await?;
    let batch_start_index = match max_index_result {
        Some(row) => row.try_get::<i64>("", "max_index")? as usize,
        None => 0,
    };

    // 2. Get queue elements from the address_queues table
    let address_queue_stmt = Statement::from_string(
        tx.get_database_backend(),
        format!(
            "SELECT tree, queue, address, seq FROM address_queues
             WHERE tree = {}
             ORDER BY seq ASC
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
        let seq: i64 = row.try_get("", "seq")?;

        let address_pubkey = SerializablePubkey::try_from(address.clone())?;
        addresses_with_trees.push(AddressWithTree {
            address: address_pubkey,
            tree: serializable_tree,
        });

        let address_seq = AddressSeq {
            address: address_pubkey,
            seq: seq as u64,
        };

        addresses.push(address_seq);
    }


    // 4. Get non-inclusion proofs for each address
    let non_inclusion_proofs = get_multiple_new_address_proofs_helper(&tx, addresses_with_trees).await?;

    // 5. Calculate subtrees from the indexed tree
    let entries = indexed_trees::Entity::find()
        .filter(indexed_trees::Column::Tree.eq(merkle_tree.clone()))
        .order_by_asc(indexed_trees::Column::LeafIndex)
        .all(&tx)
        .await
        .map_err(|e| PhotonApiError::UnexpectedError(format!("DB error: {}", e)))?;

    let mut subtrees = vec![[0u8; 32]; tree_info.height as usize];

    // If we have entries, calculate the subtrees
    if !entries.is_empty() {
        // Build initial layer from leaf hashes
        let mut current_layer: Vec<Vec<u8>> = entries.iter()
            .map(|e| compute_range_node_hash(e)
                .map_err(|e| PhotonApiError::UnexpectedError(format!("Failed to compute range node hash: {}", e)))
                .map(|h| h.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;

        let mut level = 0;
        while !current_layer.is_empty() && level < tree_info.height as usize {
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
                    let parent = compute_parent_hash(chunk[0].clone(), chunk[1].clone())
                        .map_err(|e| PhotonApiError::UnexpectedError(format!("Failed to compute parent hash: {}", e)))?;
                    next_layer.push(parent);
                } else {
                    next_layer.push(chunk[0].clone());
                }
            }

            current_layer = next_layer;
            level += 1;
        }
    }

    Ok(GetBatchAddressUpdateInfoResponse {
        context,
        start_index: batch_start_index as u64,
        addresses,
        non_inclusion_proofs,
        subtrees,
    })
}

fn format_bytes(bytes: Vec<u8>, database_backend: DatabaseBackend) -> String {
    let hex_bytes = hex::encode(bytes);
    match database_backend {
        DatabaseBackend::Postgres => format!("E'\\\\x{}'", hex_bytes),
        DatabaseBackend::Sqlite => format!("x'{}'", hex_bytes),
        _ => unimplemented!(),
    }
}
