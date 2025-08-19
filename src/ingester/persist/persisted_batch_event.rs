use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::dao::generated::{accounts, address_queues};
use crate::ingester::error::IngesterError;
use crate::ingester::parser::indexer_events::BatchEvent;
use crate::ingester::parser::{
    indexer_events::MerkleTreeEvent, merkle_tree_events_parser::BatchMerkleTreeEvents,
};
use crate::ingester::persist::leaf_node::{persist_leaf_nodes, LeafNode, STATE_TREE_HEIGHT_V2};
use crate::ingester::persist::persisted_indexed_merkle_tree::multi_append;
use crate::ingester::persist::MAX_SQL_INSERTS;
use crate::migration::Expr;
use light_batched_merkle_tree::constants::DEFAULT_BATCH_ADDRESS_TREE_HEIGHT;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder,
    QueryTrait,
};

const ZKP_BATCH_SIZE: usize = 500;

/// We need to find the events of the same tree:
/// - order them by sequence number and execute them in order
///     HashMap<pubkey, Vec<Event(BatchAppendEvent, seq)>>
/// - execute a single function call to persist all changed nodes
pub async fn persist_batch_events(
    txn: &DatabaseTransaction,
    mut events: BatchMerkleTreeEvents,
) -> Result<(), IngesterError> {
    for (_, events) in events.iter_mut() {
        events.sort_by(|a, b| a.0.cmp(&b.0));

        // Process each event in sequence
        for (_, event) in events.iter() {
            // Batch size is 500 for batched State Merkle trees.
            let mut leaf_nodes = Vec::with_capacity(ZKP_BATCH_SIZE);
            match event {
                MerkleTreeEvent::BatchNullify(batch_nullify_event) => {
                    persist_batch_nullify_event(txn, batch_nullify_event, &mut leaf_nodes).await
                }
                MerkleTreeEvent::BatchAppend(batch_append_event) => {
                    persist_batch_append_event(txn, batch_append_event, &mut leaf_nodes).await
                }
                MerkleTreeEvent::BatchAddressAppend(batch_address_append_event) => {
                    persist_batch_address_append_event(txn, batch_address_append_event).await
                }
                _ => Err(IngesterError::InvalidEvent),
            }?;

            if leaf_nodes.len() <= MAX_SQL_INSERTS {
                persist_leaf_nodes(txn, leaf_nodes, STATE_TREE_HEIGHT_V2 + 1).await?;
            } else {
                // Currently not used but a safeguard in case the batch size changes.
                for leaf_nodes_chunk in leaf_nodes.chunks(MAX_SQL_INSERTS) {
                    persist_leaf_nodes(txn, leaf_nodes_chunk.to_vec(), STATE_TREE_HEIGHT_V2 + 1)
                        .await?;
                }
            }
        }
    }
    Ok(())
}

/// Persists a batch append event.
/// 1. Create leaf nodes with the account hash as leaf.
/// 2. Remove inserted elements from the database output queue.
async fn persist_batch_append_event(
    txn: &DatabaseTransaction,
    batch_append_event: &BatchEvent,
    leaf_nodes: &mut Vec<LeafNode>,
) -> Result<(), IngesterError> {
    // 1. Create leaf nodes with the account hash as leaf.
    //      Leaf indices are used as output queue indices.
    //      The leaf index range of the batch append event is
    //      [old_next_index, new_next_index).
    
    // Validation checks performed:
    // 1. Tree filter: Accounts belong to the correct merkle tree
    // 2. Leaf range: Accounts are in range [old_next_index, new_next_index)
    // 3. In queue: Accounts must be in output queue (in_output_queue = true)
    // 4. Count validation: Exactly (new_next_index - old_next_index) accounts must be found
    // 5. Sequential indices: Leaf indices must be sequential with no gaps
    // 6. Account hash exists: Each account must have a non-null hash
    // 7. Update verification: Database update must affect exactly expected_count rows
    // Note: We do NOT check spent status as accounts can be nullified before being appended
    let accounts = accounts::Entity::find()
        .filter(
            // Validation 2: Leaf range - Accounts are in range [old_next_index, new_next_index)
            accounts::Column::LeafIndex
                .gte(batch_append_event.old_next_index as i64)
                .and(accounts::Column::LeafIndex.lt(batch_append_event.new_next_index as i64))
                // Validation 1: Tree filter - Accounts belong to the correct merkle tree
                .and(accounts::Column::Tree.eq(batch_append_event.merkle_tree_pubkey.to_vec()))
                // Validation 3: In queue - Accounts must be in output queue
                .and(accounts::Column::InOutputQueue.eq(true)),
        )
        .order_by_asc(accounts::Column::LeafIndex)
        .all(txn)
        .await?;
    
    // Validation 4: Count validation - Exactly (new_next_index - old_next_index) accounts must be found
    let expected_count = (batch_append_event.new_next_index - batch_append_event.old_next_index) as usize;
    if accounts.len() != expected_count {
        return Err(IngesterError::ParserError(
            format!("Expected {} accounts in append batch, found {}", expected_count, accounts.len())
        ));
    }
    
    // Process accounts and perform per-account validations
    let mut expected_leaf_index = batch_append_event.old_next_index;
    
    for account in &accounts {
        // Validation 5: Sequential indices - Leaf indices must be sequential with no gaps
        if account.leaf_index != expected_leaf_index as i64 {
            return Err(IngesterError::ParserError(
                format!("Gap in leaf indices: expected {}, got {}", expected_leaf_index, account.leaf_index)
            ));
        }
        expected_leaf_index += 1;
        
        // Validation 6: Account hash exists - Each account must have a non-empty hash
        // Note: We don't validate size as we assume DB entries are correct
        if account.hash.is_empty() {
            return Err(IngesterError::ParserError("Account hash is missing".to_string()));
        }
        
        // Create leaf node
        leaf_nodes.push(LeafNode {
            tree: SerializablePubkey::try_from(account.tree.clone()).map_err(|_| {
                IngesterError::ParserError(
                    "Failed to convert tree to SerializablePubkey".to_string(),
                )
            })?,
            seq: Some(batch_append_event.sequence_number as u32),
            leaf_index: account.leaf_index as u32,
            hash: Hash::new(account.hash.as_slice()).map_err(|_| {
                IngesterError::ParserError("Failed to convert account hash to Hash".to_string())
            })?,
        });
    }

    // 2. Remove inserted elements from the output queue.
    let query = accounts::Entity::update_many()
        .col_expr(accounts::Column::InOutputQueue, Expr::value(false))
        .filter(
            accounts::Column::LeafIndex
                .gte(batch_append_event.old_next_index as i64)
                .and(accounts::Column::LeafIndex.lt(batch_append_event.new_next_index as i64))
                .and(accounts::Column::Tree.eq(batch_append_event.merkle_tree_pubkey.to_vec())),
        )
        .build(txn.get_database_backend());
    
    let result = txn.execute(query).await?;
    
    // Validation 7: Update verification - Database update must affect exactly expected_count rows
    if result.rows_affected() != expected_count as u64 {
        return Err(IngesterError::ParserError(
            format!("Update affected {} rows, expected {}", result.rows_affected(), expected_count)
        ));
    }
    
    Ok(())
}

/// Persists a batch nullify event.
/// 1. Create leaf nodes with nullifier as leaf.
/// 2. Mark elements as nullified in tree
///     and remove them from the database nullifier queue.
async fn persist_batch_nullify_event(
    txn: &DatabaseTransaction,
    batch_nullify_event: &BatchEvent,
    leaf_nodes: &mut Vec<LeafNode>,
) -> Result<(), IngesterError> {
    // 1. Create leaf nodes with nullifier as leaf.
    //      Nullifier queue index is continuously incremented by 1
    //      with each element insertion into the nullifier queue.

    // Validation checks performed:
    // 1. Tree filter: Accounts belong to the correct merkle tree
    // 2. Queue range: Accounts are in batch range [old_next_index, new_next_index)
    // 3. Spent state: Accounts must be spent (spent = true)
    // 4. Not nullified: Accounts must not yet be nullified in tree (nullified_in_tree = false)
    // 5. In tree: Accounts must already be in tree, not in queue (in_output_queue = false)
    // 6. Count validation: Exactly (new_next_index - old_next_index) accounts must be found
    // 7. Sequential indices: Queue indices must be sequential with no gaps
    // 8. Nullifier exists: Each account must have a non-null nullifier
    // 9. Update verification: Database update must affect exactly expected_count rows
    let accounts = accounts::Entity::find()
        .filter(
            // Validation 2: Queue range - Accounts are in batch range [old_next_index, new_next_index)
            accounts::Column::NullifierQueueIndex
                .gte(batch_nullify_event.old_next_index)
                .and(accounts::Column::NullifierQueueIndex.lt(batch_nullify_event.new_next_index))
                // Validation 1: Tree filter - Accounts belong to the correct merkle tree
                .and(accounts::Column::Tree.eq(batch_nullify_event.merkle_tree_pubkey.to_vec()))
                // Validation 3: Spent state - Accounts must be spent
                .and(accounts::Column::Spent.eq(true))
                // Validation 4: Not nullified - Accounts must not yet be nullified in tree
                .and(accounts::Column::NullifiedInTree.eq(false))
                // Validation 5: In tree - Accounts must already be in tree, not in queue
                .and(accounts::Column::InOutputQueue.eq(false)),
        )
        .order_by_asc(accounts::Column::NullifierQueueIndex)
        .all(txn)
        .await?;

    // Validation 6: Count validation - Exactly (new_next_index - old_next_index) accounts must be found
    let expected_count =
        (batch_nullify_event.new_next_index - batch_nullify_event.old_next_index) as usize;
    if accounts.len() != expected_count {
        return Err(IngesterError::ParserError(format!(
            "Expected {} accounts in nullifier batch, found {}",
            expected_count,
            accounts.len()
        )));
    }

    let mut expected_index = batch_nullify_event.old_next_index;

    for account in &accounts {
        // Validation 7: Sequential indices - Queue indices must be sequential with no gaps
        let queue_index = account.nullifier_queue_index.ok_or_else(|| {
            IngesterError::ParserError("Missing nullifier queue index".to_string())
        })?;
        if queue_index != expected_index as i64 {
            return Err(IngesterError::ParserError(format!(
                "Gap in nullifier queue: expected {}, got {}",
                expected_index, queue_index
            )));
        }
        expected_index += 1;

        // Validation 8: Nullifier exists - Each account must have a non-null nullifier
        let nullifier = account
            .nullifier
            .as_ref()
            .ok_or_else(|| IngesterError::ParserError("Nullifier is missing".to_string()))?;

        leaf_nodes.push(LeafNode {
            tree: SerializablePubkey::try_from(account.tree.clone()).map_err(|_| {
                IngesterError::ParserError(
                    "Failed to convert tree to SerializablePubkey".to_string(),
                )
            })?,
            seq: Some(batch_nullify_event.sequence_number as u32),
            leaf_index: account.leaf_index as u32,
            hash: Hash::new(nullifier.as_slice()).map_err(|_| {
                IngesterError::ParserError("Failed to convert nullifier to Hash".to_string())
            })?,
        });
    }

    // 2. Mark elements as nullified in tree and
    //      remove them from the database nullifier queue.
    let query = accounts::Entity::update_many()
        .col_expr(
            accounts::Column::NullifierQueueIndex,
            Expr::value(Option::<i64>::None),
        )
        .col_expr(accounts::Column::NullifiedInTree, Expr::value(true))
        .filter(
            accounts::Column::NullifierQueueIndex
                .gte(batch_nullify_event.old_next_index)
                .and(accounts::Column::NullifierQueueIndex.lt(batch_nullify_event.new_next_index))
                .and(accounts::Column::Tree.eq(batch_nullify_event.merkle_tree_pubkey.to_vec())),
        )
        .build(txn.get_database_backend());

    let result = txn.execute(query).await?;

    // Validation 9: Update verification - Database update must affect exactly expected_count rows
    if result.rows_affected() != expected_count as u64 {
        return Err(IngesterError::ParserError(format!(
            "Update affected {} rows, expected {}",
            result.rows_affected(),
            expected_count
        )));
    }

    Ok(())
}

/// Persists a batch address append event.
/// 1. Create leaf nodes with the address value as leaf.
/// 2. Remove inserted elements from the database address queue.
async fn persist_batch_address_append_event(
    txn: &DatabaseTransaction,
    batch_address_append_event: &BatchEvent,
) -> Result<(), IngesterError> {
    // Validation checks performed:
    // 1. Tree filter: Addresses belong to the correct address tree
    // 2. Queue range: Addresses are in range [old_next_index, new_next_index)
    // 3. Count validation: Exactly (new_next_index - old_next_index) addresses must be found
    // 4. Sequential indices: Queue indices must be sequential with no gaps
    // 5. Address exists: Each address must have a non-empty value
    // 6. Delete verification: Database delete must affect exactly expected_count rows
    
    let addresses = address_queues::Entity::find()
        .filter(
            // Validation 2: Queue range - Addresses are in range [old_next_index, new_next_index)
            address_queues::Column::QueueIndex
                .gte(batch_address_append_event.old_next_index as i64)
                .and(address_queues::Column::QueueIndex.lt(batch_address_append_event.new_next_index as i64))
                // Validation 1: Tree filter - Addresses belong to the correct address tree
                .and(address_queues::Column::Tree.eq(batch_address_append_event.merkle_tree_pubkey.to_vec())),
        )
        .order_by_asc(address_queues::Column::QueueIndex)
        .all(txn)
        .await?;
    
    // Validation 3: Count validation - Exactly (new_next_index - old_next_index) addresses must be found
    let expected_count = (batch_address_append_event.new_next_index - batch_address_append_event.old_next_index) as usize;
    if addresses.len() != expected_count {
        return Err(IngesterError::ParserError(
            format!("Expected {} addresses in address append batch, found {}", expected_count, addresses.len())
        ));
    }
    
    // Process addresses and perform per-address validations
    let mut expected_queue_index = batch_address_append_event.old_next_index;
    let mut address_values = Vec::with_capacity(expected_count);
    
    for address in &addresses {
        // Validation 4: Sequential indices - Queue indices must be sequential with no gaps
        if address.queue_index != expected_queue_index as i64 {
            return Err(IngesterError::ParserError(
                format!("Gap in address queue indices: expected {}, got {}", expected_queue_index, address.queue_index)
            ));
        }
        expected_queue_index += 1;
        
        // Validation 5: Address exists - Each address must have a non-empty value
        // Note: We don't validate size as we assume DB entries are correct
        if address.address.is_empty() {
            return Err(IngesterError::ParserError("Address value is missing".to_string()));
        }
        
        address_values.push(address.address.clone());
    }

    // 1. Append the addresses to the indexed merkle tree.
    multi_append(
        txn,
        address_values,
        batch_address_append_event.merkle_tree_pubkey.to_vec(),
        DEFAULT_BATCH_ADDRESS_TREE_HEIGHT + 1,
        Some(batch_address_append_event.sequence_number as u32),
    )
    .await?;

    // 2. Remove inserted elements from the database address queue.
    let result = address_queues::Entity::delete_many()
        .filter(
            address_queues::Column::QueueIndex
                .gte(batch_address_append_event.old_next_index as i64)
                .and(address_queues::Column::QueueIndex.lt(batch_address_append_event.new_next_index as i64))
                .and(address_queues::Column::Tree.eq(batch_address_append_event.merkle_tree_pubkey.to_vec())),
        )
        .exec(txn)
        .await?;
    
    // Validation 6: Delete verification - Database delete must affect exactly expected_count rows
    if result.rows_affected != expected_count as u64 {
        return Err(IngesterError::ParserError(
            format!("Delete affected {} rows, expected {}", result.rows_affected, expected_count)
        ));
    }

    Ok(())
}
