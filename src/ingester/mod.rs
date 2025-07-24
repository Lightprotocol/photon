use std::thread::sleep;
use std::time::Duration;

use cadence_macros::statsd_count;
use error::IngesterError;

use parser::parse_transaction;
use sea_orm::sea_query::OnConflict;
use sea_orm::ConnectionTrait;
use sea_orm::DatabaseConnection;
use sea_orm::DatabaseTransaction;

use sea_orm::EntityTrait;
use sea_orm::QueryTrait;
use sea_orm::Set;
use sea_orm::TransactionTrait;

use self::parser::state_update::{StateUpdate, SequenceGapError};
use self::rewind_controller::{RewindController, determine_rewind_slot};
use self::persist::persist_state_update;
use self::persist::MAX_SQL_INSERTS;
use self::typedefs::block_info::BlockInfo;
use self::typedefs::block_info::BlockMetadata;
use crate::dao::generated::blocks;
use crate::metric;
pub mod error;
pub mod fetchers;
pub mod indexer;
pub mod parser;
pub mod persist;
pub mod rewind_controller;
pub mod typedefs;

fn derive_block_state_update(
    block: &BlockInfo,
    rewind_controller: Option<&RewindController>,
) -> Result<StateUpdate, IngesterError> {
    let mut state_updates: Vec<StateUpdate> = Vec::new();
    for transaction in &block.transactions {
        state_updates.push(parse_transaction(transaction, block.metadata.slot)?);
    }
    
    match StateUpdate::merge_updates_with_slot(state_updates, Some(block.metadata.slot)) {
        Ok(merged_update) => Ok(merged_update),
        Err(SequenceGapError::GapDetected(gaps)) => {
            if let Some(controller) = rewind_controller {
                let rewind_slot = determine_rewind_slot(&gaps);
                let reason = format!(
                    "Sequence gaps detected in block {}: {} gaps found",
                    block.metadata.slot,
                    gaps.len()
                );
                controller.request_rewind(rewind_slot, reason)?;
            }
            Err(IngesterError::SequenceGapDetected(gaps))
        }
    }
}

pub async fn index_block(
    db: &DatabaseConnection,
    block: &BlockInfo,
    rewind_controller: Option<&RewindController>,
) -> Result<(), IngesterError> {
    let txn = db.begin().await?;
    index_block_metadatas(&txn, vec![&block.metadata]).await?;
    persist_state_update(&txn, derive_block_state_update(block, rewind_controller)?).await?;
    txn.commit().await?;
    Ok(())
}

async fn index_block_metadatas(
    tx: &DatabaseTransaction,
    blocks: Vec<&BlockMetadata>,
) -> Result<(), IngesterError> {
    for block_chunk in blocks.chunks(MAX_SQL_INSERTS) {
        let block_models: Vec<blocks::ActiveModel> = block_chunk
            .iter()
            .map(|block| {
                Ok::<blocks::ActiveModel, IngesterError>(blocks::ActiveModel {
                    slot: Set(block.slot as i64),
                    parent_slot: Set(block.parent_slot as i64),
                    block_time: Set(block.block_time),
                    blockhash: Set(block.blockhash.clone().into()),
                    parent_blockhash: Set(block.parent_blockhash.clone().into()),
                    block_height: Set(block.block_height as i64),
                })
            })
            .collect::<Result<Vec<blocks::ActiveModel>, IngesterError>>()?;

        // We first build the query and then execute it because SeaORM has a bug where it always throws
        // expected not to insert anything if the key already exists.
        let query = blocks::Entity::insert_many(block_models)
            .on_conflict(
                OnConflict::column(blocks::Column::Slot)
                    .do_nothing()
                    .to_owned(),
            )
            .build(tx.get_database_backend());
        tx.execute(query).await?;
    }
    Ok(())
}

pub async fn index_block_batch(
    db: &DatabaseConnection,
    block_batch: &Vec<BlockInfo>,
    rewind_controller: Option<&RewindController>,
) -> Result<(), IngesterError> {
    let blocks_len = block_batch.len();
    let tx = db.begin().await?;
    let block_metadatas: Vec<&BlockMetadata> = block_batch.iter().map(|b| &b.metadata).collect();
    index_block_metadatas(&tx, block_metadatas).await?;
    let mut state_updates = Vec::new();
    for block in block_batch {
        state_updates.push(derive_block_state_update(block, rewind_controller)?);
    }
    
    if block_batch.is_empty() {
        return Ok(()); // Or return an appropriate error
    }

    let merged_state_update = match StateUpdate::merge_updates_with_slot(
        state_updates, 
        Some(block_batch.last().unwrap().metadata.slot)
    ) {
        Ok(merged) => merged,
        Err(SequenceGapError::GapDetected(gaps)) => {
            if let Some(controller) = rewind_controller {
                let rewind_slot = determine_rewind_slot(&gaps);
                let reason = format!(
                    "Sequence gaps detected in batch ending at slot {}: {} gaps found",
                    block_batch.last().unwrap().metadata.slot,
                    gaps.len()
                );
                controller.request_rewind(rewind_slot, reason)?;
            }
            return Err(IngesterError::SequenceGapDetected(gaps));
        }
    };
    
    persist::persist_state_update(&tx, merged_state_update).await?;
    metric! {
        statsd_count!("blocks_indexed", blocks_len as i64);
    }
    tx.commit().await?;
    Ok(())
}

pub async fn index_block_batch_with_infinite_retries(
    db: &DatabaseConnection,
    block_batch: Vec<BlockInfo>,
    rewind_controller: Option<&RewindController>,
) {
    loop {
        match index_block_batch(db, &block_batch, rewind_controller).await {
            Ok(()) => return,
            Err(IngesterError::SequenceGapDetected(_)) => {
                // For sequence gaps, we don't retry - we let the rewind mechanism handle it
                log::error!("Sequence gap detected in batch, stopping processing to allow rewind");
                return;
            }
            Err(e) => {
                let start_block = block_batch.first().unwrap().metadata.slot;
                let end_block = block_batch.last().unwrap().metadata.slot;
                log::error!(
                    "Failed to index block batch {}-{}. Got error {}",
                    start_block,
                    end_block,
                    e
                );
                sleep(Duration::from_secs(1));
            }
        }
    }
}
