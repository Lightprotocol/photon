use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    path::PathBuf,
    thread::sleep,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use cadence_macros::statsd_count;
use error::IngesterError;
use light_batched_merkle_tree::queue::BatchedQueueAccount;
use serde::Serialize;

use parser::parse_transaction;
use parser::TreeResolver;
use sea_orm::sea_query::OnConflict;
use sea_orm::ColumnTrait;
use sea_orm::ConnectionTrait;
use sea_orm::DatabaseTransaction;
use sea_orm::{DatabaseConnection, QueryFilter, TransactionTrait};

use sea_orm::EntityTrait;
use sea_orm::QueryTrait;
use sea_orm::Set;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;

use self::parser::indexer_events::MerkleTreeEvent;
use self::parser::state_update::StateUpdate;
use self::parser::tree_info::TreeInfo;
use self::persist::persist_state_update;
use self::persist::MAX_SQL_INSERTS;
use self::typedefs::block_info::BlockInfo;
use self::typedefs::block_info::BlockMetadata;
use crate::dao::generated::{blocks, prelude::TreeMetadata, tree_metadata};
use crate::metric;
use crate::monitor::tree_metadata_sync::parse_tree_account_data;
pub mod error;
pub mod fetchers;
pub mod indexer;
pub mod parser;
pub mod persist;
pub mod startup_cleanup;
pub mod typedefs;

fn dump_dir() -> PathBuf {
    env::var_os("PHOTON_INGEST_DUMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("test-ledger/photon-ingest-dumps"))
}

fn sequence_gap_message(error: &IngesterError) -> Option<&str> {
    let IngesterError::ParserError(message) = error else {
        return None;
    };
    if message.contains("Sequence gap detected") {
        Some(message.as_str())
    } else {
        None
    }
}

#[derive(Serialize)]
struct PhotonTreeMetadataSnapshot {
    queue_pubkey: String,
    tree_type: i32,
    height: i32,
    root_history_capacity: i64,
    sequence_number: i64,
    next_index: i64,
    last_synced_slot: i64,
}

#[derive(Serialize)]
struct TreeInfoSnapshot {
    queue_pubkey: String,
    tree_type: String,
    height: u32,
    root_history_capacity: u64,
}

#[derive(Serialize)]
struct TreeAccountDecodedSummary {
    tree_type: String,
    queue_pubkey: String,
    root_history_capacity: usize,
    height: u32,
    sequence_number: u64,
    next_index: u64,
    owner: String,
}

#[derive(Serialize)]
struct QueueBatchSummary {
    batch_index: usize,
    state: String,
    sequence_number: u64,
    start_index: u64,
    start_slot: u64,
    root_index: u32,
    num_inserted_elements: u64,
    num_inserted_zkps: u64,
    num_inserted_in_current_zkp_batch: u64,
    num_ready_zkp_updates: u64,
    bloom_filter_zeroed: bool,
}

#[derive(Serialize)]
struct OutputQueueDecodedSummary {
    queue_type: u64,
    associated_merkle_tree: String,
    pending_batch_index: u64,
    next_index: u64,
    batch_size: u64,
    zkp_batch_size: u64,
    tree_capacity: u64,
    value_vec_lengths: [usize; 2],
    hash_chain_store_lengths: [usize; 2],
    batches: Vec<QueueBatchSummary>,
}

#[derive(Serialize)]
struct RpcAccountSnapshot {
    role: String,
    pubkey: String,
    exists: bool,
    lamports: Option<u64>,
    owner: Option<String>,
    executable: Option<bool>,
    rent_epoch: Option<u64>,
    data_len: Option<usize>,
    data_base64: Option<String>,
    tree_summary: Option<TreeAccountDecodedSummary>,
    output_queue_summary: Option<OutputQueueDecodedSummary>,
    rpc_error: Option<String>,
}

#[derive(Serialize)]
struct SequenceGapEventSummary {
    sequence_number: u64,
    signature: String,
    slot: u64,
}

#[derive(Serialize)]
struct SequenceGapTreeSnapshot {
    tree_pubkey: String,
    photon_tree_metadata: Option<PhotonTreeMetadataSnapshot>,
    tree_info: Option<TreeInfoSnapshot>,
    event_sequences: Vec<SequenceGapEventSummary>,
    referenced_queue_pubkeys: Vec<String>,
    tree_account: RpcAccountSnapshot,
    queue_accounts: Vec<RpcAccountSnapshot>,
}

async fn fetch_photon_tree_metadata_snapshot(
    db: &DatabaseConnection,
    tree_pubkey: &Pubkey,
) -> Result<Option<PhotonTreeMetadataSnapshot>, IngesterError> {
    let metadata = TreeMetadata::find()
        .filter(tree_metadata::Column::TreePubkey.eq(tree_pubkey.to_bytes().to_vec()))
        .one(db)
        .await?;

    let Some(metadata) = metadata else {
        return Ok(None);
    };
    let queue_pubkey = Pubkey::try_from(metadata.queue_pubkey.as_slice())
        .map_err(|_| IngesterError::ParserError("Invalid queue pubkey length in DB".to_string()))?;

    Ok(Some(PhotonTreeMetadataSnapshot {
        queue_pubkey: queue_pubkey.to_string(),
        tree_type: metadata.tree_type,
        height: metadata.height,
        root_history_capacity: metadata.root_history_capacity,
        sequence_number: metadata.sequence_number,
        next_index: metadata.next_index,
        last_synced_slot: metadata.last_synced_slot,
    }))
}

fn parse_output_queue_summary(account_data: &[u8]) -> Option<OutputQueueDecodedSummary> {
    let mut account_data = account_data.to_vec();
    let queue = BatchedQueueAccount::output_from_bytes(&mut account_data).ok()?;
    let metadata = queue.get_metadata();

    Some(OutputQueueDecodedSummary {
        queue_type: metadata.metadata.queue_type,
        associated_merkle_tree: Pubkey::new_from_array(
            metadata.metadata.associated_merkle_tree.to_bytes(),
        )
        .to_string(),
        pending_batch_index: metadata.batch_metadata.pending_batch_index,
        next_index: metadata.batch_metadata.next_index,
        batch_size: metadata.batch_metadata.batch_size,
        zkp_batch_size: metadata.batch_metadata.zkp_batch_size,
        tree_capacity: metadata.tree_capacity,
        value_vec_lengths: [queue.value_vecs[0].len(), queue.value_vecs[1].len()],
        hash_chain_store_lengths: [
            queue.hash_chain_stores[0].len(),
            queue.hash_chain_stores[1].len(),
        ],
        batches: metadata
            .batch_metadata
            .batches
            .iter()
            .enumerate()
            .map(|(batch_index, batch)| QueueBatchSummary {
                batch_index,
                state: format!("{:?}", batch.get_state()),
                sequence_number: batch.sequence_number,
                start_index: batch.start_index,
                start_slot: batch.start_slot,
                root_index: batch.root_index,
                num_inserted_elements: batch.get_num_inserted_elements(),
                num_inserted_zkps: batch.get_num_inserted_zkps(),
                num_inserted_in_current_zkp_batch: batch.get_num_inserted_zkp_batch(),
                num_ready_zkp_updates: batch.get_num_ready_zkp_updates(),
                bloom_filter_zeroed: batch.bloom_filter_is_zeroed(),
            })
            .collect(),
    })
}

async fn fetch_account_snapshot(
    rpc_client: &RpcClient,
    pubkey: Pubkey,
    role: &str,
) -> RpcAccountSnapshot {
    match rpc_client
        .get_account_with_commitment(&pubkey, CommitmentConfig::confirmed())
        .await
    {
        Ok(response) => match response.value {
            Some(account) => RpcAccountSnapshot {
                role: role.to_string(),
                pubkey: pubkey.to_string(),
                exists: true,
                lamports: Some(account.lamports),
                owner: Some(account.owner.to_string()),
                executable: Some(account.executable),
                rent_epoch: Some(account.rent_epoch),
                data_len: Some(account.data.len()),
                data_base64: Some(BASE64_STANDARD.encode(&account.data)),
                tree_summary: parse_tree_account_data(pubkey, &account)
                    .ok()
                    .flatten()
                    .map(|(tree_type, data)| TreeAccountDecodedSummary {
                        tree_type: format!("{:?}", tree_type),
                        queue_pubkey: data.queue_pubkey.to_string(),
                        root_history_capacity: data.root_history_capacity,
                        height: data.height,
                        sequence_number: data.sequence_number,
                        next_index: data.next_index,
                        owner: data.owner.to_string(),
                    }),
                output_queue_summary: parse_output_queue_summary(&account.data),
                rpc_error: None,
            },
            None => RpcAccountSnapshot {
                role: role.to_string(),
                pubkey: pubkey.to_string(),
                exists: false,
                lamports: None,
                owner: None,
                executable: None,
                rent_epoch: None,
                data_len: None,
                data_base64: None,
                tree_summary: None,
                output_queue_summary: None,
                rpc_error: None,
            },
        },
        Err(err) => RpcAccountSnapshot {
            role: role.to_string(),
            pubkey: pubkey.to_string(),
            exists: false,
            lamports: None,
            owner: None,
            executable: None,
            rent_epoch: None,
            data_len: None,
            data_base64: None,
            tree_summary: None,
            output_queue_summary: None,
            rpc_error: Some(err.to_string()),
        },
    }
}

async fn build_sequence_gap_tree_snapshots(
    db: &DatabaseConnection,
    block_batch: &[BlockInfo],
    rpc_client: &RpcClient,
) -> Result<Vec<SequenceGapTreeSnapshot>, IngesterError> {
    let mut resolver = TreeResolver::new(rpc_client);
    let mut state_updates = Vec::new();
    for block in block_batch {
        state_updates.push(derive_block_state_update(db, block, &mut resolver).await?);
    }

    let merged = StateUpdate::merge_updates(state_updates);
    let mut snapshots = Vec::new();

    for (tree_bytes, events) in &merged.batch_merkle_tree_events {
        let tree_pubkey = Pubkey::from(*tree_bytes);
        let mut sorted_events = events.clone();
        sorted_events.sort_by_key(|event| event.sequence_number);

        let tree_info = TreeInfo::get_by_pubkey(db, &tree_pubkey)
            .await
            .map_err(|e| IngesterError::ParserError(format!("Failed to fetch tree info: {}", e)))?;
        let photon_tree_metadata = fetch_photon_tree_metadata_snapshot(db, &tree_pubkey).await?;

        let mut queue_pubkeys = BTreeSet::new();
        if let Some(tree_info) = &tree_info {
            queue_pubkeys.insert(tree_info.queue);
        }
        for event in &sorted_events {
            let output_queue_pubkey = match &event.event {
                MerkleTreeEvent::BatchAppend(batch_event)
                | MerkleTreeEvent::BatchNullify(batch_event)
                | MerkleTreeEvent::BatchAddressAppend(batch_event) => {
                    batch_event.output_queue_pubkey.map(Pubkey::from)
                }
                _ => None,
            };
            if let Some(queue_pubkey) = output_queue_pubkey {
                queue_pubkeys.insert(queue_pubkey);
            }
        }

        let tree_account = fetch_account_snapshot(rpc_client, tree_pubkey, "tree").await;
        let mut queue_accounts = Vec::new();
        for queue_pubkey in &queue_pubkeys {
            if *queue_pubkey != tree_pubkey {
                queue_accounts
                    .push(fetch_account_snapshot(rpc_client, *queue_pubkey, "queue").await);
            }
        }

        snapshots.push(SequenceGapTreeSnapshot {
            tree_pubkey: tree_pubkey.to_string(),
            photon_tree_metadata,
            tree_info: tree_info.map(|tree_info| TreeInfoSnapshot {
                queue_pubkey: tree_info.queue.to_string(),
                tree_type: format!("{:?}", tree_info.tree_type),
                height: tree_info.height,
                root_history_capacity: tree_info.root_history_capacity,
            }),
            event_sequences: sorted_events
                .into_iter()
                .map(|event| SequenceGapEventSummary {
                    sequence_number: event.sequence_number,
                    signature: event.signature.to_string(),
                    slot: event.slot,
                })
                .collect(),
            referenced_queue_pubkeys: queue_pubkeys.iter().map(ToString::to_string).collect(),
            tree_account,
            queue_accounts,
        });
    }

    Ok(snapshots)
}

fn maybe_dump_sequence_gap_batch(
    block_batch: &[BlockInfo],
    error: &IngesterError,
) -> Option<PathBuf> {
    let message = sequence_gap_message(error)?;

    let start_slot = block_batch.first()?.metadata.slot;
    let end_slot = block_batch.last()?.metadata.slot;
    let path = dump_dir().join(format!("sequence-gap-{start_slot}-{end_slot}.json"));
    if path.exists() {
        return Some(path);
    }

    let parent = path.parent()?;
    fs::create_dir_all(parent).ok()?;
    let file = File::create(&path).ok()?;
    serde_json::to_writer_pretty(
        file,
        &serde_json::json!({
            "error": message,
            "start_slot": start_slot,
            "end_slot": end_slot,
            "blocks": block_batch,
        }),
    )
    .ok()?;

    Some(path)
}

async fn maybe_dump_sequence_gap_account_snapshots(
    db: &DatabaseConnection,
    block_batch: &[BlockInfo],
    rpc_client: &RpcClient,
    error: &IngesterError,
) -> Option<PathBuf> {
    let message = sequence_gap_message(error)?;

    let start_slot = block_batch.first()?.metadata.slot;
    let end_slot = block_batch.last()?.metadata.slot;
    let path = dump_dir().join(format!(
        "sequence-gap-{start_slot}-{end_slot}.accounts.json"
    ));
    if path.exists() {
        return Some(path);
    }

    let snapshots = build_sequence_gap_tree_snapshots(db, block_batch, rpc_client).await;
    let payload = match snapshots {
        Ok(trees) => serde_json::json!({
            "error": message,
            "start_slot": start_slot,
            "end_slot": end_slot,
            "trees": trees,
        }),
        Err(snapshot_error) => serde_json::json!({
            "error": message,
            "start_slot": start_slot,
            "end_slot": end_slot,
            "snapshot_error": snapshot_error.to_string(),
        }),
    };

    let parent = path.parent()?;
    fs::create_dir_all(parent).ok()?;
    let file = File::create(&path).ok()?;
    serde_json::to_writer_pretty(file, &payload).ok()?;

    Some(path)
}

async fn derive_block_state_update<T>(
    conn: &T,
    block: &BlockInfo,
    resolver: &mut TreeResolver<'_>,
) -> Result<StateUpdate, IngesterError>
where
    T: ConnectionTrait + TransactionTrait,
{
    let mut state_updates: Vec<StateUpdate> = Vec::new();
    for transaction in &block.transactions {
        state_updates
            .push(parse_transaction(conn, transaction, block.metadata.slot, resolver).await?);
    }
    Ok(StateUpdate::merge_updates(state_updates))
}

pub async fn index_block(
    db: &DatabaseConnection,
    block: &BlockInfo,
    rpc_client: &RpcClient,
) -> Result<(), IngesterError> {
    let txn = db.begin().await?;
    index_block_metadatas(&txn, vec![&block.metadata]).await?;
    let mut resolver = TreeResolver::new(rpc_client);
    persist_state_update(
        &txn,
        derive_block_state_update(&txn, block, &mut resolver).await?,
    )
    .await?;
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
    rpc_client: &RpcClient,
) -> Result<(), IngesterError> {
    let blocks_len = block_batch.len();
    let tx = db.begin().await?;
    let block_metadatas: Vec<&BlockMetadata> = block_batch.iter().map(|b| &b.metadata).collect();
    index_block_metadatas(&tx, block_metadatas).await?;
    let mut state_updates = Vec::new();
    let mut resolver = TreeResolver::new(rpc_client);
    for block in block_batch {
        state_updates.push(derive_block_state_update(&tx, block, &mut resolver).await?);
    }
    persist::persist_state_update(&tx, StateUpdate::merge_updates(state_updates)).await?;
    metric! {
        statsd_count!("blocks_indexed", blocks_len as i64);
    }
    tx.commit().await?;
    Ok(())
}

pub async fn index_block_batch_with_infinite_retries(
    db: &DatabaseConnection,
    block_batch: Vec<BlockInfo>,
    rpc_client: &RpcClient,
) {
    loop {
        match index_block_batch(db, &block_batch, rpc_client).await {
            Ok(()) => return,
            Err(e) => {
                let start_block = block_batch.first().unwrap().metadata.slot;
                let end_block = block_batch.last().unwrap().metadata.slot;
                let dump_path = maybe_dump_sequence_gap_batch(&block_batch, &e);
                let account_dump_path =
                    maybe_dump_sequence_gap_account_snapshots(db, &block_batch, rpc_client, &e)
                        .await;
                log::error!(
                    "Failed to index block batch {}-{}. Got error {}{}{}",
                    start_block,
                    end_block,
                    e,
                    dump_path
                        .as_ref()
                        .map(|path| format!(". Dumped in-memory block batch to {}", path.display()))
                        .unwrap_or_default(),
                    account_dump_path
                        .as_ref()
                        .map(|path| format!(
                            ". Dumped on-chain tree/queue snapshots to {}",
                            path.display()
                        ))
                        .unwrap_or_default(),
                );
                sleep(Duration::from_secs(1));
            }
        }
    }
}
