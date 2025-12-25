use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_stream::stream;
use bytes::Bytes;
use futures::StreamExt;
use log::info;

use photon_indexer::ingester::typedefs::block_info::BlockInfo;
use photon_indexer::snapshot::{
    get_snapshot_files_with_metadata, load_block_stream_from_directory_adapter, DirectoryAdapter,
};

const SNAPSHOT_VERSION: u8 = 1;

/// Load all blocks from a snapshot into memory
pub async fn load_all_blocks(
    directory_adapter: Arc<DirectoryAdapter>,
) -> anyhow::Result<Vec<BlockInfo>> {
    let block_stream = load_block_stream_from_directory_adapter(directory_adapter).await;
    futures::pin_mut!(block_stream);

    let mut all_blocks = Vec::new();
    while let Some(blocks) = block_stream.next().await {
        all_blocks.extend(blocks);
    }

    // Sort by slot
    all_blocks.sort_by_key(|b| b.metadata.slot);

    Ok(all_blocks)
}

/// Merge new blocks into existing blocks, deduplicating by slot and signature
pub fn merge_blocks(existing: Vec<BlockInfo>, new_blocks: Vec<BlockInfo>) -> Vec<BlockInfo> {
    // Build a map of slot -> block
    let mut blocks_by_slot: HashMap<u64, BlockInfo> = HashMap::new();

    // Add existing blocks first
    for block in existing {
        blocks_by_slot.insert(block.metadata.slot, block);
    }

    // Merge new blocks
    for new_block in new_blocks {
        let slot = new_block.metadata.slot;
        if let Some(existing_block) = blocks_by_slot.get_mut(&slot) {
            // Merge transactions, deduplicating by signature
            let existing_sigs: HashSet<_> = existing_block
                .transactions
                .iter()
                .map(|tx| tx.signature)
                .collect();

            for tx in new_block.transactions {
                if !existing_sigs.contains(&tx.signature) {
                    existing_block.transactions.push(tx);
                }
            }
        } else {
            blocks_by_slot.insert(slot, new_block);
        }
    }

    // Convert back to sorted vec
    let mut merged: Vec<BlockInfo> = blocks_by_slot.into_values().collect();
    merged.sort_by_key(|b| b.metadata.slot);
    merged
}

/// Write blocks to a snapshot file, overwriting existing files
pub async fn write_snapshot(
    directory_adapter: Arc<DirectoryAdapter>,
    blocks: Vec<BlockInfo>,
) -> anyhow::Result<()> {
    if blocks.is_empty() {
        return Err(anyhow::anyhow!("No blocks to write"));
    }

    let start_slot = blocks.first().unwrap().metadata.slot;
    let end_slot = blocks.last().unwrap().metadata.slot;

    info!(
        "Writing snapshot with {} blocks (slots {} - {})",
        blocks.len(),
        start_slot,
        end_slot
    );

    // Delete existing snapshot files
    let existing_files = get_snapshot_files_with_metadata(directory_adapter.as_ref()).await?;
    for file in existing_files {
        info!("Deleting old snapshot file: {}", file.file);
        directory_adapter.delete_file(file.file).await?;
    }

    // Serialize all blocks
    let mut serialized_blocks = Vec::new();
    for block in &blocks {
        let block_bytes = bincode::serialize(block)?;
        serialized_blocks.extend(block_bytes);
    }

    // Create the snapshot file with version header
    let snapshot_name = format!("snapshot-{}-{}", start_slot, end_slot);
    info!("Writing snapshot: {}", snapshot_name);

    // Version byte (1) + start_slot (8 bytes) + end_slot (8 bytes) + block data
    let mut header = Vec::with_capacity(17);
    header.push(SNAPSHOT_VERSION);
    header.extend(start_slot.to_le_bytes());
    header.extend(end_slot.to_le_bytes());

    // Combine header and block data
    let mut full_data = header;
    full_data.extend(serialized_blocks);

    let byte_stream = stream! {
        yield Ok(Bytes::from(full_data));
    };

    directory_adapter
        .write_file(snapshot_name, byte_stream)
        .await?;

    info!("Snapshot written successfully");

    Ok(())
}
