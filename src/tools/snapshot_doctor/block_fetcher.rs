use std::sync::Arc;

use futures::{stream, StreamExt};
use log::info;
use solana_client::{nonblocking::rpc_client::RpcClient, rpc_config::RpcBlockConfig, rpc_request::RpcError};
use solana_commitment_config::CommitmentConfig;
use solana_transaction_status::{TransactionDetails, UiTransactionEncoding};

use photon_indexer::ingester::typedefs::block_info::{parse_ui_confirmed_blocked, BlockInfo};
use photon_indexer::snapshot::is_compression_transaction;

const SKIPPED_BLOCK_ERRORS: [i64; 2] = [-32007, -32009];

/// Fetch a single block with infinite retries
async fn fetch_block_with_retries(rpc_client: Arc<RpcClient>, slot: u64) -> Option<BlockInfo> {
    let mut retry_count = 0;
    loop {
        match rpc_client
            .get_block_with_config(
                slot,
                RpcBlockConfig {
                    encoding: Some(UiTransactionEncoding::Base64),
                    transaction_details: Some(TransactionDetails::Full),
                    rewards: Some(false),
                    commitment: Some(CommitmentConfig::confirmed()),
                    max_supported_transaction_version: Some(0),
                },
            )
            .await
        {
            Ok(block) => {
                return Some(parse_ui_confirmed_blocked(block, slot).unwrap());
            }
            Err(e) => {
                if let solana_client::client_error::ClientErrorKind::RpcError(
                    RpcError::RpcResponseError { code, .. },
                ) = *e.kind
                {
                    if SKIPPED_BLOCK_ERRORS.contains(&code) {
                        log::debug!("Skipped block: {}", slot);
                        return None;
                    }
                }
                retry_count += 1;
                if retry_count % 10 == 0 {
                    log::warn!(
                        "Failed to fetch block {} after {} retries: {:?}",
                        slot,
                        retry_count,
                        e
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Fetch blocks for a list of slots with concurrent fetching
pub async fn fetch_blocks_for_slots(
    rpc_client: Arc<RpcClient>,
    slots: Vec<u64>,
    max_concurrent: usize,
) -> Vec<BlockInfo> {
    if slots.is_empty() {
        return Vec::new();
    }

    info!("Fetching {} slots from RPC...", slots.len());

    let total_slots = slots.len();
    let fetched = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let blocks: Vec<Option<BlockInfo>> = stream::iter(slots)
        .map(|slot| {
            let rpc_client = rpc_client.clone();
            let fetched = fetched.clone();
            async move {
                let block = fetch_block_with_retries(rpc_client, slot).await;
                let count = fetched.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if count % 100 == 0 || count == total_slots {
                    info!("Fetched {}/{} slots", count, total_slots);
                }
                block
            }
        })
        .buffer_unordered(max_concurrent)
        .collect()
        .await;

    // Filter out None values (skipped blocks) and filter for compression transactions
    let blocks: Vec<BlockInfo> = blocks
        .into_iter()
        .flatten()
        .map(|block| filter_compression_transactions(block))
        .filter(|block| !block.transactions.is_empty())
        .collect();

    info!(
        "Fetched {} blocks with compression transactions",
        blocks.len()
    );

    blocks
}

/// Filter a block to only include compression transactions
fn filter_compression_transactions(block: BlockInfo) -> BlockInfo {
    BlockInfo {
        metadata: block.metadata,
        transactions: block
            .transactions
            .into_iter()
            .filter(|tx| is_compression_transaction(tx))
            .collect(),
    }
}
