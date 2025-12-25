use std::sync::Arc;

use clap::Parser;
use log::{error, info};
use solana_client::nonblocking::rpc_client::RpcClient;

use photon_indexer::common::{setup_logging, LoggingFormat};
use photon_indexer::snapshot::DirectoryAdapter;

mod block_fetcher;
mod gap_analyzer;
mod snapshot_merger;

use block_fetcher::fetch_blocks_for_slots;
use gap_analyzer::{analyze_snapshot_gaps, compute_slots_to_fetch};
use snapshot_merger::{load_all_blocks, merge_blocks, write_snapshot};

/// Photon Snapshot Doctor: repairs sequence gaps in snapshots by refetching missing blocks
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Snapshot directory (local filesystem)
    #[arg(long)]
    snapshot_dir: Option<String>,

    /// R2 bucket name
    #[arg(long)]
    r2_bucket: Option<String>,

    /// R2 prefix
    #[arg(long, default_value = "")]
    r2_prefix: String,

    /// GCS bucket name
    #[arg(long)]
    gcs_bucket: Option<String>,

    /// GCS prefix
    #[arg(long, default_value = "")]
    gcs_prefix: String,

    /// RPC URL for fetching missing blocks
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,

    /// Max concurrent block fetches
    #[arg(long, default_value_t = 10)]
    max_concurrent_fetches: usize,

    /// Max repair iterations (safety limit)
    #[arg(long, default_value_t = 10)]
    max_iterations: u32,

    /// Dry run - analyze only, don't repair
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Logging format
    #[arg(short, long, default_value_t = LoggingFormat::Standard)]
    logging_format: LoggingFormat,

    /// Show verbose output
    #[arg(long, default_value_t = false)]
    verbose: bool,
}

async fn create_directory_adapter(args: &Args) -> anyhow::Result<Arc<DirectoryAdapter>> {
    match (
        args.snapshot_dir.clone(),
        args.r2_bucket.clone(),
        args.gcs_bucket.clone(),
    ) {
        (Some(snapshot_dir), None, None) => {
            Ok(Arc::new(DirectoryAdapter::from_local_directory(snapshot_dir)))
        }
        (None, Some(r2_bucket), None) => Ok(Arc::new(
            DirectoryAdapter::from_r2_bucket_and_prefix_and_env(r2_bucket, args.r2_prefix.clone())
                .await,
        )),
        (None, None, Some(gcs_bucket)) => Ok(Arc::new(
            DirectoryAdapter::from_gcs_bucket_and_prefix_and_env(
                gcs_bucket,
                args.gcs_prefix.clone(),
            )
            .await,
        )),
        _ => Err(anyhow::anyhow!(
            "Exactly one of snapshot_dir, r2_bucket, or gcs_bucket must be provided"
        )),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    setup_logging(args.logging_format.clone());

    let directory_adapter = create_directory_adapter(&args).await?;
    let rpc_client = Arc::new(RpcClient::new(args.rpc_url.clone()));

    info!("Photon Snapshot Doctor starting...");
    info!("RPC URL: {}", args.rpc_url);
    info!("Max concurrent fetches: {}", args.max_concurrent_fetches);
    info!("Max iterations: {}", args.max_iterations);
    if args.dry_run {
        info!("DRY RUN MODE - no changes will be made");
    }

    let mut iteration = 0;
    loop {
        iteration += 1;
        info!("=== Iteration {} ===", iteration);

        // Analyze for gaps
        let analysis = analyze_snapshot_gaps(directory_adapter.clone()).await?;

        if analysis.gaps.is_empty() {
            info!("No sequence gaps detected! Snapshot is healthy.");
            break;
        }

        error!("Found {} sequence gaps:", analysis.gaps.len());
        for gap in &analysis.gaps {
            error!(
                "  Tree {}: expected seq {}, found seq {} (gap of {}) at slot {}, tx {}",
                gap.tree,
                gap.expected_seq,
                gap.found_seq,
                gap.found_seq - gap.expected_seq,
                gap.gap_slot,
                gap.gap_signature
            );
            if args.verbose {
                error!(
                    "    Previous seq slot: {}, search range: [{}, {}]",
                    gap.prev_seq_slot,
                    gap.prev_seq_slot + 1,
                    gap.gap_slot - 1
                );
            }
        }

        if args.dry_run {
            info!("Dry run mode - not making any repairs");
            return Err(anyhow::anyhow!(
                "Sequence gaps detected (dry run mode, no repairs made)"
            ));
        }

        if iteration > args.max_iterations {
            error!(
                "Max iterations ({}) reached, aborting",
                args.max_iterations
            );
            return Err(anyhow::anyhow!(
                "Failed to repair all gaps after {} iterations",
                args.max_iterations
            ));
        }

        // Compute slots to fetch
        let slots_to_fetch = compute_slots_to_fetch(&analysis.gaps);
        if slots_to_fetch.is_empty() {
            error!("No slots to fetch - gaps may be at snapshot boundaries");
            return Err(anyhow::anyhow!(
                "Cannot determine slots to fetch for gap repair"
            ));
        }

        info!(
            "Need to fetch {} slots: {:?}",
            slots_to_fetch.len(),
            if slots_to_fetch.len() <= 10 {
                format!("{:?}", slots_to_fetch)
            } else {
                format!(
                    "[{}, {}, ... {} more ... {}, {}]",
                    slots_to_fetch[0],
                    slots_to_fetch[1],
                    slots_to_fetch.len() - 4,
                    slots_to_fetch[slots_to_fetch.len() - 2],
                    slots_to_fetch[slots_to_fetch.len() - 1]
                )
            }
        );

        // Fetch missing blocks
        let new_blocks = fetch_blocks_for_slots(
            rpc_client.clone(),
            slots_to_fetch,
            args.max_concurrent_fetches,
        )
        .await;

        if new_blocks.is_empty() {
            info!("No new compression blocks found in fetched slots");
            info!("This may indicate the missing transactions were not compression-related");
            // Continue to next iteration - the gaps might resolve with a fresh analysis
            // or we may need to expand the search range
        } else {
            info!("Fetched {} blocks with compression transactions", new_blocks.len());

            // Load existing blocks
            info!("Loading existing blocks from snapshot...");
            let existing_blocks = load_all_blocks(directory_adapter.clone()).await?;
            info!("Loaded {} existing blocks", existing_blocks.len());

            // Merge blocks
            info!("Merging blocks...");
            let merged_blocks = merge_blocks(existing_blocks, new_blocks);
            info!("Merged to {} total blocks", merged_blocks.len());

            // Write new snapshot
            info!("Writing repaired snapshot...");
            write_snapshot(directory_adapter.clone(), merged_blocks).await?;
        }

        info!("Iteration {} complete, re-validating...", iteration);
    }

    info!("Snapshot repair complete!");
    Ok(())
}
