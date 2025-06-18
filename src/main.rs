use std::fs::File;

use async_std::stream::StreamExt;
use async_stream::stream;
use clap::Parser;
use futures::pin_mut;
use jsonrpsee::server::ServerHandle;
use log::{error, info, warn};
use photon_indexer::api::{self, api::PhotonApi};

use photon_indexer::common::{
    fetch_block_parent_slot, fetch_current_slot_with_infinite_retry, get_network_start_slot,
    get_rpc_client, setup_logging, setup_metrics, setup_pg_pool, LoggingFormat,
};

use photon_indexer::ingester::dump::{BlockDumpLoader, BlockDumper, DumpConfig, DumpFormat};
use photon_indexer::ingester::fetchers::BlockStreamConfig;
use photon_indexer::ingester::indexer::{
    fetch_last_indexed_slot_with_infinite_retry, index_block_stream, index_block_stream_with_dumper,
};
use photon_indexer::migration::{
    sea_orm::{DatabaseBackend, DatabaseConnection, SqlxPostgresConnector, SqlxSqliteConnector},
    Migrator, MigratorTrait,
};

use photon_indexer::monitor::continously_monitor_photon;
use photon_indexer::snapshot::{
    get_snapshot_files_with_metadata, load_block_stream_from_directory_adapter, DirectoryAdapter,
};
use solana_client::nonblocking::rpc_client::RpcClient;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use std::env::temp_dir;
use std::path::PathBuf;
use std::sync::Arc;

/// Photon: a compressed transaction Solana indexer
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Port to expose the local Photon API
    // We use a random default port to avoid conflicts with other services
    #[arg(short, long, default_value_t = 8784)]
    port: u16,

    /// URL of the RPC server
    #[arg(short, long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,

    /// DB URL to store indexing data. By default we use an in-memory SQLite database.
    #[arg(short, long)]
    db_url: Option<String>,

    /// The start slot to begin indexing from. Defaults to the last indexed slot in the database plus
    /// one.
    #[arg(short, long)]
    start_slot: Option<String>,

    /// Max database connections to use in database pool
    #[arg(long, default_value_t = 10)]
    max_db_conn: u32,

    /// Logging format
    #[arg(short, long, default_value_t = LoggingFormat::Standard)]
    logging_format: LoggingFormat,

    /// Max number of blocks to fetch concurrently. Generally, this should be set to be as high
    /// as possible without reaching RPC rate limits.
    #[arg(short, long)]
    max_concurrent_block_fetches: Option<usize>,

    /// Light Prover url to use for verifying proofs
    #[arg(long, default_value = "http://127.0.0.1:3001")]
    prover_url: String,

    /// Snasphot directory
    #[arg(long, default_value = None)]
    snapshot_dir: Option<String>,

    #[arg(short, long, default_value = None)]
    /// Yellowstone gRPC URL. If it's inputed, then the indexer will use gRPC to fetch new blocks
    /// instead of polling. It will still use RPC to fetch blocks if
    grpc_url: Option<String>,

    /// Disable indexing
    #[arg(long, action = clap::ArgAction::SetTrue)]
    disable_indexing: bool,

    /// Disable API
    #[arg(long, action = clap::ArgAction::SetTrue)]
    disable_api: bool,

    /// Custom account compression program ID (optional)
    #[arg(long, default_value = "8bAVNbY2KtCsLZSGFRQ9s44p1sewzLz68q7DLFsBannh")]
    compression_program_id: String,

    /// Light compressed token program ID (optional)
    #[arg(long, default_value = "7ufxL4dJT6zsn9pQysqMm7GkYX8bf1cEQ1K6WHQtqojZ")]
    light_compressed_token_program_id: String,

    /// Light system program pinocchio ID (optional)
    #[arg(long, default_value = "EpgpSRSHbohAPC5XixPCNsNeq8yHfNsj3XorUWk6hVMT")]
    light_system_program_pinocchio_id: String,

    /// Light registry program ID (optional)
    #[arg(long, default_value = "42pUw7FrXo7cdmoFdFqCmgsKFAuRhpVW52W1fNgJKiR7")]
    light_registry_program_id: String,

    /// Metrics endpoint in the format `host:port`
    /// If provided, metrics will be sent to the specified statsd server.
    #[arg(long, default_value = None)]
    metrics_endpoint: Option<String>,

    /// Enable block dumping to files during indexing
    #[arg(long, action = clap::ArgAction::SetTrue)]
    enable_block_dump: bool,

    /// Directory to store block dumps (defaults to ./block_dumps)
    #[arg(long)]
    dump_dir: Option<String>,

    /// Maximum number of blocks per dump file
    #[arg(long, default_value_t = 1000)]
    blocks_per_dump_file: usize,

    /// Dump file format (json or bincode)
    #[arg(long, default_value = "json")]
    dump_format: String,

    /// Load blocks from dump directory instead of RPC (for reindexing)
    #[arg(long)]
    load_from_dumps: Option<String>,

    /// Start slot for loading from dumps (optional)
    #[arg(long)]
    dump_start_slot: Option<u64>,

    /// End slot for loading from dumps (optional)
    #[arg(long)]
    dump_end_slot: Option<u64>,
}

async fn start_api_server(
    db: Arc<DatabaseConnection>,
    rpc_client: Arc<RpcClient>,
    prover_url: String,
    api_port: u16,
) -> ServerHandle {
    let api = PhotonApi::new(db, rpc_client, prover_url);
    api::rpc_server::run_server(api, api_port).await.unwrap()
}

async fn setup_temporary_sqlite_database_pool(max_connections: u32) -> SqlitePool {
    let dir = temp_dir();
    if !dir.exists() {
        std::fs::create_dir_all(&dir).unwrap();
    }
    let db_name = "photon_indexer.db";
    let path = dir.join(db_name);
    if path.exists() {
        std::fs::remove_file(&path).unwrap();
    }
    info!("Creating temporary SQLite database at: {:?}", path);
    File::create(&path).unwrap();
    let db_path = format!("sqlite:////{}", path.to_str().unwrap());
    setup_sqlite_pool(&db_path, max_connections).await
}

async fn setup_sqlite_pool(db_url: &str, max_connections: u32) -> SqlitePool {
    let options: SqliteConnectOptions = db_url.parse().unwrap();
    SqlitePoolOptions::new()
        .max_connections(max_connections)
        .min_connections(1)
        .connect_with(options)
        .await
        .unwrap()
}

pub fn parse_db_type(db_url: &str) -> DatabaseBackend {
    if db_url.starts_with("postgres://") {
        DatabaseBackend::Postgres
    } else if db_url.starts_with("sqlite://") {
        DatabaseBackend::Sqlite
    } else {
        unimplemented!("Unsupported database type: {}", db_url)
    }
}

async fn setup_database_connection(
    db_url: Option<String>,
    max_connections: u32,
) -> Arc<DatabaseConnection> {
    Arc::new(match db_url {
        Some(db_url) => {
            let db_type = parse_db_type(&db_url);
            match db_type {
                DatabaseBackend::Postgres => SqlxPostgresConnector::from_sqlx_postgres_pool(
                    setup_pg_pool(&db_url, max_connections).await,
                ),
                DatabaseBackend::Sqlite => SqlxSqliteConnector::from_sqlx_sqlite_pool(
                    setup_sqlite_pool(&db_url, max_connections).await,
                ),
                _ => unimplemented!("Unsupported database type: {}", db_url),
            }
        }
        None => SqlxSqliteConnector::from_sqlx_sqlite_pool(
            setup_temporary_sqlite_database_pool(max_connections).await,
        ),
    })
}

fn continously_index_new_blocks(
    block_stream_config: BlockStreamConfig,
    db: Arc<DatabaseConnection>,
    rpc_client: Arc<RpcClient>,
    last_indexed_slot: u64,
    block_dumper: Option<Arc<BlockDumper>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let block_stream = block_stream_config.load_block_stream();
        index_block_stream_with_dumper(
            block_stream,
            db,
            rpc_client.clone(),
            last_indexed_slot,
            None,
            block_dumper,
        )
        .await;
    })
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    setup_logging(args.logging_format);
    setup_metrics(args.metrics_endpoint);

    // Use the compression program ID from the command line arguments
    if let Err(err) =
        photon_indexer::ingester::parser::set_compression_program_id(&args.compression_program_id)
    {
        error!("Failed to set compression program ID: {}", err);
        std::process::exit(1);
    }

    if let Err(err) = photon_indexer::ingester::parser::set_light_compressed_token_program_id(
        &args.light_compressed_token_program_id,
    ) {
        error!("Failed to set light compressed token program ID: {}", err);
        std::process::exit(1);
    }

    if let Err(err) = photon_indexer::ingester::parser::set_light_system_program_pinocchio_id(
        &args.light_system_program_pinocchio_id,
    ) {
        error!("Failed to set light system program pinocchio ID: {}", err);
        std::process::exit(1);
    }

    if let Err(err) = photon_indexer::ingester::parser::set_light_registry_program_id(
        &args.light_registry_program_id,
    ) {
        error!("Failed to set light registry program ID: {}", err);
        std::process::exit(1);
    }

    let db_conn = setup_database_connection(args.db_url.clone(), args.max_db_conn).await;
    if args.db_url.is_none() {
        info!("Running migrations...");
        Migrator::up(db_conn.as_ref(), None).await.unwrap();
    }
    let is_rpc_node_local = args.rpc_url.contains("127.0.0.1");
    let rpc_client = get_rpc_client(&args.rpc_url);

    // Handle snapshot loading
    if let Some(snapshot_dir) = args.snapshot_dir {
        let directory_adapter = Arc::new(DirectoryAdapter::from_local_directory(snapshot_dir));
        let snapshot_files = get_snapshot_files_with_metadata(&directory_adapter)
            .await
            .unwrap();
        if !snapshot_files.is_empty() {
            info!("Detected snapshot files. Loading snapshot...");
            let last_slot = snapshot_files.last().unwrap().end_slot;
            let block_stream =
                load_block_stream_from_directory_adapter(directory_adapter.clone()).await;
            pin_mut!(block_stream);
            let first_blocks = block_stream.next().await.unwrap();
            let last_indexed_slot = first_blocks.first().unwrap().metadata.parent_slot;
            let block_stream = stream! {
                yield first_blocks;
                while let Some(blocks) = block_stream.next().await {
                    yield blocks;
                }
            };
            index_block_stream(
                block_stream,
                db_conn.clone(),
                rpc_client.clone(),
                last_indexed_slot,
                Some(last_slot),
            )
            .await;
        }
    }

    // Handle loading from dump files
    if let Some(dump_dir) = &args.load_from_dumps {
        info!("Loading blocks from dump directory: {}", dump_dir);

        let loader = match BlockDumpLoader::new(PathBuf::from(dump_dir)) {
            Ok(loader) => loader,
            Err(e) => {
                error!("Failed to create dump loader: {}", e);
                std::process::exit(1);
            }
        };

        let stats = loader.get_stats();
        info!(
            "Found {} dump files with {} total blocks",
            stats.total_files, stats.total_blocks
        );

        if let Some((min_slot, max_slot)) = stats.slot_range {
            info!("Dump files cover slot range: {} to {}", min_slot, max_slot);
        }

        // Validate dump files
        match loader.validate_dump_files() {
            Ok(validation) => {
                if !validation.is_valid() {
                    warn!("Dump file validation issues found:");
                    if !validation.invalid_files.is_empty() {
                        warn!("Invalid files: {:?}", validation.invalid_files);
                    }
                    if !validation.missing_slots.is_empty() {
                        warn!("Missing slots: {:?}", validation.missing_slots.len());
                    }
                    if !validation.duplicate_slots.is_empty() {
                        warn!("Duplicate slots: {:?}", validation.duplicate_slots.len());
                    }
                }
            }
            Err(e) => {
                warn!("Failed to validate dump files: {}", e);
            }
        }

        // Create block stream from dumps
        let block_stream = match (args.dump_start_slot, args.dump_end_slot) {
            (Some(start_slot), Some(end_slot)) => {
                info!(
                    "Loading blocks from dumps in slot range: {} to {}",
                    start_slot, end_slot
                );
                loader.create_block_stream_in_range(start_slot, end_slot)
            }
            (Some(start_slot), None) => {
                // If only start slot is provided, use end slot as the maximum available
                if let Some((_, max_slot)) = loader.get_total_slot_range() {
                    info!(
                        "Loading blocks from dumps starting from slot: {} to {}",
                        start_slot, max_slot
                    );
                    loader.create_block_stream_in_range(start_slot, max_slot)
                } else {
                    info!("Loading all blocks from dumps (no slot range available)");
                    loader.create_block_stream()
                }
            }
            (None, Some(end_slot)) => {
                // If only end slot is provided, use start slot as the minimum available
                if let Some((min_slot, _)) = loader.get_total_slot_range() {
                    info!(
                        "Loading blocks from dumps from slot: {} to {}",
                        min_slot, end_slot
                    );
                    loader.create_block_stream_in_range(min_slot, end_slot)
                } else {
                    info!("Loading all blocks from dumps (no slot range available)");
                    loader.create_block_stream()
                }
            }
            (None, None) => {
                info!("Loading all blocks from dumps");
                loader.create_block_stream()
            }
        };

        // Determine the last indexed slot for dump loading
        let last_indexed_slot = args.dump_start_slot.unwrap_or(0).saturating_sub(1);
        let end_slot = args.dump_end_slot;

        index_block_stream(
            block_stream,
            db_conn.clone(),
            rpc_client.clone(),
            last_indexed_slot,
            end_slot,
        )
        .await;

        info!("Finished loading blocks from dump files");
        return; // Exit after loading from dumps
    }

    let (indexer_handle, monitor_handle) = match args.disable_indexing {
        true => {
            info!("Indexing is disabled");
            (None, None)
        }
        false => {
            info!("Starting indexer...");
            // For localnet we can safely use a large batch size to speed up indexing.
            let max_concurrent_block_fetches = match args.max_concurrent_block_fetches {
                Some(max_concurrent_block_fetches) => max_concurrent_block_fetches,
                None => {
                    if is_rpc_node_local {
                        200
                    } else {
                        20
                    }
                }
            };
            let last_indexed_slot = match args.start_slot {
                Some(start_slot) => match start_slot.as_str() {
                    "latest" => fetch_current_slot_with_infinite_retry(&rpc_client).await,
                    _ => {
                        fetch_block_parent_slot(&rpc_client, start_slot.parse::<u64>().unwrap())
                            .await
                    }
                },
                None => fetch_last_indexed_slot_with_infinite_retry(db_conn.as_ref())
                    .await
                    .unwrap_or(
                        get_network_start_slot(&rpc_client)
                            .await
                            .try_into()
                            .unwrap(),
                    )
                    .try_into()
                    .unwrap(),
            };

            // Setup block dumper if enabled
            let block_dumper = if args.enable_block_dump {
                let dump_format = match args.dump_format.as_str() {
                    "json" => DumpFormat::Json,
                    "bincode" => DumpFormat::Bincode,
                    _ => {
                        error!(
                            "Invalid dump format: {}. Use 'json' or 'bincode'",
                            args.dump_format
                        );
                        std::process::exit(1);
                    }
                };

                let dump_config = DumpConfig {
                    dump_dir: PathBuf::from(
                        args.dump_dir.unwrap_or_else(|| "./block_dumps".to_string()),
                    ),
                    blocks_per_file: args.blocks_per_dump_file,
                    compress: false,
                    format: dump_format,
                };

                match BlockDumper::new(dump_config) {
                    Ok(dumper) => {
                        info!(
                            "Block dumping enabled to directory: {:?}",
                            dumper.config.dump_dir
                        );
                        Some(Arc::new(dumper))
                    }
                    Err(e) => {
                        error!("Failed to create block dumper: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                None
            };

            let block_stream_config = BlockStreamConfig {
                rpc_client: rpc_client.clone(),
                max_concurrent_block_fetches,
                last_indexed_slot,
                geyser_url: args.grpc_url,
            };

            (
                Some(continously_index_new_blocks(
                    block_stream_config,
                    db_conn.clone(),
                    rpc_client.clone(),
                    last_indexed_slot,
                    block_dumper,
                )),
                Some(continously_monitor_photon(
                    db_conn.clone(),
                    rpc_client.clone(),
                )),
            )
        }
    };

    info!("Starting API server with port {}...", args.port);
    let api_handler = if args.disable_api {
        None
    } else {
        Some(
            start_api_server(
                db_conn.clone(),
                rpc_client.clone(),
                args.prover_url,
                args.port,
            )
            .await,
        )
    };

    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            if let Some(indexer_handle) = indexer_handle {
                info!("Shutting down indexer...");
                indexer_handle.abort();
                indexer_handle
                    .await
                    .expect_err("Indexer should have been aborted");
            }
            if let Some(api_handler) = &api_handler {
                info!("Shutting down API server...");
                api_handler.stop().unwrap();
            }

            if let Some(monitor_handle) = monitor_handle {
                info!("Shutting down monitor...");
                monitor_handle.abort();
                monitor_handle
                    .await
                    .expect_err("Monitor should have been aborted");
            }
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }
    // We need to wait for the API server to stop to ensure that all clean up is done
    if let Some(api_handler) = api_handler {
        tokio::spawn(api_handler.stopped());
    }
}
