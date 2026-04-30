use std::sync::Arc;

use clap::Parser;
use log::info;
use photon_indexer::common::{setup_logging, LoggingFormat};
use photon_indexer::zone_rpc::api::ZoneRpcApi;
use photon_indexer::zone_rpc::private_api::ZoneRpcPrivateApi;
use photon_indexer::zone_rpc::private_db::{migrate_zone_private_db, SqlZonePrivateStore};
use photon_indexer::zone_rpc::prover_client::ProverProofClient;
use photon_indexer::zone_rpc::server::run_zone_rpc_server;
use sea_orm::Database;

/// Local/dev Zone RPC sidecar for the zoned shielded-pool PoC.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Photon public database URL. Can also be set with PHOTON_DATABASE_URL.
    #[arg(long)]
    photon_database_url: Option<String>,

    /// Private Zone RPC database URL. Can also be set with ZONE_PRIVATE_DATABASE_URL.
    #[arg(long)]
    zone_private_database_url: Option<String>,

    /// Port to expose the Zone RPC sidecar API.
    #[arg(long, default_value_t = 8785)]
    port: u16,

    /// Max concurrent HTTP connections for jsonrpsee.
    #[arg(long, default_value_t = 1024)]
    max_http_connections: u32,

    /// Create/update the private Zone RPC schema before serving.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    migrate_private_db: bool,

    /// Enable local allow-all authorization. Required until signed requests land.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    allow_local_dev_auth: bool,

    /// Optional prover-server URL for fetch_proofs. Can also be set with PROVER_URL.
    #[arg(long)]
    prover_url: Option<String>,

    /// Optional prover-server API key. Can also be set with PROVER_API_KEY.
    #[arg(long)]
    prover_api_key: Option<String>,

    /// Logging format.
    #[arg(long, default_value_t = LoggingFormat::Standard)]
    logging_format: LoggingFormat,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    setup_logging(args.logging_format);

    if !args.allow_local_dev_auth {
        anyhow::bail!(
            "zone-rpc only supports --allow-local-dev-auth in this PoC; do not expose it publicly"
        );
    }

    let photon_database_url = required_arg_or_env(
        args.photon_database_url,
        "PHOTON_DATABASE_URL",
        "--photon-database-url",
    )?;
    let zone_private_database_url = required_arg_or_env(
        args.zone_private_database_url,
        "ZONE_PRIVATE_DATABASE_URL",
        "--zone-private-database-url",
    )?;

    let photon_conn = Arc::new(Database::connect(&photon_database_url).await?);
    let private_conn = Database::connect(&zone_private_database_url).await?;
    if args.migrate_private_db {
        migrate_zone_private_db(&private_conn).await?;
    }

    let private_store = SqlZonePrivateStore::new(private_conn);
    let private_api = ZoneRpcPrivateApi::new_unchecked_for_local_testing(private_store);
    let prover_url = args.prover_url.or_else(|| std::env::var("PROVER_URL").ok());
    let prover_api_key = args
        .prover_api_key
        .or_else(|| std::env::var("PROVER_API_KEY").ok());
    let api = match prover_url {
        Some(prover_url) if !prover_url.is_empty() => ZoneRpcApi::with_proof_client(
            photon_conn,
            private_api,
            ProverProofClient::new(prover_url, prover_api_key),
        ),
        _ => ZoneRpcApi::new(photon_conn, private_api),
    };

    let handle = run_zone_rpc_server(api, args.port, args.max_http_connections).await?;
    info!("Zone RPC sidecar listening on 0.0.0.0:{}", args.port);

    tokio::signal::ctrl_c().await?;
    handle.stop()?;
    handle.stopped().await;
    Ok(())
}

fn required_arg_or_env(
    value: Option<String>,
    env_name: &str,
    flag_name: &str,
) -> Result<String, anyhow::Error> {
    match value.or_else(|| std::env::var(env_name).ok()) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => anyhow::bail!("{flag_name} or {env_name} is required"),
    }
}
