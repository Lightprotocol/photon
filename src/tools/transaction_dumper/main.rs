use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde_json::json;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_request::RpcRequest;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta;
use tokio::time::sleep;

/// Transaction dumper CLI tool for fetching tree transactions from Solana
#[derive(Parser, Debug)]
#[command(
    version,
    about = "Dump all transactions for a specific tree from Solana devnet"
)]
struct Args {
    /// Command to execute
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Dump all transactions for a specific tree
    Dump {
        /// Tree public key to fetch transactions for
        #[arg(short, long)]
        pubkey: String,

        /// Output directory for transaction files
        #[arg(short, long, default_value = "../transactions")]
        output_dir: String,

        /// RPC endpoint URL
        #[arg(short, long, default_value = "https://api.devnet.solana.com")]
        rpc_url: String,

        /// Maximum number of signatures to fetch per request
        #[arg(long, default_value = "1000")]
        limit: usize,

        /// Delay between requests in milliseconds
        #[arg(long, default_value = "100")]
        delay_ms: u64,

        /// Skip existing transaction files
        #[arg(long)]
        skip_existing: bool,
    },
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();

    match args.command {
        Commands::Dump {
            pubkey,
            output_dir,
            rpc_url,
            limit,
            delay_ms,
            skip_existing,
        } => {
            if let Err(e) = dump_transactions(
                &pubkey,
                &output_dir,
                &rpc_url,
                limit,
                delay_ms,
                skip_existing,
            )
            .await
            {
                eprintln!("Error dumping transactions: {}", e);
                std::process::exit(1);
            }
        }
    }
}

async fn dump_transactions(
    pubkey: &str,
    output_dir: &str,
    rpc_url: &str,
    limit: usize,
    delay_ms: u64,
    skip_existing: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let pubkey: Pubkey = pubkey
        .parse()
        .map_err(|e| format!("Invalid tree pubkey: {}", e))?;

    // Create RPC client
    let rpc_client = RpcClient::new_with_timeout_and_commitment(
        rpc_url.to_string(),
        Duration::from_secs(60),
        CommitmentConfig::confirmed(),
    );

    // Create output directory
    let tree_dir = PathBuf::from(output_dir).join(format!("txs_{}", pubkey));
    fs::create_dir_all(&tree_dir)?;

    println!("Fetching transactions for program id: {}", pubkey);
    println!("Output directory: {}", tree_dir.display());
    println!("RPC endpoint: {}", rpc_url);

    // Get all signatures for the tree address
    let signatures = fetch_all_signatures(&rpc_client, &pubkey, limit, delay_ms).await?;
    println!("Found {} signatures", signatures.len());

    // Track existing files if skip_existing is enabled
    let existing_files: HashSet<String> = if skip_existing {
        fs::read_dir(&tree_dir)
            .unwrap_or_else(|_| fs::read_dir(".").unwrap()) // fallback to avoid crash
            .filter_map(|entry| {
                entry
                    .ok()
                    .and_then(|e| e.file_name().to_str().map(|s| s.to_string()))
            })
            .collect()
    } else {
        HashSet::new()
    };

    // Fetch and save each transaction
    let mut successful_count = 0;
    let mut failed_count = 0;
    let mut skipped_count = 0;

    for (i, signature) in signatures.iter().enumerate() {
        let signature_str = signature.to_string();
        let file_name = format!("{}_{}.json", i, signature_str);
        // Skip if file already exists and skip_existing is enabled
        if skip_existing && existing_files.contains(&signature_str) {
            skipped_count += 1;
            if i % 10 == 0 {
                println!(
                    "Progress: {}/{} (skipped: {}, success: {}, failed: {})",
                    i + 1,
                    signatures.len(),
                    skipped_count,
                    successful_count,
                    failed_count
                );
            }
            continue;
        }

        println!("Fetching transaction: {}", signature_str);
        match fetch_transaction(&rpc_client, signature).await {
            Ok(transaction_data) => {
                let file_path = tree_dir.join(&file_name);
                println!("Saving transaction to: {}", file_path.display());
                match fs::write(&file_path, &transaction_data) {
                    Ok(_) => {
                        successful_count += 1;
                        println!("✓ Saved transaction: {}", file_name);
                    }
                    Err(e) => {
                        failed_count += 1;
                        println!("✗ Failed to save transaction {}: {}", file_name, e);
                    }
                }
            }
            Err(e) => {
                failed_count += 1;
                println!("✗ Failed to fetch transaction {}: {}", signature_str, e);
            }
        }

        // Progress update every 10 transactions
        if i % 10 == 0 {
            println!(
                "Progress: {}/{} (skipped: {}, success: {}, failed: {})",
                i + 1,
                signatures.len(),
                skipped_count,
                successful_count,
                failed_count
            );
        }

        // Rate limiting
        if delay_ms > 0 {
            sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    println!("\nTransaction dump completed!");
    println!("Total signatures processed: {}", signatures.len());
    println!("Successfully saved: {}", successful_count);
    println!("Failed: {}", failed_count);
    println!("Skipped (already exists): {}", skipped_count);
    println!("Output directory: {}", tree_dir.display());

    Ok(())
}

async fn fetch_all_signatures(
    rpc_client: &RpcClient,
    address: &Pubkey,
    limit: usize,
    delay_ms: u64,
) -> Result<Vec<Signature>, Box<dyn std::error::Error>> {
    let mut all_signatures = Vec::new();
    let mut before_signature: Option<String> = None;

    loop {
        let config = json!({
            "before": before_signature,
            "limit": limit,
            "commitment": "confirmed"
        });

        println!(
            "Fetching signatures batch (before: {:?}, limit: {})...",
            before_signature, limit
        );

        let response: serde_json::Value = match rpc_client
            .send(
                RpcRequest::GetSignaturesForAddress,
                json!([address.to_string(), config]),
            )
            .await
        {
            Ok(resp) => {
                println!(
                    "RPC response received: {}",
                    serde_json::to_string_pretty(&resp)
                        .unwrap_or_else(|_| "Failed to serialize response".to_string())
                );
                resp
            }
            Err(e) => {
                println!("RPC request failed: {}", e);
                return Err(e.into());
            }
        };

        let signatures_data = response
            .as_array()
            .ok_or("Expected array response from getSignaturesForAddress")?;

        if signatures_data.is_empty() {
            println!("No more signatures found, stopping...");
            break;
        }

        println!("Fetched {} signatures in this batch", signatures_data.len());

        // Parse signatures and add to our collection
        for sig_info in signatures_data {
            if let Some(signature_str) = sig_info.get("signature").and_then(|s| s.as_str()) {
                if let Ok(signature) = signature_str.parse::<Signature>() {
                    all_signatures.push(signature);
                }
            }
        }

        // Set up for next iteration
        if let Some(last_sig_info) = signatures_data.last() {
            if let Some(signature_str) = last_sig_info.get("signature").and_then(|s| s.as_str()) {
                before_signature = Some(signature_str.to_string());
            } else {
                break;
            }
        } else {
            break;
        }

        // If we got fewer signatures than requested, we've reached the end
        if signatures_data.len() < limit {
            break;
        }

        // Rate limiting between batches
        if delay_ms > 0 {
            sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    Ok(all_signatures)
}

async fn fetch_transaction(
    rpc_client: &RpcClient,
    signature: &Signature,
) -> Result<String, Box<dyn std::error::Error>> {
    let config = json!({
        "encoding": "base64",
        "commitment": "confirmed",
        "maxSupportedTransactionVersion": 0
    });

    println!("Fetching transaction data for signature: {}", signature);

    let response: serde_json::Value = match rpc_client
        .send(
            RpcRequest::GetTransaction,
            json!([signature.to_string(), config]),
        )
        .await
    {
        Ok(resp) => {
            println!(
                "Raw transaction response: {}",
                serde_json::to_string_pretty(&resp)
                    .unwrap_or_else(|_| "Failed to serialize".to_string())
            );
            resp
        }
        Err(e) => {
            println!("Failed to fetch transaction {}: {}", signature, e);
            return Err(e.into());
        }
    };

    // Return the raw response for now to see what we're actually getting
    Ok(serde_json::to_string_pretty(&response)?)
}
