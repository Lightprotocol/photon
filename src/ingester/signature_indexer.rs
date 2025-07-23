use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use log::{error, info, warn};
use sea_orm::{DatabaseConnection, TransactionTrait};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionEncoding;

use super::error::IngesterError;
use super::parser::parse_transaction;
use super::persist::persist_state_update;
use super::typedefs::block_info::TransactionInfo;

const RPC_CONFIG: RpcTransactionConfig = RpcTransactionConfig {
    encoding: Some(UiTransactionEncoding::Base64),
    commitment: Some(CommitmentConfig {
        commitment: CommitmentLevel::Confirmed,
    }),
    max_supported_transaction_version: Some(0),
};

pub fn read_signatures_from_file(file_path: &str) -> Result<Vec<Signature>, IngesterError> {
    let file = File::open(file_path).map_err(|e| {
        IngesterError::ParserError(format!("Failed to open signatures file {}: {}", file_path, e))
    })?;
    
    let reader = BufReader::new(file);
    let mut signatures = Vec::new();
    
    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| {
            IngesterError::ParserError(format!("Failed to read line {} from {}: {}", line_num + 1, file_path, e))
        })?;
        
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        
        match Signature::from_str(line) {
            Ok(signature) => signatures.push(signature),
            Err(e) => {
                warn!("Invalid signature on line {}: {} ({})", line_num + 1, line, e);
                continue;
            }
        }
    }
    
    info!("Loaded {} signatures from {}", signatures.len(), file_path);
    Ok(signatures)
}

pub async fn fetch_transaction_from_signature(
    rpc_client: &RpcClient,
    signature: &Signature,
) -> Result<TransactionInfo, IngesterError> {
    let encoded_transaction = rpc_client
        .get_transaction_with_config(signature, RPC_CONFIG)
        .await
        .map_err(|e| {
            IngesterError::ParserError(format!(
                "Failed to fetch transaction {}: {}",
                signature, e
            ))
        })?;
    
    TransactionInfo::try_from(encoded_transaction)
}

pub async fn index_signatures_from_file(
    db: Arc<DatabaseConnection>,
    rpc_client: Arc<RpcClient>,
    file_path: &str,
) -> Result<(), IngesterError> {
    let signatures = read_signatures_from_file(file_path)?;
    
    info!("Starting to index {} signatures from file", signatures.len());
    
    for (i, signature) in signatures.iter().enumerate() {
        loop {
            match process_single_signature(db.clone(), rpc_client.clone(), signature).await {
                Ok(()) => {
                    if (i + 1) % 10 == 0 {
                        info!("Indexed {} / {} signatures", i + 1, signatures.len());
                    }
                    break;
                }
                Err(e) => {
                    error!("Failed to index signature {}: {}. Retrying in 1 second...", signature, e);
                    sleep(Duration::from_secs(1));
                }
            }
        }
    }
    
    info!("Finished indexing all {} signatures", signatures.len());
    Ok(())
}

async fn process_single_signature(
    db: Arc<DatabaseConnection>,
    rpc_client: Arc<RpcClient>,
    signature: &Signature,
) -> Result<(), IngesterError> {
    let transaction_info = fetch_transaction_from_signature(&rpc_client, signature).await?;
    
    // Use slot 0 since we don't have block context
    let state_update = parse_transaction(&transaction_info, 0)?;
    
    let tx = db.as_ref().begin().await?;
    persist_state_update(&tx, state_update).await?;
    tx.commit().await?;
    
    Ok(())
}