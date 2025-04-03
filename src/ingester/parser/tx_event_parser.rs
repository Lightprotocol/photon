use crate::common::typedefs::account::AccountWithContext;
use crate::ingester::error::IngesterError;
use crate::ingester::parser::indexer_events::{
    MerkleTreeSequenceNumber, PublicTransactionEvent, PublicTransactionEventV1
};
use solana_sdk::pubkey::Pubkey;
use crate::ingester::parser::state_update::{AccountTransaction, StateUpdate};
use crate::ingester::parser::{ACCOUNT_COMPRESSION_PROGRAM_ID, NOOP_PROGRAM_ID, SYSTEM_PROGRAM};
use crate::ingester::typedefs::block_info::{Instruction, TransactionInfo};
use anchor_lang::AnchorDeserialize;
use light_compressed_account::TreeType;
use log::info;
use solana_sdk::signature::Signature;
use std::collections::HashMap;

pub async fn parse_legacy_public_transaction_event(
    tx: &TransactionInfo,
    slot: u64,
    instruction: &Instruction,
    next_instruction: &Instruction,
    next_next_instruction: &Instruction,
) -> Result<Option<StateUpdate>, IngesterError> {
    if ACCOUNT_COMPRESSION_PROGRAM_ID == instruction.program_id
        && next_instruction.program_id == SYSTEM_PROGRAM
        && next_next_instruction.program_id == NOOP_PROGRAM_ID
        && tx.error.is_none()
    {
        info!(
            "Indexing transaction with slot {} and id {}",
            slot, tx.signature
        );

        let public_transaction_event =
            PublicTransactionEventV1::deserialize(&mut next_next_instruction.data.as_slice())
                .map_err(|e| {
                    IngesterError::ParserError(format!(
                        "Failed to deserialize PublicTransactionEvent: {}",
                        e
                    ))
                })?;

        parse_public_transaction_event(
            tx.signature,
            slot,
            PublicTransactionEvent::V1(public_transaction_event),
            None, // No database connection here
        )
        .await
        .map(Some)
    } else {
        Ok(None)
    }
}

pub async fn parse_public_transaction_event(
    tx: Signature,
    slot: u64,
    transaction_event: PublicTransactionEvent,
    db_conn: Option<&sea_orm::DatabaseConnection>,
) -> Result<StateUpdate, IngesterError> {
    use crate::ingester::parser::tree_info::{TreeInfo, TreeInfoService};
    
    let mut state_update = StateUpdate::new();
    
    // Track sequence values for state trees (needed for incrementing)
    let mut seq_counters: HashMap<Pubkey, u64> = HashMap::new();
    
    // Create a map of tree information from sequence numbers
    let mut tree_info_map: HashMap<Pubkey, TreeInfo> = HashMap::new();
    
    // Process sequence numbers to populate tree info
    for seq in transaction_event.sequence_numbers().iter() {
        let tree_pubkey = seq.tree_pubkey();
        let seq_value = seq.seq();
        
        // Store sequence value for state trees
        seq_counters.insert(tree_pubkey, seq_value);
        
        match seq {
            MerkleTreeSequenceNumber::V1(_) => {
                // For V1, try to look up tree info from the database first
                let tree_info = if let Some(conn) = db_conn {
                    match TreeInfoService::get_tree_info(conn, &tree_pubkey.to_string()).await {
                        Ok(Some(ti)) => {
                            log::info!("Found tree info in database for tree: {}", tree_pubkey);
                            ti
                        },
                        _ => {
                            panic!("No tree info found in database for tree: {}", tree_pubkey);
                        }
                    }
                } else {
                    panic!("No database connection and no tree info for tree: {}", tree_pubkey);
                };
                
                // Store tree info for both tree and queue pubkey lookups
                tree_info_map.insert(tree_pubkey, tree_info.clone());
                tree_info_map.insert(tree_info.queue, tree_info.clone());
            },
            MerkleTreeSequenceNumber::V2(v2) => {
                // For V2, we have full tree info from the event
                let tree_info = TreeInfo {
                    tree: v2.tree_pubkey,
                    queue: v2.queue_pubkey,
                    height: match TreeType::from(v2.tree_type) {
                        TreeType::State => 26,
                        TreeType::Address => 26,
                        TreeType::BatchedState => 32,
                        TreeType::BatchedAddress => 40,
                    },
                    tree_type: TreeType::from(v2.tree_type),
                };
                
                // Store by both tree and queue pubkey for lookup
                tree_info_map.insert(v2.tree_pubkey, tree_info.clone());
                tree_info_map.insert(v2.queue_pubkey, tree_info);
                
                log::info!("Using tree info from V2 event: tree={}, queue={}, type={:?}", 
                         v2.tree_pubkey, v2.queue_pubkey, TreeType::from(v2.tree_type));
            }
        }
    }

    for hash in transaction_event.input_compressed_account_hashes() {
        state_update.in_accounts.insert(hash.into());
    }

    for ((out_account, hash), leaf_index) in transaction_event
        .output_compressed_accounts()
        .iter()
        .zip(transaction_event.output_compressed_account_hashes())
        .zip(transaction_event.output_leaf_indices().iter())
    {
        // The pubkey from the array might be either tree or queue pubkey
        let maybe_tree_or_queue = transaction_event.pubkey_array()[out_account.merkle_tree_index as usize];
        
        // Look up tree info from our map first
        let tree_info_opt = if let Some(tree_info) = tree_info_map.get(&maybe_tree_or_queue) {
            // Found in our existing map
            Some(tree_info.clone())
        } else if let Some(conn) = db_conn {
            // Try lookup in database if not in our map
            match TreeInfoService::get_tree_info(conn, &maybe_tree_or_queue.to_string()).await {
                Ok(Some(ti)) => {
                    // Cache the result for future lookups
                    log::info!("Found tree info in database for pubkey: {}", maybe_tree_or_queue);
                    tree_info_map.insert(maybe_tree_or_queue, ti.clone());
                    tree_info_map.insert(ti.tree, ti.clone());
                    tree_info_map.insert(ti.queue, ti.clone());
                    Some(ti)
                },
                _ => {
                    // Not found in database, use default for unknown pubkey
                    log::warn!("No tree info found for pubkey: {}", maybe_tree_or_queue);
                    None
                }
            }
        } else {
            // No database connection, use fallback logic
            log::warn!("No database connection and no tree info for pubkey: {}", maybe_tree_or_queue);
            None
        };
            
        if let Some(tree_info) = tree_info_opt {
            let tree_pubkey = tree_info.tree;
            let queue_pubkey = tree_info.queue;
            let tree_type = tree_info.tree_type;
            
            // Get the sequence value and increment it if needed
            let mut seq = None;
            if tree_type == TreeType::State {
                if let Some(seq_value) = seq_counters.get_mut(&tree_pubkey) {
                    seq = Some(*seq_value);
                    *seq_value += 1;
                }
            }
            
            let in_output_queue = tree_type == TreeType::BatchedState;
            let enriched_account = AccountWithContext::new(
                out_account.compressed_account.clone(),
                hash,
                tree_pubkey,
                queue_pubkey,
                *leaf_index,
                slot,
                seq,
                in_output_queue,
                false,
                None,
                None,
                tree_type,
            );
            
            state_update.out_accounts.push(enriched_account);
        } else {
            // We don't have tree info for this pubkey, use defaults
            log::warn!("No tree info found for pubkey: {}, using defaults", maybe_tree_or_queue);
            
            // Default to treating the pubkey as both tree and queue
            let tree_pubkey = maybe_tree_or_queue;
            let queue_pubkey = maybe_tree_or_queue;
            let tree_type = TreeType::State;
            
            let enriched_account = AccountWithContext::new(
                out_account.compressed_account.clone(),
                hash,
                tree_pubkey,
                queue_pubkey,
                *leaf_index,
                slot,
                None, // No sequence number
                false, // Not in output queue
                false,
                None,
                None,
                tree_type,
            );
            
            state_update.out_accounts.push(enriched_account);
        }
    }

    state_update
        .account_transactions
        .extend(
            state_update
                .in_accounts
                .iter()
                .map(|hash| AccountTransaction {
                    hash: hash.clone(),
                    signature: tx,
                }),
        );

    state_update
        .account_transactions
        .extend(
            state_update
                .out_accounts
                .iter()
                .map(|a| AccountTransaction {
                    hash: a.account.hash.clone(),
                    signature: tx,
                }),
        );

    Ok(state_update)
}
