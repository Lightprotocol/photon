use crate::ingester::error::IngesterError;
use crate::ingester::parser::indexer_events::{
    BatchPublicTransactionEvent, CompressedAccount, CompressedAccountData,
    MerkleTreeSequenceNumberV2, OutputCompressedAccountWithPackedContext, PublicTransactionEvent,
    PublicTransactionEventV2,
};
use crate::ingester::parser::state_update::StateUpdate;
use crate::ingester::parser::tree_info::TreeInfoService;
use crate::ingester::parser::tx_event_parser::parse_public_transaction_event;

use light_compressed_account::indexer_event::parse::event_from_light_transaction;
use solana_program::pubkey::Pubkey;
use solana_sdk::signature::Signature;

pub fn parse_public_transaction_event_v2(
    program_ids: &[Pubkey],
    instructions: &[Vec<u8>],
    accounts: Vec<Vec<Pubkey>>,
) -> Option<Vec<BatchPublicTransactionEvent>> {
    let events = event_from_light_transaction(program_ids, instructions, accounts).ok()?;
    events.map(|events| {
        events
            .into_iter()
            .map(|public_transaction_event| {
                let event = PublicTransactionEventV2 {
                    input_compressed_account_hashes: public_transaction_event
                        .event
                        .input_compressed_account_hashes,
                    output_compressed_account_hashes: public_transaction_event
                        .event
                        .output_compressed_account_hashes,
                    output_compressed_accounts: public_transaction_event
                        .event
                        .output_compressed_accounts
                        .iter()
                        .map(|x| OutputCompressedAccountWithPackedContext {
                            compressed_account: CompressedAccount {
                                owner: x.compressed_account.owner,
                                lamports: x.compressed_account.lamports,
                                address: x.compressed_account.address,
                                data: x.compressed_account.data.as_ref().map(|d| {
                                    CompressedAccountData {
                                        discriminator: d.discriminator,
                                        data: d.data.clone(),
                                        data_hash: d.data_hash,
                                    }
                                }),
                            },
                            merkle_tree_index: x.merkle_tree_index,
                        })
                        .collect(),
                    output_leaf_indices: public_transaction_event.event.output_leaf_indices,
                    sequence_numbers: public_transaction_event
                        .event
                        .sequence_numbers
                        .iter()
                        .map(|x| MerkleTreeSequenceNumberV2 {
                            tree_pubkey: x.tree_pubkey,
                            queue_pubkey: x.queue_pubkey,
                            tree_type: x.tree_type,
                            seq: x.seq,
                        })
                        .collect(),
                    relay_fee: public_transaction_event.event.relay_fee,
                    is_compress: public_transaction_event.event.is_compress,
                    compression_lamports: public_transaction_event
                        .event
                        .compress_or_decompress_lamports,
                    pubkey_array: public_transaction_event.event.pubkey_array,
                    message: public_transaction_event.event.message,
                };
                let batch_public_transaction_event = BatchPublicTransactionEvent {
                    event,
                    new_addresses: public_transaction_event.new_addresses,
                    input_sequence_numbers: public_transaction_event
                        .input_sequence_numbers
                        .iter()
                        .map(|x| MerkleTreeSequenceNumberV2 {
                            tree_pubkey: x.tree_pubkey,
                            queue_pubkey: x.queue_pubkey,
                            tree_type: x.tree_type,
                            seq: x.seq,
                        })
                        .collect(),
                    address_sequence_numbers: public_transaction_event
                        .address_sequence_numbers
                        .iter()
                        .map(|x| MerkleTreeSequenceNumberV2 {
                            tree_pubkey: x.tree_pubkey,
                            queue_pubkey: x.queue_pubkey,
                            tree_type: x.tree_type,
                            seq: x.seq,
                        })
                        .collect(),
                    batch_input_accounts: public_transaction_event.batch_input_accounts,
                    tx_hash: public_transaction_event.tx_hash,
                };
                batch_public_transaction_event
            })
            .collect::<Vec<_>>()
    })
}

pub async fn process_tree_metadata_from_v2_events(
    txn: &sea_orm::DatabaseTransaction,
    transaction_events: &[BatchPublicTransactionEvent],
) -> Result<(), anyhow::Error> {
    for event in transaction_events {
        // Process sequence numbers from the event
        for seq_num in &event.event.sequence_numbers {
            TreeInfoService::save_from_sequence_number(txn, seq_num).await?;
        }
        
        // Process input sequence numbers
        for seq_num in &event.input_sequence_numbers {
            TreeInfoService::save_from_sequence_number(txn, seq_num).await?;
        }
        
        // Process address sequence numbers
        for seq_num in &event.address_sequence_numbers {
            TreeInfoService::save_from_sequence_number(txn, seq_num).await?;
        }
    }
    
    Ok(())
}

pub async fn create_state_update(
    tx: Signature,
    slot: u64,
    transaction_event: Vec<BatchPublicTransactionEvent>,
) -> Result<StateUpdate, IngesterError> {
    if transaction_event.is_empty() {
        return Ok(StateUpdate::new());
    }
    
    let mut state_updates = Vec::new();
    for event in transaction_event.iter() {
        let mut state_update_event = parse_public_transaction_event(
            tx,
            slot,
            PublicTransactionEvent::V2(event.event.clone()),
            None, // No database connection here
        ).await?;
        state_update_event
            .input_context
            .extend(event.batch_input_accounts.clone());
        state_updates.push(state_update_event);
    }
    
    let mut merged_state_update = StateUpdate::merge_updates(state_updates);
    
    // Store the original transaction events for later use
    merged_state_update.batch_transaction_events = Some(transaction_event);
    
    Ok(merged_state_update)
}