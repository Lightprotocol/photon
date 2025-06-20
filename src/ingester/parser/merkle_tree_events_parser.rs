use std::collections::HashMap;

use crate::ingester::error::IngesterError;
use crate::ingester::parser::indexer_events::{
    IndexedMerkleTreeEvent, MerkleTreeEvent, NullifierEvent,
};
use crate::ingester::parser::state_update::{
    IndexedTreeLeafUpdate, LeafNullification, StateUpdate,
};
use crate::ingester::parser::{get_compression_program_id, NOOP_PROGRAM_ID};
use crate::ingester::typedefs::block_info::{Instruction, TransactionInfo};
use borsh::BorshDeserialize;
use solana_pubkey::Pubkey;
use solana_sdk::signature::Signature;

/// A map of merkle tree events and sequence numbers by merkle tree pubkey.
/// We keep sequence number to order the events.
pub type BatchMerkleTreeEvents = HashMap<[u8; 32], Vec<(u64, MerkleTreeEvent)>>;

pub fn parse_merkle_tree_event(
    instruction: &Instruction,
    next_instruction: &Instruction,
    tx: &TransactionInfo,
) -> Result<Option<StateUpdate>, IngesterError> {
    if get_compression_program_id() == instruction.program_id
        && next_instruction.program_id == NOOP_PROGRAM_ID
        && tx.error.is_none()
    {
        let merkle_tree_event = MerkleTreeEvent::deserialize(&mut next_instruction.data.as_slice());
        if let Ok(merkle_tree_event) = merkle_tree_event {
            let mut state_update = StateUpdate::new();
            let event = match merkle_tree_event {
                MerkleTreeEvent::V2(nullifier_event) => {
                    parse_nullifier_event_v1(tx.signature, nullifier_event)
                }
                MerkleTreeEvent::V3(indexed_merkle_tree_event) => {
                    parse_indexed_merkle_tree_update(indexed_merkle_tree_event)
                }
                MerkleTreeEvent::BatchAppend(batch_event) => {
                    state_update
                        .batch_merkle_tree_events
                        .entry(batch_event.merkle_tree_pubkey)
                        .or_default()
                        .push((
                            batch_event.sequence_number,
                            MerkleTreeEvent::BatchAppend(batch_event),
                        ));
                    state_update
                }
                MerkleTreeEvent::BatchNullify(batch_event) => {
                    state_update
                        .batch_merkle_tree_events
                        .entry(batch_event.merkle_tree_pubkey)
                        .or_default()
                        .push((
                            batch_event.sequence_number,
                            MerkleTreeEvent::BatchNullify(batch_event),
                        ));
                    state_update
                }
                MerkleTreeEvent::BatchAddressAppend(batch_event) => {
                    state_update
                        .batch_merkle_tree_events
                        .entry(batch_event.merkle_tree_pubkey)
                        .or_default()
                        .push((
                            batch_event.sequence_number,
                            MerkleTreeEvent::BatchAddressAppend(batch_event),
                        ));
                    state_update
                }
                _ => Err(IngesterError::ParserError(
                    "Expected nullifier event or merkle tree update".to_string(),
                ))?,
            };
            Ok(Some(event))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

/// Parse a V1 state tree nullifier event.
fn parse_nullifier_event_v1(tx: Signature, nullifier_event: NullifierEvent) -> StateUpdate {
    let NullifierEvent {
        id,
        nullified_leaves_indices,
        seq,
    } = nullifier_event;

    let mut state_update = StateUpdate::new();

    for (i, leaf_index) in nullified_leaves_indices.iter().enumerate() {
        let leaf_nullification: LeafNullification = {
            LeafNullification {
                tree: Pubkey::from(id),
                leaf_index: *leaf_index,
                seq: seq + i as u64,
                signature: tx,
            }
        };
        state_update.leaf_nullifications.insert(leaf_nullification);
    }

    state_update
}

fn parse_indexed_merkle_tree_update(
    indexed_merkle_tree_event: IndexedMerkleTreeEvent,
) -> StateUpdate {
    let IndexedMerkleTreeEvent {
        id,
        updates,
        mut seq,
    } = indexed_merkle_tree_event;
    let mut state_update = StateUpdate::new();

    for update in updates {
        for (leaf, hash) in [
            (update.new_low_element, update.new_low_element_hash),
            (update.new_high_element, update.new_high_element_hash),
        ]
        .iter()
        {
            let indexed_tree_leaf_update = IndexedTreeLeafUpdate {
                tree: Pubkey::from(id),
                hash: *hash,
                leaf: *leaf,
                seq,
            };
            seq += 1;
            state_update.indexed_merkle_tree_updates.insert(
                (indexed_tree_leaf_update.tree, leaf.index as u64),
                indexed_tree_leaf_update,
            );
        }
    }

    state_update
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::parser::parse_transaction;
    use crate::ingester::typedefs::block_info::{Instruction, InstructionGroup, TransactionInfo};
    use solana_client::rpc_client::RpcClient;
    use solana_client::rpc_config::RpcTransactionConfig;
    use solana_sdk::commitment_config::CommitmentConfig;
    use solana_transaction_status::{
        option_serializer::OptionSerializer, EncodedTransaction, UiMessage, UiTransactionEncoding,
    };
    use std::str::FromStr;

    #[test]
    fn test_parse_transaction_with_devnet_transaction() {
        // let signature_str = "37F8pkrTWQyMZVwtk4h2pSY9RoYaLxpk3sYMvWBw7MY4xdck2euAPrQG68du37bPrLoCCfwH5ubrYqBSA6m7cyJo";
        let signature_str = "2C4xaWLBcpUzmcpL2f1uzubHcRxXHDLUmmCFt9mdLN7uTyeyWBXbaheowwgxDEmaEJNrX14m84giyMgBdUKM73RY";
        let signature = Signature::from_str(signature_str).expect("Invalid signature");

        // Create RPC client for devnet
        let rpc_client = RpcClient::new("https://api.devnet.solana.com");

        // Fetch transaction with detailed config
        let config = RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        };

        let tx_result = rpc_client
            .get_transaction_with_config(&signature, config)
            .expect("Failed to fetch transaction from RPC");

        // Get slot before converting
        let slot = tx_result.slot;

        // Parse transaction manually from RPC response
        let transaction = &tx_result.transaction;
        let meta = transaction.meta.as_ref().expect("Transaction meta missing");

        let signature = Signature::from_str(signature_str).unwrap();
        let error = meta.err.as_ref().map(|e| e.to_string());

        // Extract transaction data from UiTransaction
        if let EncodedTransaction::Json(ui_tx) = &transaction.transaction {
            if let UiMessage::Raw(raw_msg) = &ui_tx.message {
                // Parse instructions
                let mut instruction_groups = Vec::new();

                for (i, instruction) in raw_msg.instructions.iter().enumerate() {
                    let program_id_index = instruction.program_id_index as usize;
                    let program_id_str = &raw_msg.account_keys[program_id_index];
                    let program_id = Pubkey::from_str(program_id_str).unwrap();

                    let data = bs58::decode(&instruction.data).into_vec().unwrap();

                    let accounts = instruction
                        .accounts
                        .iter()
                        .map(|idx| {
                            let account_idx = *idx as usize;
                            let account_str = &raw_msg.account_keys[account_idx];
                            Pubkey::from_str(account_str).unwrap()
                        })
                        .collect();

                    let outer_instruction = Instruction {
                        program_id,
                        data,
                        accounts,
                    };

                    // Parse inner instructions for this outer instruction
                    let mut inner_instructions_for_group = Vec::new();
                    if let OptionSerializer::Some(inner_array) = &meta.inner_instructions {
                        for inner_group in inner_array {
                            if inner_group.index == i as u8 {
                                for inner_inst in &inner_group.instructions {
                                    if let solana_transaction_status::UiInstruction::Compiled(
                                        compiled,
                                    ) = inner_inst
                                    {
                                        let inner_program_id_index =
                                            compiled.program_id_index as usize;
                                        let inner_program_id_str =
                                            &raw_msg.account_keys[inner_program_id_index];
                                        let inner_program_id =
                                            Pubkey::from_str(inner_program_id_str).unwrap();

                                        let inner_data =
                                            bs58::decode(&compiled.data).into_vec().unwrap();

                                        let inner_accounts = compiled
                                            .accounts
                                            .iter()
                                            .map(|idx| {
                                                let account_idx = *idx as usize;
                                                let account_str =
                                                    &raw_msg.account_keys[account_idx];
                                                Pubkey::from_str(account_str).unwrap()
                                            })
                                            .collect();

                                        inner_instructions_for_group.push(Instruction {
                                            program_id: inner_program_id,
                                            data: inner_data,
                                            accounts: inner_accounts,
                                        });
                                    }
                                }
                            }
                        }
                    }

                    instruction_groups.push(InstructionGroup {
                        outer_instruction,
                        inner_instructions: inner_instructions_for_group,
                    });
                }

                let tx_info = TransactionInfo {
                    instruction_groups,
                    signature,
                    error,
                };

                println!("Transaction signature: {}", signature);
                println!("Transaction slot: {}", slot);
                println!("Transaction error: {:?}", tx_info.error);

                // Print instruction details for debugging
                for (i, instruction_group) in tx_info.instruction_groups.iter().enumerate() {
                    println!(
                        "Instruction group {}: outer program_id: {}",
                        i, instruction_group.outer_instruction.program_id
                    );
                    println!(
                        "  Outer instruction data length: {}",
                        instruction_group.outer_instruction.data.len()
                    );
                    for (j, inner_inst) in instruction_group.inner_instructions.iter().enumerate() {
                        println!(
                            "  Inner instruction {}: program_id: {}, data length: {}",
                            j,
                            inner_inst.program_id,
                            inner_inst.data.len()
                        );
                    }
                }

                // Parse the complete transaction
                match parse_transaction(&tx_info, slot) {
                    Ok(state_update) => {
                        println!("\n=== PARSE TRANSACTION RESULT ===");
                        println!("State update: {:?}", state_update);

                        // Print details about different types of events
                        if !state_update.leaf_nullifications.is_empty() {
                            println!(
                                "\nLeaf nullifications found: {}",
                                state_update.leaf_nullifications.len()
                            );
                            for nullification in &state_update.leaf_nullifications {
                                println!("  {:?}", nullification);
                            }
                        }

                        if !state_update.indexed_merkle_tree_updates.is_empty() {
                            println!(
                                "\nIndexed merkle tree updates found: {}",
                                state_update.indexed_merkle_tree_updates.len()
                            );
                            for (key, update) in &state_update.indexed_merkle_tree_updates {
                                println!("  Key: {:?}, Update: {:?}", key, update);
                            }
                        }

                        if !state_update.batch_merkle_tree_events.is_empty() {
                            println!(
                                "\nBatch merkle tree events found: {}",
                                state_update.batch_merkle_tree_events.len()
                            );
                            for (tree_pubkey, events) in &state_update.batch_merkle_tree_events {
                                println!(
                                    "  Tree: {:?}, Events: {} events",
                                    tree_pubkey,
                                    events.len()
                                );
                                for (seq, event) in events {
                                    println!("    Seq: {}, Event: {:?}", seq, event);
                                }
                            }
                        }

                        if !state_update.out_accounts.is_empty() {
                            println!("\nOut accounts found: {}", state_update.out_accounts.len());
                            for account in &state_update.out_accounts {
                                println!("  {:?}", account);
                            }
                        }

                        if !state_update.in_accounts.is_empty() {
                            println!("\nIn accounts found: {}", state_update.in_accounts.len());
                            for account in &state_update.in_accounts {
                                println!("  {:?}", account);
                            }
                        }

                        if !state_update.transactions.is_empty() {
                            println!("\nTransactions found: {}", state_update.transactions.len());
                            for tx in &state_update.transactions {
                                println!("  Transaction: {:?}", tx);
                            }
                        }

                        println!("\n=== END PARSE TRANSACTION RESULT ===");
                    }
                    Err(e) => {
                        println!("Error parsing transaction: {:?}", e);
                    }
                }
            } else {
                panic!("Unexpected message format");
            }
        } else {
            panic!("Unexpected transaction format");
        }
    }
}
