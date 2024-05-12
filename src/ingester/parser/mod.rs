use borsh::BorshDeserialize;
use byteorder::{ByteOrder, LittleEndian};
use log::debug;
use solana_sdk::{pubkey::Pubkey, signature::Signature};
use crate::{
    common::typedefs::{
        account::{Account, AccountData},
        bs64_string::Base64String,
        hash::Hash,
        serializable_pubkey::SerializablePubkey,
        unsigned_integer::UnsignedInteger,
    },
    ingester::parser::{indexer_events::PathNode, state_update::EnrichedPathNode},
};

use super::{error::IngesterError, typedefs::block_info::TransactionInfo};

use self::{
    indexer_events::{ChangelogEvent, Changelogs, CompressedAccount, PublicTransactionEvent},
    state_update::{AccountTransaction, PathUpdate, StateUpdate},
};

pub mod indexer_events;
pub mod state_update;

use solana_program::pubkey;
use crate::ingester::parser::indexer_events::{Nullifier, NullifyEvent};

const ACCOUNT_COMPRESSION_PROGRAM_ID: Pubkey =
    pubkey!("5QPEJ5zDsVou9FQS3KCauKswM3VwBEBu4dpL9xTqkWwN");
const SYSTEM_PROGRAM: Pubkey = pubkey!("11111111111111111111111111111111");
const NOOP_PROGRAM_ID: Pubkey = pubkey!("noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV");

pub fn parse_transaction(tx: &TransactionInfo, slot: u64) -> Result<StateUpdate, IngesterError> {
    let mut state_updates = Vec::new();
    let mut logged_transaction = false;

    for instruction_group in tx.clone().instruction_groups {
        let mut ordered_instructions = Vec::new();
        ordered_instructions.push(instruction_group.outer_instruction);
        ordered_instructions.extend(instruction_group.inner_instructions);

        for (index, instruction) in ordered_instructions.iter().enumerate() {
            let is_account_compression_instruction = instruction.program_id == ACCOUNT_COMPRESSION_PROGRAM_ID;
            if !is_account_compression_instruction {
                continue;
            }
            let contains_noop_account = instruction.accounts.contains(&NOOP_PROGRAM_ID);
            if !contains_noop_account {
                continue;
            }
            let is_state_update = ordered_instructions.len() - index > 3;
            let is_nullify = ordered_instructions.len() - index == 3;

            // transfer:
            if is_state_update {
                let next_instruction = &ordered_instructions[index + 1];
                let next_next_instruction = &ordered_instructions[index + 2];
                let next_next_next_instruction = &ordered_instructions[index + 3];
                // We need to check if the account compression instruction contains a noop account to determine
                // if the instruction emits a noop event. If it doesn't then we want to avoid indexing
                // the following noop instruction because it'll contain either irrelevant or malicious data.

                let is_noop_instruction = next_instruction.program_id == NOOP_PROGRAM_ID;
                let is_system_instruction = next_next_instruction.program_id == SYSTEM_PROGRAM;
                let is_noop_instruction_after_system = next_next_next_instruction.program_id == NOOP_PROGRAM_ID;

                if is_account_compression_instruction
                    && contains_noop_account
                    && is_noop_instruction
                    && is_system_instruction
                    && is_noop_instruction_after_system
                {
                    if !logged_transaction {
                        debug!(
                            "Indexing transaction with slot {} and id {}",
                            slot, tx.signature
                        );
                        logged_transaction = true;
                    }
                    let changelogs = Changelogs::deserialize(&mut next_instruction.data.as_slice())
                        .map_err(|e| {
                            IngesterError::ParserError(format!(
                                "Failed to deserialize Changelogs: {}",
                                e
                            ))
                        })?;

                    let public_transaction_event = PublicTransactionEvent::deserialize(
                        &mut next_next_next_instruction.data.as_slice(),
                    )
                    .map_err(|e| {
                        IngesterError::ParserError(format!(
                            "Failed to deserialize PublicTransactionEvent: {}",
                            e
                        ))
                    })?;

                    let state_update = parse_public_transaction_event(
                        tx.signature,
                        slot,
                        public_transaction_event,
                        changelogs,
                    )?;

                    state_updates.push(state_update);
                }
            }
            else if is_nullify {
                let next_instruction = &ordered_instructions[index + 1];
                let next_next_instruction = &ordered_instructions[index + 2];
                let is_next_noop_instruction = next_instruction.program_id == NOOP_PROGRAM_ID;
                let is_next_next_noop_instruction = next_next_instruction.program_id == NOOP_PROGRAM_ID;

                if !is_next_noop_instruction || !is_next_next_noop_instruction {
                    continue;
                }

                if !logged_transaction {
                    debug!(
                            "Indexing transaction with slot {} and id {}",
                            slot, tx.signature
                        );
                    logged_transaction = true;
                }

                let changelogs = Changelogs::deserialize(&mut next_next_instruction.data.as_slice())
                    .map_err(|e| {
                        IngesterError::ParserError(format!(
                            "Failed to deserialize Changelogs: {}",
                            e
                        ))
                    })?;

                let nullifiers = Nullifier::deserialize(&mut next_instruction.data.as_slice())
                    .map_err(|e| {
                        IngesterError::ParserError(format!(
                            "Failed to deserialize Changelogs: {}",
                            e
                        ))
                    })?;

                let state_update = parse_nullify_event(
                    tx.signature,
                    slot,
                    changelogs,
                    nullifiers,
                )?;
                state_updates.push(state_update);
            }
        }
    }
    Ok(StateUpdate::merge_updates(state_updates))
}

fn parse_account_data(
    compressed_account: CompressedAccount,
    hash: [u8; 32],
    tree: Pubkey,
    leaf_index: u32,
    slot: u64,
    seq: Option<u64>,
) -> Account {
    let CompressedAccount {
        owner,
        lamports,
        address,
        data,
    } = compressed_account;

    let data = data.map(|d| AccountData {
        discriminator: UnsignedInteger(LittleEndian::read_u64(&d.discriminator)),
        data: Base64String(d.data),
        data_hash: Hash::from(d.data_hash),
    });

    Account {
        owner: owner.into(),
        lamports: UnsignedInteger(lamports),
        address: address.map(SerializablePubkey::from),
        data,
        hash: hash.into(),
        slot_created: UnsignedInteger(slot),
        leaf_index: UnsignedInteger(leaf_index as u64),
        tree: SerializablePubkey::from(tree),
        seq: seq.map(UnsignedInteger),
    }
}

fn parse_public_transaction_event(
    tx: Signature,
    slot: u64,
    transaction_event: PublicTransactionEvent,
    changelogs: Changelogs,
) -> Result<StateUpdate, IngesterError> {
    let PublicTransactionEvent {
        input_compressed_account_hashes,
        output_compressed_account_hashes,
        output_compressed_accounts,
        ..
    } = transaction_event;

    let mut state_update = StateUpdate::new();

    for hash in input_compressed_account_hashes {
        state_update.in_accounts.insert(hash.into());
    }
    let path_updates = extract_path_updates(&changelogs);

    if output_compressed_accounts.len() != path_updates.len() {
        return Err(IngesterError::MalformedEvent {
            msg: format!(
                "Number of path updates did not match the number of output accounts (txn: {})",
                tx,
            ),
        });
    }

    for (((out_account, path), hash), leaf_index) in output_compressed_accounts
        .into_iter()
        .zip(path_updates.iter())
        .zip(output_compressed_account_hashes)
        .zip(transaction_event.output_leaf_indices.iter())
    {
        let enriched_account = parse_account_data(
            out_account,
            hash,
            path.tree.into(),
            *leaf_index,
            slot,
            Some(path.seq),
        );
        state_update.out_accounts.push(enriched_account);
    }

    for ((path_index, path), leaf_index) in path_updates
        .into_iter()
        .enumerate()
        .zip(transaction_event.output_leaf_indices)
    {
        for (i, node) in path.path.iter().enumerate() {
            state_update.path_nodes.insert(
                (path.tree, node.index),
                EnrichedPathNode {
                    node: node.clone(),
                    slot,
                    tree: path.tree,
                    seq: path.seq + path_index as u64,
                    level: i,
                    tree_depth: path.path.len(),
                    leaf_index: if i == 0 { Some(leaf_index) } else { None },
                },
            );
        }
    }

    state_update
        .account_transactions
        .extend(
            state_update
                .in_accounts
                .iter()
                .map(|hash| AccountTransaction {
                    hash: *hash,
                    signature: tx,
                    slot,
                }),
        );

    state_update
        .account_transactions
        .extend(
            state_update
                .out_accounts
                .iter()
                .map(|a| AccountTransaction {
                    hash: a.hash,
                    signature: tx,
                    slot,
                }),
        );

    Ok(state_update)
}

fn parse_nullify_event(
    tx: Signature,
    slot: u64,
    changelogs: Changelogs,
    nullifiers: Nullifier,
) -> Result<StateUpdate, IngesterError> { let mut state_update = StateUpdate::new();
    let path_updates = extract_path_updates(&changelogs);

    // Ensure consistency between path updates and nullified accounts
    if path_updates.len() != nullifiers.nullifiers.len() {
        return Err(IngesterError::MalformedEvent {
            msg: format!(
                "Number of path updates ({}) did not match the number of nullified accounts ({}) (txn: {})",
                path_updates.len(), nullifiers.nullifiers.len(), tx,
            ),
        });
    }

    // Collect nullification information (tree_id, leaf_index) for later processing
    for (_, nullify_event) in path_updates.iter().zip(nullifiers.nullifiers.iter()) {
        let NullifyEvent::V1(nullify_event) = nullify_event;
        state_update.nullified_leaf_indices.push((nullify_event.id, nullify_event.index as u32));
    }

    // Process path updates and populate relevant fields in state_update
    for (path_index, path) in path_updates.into_iter().enumerate() {
        for (i, node) in path.path.iter().enumerate() {
            state_update.path_nodes.insert(
                (path.tree, node.index),
                EnrichedPathNode {
                    node: node.clone(),
                    slot,
                    tree: path.tree,
                    seq: path.seq + path_index as u64,
                    level: i,
                    tree_depth: path.path.len(),
                    // Leave leaf_index as None, as we don't have the account hash yet
                    leaf_index: None,
                },
            );
        }
    }

    Ok(state_update)
}

fn extract_path_updates(changelogs: &Changelogs) -> Vec<PathUpdate> {
    changelogs
        .changelogs
        .iter()
        .flat_map(|cl| match cl {
            ChangelogEvent::V1(cl) => {
                let tree_id = cl.id;
                cl.paths.iter().map(move |p| PathUpdate {
                    tree: tree_id,
                    path: p
                        .iter()
                        .map(|node| PathNode {
                            node: node.node,
                            index: node.index,
                        })
                        .collect(),
                    seq: cl.seq,
                })
            }
        })
        .collect::<Vec<_>>()
}
