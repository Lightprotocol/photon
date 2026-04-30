use merkle_tree_events_parser::parse_merkle_tree_event;
use solana_pubkey::Pubkey;
use std::sync::OnceLock;
use tx_event_parser::parse_public_transaction_event_v1;
use tx_event_parser_v2::create_state_update_v2;

use super::{error::IngesterError, typedefs::block_info::TransactionInfo};

use self::state_update::{StateUpdate, Transaction};
pub use self::tree_info::TreeResolver;

pub mod indexer_events;
pub mod merkle_tree_events_parser;
pub mod shielded_pool_event_parser;
pub mod shielded_pool_events;
#[cfg(any(test, feature = "shielded-fixtures"))]
pub mod shielded_pool_test_fixture;
pub mod state_update;
pub mod tree_info;
mod tx_event_parser;
pub mod tx_event_parser_v2;

use crate::ingester::parser::tx_event_parser_v2::parse_public_transaction_event_v2;
use solana_pubkey::pubkey;

pub const NOOP_PROGRAM_ID: Pubkey = pubkey!("noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV");
pub const SHIELDED_POOL_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0x53; 32]);
const SYSTEM_PROGRAM: Pubkey = pubkey!("11111111111111111111111111111111");
const VOTE_PROGRAM_ID: Pubkey = pubkey!("Vote111111111111111111111111111111111111111");

// Compression program ID can be overridden at runtime
static ACCOUNT_COMPRESSION_PROGRAM_ID: OnceLock<Pubkey> = OnceLock::new();
static SHIELDED_POOL_PROGRAM_ID_OVERRIDE: OnceLock<Pubkey> = OnceLock::new();
pub fn get_compression_program_id() -> Pubkey {
    *ACCOUNT_COMPRESSION_PROGRAM_ID
        .get_or_init(|| pubkey!("compr6CUsB5m2jS4Y3831ztGSTnDpnKJTKS95d64XVq"))
}
pub fn set_compression_program_id(program_id_str: &str) -> Result<(), String> {
    match program_id_str.parse::<Pubkey>() {
        Ok(pubkey) => match ACCOUNT_COMPRESSION_PROGRAM_ID.set(pubkey) {
            Ok(_) => Ok(()),
            Err(_) => Err("Compression program ID has already been set".to_string()),
        },
        Err(err) => Err(format!("Invalid compression program ID: {}", err)),
    }
}

pub fn get_shielded_pool_program_id() -> Pubkey {
    *SHIELDED_POOL_PROGRAM_ID_OVERRIDE.get_or_init(|| SHIELDED_POOL_PROGRAM_ID)
}
pub fn set_shielded_pool_program_id(program_id_str: &str) -> Result<(), String> {
    match program_id_str.parse::<Pubkey>() {
        Ok(pubkey) => match SHIELDED_POOL_PROGRAM_ID_OVERRIDE.set(pubkey) {
            Ok(_) => Ok(()),
            Err(_) => Err("Shielded pool program ID has already been set".to_string()),
        },
        Err(err) => Err(format!("Invalid shielded pool program ID: {}", err)),
    }
}

// Expected tree owner - only index trees owned by this pubkey (filters out external trees)
// Set to None to disable filtering and index all trees
pub const EXPECTED_TREE_OWNER: Option<Pubkey> =
    Some(pubkey!("24rt4RgeyjUCWGS2eF7L7gyNMuz6JWdqYpAvb1KRoHxs"));

pub async fn parse_transaction<T>(
    conn: &T,
    tx: &TransactionInfo,
    slot: u64,
    resolver: &mut TreeResolver<'_>,
) -> Result<StateUpdate, IngesterError>
where
    T: sea_orm::ConnectionTrait + sea_orm::TransactionTrait,
{
    if tx.error.is_some() {
        log::debug!(
            "Skipping failed transaction {} with error: {:?}",
            tx.signature,
            tx.error
        );
        return Ok(StateUpdate::new());
    }

    let mut state_updates = Vec::new();
    let mut is_compression_transaction = false;

    for instruction_group in tx.clone().instruction_groups {
        let mut ordered_instructions = Vec::new();
        ordered_instructions.push(instruction_group.outer_instruction.clone());
        ordered_instructions.extend(instruction_group.inner_instructions.clone());
        let mut group_compressed_output_contexts = Vec::new();
        let mut group_compressed_output_index_offset = 0u32;

        let mut vec_accounts = Vec::<Vec<Pubkey>>::new();
        let mut vec_instructions_data = Vec::new();
        let mut program_ids = Vec::new();

        ordered_instructions.iter().for_each(|inner_instruction| {
            vec_instructions_data.push(inner_instruction.data.clone());
            vec_accounts.push(inner_instruction.accounts.clone());
            program_ids.push(inner_instruction.program_id);
        });

        if let Some(event) =
            parse_public_transaction_event_v2(&program_ids, &vec_instructions_data, vec_accounts)
        {
            let state_update =
                create_state_update_v2(conn, tx.signature, slot, event, resolver).await?;
            is_compression_transaction = true;
            group_compressed_output_contexts
                .extend(state_update.compressed_output_contexts.clone());
            state_updates.push(state_update);
        } else {
            for (index, instruction) in ordered_instructions.iter().enumerate() {
                if ordered_instructions.len() - index > 1
                    && get_compression_program_id() == instruction.program_id
                {
                    // Look for a NOOP_PROGRAM_ID instruction after one or two SYSTEM_PROGRAM instructions
                    // We handle up to two system program instructions in the case where we also have to pay a tree rollover fee
                    let mut noop_instruction_index = None;
                    let mut system_program_count = 0;
                    let mut all_intermediate_are_system = true;

                    // Search for the NOOP instruction, ensuring we find at least one SYSTEM_PROGRAM but no more than two
                    for (i, current_instruction) in
                        ordered_instructions.iter().enumerate().skip(index + 1)
                    {
                        if current_instruction.program_id == NOOP_PROGRAM_ID {
                            noop_instruction_index = Some(i);
                            break;
                        } else if current_instruction.program_id == SYSTEM_PROGRAM {
                            system_program_count += 1;
                            if system_program_count > 2 {
                                all_intermediate_are_system = false;
                                break;
                            }
                        } else {
                            all_intermediate_are_system = false;
                            break;
                        }
                    }

                    // If we found a NOOP instruction, exactly one or two SYSTEM_PROGRAM instructions, and all intermediates were valid
                    if let Some(noop_index) = noop_instruction_index {
                        if (1..=2).contains(&system_program_count) && all_intermediate_are_system {
                            if let Some(mut state_update) = parse_public_transaction_event_v1(
                                conn,
                                tx,
                                slot,
                                instruction,
                                &ordered_instructions[noop_index],
                                resolver,
                            )
                            .await?
                            {
                                is_compression_transaction = true;
                                let output_count =
                                    u32::try_from(state_update.compressed_output_contexts.len())
                                        .map_err(|_| {
                                            IngesterError::ParserError(
                                                "too many compressed output contexts".to_string(),
                                            )
                                        })?;
                                for context in &mut state_update.compressed_output_contexts {
                                    context.compressed_output_index = context
                                        .compressed_output_index
                                        .checked_add(group_compressed_output_index_offset)
                                        .ok_or_else(|| {
                                            IngesterError::ParserError(
                                                "compressed output index overflow while flattening v1 events"
                                                    .to_string(),
                                            )
                                        })?;
                                }
                                group_compressed_output_index_offset =
                                    group_compressed_output_index_offset
                                        .checked_add(output_count)
                                        .ok_or_else(|| {
                                            IngesterError::ParserError(
                                                "compressed output index offset overflow while flattening v1 events"
                                                    .to_string(),
                                            )
                                        })?;
                                group_compressed_output_contexts
                                    .extend(state_update.compressed_output_contexts.clone());
                                state_updates.push(state_update);
                            }
                        }
                    }
                }
            }
        }

        // Shielded-pool Noop payloads are only trusted when emitted by the
        // configured shielded-pool program, and each output must bind to a
        // Light public output context from the same Solana transaction.
        let shielded_pool_program_id = get_shielded_pool_program_id();
        let shielded_update = self::shielded_pool_event_parser::parse_shielded_pool_events(
            &instruction_group,
            tx.signature,
            slot,
            &[shielded_pool_program_id],
            &group_compressed_output_contexts,
        );
        if !shielded_update.shielded_tx_events.is_empty()
            || !shielded_update.shielded_outputs.is_empty()
            || !shielded_update.shielded_nullifier_events.is_empty()
        {
            state_updates.push(shielded_update);
        }

        for (index, _) in ordered_instructions.iter().enumerate() {
            if ordered_instructions.len() - index > 1 {
                if let Some(state_update) = parse_merkle_tree_event(
                    &ordered_instructions[index],
                    &ordered_instructions[index + 1],
                    tx,
                )? {
                    is_compression_transaction = true;
                    state_updates.push(state_update);
                }
            }
        }
    }

    let mut state_update = StateUpdate::merge_updates(state_updates.clone());
    if !is_voting_transaction(tx) || is_compression_transaction {
        state_update.transactions.insert(Transaction {
            signature: tx.signature,
            slot,
            uses_compression: is_compression_transaction,
            error: tx.error.clone(),
        });
    }

    Ok(state_update)
}

fn is_voting_transaction(tx: &TransactionInfo) -> bool {
    tx.instruction_groups
        .iter()
        .any(|group| group.outer_instruction.program_id == VOTE_PROGRAM_ID)
}
