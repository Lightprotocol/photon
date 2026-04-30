//! Parser for the zoned shielded-pool transaction event.
//!
//! Photon receives outer/inner instruction groups in `TransactionInfo`. The
//! shielded-pool program emits its event by CPI'ing the SPL Noop program with
//! Borsh-serialized `ShieldedPoolTxEvent` bytes. We only trust Noop payloads
//! emitted by an allowlisted outer shielded-pool program.
//!
//! Failures are logged and skipped: a malformed shielded-pool event must not
//! stop unrelated indexing in the same transaction (compression events,
//! merkle tree events, etc).

use crate::ingester::parser::shielded_pool_events::{
    ShieldedNullifierEvent, ShieldedPoolTxEvent, ShieldedUtxoOutputEvent,
};
use crate::ingester::parser::state_update::{
    CompressedOutputContextRecord, ShieldedNullifierEventRecord, ShieldedOutputRecord,
    ShieldedTxEventRecord, StateUpdate,
};
use crate::ingester::parser::NOOP_PROGRAM_ID;
use crate::ingester::typedefs::block_info::InstructionGroup;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use std::collections::HashMap;

/// Inspect a single instruction group and add shielded-pool transaction
/// events to the returned `StateUpdate`. Noop payloads are considered
/// shielded-pool events only when the group outer program is allowlisted.
pub fn parse_shielded_pool_events(
    instruction_group: &InstructionGroup,
    tx_signature: Signature,
    slot: u64,
    allowed_emitters: &[Pubkey],
    compressed_output_contexts: &[CompressedOutputContextRecord],
) -> StateUpdate {
    let mut state_update = StateUpdate::new();

    if !allowed_emitters
        .iter()
        .any(|program_id| *program_id == instruction_group.outer_instruction.program_id)
    {
        return state_update;
    }

    let mut tx_event_index_seen = 0u32;

    for instruction in &instruction_group.inner_instructions {
        if instruction.program_id != NOOP_PROGRAM_ID {
            continue;
        }
        let data = instruction.data.as_slice();

        if ShieldedPoolTxEvent::matches_discriminator(data) {
            match ShieldedPoolTxEvent::from_event_bytes(data) {
                Ok(event) => {
                    if let Err(err) = apply_tx_event(
                        &mut state_update,
                        tx_signature,
                        slot,
                        event,
                        &mut tx_event_index_seen,
                        compressed_output_contexts,
                    ) {
                        log::warn!(
                            "Skipping malformed shielded-pool event in tx {}: {}",
                            tx_signature,
                            err
                        );
                    }
                }
                Err(err) => {
                    log::warn!(
                        "Skipping malformed shielded-pool event in tx {}: {}",
                        tx_signature,
                        err
                    );
                }
            }
            continue;
        }

        if matches_nullifier_discriminator(data) {
            match try_decode_nullifier_event(data) {
                Ok(event) => {
                    if let Err(err) = apply_nullifier_event(
                        &mut state_update,
                        tx_signature,
                        slot,
                        event,
                        tx_event_index_seen,
                    ) {
                        log::warn!(
                            "Skipping malformed shielded-pool nullifier event in tx {}: {}",
                            tx_signature,
                            err
                        );
                    }
                }
                Err(err) => log::warn!(
                    "Skipping malformed shielded-pool nullifier event in tx {}: {}",
                    tx_signature,
                    err
                ),
            }
        }
    }

    state_update
}

fn apply_tx_event(
    state_update: &mut StateUpdate,
    tx_signature: Signature,
    slot: u64,
    event: ShieldedPoolTxEvent,
    tx_event_index_seen: &mut u32,
    compressed_output_contexts: &[CompressedOutputContextRecord],
) -> Result<(), String> {
    let event_index = event.tx_event_index;
    if event_index != *tx_event_index_seen {
        return Err(format!(
            "unexpected shielded-pool tx_event_index {}, expected {}",
            event_index, *tx_event_index_seen
        ));
    }
    *tx_event_index_seen = event_index + 1;

    if let Some(zone_hash) = event.zone_config_hash {
        state_update
            .shielded_zone_configs_seen
            .entry(zone_hash)
            .and_modify(|existing| *existing = (*existing).max(slot))
            .or_insert(slot);
    }

    let ShieldedPoolTxEvent {
        version,
        instruction_tag,
        tx_kind,
        protocol_config,
        zone_config_hash,
        tx_ephemeral_pubkey,
        encrypted_tx_ephemeral_keys,
        operation_commitment,
        public_input_hash,
        utxo_public_inputs_hash,
        tree_public_inputs_hash,
        nullifier_chain,
        input_nullifiers,
        public_delta,
        relayer_fee,
        outputs,
        ..
    } = event;

    let compressed_outputs_by_index = compressed_output_contexts
        .iter()
        .map(|context| (context.compressed_output_index, context))
        .collect::<HashMap<_, _>>();

    let mut output_records = Vec::with_capacity(outputs.len());

    for output in outputs {
        let ShieldedUtxoOutputEvent {
            output_index,
            compressed_output_index,
            utxo_hash,
            encrypted_utxo,
            encrypted_utxo_hash,
        } = output;
        let compressed_context = compressed_outputs_by_index
            .get(&compressed_output_index)
            .ok_or_else(|| {
                format!(
                    "shielded output {} references missing compressed_output_index {}",
                    output_index, compressed_output_index
                )
            })?;
        match compressed_context.data_hash {
            Some(data_hash) if data_hash == utxo_hash => {}
            Some(data_hash) => {
                return Err(format!(
                    "shielded output {} utxo_hash does not match compressed account data_hash: {:?} != {:?}",
                    output_index, utxo_hash, data_hash
                ));
            }
            None => {
                return Err(format!(
                    "shielded output {} references compressed output {} without data_hash",
                    output_index, compressed_output_index
                ));
            }
        }

        output_records.push(ShieldedOutputRecord {
            tx_signature,
            event_index,
            output_index,
            compressed_output_index,
            slot,
            utxo_hash,
            compressed_account_hash: compressed_context.compressed_account_hash,
            utxo_tree: compressed_context.tree.to_bytes(),
            leaf_index: compressed_context.leaf_index,
            tree_sequence: compressed_context.tree_sequence,
            encrypted_utxo,
            encrypted_utxo_hash,
            zone_config_hash,
        });
    }

    state_update.shielded_tx_events.push(ShieldedTxEventRecord {
        tx_signature,
        event_index,
        slot,
        version,
        instruction_tag,
        tx_kind,
        protocol_config,
        zone_config_hash,
        tx_ephemeral_pubkey,
        encrypted_tx_ephemeral_keys,
        operation_commitment,
        public_input_hash,
        utxo_public_inputs_hash,
        tree_public_inputs_hash,
        nullifier_chain,
        input_nullifiers,
        public_delta,
        relayer_fee,
    });
    state_update.shielded_outputs.extend(output_records);

    Ok(())
}

/// Discriminator for the spend event. Mirrors the tx event in shape but uses
/// a distinct prefix so the two events don't shadow each other.
pub const SHIELDED_POOL_NULLIFIER_EVENT_V1_DISCRIMINATOR: [u8; 8] =
    [b's', b'h', b'l', b'd', b'n', b'l', b'v', b'1'];

fn matches_nullifier_discriminator(data: &[u8]) -> bool {
    data.len() >= SHIELDED_POOL_NULLIFIER_EVENT_V1_DISCRIMINATOR.len()
        && data[..SHIELDED_POOL_NULLIFIER_EVENT_V1_DISCRIMINATOR.len()]
            == SHIELDED_POOL_NULLIFIER_EVENT_V1_DISCRIMINATOR
}

fn try_decode_nullifier_event(data: &[u8]) -> Result<ShieldedNullifierEvent, std::io::Error> {
    use borsh::BorshDeserialize;
    let event = ShieldedNullifierEvent::try_from_slice(data)?;
    if event.event_discriminator != SHIELDED_POOL_NULLIFIER_EVENT_V1_DISCRIMINATOR {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "nullifier event discriminator mismatch",
        ));
    }
    if event.version != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported shielded-pool nullifier event version",
        ));
    }
    Ok(event)
}

fn apply_nullifier_event(
    state_update: &mut StateUpdate,
    tx_signature: Signature,
    slot: u64,
    event: ShieldedNullifierEvent,
    next_tx_event_index: u32,
) -> Result<(), String> {
    if event.tx_event_index >= next_tx_event_index {
        return Err(format!(
            "nullifier references unknown shielded-pool tx_event_index {}",
            event.tx_event_index
        ));
    }

    state_update
        .shielded_nullifier_events
        .push(ShieldedNullifierEventRecord {
            tx_signature,
            event_index: event.tx_event_index,
            slot,
            nullifier: event.nullifier,
            nullifier_tree: event.nullifier_tree,
        });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::parser::shielded_pool_events::{
        EncryptedTxEphemeralKey, EncryptedTxEphemeralKeyRole, ShieldedPoolTxKind,
        ShieldedPublicDelta, ShieldedUtxoOutputEvent, SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR,
        SHIELDED_POOL_TX_EVENT_VERSION,
    };
    use crate::ingester::parser::state_update::CompressedOutputContextRecord;
    use crate::ingester::parser::SHIELDED_POOL_PROGRAM_ID;
    use crate::ingester::typedefs::block_info::Instruction;
    use solana_pubkey::Pubkey;

    fn noop_instruction(data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: NOOP_PROGRAM_ID,
            data,
            accounts: vec![],
        }
    }

    fn other_program_instruction(data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: Pubkey::new_unique(),
            data,
            accounts: vec![],
        }
    }

    fn instruction_group(
        outer_program_id: Pubkey,
        inner_instructions: Vec<Instruction>,
    ) -> InstructionGroup {
        InstructionGroup {
            outer_instruction: Instruction {
                program_id: outer_program_id,
                data: vec![],
                accounts: vec![],
            },
            inner_instructions,
        }
    }

    fn authorized_group(inner_instructions: Vec<Instruction>) -> InstructionGroup {
        instruction_group(SHIELDED_POOL_PROGRAM_ID, inner_instructions)
    }

    fn parse_test_group(group: &InstructionGroup) -> StateUpdate {
        parse_shielded_pool_events(
            group,
            Signature::default(),
            100,
            &[SHIELDED_POOL_PROGRAM_ID],
            &sample_compressed_output_contexts(4),
        )
    }

    fn sample_compressed_output_contexts(count: u32) -> Vec<CompressedOutputContextRecord> {
        (0..count)
            .map(|i| CompressedOutputContextRecord {
                compressed_output_index: i,
                compressed_account_hash: [0xa0u8.wrapping_add(i as u8); 32],
                tree: Pubkey::new_from_array([0xb0u8.wrapping_add(i as u8); 32]),
                leaf_index: 10 + i as u64,
                tree_sequence: 100 + i as u64,
                data_hash: Some([i as u8; 32]),
            })
            .collect()
    }

    fn sample_tx_event(index: u32, output_count: u8) -> ShieldedPoolTxEvent {
        let outputs = (0..output_count)
            .map(|i| ShieldedUtxoOutputEvent {
                output_index: i,
                compressed_output_index: i as u32,
                utxo_hash: [i; 32],
                encrypted_utxo: vec![1, 2, 3, i],
                encrypted_utxo_hash: [i ^ 0xff; 32],
            })
            .collect();
        ShieldedPoolTxEvent {
            event_discriminator: SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR,
            version: SHIELDED_POOL_TX_EVENT_VERSION,
            tx_event_index: index,
            instruction_tag: 1,
            tx_kind: ShieldedPoolTxKind::ProoflessShield,
            protocol_config: [7; 32],
            zone_config_hash: Some([9; 32]),
            tx_ephemeral_pubkey: [3; 32],
            encrypted_tx_ephemeral_keys: vec![EncryptedTxEphemeralKey {
                role: EncryptedTxEphemeralKeyRole::Auditor,
                key_id: 1,
                key_version: 1,
                hpke_ephemeral_pubkey: [4; 32],
                encrypted_tx_ephemeral_key: vec![0xaa; 48],
                auth_tag: [5; 16],
            }],
            operation_commitment: [6; 32],
            public_input_hash: None,
            utxo_public_inputs_hash: None,
            tree_public_inputs_hash: None,
            nullifier_chain: None,
            input_nullifiers: vec![],
            public_delta: ShieldedPublicDelta::default(),
            relayer_fee: None,
            outputs,
        }
    }

    fn sample_nullifier_event(index: u32) -> ShieldedNullifierEvent {
        ShieldedNullifierEvent {
            event_discriminator: SHIELDED_POOL_NULLIFIER_EVENT_V1_DISCRIMINATOR,
            version: 1,
            nullifier: [0x11; 32],
            nullifier_tree: [0x22; 32],
            tx_event_index: index,
        }
    }

    #[test]
    fn parses_one_event_with_two_outputs() {
        let event = sample_tx_event(0, 2);
        let bytes = event.to_event_bytes().unwrap();
        let group = authorized_group(vec![noop_instruction(bytes)]);

        let state_update = parse_test_group(&group);

        assert_eq!(state_update.shielded_tx_events.len(), 1);
        assert_eq!(state_update.shielded_outputs.len(), 2);
        assert_eq!(state_update.shielded_zone_configs_seen.len(), 1);
        assert_eq!(state_update.shielded_outputs[0].output_index, 0);
        assert_eq!(state_update.shielded_outputs[1].output_index, 1);
        assert_eq!(state_update.shielded_outputs[0].slot, 100);
        assert_eq!(state_update.shielded_outputs[0].compressed_output_index, 0);
        assert_eq!(state_update.shielded_outputs[0].leaf_index, 10);
        assert_eq!(state_update.shielded_outputs[0].tree_sequence, 100);
        assert_eq!(
            state_update.shielded_outputs[0].compressed_account_hash,
            [0xa0; 32]
        );
    }

    #[test]
    fn skips_event_without_matching_compressed_output_context() {
        let event = sample_tx_event(0, 1);
        let group = authorized_group(vec![noop_instruction(event.to_event_bytes().unwrap())]);

        let state_update = parse_shielded_pool_events(
            &group,
            Signature::default(),
            100,
            &[SHIELDED_POOL_PROGRAM_ID],
            &[],
        );

        assert_eq!(state_update.shielded_tx_events.len(), 0);
        assert_eq!(state_update.shielded_outputs.len(), 0);
    }

    #[test]
    fn ignores_non_noop_instructions() {
        let event = sample_tx_event(0, 1);
        let bytes = event.to_event_bytes().unwrap();
        let group = authorized_group(vec![
            other_program_instruction(bytes.clone()), // wrong program id
            noop_instruction(vec![0xde, 0xad]),       // noop, but not our discriminator
        ]);

        let state_update = parse_test_group(&group);
        assert_eq!(state_update.shielded_tx_events.len(), 0);
        assert_eq!(state_update.shielded_outputs.len(), 0);
    }

    #[test]
    fn ignores_noop_event_from_unauthorized_outer_program() {
        let event = sample_tx_event(0, 1);
        let group = instruction_group(
            Pubkey::new_unique(),
            vec![noop_instruction(event.to_event_bytes().unwrap())],
        );

        let state_update = parse_test_group(&group);

        assert_eq!(state_update.shielded_tx_events.len(), 0);
        assert_eq!(state_update.shielded_outputs.len(), 0);
    }

    #[test]
    fn skips_malformed_event_but_keeps_subsequent_valid_event() {
        let mut malformed = sample_tx_event(0, 1).to_event_bytes().unwrap();
        // Corrupt the bytes after the discriminator so borsh fails to decode.
        let len = malformed.len();
        for byte in &mut malformed[SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR.len()..len] {
            *byte = 0xff;
        }
        let valid = sample_tx_event(0, 1).to_event_bytes().unwrap();

        let group = authorized_group(vec![noop_instruction(malformed), noop_instruction(valid)]);
        let state_update = parse_test_group(&group);

        assert_eq!(state_update.shielded_tx_events.len(), 1);
        assert_eq!(state_update.shielded_outputs.len(), 1);
    }

    #[test]
    fn parses_two_events_in_one_transaction() {
        let event_a = sample_tx_event(0, 1);
        let event_b = sample_tx_event(1, 2);
        let group = authorized_group(vec![
            noop_instruction(event_a.to_event_bytes().unwrap()),
            noop_instruction(event_b.to_event_bytes().unwrap()),
        ]);

        let state_update = parse_test_group(&group);

        assert_eq!(state_update.shielded_tx_events.len(), 2);
        assert_eq!(state_update.shielded_outputs.len(), 3);
        assert_eq!(state_update.shielded_tx_events[0].event_index, 0);
        assert_eq!(state_update.shielded_tx_events[1].event_index, 1);
    }

    #[test]
    fn skips_duplicate_tx_event_index() {
        let event_a = sample_tx_event(0, 1);
        let event_b = sample_tx_event(0, 1);
        let group = authorized_group(vec![
            noop_instruction(event_a.to_event_bytes().unwrap()),
            noop_instruction(event_b.to_event_bytes().unwrap()),
        ]);

        let state_update = parse_test_group(&group);

        assert_eq!(state_update.shielded_tx_events.len(), 1);
        assert_eq!(state_update.shielded_outputs.len(), 1);
        assert_eq!(state_update.shielded_tx_events[0].event_index, 0);
    }

    #[test]
    fn skips_out_of_order_tx_event_index() {
        let event = sample_tx_event(1, 1);
        let group = authorized_group(vec![noop_instruction(event.to_event_bytes().unwrap())]);

        let state_update = parse_test_group(&group);

        assert_eq!(state_update.shielded_tx_events.len(), 0);
        assert_eq!(state_update.shielded_outputs.len(), 0);
    }

    #[test]
    fn skips_nullifier_without_parent_tx_event() {
        let nullifier = sample_nullifier_event(0);
        let group = authorized_group(vec![noop_instruction(borsh::to_vec(&nullifier).unwrap())]);

        let state_update = parse_test_group(&group);

        assert_eq!(state_update.shielded_tx_events.len(), 0);
        assert_eq!(state_update.shielded_nullifier_events.len(), 0);
    }

    #[test]
    fn parses_nullifier_after_parent_tx_event() {
        let event = sample_tx_event(0, 1);
        let nullifier = sample_nullifier_event(0);
        let group = authorized_group(vec![
            noop_instruction(event.to_event_bytes().unwrap()),
            noop_instruction(borsh::to_vec(&nullifier).unwrap()),
        ]);

        let state_update = parse_test_group(&group);

        assert_eq!(state_update.shielded_tx_events.len(), 1);
        assert_eq!(state_update.shielded_nullifier_events.len(), 1);
        assert_eq!(
            state_update.shielded_nullifier_events[0].nullifier,
            nullifier.nullifier
        );
    }
}
