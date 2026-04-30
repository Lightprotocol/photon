//! Test-only emitter for the zoned shielded-pool transaction event.
//!
//! The implementation plan calls for a dummy emitter that
//! produces canonical `ShieldedPoolTxEvent` Borsh bytes wrapped in a Noop CPI,
//! together with a fixture-only plaintext sidecar Zone RPC can project. This
//! module is the in-process equivalent: it builds a `TransactionInfo` whose
//! inner instructions match exactly what the future on-chain shielded-pool
//! program will emit.
//!
//! The helpers are public so the e2e test in photon and a sibling Zone RPC
//! crate can both reuse them. They live under `parser/` to keep the canonical
//! event format and its emitter side-by-side; if the format changes, the
//! emitter and parser are updated in lockstep.

use ark_bn254::Fr;
use borsh::BorshSerialize;
use light_compressed_account::{
    constants::{LIGHT_SYSTEM_PROGRAM_ID, REGISTERED_PROGRAM_PDA},
    discriminators::{DISCRIMINATOR_INSERT_INTO_QUEUES, DISCRIMINATOR_INVOKE_CPI},
    instruction_data::{
        data::OutputCompressedAccountWithPackedContext as LightOutputCompressedAccountWithPackedContext,
        insert_into_queues::{
            AppendLeavesInput, InsertIntoQueuesInstructionDataMut,
            MerkleTreeSequenceNumber as LightMerkleTreeSequenceNumber,
        },
        invoke_cpi::InstructionDataInvokeCpi,
    },
    Pubkey as LightPubkey, TreeType,
};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use solana_pubkey::{pubkey, Pubkey};
use solana_signature::Signature;

use crate::ingester::parser::indexer_events::{BatchEvent, MerkleTreeEvent};
use crate::ingester::parser::shielded_pool_events::{
    EncryptedTxEphemeralKey, EncryptedTxEphemeralKeyRole, FixturePlaintextPayload,
    FixturePlaintextSidecar, ShieldedPoolTxEvent, ShieldedPoolTxKind, ShieldedPublicDelta,
    ShieldedUtxoOutputEvent, SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR,
    SHIELDED_POOL_TX_EVENT_VERSION,
};
use crate::ingester::parser::state_update::CompressedOutputContextRecord;
use crate::ingester::parser::{
    get_compression_program_id, NOOP_PROGRAM_ID, SHIELDED_POOL_TEST_PROGRAM_ID,
};
use crate::ingester::typedefs::block_info::{Instruction, InstructionGroup, TransactionInfo};

const FIXTURE_UTXO_TREE: [u8; 32] = [0xAB; 32];
const FIXTURE_TREE_SEQUENCE: u64 = 1;
const FIXTURE_LEAF_INDEX_BASE: u32 = 0;
const FIXTURE_ROOT_HISTORY_CAPACITY: u64 = 64;
const FIXTURE_COMPRESSED_ACCOUNT_DISCRIMINATOR: [u8; 8] = *b"shldutxo";

/// Owner identifiers and amounts for one fixture output. Plaintext-only;
/// production events never carry these fields directly.
#[derive(Debug, Clone)]
pub struct FixtureOwnerSpec {
    pub owner_pubkey: [u8; 32],
    pub token_mint: [u8; 32],
    pub spl_amount: u64,
    pub sol_amount: u64,
    pub blinding: [u8; 32],
}

/// What the emitter produces: the canonical event, the matching plaintext
/// sidecar, and the synthesized `TransactionInfo` ready to feed into
/// `parse_transaction`. Returning all three keeps the test wiring honest —
/// changing one field on either side without updating the others is a build
/// error rather than a silent test pass.
pub struct DummyShieldedPoolFixture {
    pub event: ShieldedPoolTxEvent,
    pub sidecar: FixturePlaintextSidecar,
    pub transaction_info: TransactionInfo,
    /// Operation commitment used as the sidecar join key because Photon
    /// persists it with the public event row.
    pub operation_commitment: [u8; 32],
}

/// Inputs for a single fixture transaction. Use this rather than positional
/// args so future fields (e.g. nullifier sets, public deltas) can be added
/// without breaking call sites.
pub struct FixtureBuilder {
    pub signature: Signature,
    pub zone_config_hash: [u8; 32],
    pub instruction_tag: u8,
    pub tx_kind: ShieldedPoolTxKind,
    pub outputs: Vec<FixtureOwnerSpec>,
}

impl FixtureBuilder {
    /// Default fixture: one output, one auditor key, public proofless shield.
    /// Slot/owner/amounts are caller-supplied so tests can exercise multiple
    /// owners or amounts in the same zone.
    pub fn proofless_shield_one_output(signature: Signature, owner: FixtureOwnerSpec) -> Self {
        Self {
            signature,
            zone_config_hash: [0x77; 32],
            instruction_tag: 1,
            tx_kind: ShieldedPoolTxKind::ProoflessShield,
            outputs: vec![owner],
        }
    }

    pub fn build(self) -> DummyShieldedPoolFixture {
        // Domain tag is a small constant — safe in BN254 Fr.
        let domain: u8 = 1;
        // Reduce the zone hash mod the BN254 Fr modulus (top byte cleared)
        // before hashing so light-poseidon does not reject it as
        // out-of-field. The canonical event still carries the unmodified
        // 32-byte value for routing/lookup; only the hash inputs are
        // reduced.
        let zone_for_hash = clear_top_byte(self.zone_config_hash);

        // Build plaintext payloads + matching utxo_hash values. The plan
        // calls for the Zone RPC sidecar to verify hash(plaintext) ==
        // utxo_hash even in dev mode, so we compute the same digest the
        // real program will compute. We use a deterministic Poseidon over
        // the canonical plaintext fields here; production may use a
        // different domain tag, but the equivalence between plaintext and
        // utxo_hash is preserved.
        let mut plaintext_payloads = Vec::with_capacity(self.outputs.len());
        let mut output_events = Vec::with_capacity(self.outputs.len());

        for (idx, owner) in self.outputs.iter().enumerate() {
            let owner_pubkey_field = clear_top_byte(owner.owner_pubkey);
            let owner_hash = poseidon_hash(&[&owner_pubkey_field]).expect("poseidon owner_hash");
            let data_hash = [0u8; 32];
            let extended_data: Vec<u8> = vec![];
            let payload = FixturePlaintextPayload {
                domain,
                owner_pubkey: owner.owner_pubkey,
                owner_hash,
                token_mint: owner.token_mint,
                spl_amount: owner.spl_amount,
                sol_amount: owner.sol_amount,
                blinding: owner.blinding,
                data_hash,
                extended_data: extended_data.clone(),
                zone_config_hash: self.zone_config_hash,
            };
            // Canonical UTXO commitment: Poseidon over the plaintext
            // fields the production circuit will hash. We deliberately keep
            // the exact field set conservative — extending it later will
            // be a migration with a fresh fixture.
            let utxo_hash =
                utxo_hash_for_payload_with_zone(&payload, &zone_for_hash).expect("utxo_hash");

            // Encrypted ciphertext is dummy bytes. The plan explicitly does
            // not require real encryption for the first vertical slice;
            // Photon stores the bytes verbatim and Zone RPC reads the
            // sidecar plaintext rather than decrypting.
            let mut encrypted_utxo = Vec::with_capacity(64);
            encrypted_utxo.extend_from_slice(&[0xC1, 0xC2, 0xC3, idx as u8]);
            encrypted_utxo.extend_from_slice(&utxo_hash); // 32 bytes of "ciphertext"
            encrypted_utxo.extend_from_slice(&[0u8; 28]); // padding to 64 bytes

            // Dummy ciphertext hash. Production will compute a real digest of
            // the encrypted payload; here it just needs to be a stable
            // 32-byte value derived from the bytes so the parser/persist
            // round trip is deterministic.
            let encrypted_utxo_hash =
                poseidon_hash(&[&utxo_hash]).expect("poseidon encrypted_utxo_hash for fixture");

            output_events.push(ShieldedUtxoOutputEvent {
                output_index: idx as u8,
                compressed_output_index: idx as u32,
                utxo_hash,
                encrypted_utxo,
                encrypted_utxo_hash,
            });
            plaintext_payloads.push(payload);
        }

        let event = ShieldedPoolTxEvent {
            event_discriminator: SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR,
            version: SHIELDED_POOL_TX_EVENT_VERSION,
            tx_event_index: 0,
            instruction_tag: self.instruction_tag,
            tx_kind: self.tx_kind.clone(),
            protocol_config: [0x42; 32],
            zone_config_hash: Some(self.zone_config_hash),
            tx_ephemeral_pubkey: [0x33; 32],
            encrypted_tx_ephemeral_keys: vec![EncryptedTxEphemeralKey {
                role: EncryptedTxEphemeralKeyRole::Auditor,
                key_id: 1,
                key_version: 1,
                hpke_ephemeral_pubkey: [0x44; 32],
                encrypted_tx_ephemeral_key: vec![0xAA; 48],
                auth_tag: [0x55; 16],
            }],
            operation_commitment: [0x66; 32],
            public_input_hash: None,
            utxo_public_inputs_hash: None,
            tree_public_inputs_hash: None,
            nullifier_chain: None,
            input_nullifiers: vec![],
            public_delta: ShieldedPublicDelta::default(),
            relayer_fee: None,
            outputs: output_events,
        };

        let event_bytes = event.to_event_bytes().expect("serialize event");
        let operation_commitment = event.operation_commitment;

        let sidecar = FixturePlaintextSidecar {
            operation_commitment,
            payloads: plaintext_payloads,
        };

        // Build a TransactionInfo that mirrors the local test program:
        // outer test-program instruction, inner Light system invoke CPI,
        // account-compression insert-into-queues, then the shielded Noop
        // payload. Photon must recover the Light public output through the
        // v2 event parser before accepting the shielded output join.
        let output_accounts = light_fixture_output_accounts(&event);
        let outer = Instruction {
            program_id: SHIELDED_POOL_TEST_PROGRAM_ID,
            data: vec![],
            accounts: vec![],
        };
        let light_system = Instruction {
            program_id: Pubkey::new_from_array(LIGHT_SYSTEM_PROGRAM_ID),
            data: light_invoke_cpi_instruction_data(output_accounts.clone()),
            accounts: light_system_accounts(),
        };
        let system = Instruction {
            program_id: pubkey!("11111111111111111111111111111111"),
            data: vec![0; 12],
            accounts: vec![],
        };
        let compression = Instruction {
            program_id: get_compression_program_id(),
            data: insert_into_queues_instruction_data(&event),
            accounts: account_compression_accounts(),
        };
        let shielded_inner = Instruction {
            program_id: NOOP_PROGRAM_ID,
            data: event_bytes,
            accounts: vec![],
        };
        let batch_append_outer = Instruction {
            program_id: get_compression_program_id(),
            data: vec![],
            accounts: vec![Pubkey::new_from_array(FIXTURE_UTXO_TREE)],
        };
        let batch_append_noop = Instruction {
            program_id: NOOP_PROGRAM_ID,
            data: batch_append_event_data(self.outputs.len()),
            accounts: vec![],
        };
        let transaction_info = TransactionInfo {
            instruction_groups: vec![
                InstructionGroup {
                    outer_instruction: outer,
                    inner_instructions: vec![light_system, system, compression, shielded_inner],
                },
                InstructionGroup {
                    outer_instruction: batch_append_outer,
                    inner_instructions: vec![batch_append_noop],
                },
            ],
            signature: self.signature,
            error: None,
        };

        DummyShieldedPoolFixture {
            event,
            sidecar,
            transaction_info,
            operation_commitment,
        }
    }
}

pub fn fixture_utxo_tree() -> [u8; 32] {
    FIXTURE_UTXO_TREE
}

pub fn fixture_tree_sequence() -> u64 {
    FIXTURE_TREE_SEQUENCE
}

pub fn fixture_leaf_index_base() -> u32 {
    FIXTURE_LEAF_INDEX_BASE
}

fn light_fixture_output_accounts(
    event: &ShieldedPoolTxEvent,
) -> Vec<LightOutputCompressedAccountWithPackedContext> {
    event
        .outputs
        .iter()
        .map(|output| LightOutputCompressedAccountWithPackedContext {
            compressed_account: light_compressed_account::compressed_account::CompressedAccount {
                owner: LightPubkey::from(SHIELDED_POOL_TEST_PROGRAM_ID.to_bytes()),
                lamports: 0,
                address: None,
                data: Some(
                    light_compressed_account::compressed_account::CompressedAccountData {
                        discriminator: FIXTURE_COMPRESSED_ACCOUNT_DISCRIMINATOR,
                        data: Vec::new(),
                        data_hash: output.utxo_hash,
                    },
                ),
            },
            merkle_tree_index: 0,
        })
        .collect()
}

fn light_invoke_cpi_instruction_data(
    output_accounts: Vec<LightOutputCompressedAccountWithPackedContext>,
) -> Vec<u8> {
    let invoke = InstructionDataInvokeCpi {
        proof: None,
        new_address_params: Vec::new(),
        input_compressed_accounts_with_merkle_context: Vec::new(),
        output_compressed_accounts: output_accounts,
        relay_fee: None,
        compress_or_decompress_lamports: None,
        is_compress: false,
        cpi_context: None,
    };
    let payload = borsh::to_vec(&invoke).expect("serialize InstructionDataInvokeCpi");
    instruction_data_with_discriminator(&DISCRIMINATOR_INVOKE_CPI, payload)
}

fn insert_into_queues_instruction_data(event: &ShieldedPoolTxEvent) -> Vec<u8> {
    let output_count = u8::try_from(event.outputs.len()).expect("fixture output count fits in u8");
    let raw_len =
        InsertIntoQueuesInstructionDataMut::required_size_for_capacity(output_count, 0, 0, 1, 0, 0);
    let mut raw = vec![0u8; raw_len];
    {
        let (mut data, _) =
            InsertIntoQueuesInstructionDataMut::new_at(&mut raw, output_count, 0, 0, 1, 0, 0)
                .expect("initialize insert-into-queues fixture data");
        data.set_invoked_by_program(true);
        data.bump = 255;
        data.num_queues = 1;
        data.num_output_queues = 1;
        data.start_output_appends = 0;
        data.num_address_queues = 0;
        data.tx_hash = [0x88; 32];
        data.output_sequence_numbers[0] = LightMerkleTreeSequenceNumber {
            tree_pubkey: LightPubkey::from(FIXTURE_UTXO_TREE),
            queue_pubkey: LightPubkey::from(FIXTURE_UTXO_TREE),
            tree_type: (TreeType::StateV2 as u64).into(),
            seq: FIXTURE_TREE_SEQUENCE.into(),
        };
        for (idx, output) in event.outputs.iter().enumerate() {
            data.leaves[idx] = AppendLeavesInput {
                account_index: idx as u8,
                leaf: fixture_compressed_account_hash(idx, &output.utxo_hash),
            };
            data.output_leaf_indices[idx] = (FIXTURE_LEAF_INDEX_BASE + idx as u32).into();
        }
    }

    let mut payload = raw;
    payload.extend_from_slice(
        &borsh::to_vec(&Vec::<LightOutputCompressedAccountWithPackedContext>::new())
            .expect("serialize empty cpi context outputs"),
    );
    instruction_data_with_discriminator(&DISCRIMINATOR_INSERT_INTO_QUEUES, payload)
}

fn batch_append_event_data(output_count: usize) -> Vec<u8> {
    let old_next_index = FIXTURE_LEAF_INDEX_BASE as u64;
    let new_next_index = old_next_index + output_count as u64;
    borsh::to_vec(&MerkleTreeEvent::BatchAppend(BatchEvent {
        merkle_tree_pubkey: FIXTURE_UTXO_TREE,
        batch_index: 0,
        zkp_batch_index: 0,
        zkp_batch_size: output_count as u64,
        old_next_index,
        new_next_index,
        // Photon recomputes the persisted tree nodes from queued accounts;
        // the event root is retained here only to match the on-chain event shape.
        new_root: [0x91; 32],
        root_index: (FIXTURE_TREE_SEQUENCE % FIXTURE_ROOT_HISTORY_CAPACITY) as u32,
        sequence_number: FIXTURE_TREE_SEQUENCE,
        output_queue_pubkey: Some(FIXTURE_UTXO_TREE),
    }))
    .expect("serialize fixture batch append event")
}

fn instruction_data_with_discriminator(discriminator: &[u8; 8], payload: Vec<u8>) -> Vec<u8> {
    let mut data = Vec::with_capacity(12 + payload.len());
    data.extend_from_slice(discriminator);
    data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    data.extend_from_slice(&payload);
    data
}

fn light_system_accounts() -> Vec<Pubkey> {
    let mut accounts = fixed_accounts(11);
    accounts.push(Pubkey::new_from_array(FIXTURE_UTXO_TREE));
    accounts
}

fn account_compression_accounts() -> Vec<Pubkey> {
    vec![
        Pubkey::new_from_array([0xA0; 32]),
        Pubkey::new_from_array(REGISTERED_PROGRAM_PDA),
        Pubkey::new_from_array(FIXTURE_UTXO_TREE),
    ]
}

fn fixed_accounts(count: usize) -> Vec<Pubkey> {
    (0..count)
        .map(|index| {
            let mut bytes = [0u8; 32];
            bytes[31] = index as u8;
            Pubkey::new_from_array(bytes)
        })
        .collect()
}

pub fn fixture_compressed_output_contexts(
    event: &ShieldedPoolTxEvent,
) -> Vec<CompressedOutputContextRecord> {
    event
        .outputs
        .iter()
        .enumerate()
        .map(|(idx, output)| CompressedOutputContextRecord {
            compressed_output_index: idx as u32,
            compressed_account_hash: fixture_compressed_account_hash(idx, &output.utxo_hash),
            tree: solana_pubkey::Pubkey::new_from_array(FIXTURE_UTXO_TREE),
            leaf_index: (FIXTURE_LEAF_INDEX_BASE + idx as u32) as u64,
            tree_sequence: FIXTURE_TREE_SEQUENCE,
            data_hash: Some(output.utxo_hash),
        })
        .collect()
}

fn fixture_compressed_account_hash(output_index: usize, utxo_hash: &[u8; 32]) -> [u8; 32] {
    let mut hash = [0xD0; 32];
    hash[..4].copy_from_slice(&(output_index as u32).to_be_bytes());
    hash[4..].copy_from_slice(&utxo_hash[..28]);
    hash
}

/// Compute the canonical UTXO commitment over the plaintext fields. This
/// hash is what `ShieldedUtxoOutputEvent.utxo_hash` must equal, and what the
/// Zone RPC projection re-checks. Inputs are reduced into BN254 Fr (top
/// byte cleared) since light-poseidon rejects out-of-field bytes.
pub fn utxo_hash_for_payload(payload: &FixturePlaintextPayload) -> Result<[u8; 32], String> {
    let zone_for_hash = clear_top_byte(payload.zone_config_hash);
    utxo_hash_for_payload_with_zone(payload, &zone_for_hash)
}

fn utxo_hash_for_payload_with_zone(
    payload: &FixturePlaintextPayload,
    zone_for_hash: &[u8; 32],
) -> Result<[u8; 32], String> {
    let mut domain_bytes = [0u8; 32];
    domain_bytes[31] = payload.domain;
    let token_mint_field = clear_top_byte(payload.token_mint);
    let blinding_field = clear_top_byte(payload.blinding);
    let spl_bytes = u128_to_be_32(payload.spl_amount as u128);
    let sol_bytes = u128_to_be_32(payload.sol_amount as u128);
    poseidon_hash(&[
        &domain_bytes,
        &payload.owner_hash,
        &token_mint_field,
        &spl_bytes,
        &sol_bytes,
        &blinding_field,
        zone_for_hash,
    ])
}

fn clear_top_byte(bytes: [u8; 32]) -> [u8; 32] {
    let mut out = bytes;
    out[0] = 0;
    out
}

/// Poseidon over 32-byte big-endian inputs. Wraps light-poseidon with the
/// width inferred from input count. Returns a 32-byte big-endian digest.
fn poseidon_hash(inputs: &[&[u8; 32]]) -> Result<[u8; 32], String> {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .map_err(|err| format!("poseidon init: {}", err))?;
    let inputs_vec: Vec<&[u8]> = inputs.iter().map(|chunk| chunk.as_slice()).collect();
    hasher
        .hash_bytes_be(&inputs_vec)
        .map_err(|err| format!("poseidon hash: {}", err))
}

fn u128_to_be_32(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Borsh-encode a sidecar to bytes. Used by Zone RPC tests that want to feed
/// the sidecar over a byte channel.
pub fn encode_sidecar(sidecar: &FixturePlaintextSidecar) -> Vec<u8> {
    borsh::to_vec(sidecar).expect("encode fixture sidecar")
}

/// Re-export with a public name so callers can do
/// `let bytes: Vec<u8> = serialize_event(&event)` without pulling borsh in.
pub fn serialize_event(event: &ShieldedPoolTxEvent) -> Vec<u8> {
    event
        .try_to_vec()
        .expect("borsh-serialize ShieldedPoolTxEvent")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::parser::shielded_pool_event_parser::parse_shielded_pool_events;
    use borsh::BorshDeserialize;

    fn fixture() -> DummyShieldedPoolFixture {
        let owner = FixtureOwnerSpec {
            owner_pubkey: [0xAA; 32],
            token_mint: [0xBB; 32],
            spl_amount: 1_000_000,
            sol_amount: 0,
            blinding: [0xCC; 32],
        };
        FixtureBuilder::proofless_shield_one_output(Signature::default(), owner).build()
    }

    #[test]
    fn dummy_event_round_trips_through_parser() {
        let f = fixture();
        let contexts = fixture_compressed_output_contexts(&f.event);
        let state_update = parse_shielded_pool_events(
            &f.transaction_info.instruction_groups[0],
            Signature::default(),
            100,
            &[SHIELDED_POOL_TEST_PROGRAM_ID],
            &contexts,
        );
        assert_eq!(state_update.shielded_tx_events.len(), 1);
        assert_eq!(state_update.shielded_outputs.len(), 1);
        let parsed = &state_update.shielded_tx_events[0];
        assert_eq!(
            parsed.zone_config_hash,
            Some(f.event.zone_config_hash.unwrap())
        );
        assert_eq!(
            state_update.shielded_outputs[0].utxo_hash,
            f.event.outputs[0].utxo_hash
        );
    }

    #[test]
    fn fixture_transaction_uses_light_v2_event_shape() {
        let f = fixture();
        let group = &f.transaction_info.instruction_groups[0];
        let mut ordered_instructions = vec![group.outer_instruction.clone()];
        ordered_instructions.extend(group.inner_instructions.clone());
        let program_ids = ordered_instructions
            .iter()
            .map(|instruction| instruction.program_id)
            .collect::<Vec<_>>();
        let instruction_data = ordered_instructions
            .iter()
            .map(|instruction| instruction.data.clone())
            .collect::<Vec<_>>();
        let accounts = ordered_instructions
            .iter()
            .map(|instruction| instruction.accounts.clone())
            .collect::<Vec<_>>();

        let public_events =
            crate::ingester::parser::tx_event_parser_v2::parse_public_transaction_event_v2(
                &program_ids,
                &instruction_data,
                accounts,
            )
            .expect("fixture should parse through Light v2 event parser");
        assert_eq!(public_events.len(), 1);
        let public_event = &public_events[0].event;
        assert_eq!(public_event.output_compressed_accounts.len(), 1);
        assert_eq!(
            public_event.output_leaf_indices,
            vec![FIXTURE_LEAF_INDEX_BASE]
        );
        assert_eq!(public_event.sequence_numbers[0].seq, FIXTURE_TREE_SEQUENCE);
        assert_eq!(
            public_event.output_compressed_accounts[0]
                .compressed_account
                .data
                .as_ref()
                .unwrap()
                .data_hash,
            f.event.outputs[0].utxo_hash
        );
    }

    #[test]
    fn sidecar_operation_commitment_matches_event() {
        let f = fixture();
        assert_eq!(f.sidecar.operation_commitment, f.operation_commitment);
        assert_eq!(f.operation_commitment, f.event.operation_commitment);
        assert_eq!(f.sidecar.payloads.len(), f.event.outputs.len());
    }

    #[test]
    fn sidecar_plaintext_hash_matches_utxo_hash() {
        let f = fixture();
        let recomputed = utxo_hash_for_payload(&f.sidecar.payloads[0]).unwrap();
        assert_eq!(recomputed, f.event.outputs[0].utxo_hash);
    }

    #[test]
    fn sidecar_round_trips_through_borsh() {
        let f = fixture();
        let bytes = encode_sidecar(&f.sidecar);
        let decoded: FixturePlaintextSidecar =
            FixturePlaintextSidecar::try_from_slice(&bytes).expect("decode sidecar");
        assert_eq!(decoded, f.sidecar);
    }
}
