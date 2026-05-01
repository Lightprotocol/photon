//! Test-only emitter for the zoned shielded-pool transaction event.
//!
//! The implementation plan calls for a local/dev emitter that
//! produces canonical `ShieldedPoolTxEvent` Borsh bytes wrapped in a Noop CPI,
//! together with a fixture-only plaintext sidecar Zone RPC can project. This
//! module is the in-process equivalent: it builds a captured proofless-append
//! transaction shape and converts it to the `TransactionInfo` Photon ingests.
//!
//! The helpers are public so the e2e test in photon and a sibling Zone RPC
//! crate can both reuse them. They live under `parser/` to keep the canonical
//! event format and its emitter side-by-side; if the format changes, the
//! emitter and parser are updated in lockstep.

use ark_bn254::Fr;
use borsh::BorshSerialize;
use light_compressed_account::{
    compressed_account::{CompressedAccount, CompressedAccountData},
    constants::{LIGHT_SYSTEM_PROGRAM_ID, REGISTERED_PROGRAM_PDA},
    discriminators::{DISCRIMINATOR_INSERT_INTO_QUEUES, DISCRIMINATOR_INVOKE_CPI},
    hash_to_bn254_field_size_be,
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
use serde::Deserialize;
use solana_pubkey::{pubkey, Pubkey};
use solana_signature::Signature;
use std::str::FromStr;

use crate::ingester::parser::indexer_events::{BatchEvent, MerkleTreeEvent};
use crate::ingester::parser::shielded_pool_events::{
    EncryptedTxEphemeralKey, EncryptedTxEphemeralKeyRole, FixturePlaintextPayload,
    FixturePlaintextSidecar, ShieldedNullifierEvent, ShieldedPoolTxEvent, ShieldedPoolTxKind,
    ShieldedPublicDelta, ShieldedUtxoOutputEvent, SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR,
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
const FIXTURE_COMPRESSED_ACCOUNT_DISCRIMINATOR: [u8; 8] = *b"shldutx1";
#[cfg(test)]
const FIXTURE_LOCAL_DEV_TOKEN_MINT: [u8; 32] = [0xBB; 32];
#[cfg(test)]
const FIXTURE_LOCAL_DEV_SPL_AMOUNT: u64 = 1_000_000;
#[cfg(test)]
const FIXTURE_LOCAL_DEV_SOL_AMOUNT: u64 = 42;
#[cfg(test)]
const FIXTURE_LOCAL_DEV_BLINDING: [u8; 32] = [0xCC; 32];
#[cfg(test)]
const FIXTURE_LOCAL_DEV_DATA_HASH: [u8; 32] = [
    23, 250, 137, 116, 255, 248, 202, 19, 117, 168, 19, 69, 127, 63, 120, 252, 52, 212, 235, 217,
    34, 186, 148, 18, 11, 14, 103, 173, 44, 236, 230, 182,
];
#[cfg(test)]
const FIXTURE_LOCAL_DEV_UTXO_HASH: [u8; 32] = [
    18, 201, 110, 230, 164, 92, 38, 97, 172, 235, 207, 8, 168, 161, 179, 51, 28, 52, 63, 194, 103,
    151, 206, 208, 244, 144, 246, 250, 33, 155, 4, 22,
];
#[cfg(test)]
const FIXTURE_LOCAL_DEV_ENCRYPTED_UTXO_HASH: [u8; 32] = [
    35, 235, 97, 155, 138, 208, 6, 8, 152, 164, 238, 115, 103, 109, 40, 186, 70, 93, 26, 111, 184,
    189, 241, 92, 17, 145, 202, 78, 85, 61, 124, 210,
];
const FIXTURE_MASP_PROGRAM_ID: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x10,
];
const FIXTURE_MASP_INPUT_SEED: u64 = 0x1001;
const FIXTURE_MASP_OUTPUT_SEED: u64 = 0x5001;

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
pub struct CapturedShieldedPoolFixture {
    pub event: ShieldedPoolTxEvent,
    pub sidecar: FixturePlaintextSidecar,
    pub captured_transaction: CapturedProoflessAppendTransaction,
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

/// Semantic representation of the local/program-test proofless append shape.
///
/// This is intentionally not just `TransactionInfo`: each field names the
/// instruction position the live transaction must contain. Tests assert this
/// shape before converting it into Photon parser input, which prevents the
/// fixture from silently drifting away from the program-test path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedProoflessAppendTransaction {
    pub signature: Signature,
    pub shielded_program_instruction: Instruction,
    pub light_system_instruction: Instruction,
    pub system_instruction: Instruction,
    pub account_compression_instruction: Instruction,
    pub shielded_event_noop_instruction: Instruction,
    pub batch_append_instruction: Instruction,
    pub batch_append_noop_instruction: Instruction,
}

impl CapturedProoflessAppendTransaction {
    pub fn to_transaction_info(&self) -> TransactionInfo {
        TransactionInfo {
            instruction_groups: vec![
                InstructionGroup {
                    outer_instruction: self.shielded_program_instruction.clone(),
                    inner_instructions: vec![
                        self.light_system_instruction.clone(),
                        self.system_instruction.clone(),
                        self.account_compression_instruction.clone(),
                        self.shielded_event_noop_instruction.clone(),
                    ],
                },
                InstructionGroup {
                    outer_instruction: self.batch_append_instruction.clone(),
                    inner_instructions: vec![self.batch_append_noop_instruction.clone()],
                },
            ],
            signature: self.signature,
            error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedProoflessSpendTransaction {
    pub signature: Signature,
    pub shielded_program_instruction: Instruction,
    pub light_system_instruction: Instruction,
    pub system_instruction: Instruction,
    pub account_compression_instruction: Instruction,
    pub shielded_event_noop_instruction: Instruction,
    pub nullifier_event_noop_instructions: Vec<Instruction>,
}

impl CapturedProoflessSpendTransaction {
    pub fn to_transaction_info(&self) -> TransactionInfo {
        let mut inner_instructions =
            Vec::with_capacity(4 + self.nullifier_event_noop_instructions.len());
        inner_instructions.push(self.light_system_instruction.clone());
        inner_instructions.push(self.system_instruction.clone());
        inner_instructions.push(self.account_compression_instruction.clone());
        inner_instructions.push(self.shielded_event_noop_instruction.clone());
        inner_instructions.extend(self.nullifier_event_noop_instructions.clone());
        TransactionInfo {
            instruction_groups: vec![InstructionGroup {
                outer_instruction: self.shielded_program_instruction.clone(),
                inner_instructions,
            }],
            signature: self.signature,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProoflessAppendCaptureSnapshot {
    pub schema_version: u32,
    pub source: String,
    pub transaction: ProoflessAppendCapturedTransactionSnapshot,
    pub expected: ProoflessAppendCaptureExpected,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProoflessAppendCapturedTransactionSnapshot {
    pub shielded_program_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub light_system_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub system_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub account_compression_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub shielded_event_noop_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub batch_append_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub batch_append_noop_instruction: ProoflessAppendCapturedInstructionSnapshot,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProoflessAppendCapturedInstructionSnapshot {
    pub name: String,
    pub program_id: String,
    pub data: String,
    pub accounts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProoflessAppendCaptureExpected {
    pub zone_config_hash: String,
    pub operation_commitment: String,
    pub data_hash: String,
    pub utxo_hash: String,
    pub encrypted_utxo_hash: String,
    pub compressed_account_hash: String,
    pub utxo_tree: String,
    pub output_queue: String,
    pub output_leaf_index: u32,
    pub tree_sequence: u64,
    pub batch_append_sequence: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProoflessSpendCaptureSnapshot {
    pub schema_version: u32,
    pub source: String,
    pub transaction: ProoflessSpendCapturedTransactionSnapshot,
    pub expected: ProoflessSpendCaptureExpected,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProoflessSpendCapturedTransactionSnapshot {
    pub shielded_program_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub light_system_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub system_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub account_compression_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub shielded_event_noop_instruction: ProoflessAppendCapturedInstructionSnapshot,
    pub nullifier_event_noop_instructions: Vec<ProoflessAppendCapturedInstructionSnapshot>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProoflessSpendCaptureExpected {
    pub zone_config_hash: String,
    pub operation_commitment: String,
    pub utxo_hash: String,
    pub utxo_leaf_index: u64,
    pub spend_nullifier: String,
    pub nullifier_chain: String,
    pub nullifier_tree: String,
}

impl ProoflessAppendCaptureSnapshot {
    pub fn from_json_str(input: &str) -> Result<Self, String> {
        let snapshot = serde_json::from_str::<Self>(input)
            .map_err(|err| format!("decode proofless append capture: {err}"))?;
        if snapshot.schema_version != 1 {
            return Err(format!(
                "unsupported proofless append capture schema {}",
                snapshot.schema_version
            ));
        }
        Ok(snapshot)
    }

    pub fn to_captured_transaction(
        &self,
        signature: Signature,
    ) -> Result<CapturedProoflessAppendTransaction, String> {
        Ok(CapturedProoflessAppendTransaction {
            signature,
            shielded_program_instruction: self
                .transaction
                .shielded_program_instruction
                .to_instruction()?,
            light_system_instruction: self.transaction.light_system_instruction.to_instruction()?,
            system_instruction: self.transaction.system_instruction.to_instruction()?,
            account_compression_instruction: self
                .transaction
                .account_compression_instruction
                .to_instruction()?,
            shielded_event_noop_instruction: self
                .transaction
                .shielded_event_noop_instruction
                .to_instruction()?,
            batch_append_instruction: self.transaction.batch_append_instruction.to_instruction()?,
            batch_append_noop_instruction: self
                .transaction
                .batch_append_noop_instruction
                .to_instruction()?,
        })
    }
}

impl ProoflessSpendCaptureSnapshot {
    pub fn from_json_str(input: &str) -> Result<Self, String> {
        let snapshot = serde_json::from_str::<Self>(input)
            .map_err(|err| format!("decode proofless spend capture: {err}"))?;
        if snapshot.schema_version != 1 {
            return Err(format!(
                "unsupported proofless spend capture schema {}",
                snapshot.schema_version
            ));
        }
        Ok(snapshot)
    }

    pub fn to_captured_transaction(
        &self,
        signature: Signature,
    ) -> Result<CapturedProoflessSpendTransaction, String> {
        let nullifier_event_noop_instructions = self
            .transaction
            .nullifier_event_noop_instructions
            .iter()
            .map(|instruction| instruction.to_instruction())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CapturedProoflessSpendTransaction {
            signature,
            shielded_program_instruction: self
                .transaction
                .shielded_program_instruction
                .to_instruction()?,
            light_system_instruction: self.transaction.light_system_instruction.to_instruction()?,
            system_instruction: self.transaction.system_instruction.to_instruction()?,
            account_compression_instruction: self
                .transaction
                .account_compression_instruction
                .to_instruction()?,
            shielded_event_noop_instruction: self
                .transaction
                .shielded_event_noop_instruction
                .to_instruction()?,
            nullifier_event_noop_instructions,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        let captured_transaction = self.to_captured_transaction(Signature::default())?;
        let tx_event = ShieldedPoolTxEvent::from_event_bytes(
            &captured_transaction.shielded_event_noop_instruction.data,
        )
        .map_err(|err| format!("decode proofless spend tx event: {err}"))?;
        if hex_0x(
            &tx_event
                .zone_config_hash
                .ok_or("spend event must be zoned")?,
        ) != self.expected.zone_config_hash
        {
            return Err("spend event zone_config_hash does not match capture expected".to_string());
        }
        if hex_0x(&tx_event.operation_commitment) != self.expected.operation_commitment {
            return Err(
                "spend event operation_commitment does not match capture expected".to_string(),
            );
        }
        if tx_event.outputs.len() != 0 {
            return Err("proofless spend capture must not create outputs".to_string());
        }
        if tx_event.input_nullifiers.len() != 1 {
            return Err(format!(
                "proofless spend capture expected one input nullifier, got {}",
                tx_event.input_nullifiers.len()
            ));
        }
        if hex_0x(&tx_event.input_nullifiers[0]) != self.expected.spend_nullifier {
            return Err("spend tx input nullifier does not match capture expected".to_string());
        }
        if hex_0x(
            &tx_event
                .nullifier_chain
                .ok_or("spend event needs nullifier_chain")?,
        ) != self.expected.nullifier_chain
        {
            return Err("spend tx nullifier_chain does not match capture expected".to_string());
        }

        if captured_transaction.nullifier_event_noop_instructions.len() != 1 {
            return Err(format!(
                "proofless spend capture expected one nullifier event, got {}",
                captured_transaction.nullifier_event_noop_instructions.len()
            ));
        }
        let nullifier_event = ShieldedNullifierEvent::from_event_bytes(
            &captured_transaction.nullifier_event_noop_instructions[0].data,
        )
        .map_err(|err| format!("decode proofless spend nullifier event: {err}"))?;
        if hex_0x(&nullifier_event.nullifier) != self.expected.spend_nullifier {
            return Err("nullifier event value does not match capture expected".to_string());
        }
        if hex_0x(&nullifier_event.nullifier_tree) != self.expected.nullifier_tree {
            return Err("nullifier event tree does not match capture expected".to_string());
        }
        Ok(())
    }
}

impl ProoflessAppendCapturedInstructionSnapshot {
    fn to_instruction(&self) -> Result<Instruction, String> {
        Ok(Instruction {
            program_id: parse_pubkey(&self.program_id)?,
            data: decode_hex_0x(&self.data)?,
            accounts: self
                .accounts
                .iter()
                .map(|account| parse_pubkey(account))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
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

    pub fn build(self) -> CapturedShieldedPoolFixture {
        // Domain tag is a small constant — safe in BN254 Fr.
        let domain: u8 = 0;
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
            let owner_hash = fixture_masp_program_owner_hash();
            let data_hash = fixture_masp_data_hash(owner.token_mint, self.zone_config_hash)
                .expect("fixture data_hash");
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
            // Canonical local/dev UTXO commitment: the same MASP UtxoHash
            // currently constrained by prover/server. Zone/token context is
            // bound through data_hash for this fixture.
            let utxo_hash = utxo_hash_for_payload(&payload).expect("utxo_hash");

            // Encrypted ciphertext is placeholder bytes. The plan explicitly does
            // not require real encryption for the first vertical slice;
            // Photon stores the bytes verbatim and Zone RPC reads the
            // sidecar plaintext rather than decrypting.
            let mut encrypted_utxo = Vec::with_capacity(64);
            encrypted_utxo.extend_from_slice(&[0xC1, 0xC2, 0xC3, idx as u8]);
            encrypted_utxo.extend_from_slice(&utxo_hash); // 32 bytes of "ciphertext"
            encrypted_utxo.extend_from_slice(&[0u8; 28]); // padding to 64 bytes

            // Placeholder ciphertext hash. Production will compute a real digest of
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

        let captured_transaction =
            captured_proofless_append_transaction(self.signature, &event, event_bytes);
        let transaction_info = captured_transaction.to_transaction_info();

        CapturedShieldedPoolFixture {
            event,
            sidecar,
            captured_transaction,
            transaction_info,
            operation_commitment,
        }
    }

    pub fn build_with_captured_transaction(
        self,
        captured_transaction: CapturedProoflessAppendTransaction,
    ) -> Result<CapturedShieldedPoolFixture, String> {
        let base = self.build();
        let captured_event = ShieldedPoolTxEvent::from_event_bytes(
            &captured_transaction.shielded_event_noop_instruction.data,
        )
        .map_err(|err| format!("decode captured shielded event: {err}"))?;
        validate_captured_event_matches_sidecar(&captured_event, &base.sidecar)?;
        let operation_commitment = captured_event.operation_commitment;
        let transaction_info = captured_transaction.to_transaction_info();

        Ok(CapturedShieldedPoolFixture {
            event: captured_event,
            sidecar: base.sidecar,
            captured_transaction,
            transaction_info,
            operation_commitment,
        })
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

pub fn fixture_light_account_owner_hash() -> [u8; 32] {
    hash_to_bn254_field_size_be(&SHIELDED_POOL_TEST_PROGRAM_ID.to_bytes())
}

pub fn fixture_light_account_tree_hash() -> [u8; 32] {
    hash_to_bn254_field_size_be(&FIXTURE_UTXO_TREE)
}

pub fn fixture_light_account_discriminator() -> [u8; 8] {
    FIXTURE_COMPRESSED_ACCOUNT_DISCRIMINATOR
}

pub fn fixture_masp_program_id() -> [u8; 32] {
    FIXTURE_MASP_PROGRAM_ID
}

pub fn fixture_masp_input_seed() -> u64 {
    FIXTURE_MASP_INPUT_SEED
}

pub fn fixture_masp_output_seed() -> u64 {
    FIXTURE_MASP_OUTPUT_SEED
}

pub fn captured_proofless_append_transaction(
    signature: Signature,
    event: &ShieldedPoolTxEvent,
    event_bytes: Vec<u8>,
) -> CapturedProoflessAppendTransaction {
    let output_accounts = light_fixture_output_accounts(event);
    CapturedProoflessAppendTransaction {
        signature,
        shielded_program_instruction: Instruction {
            program_id: SHIELDED_POOL_TEST_PROGRAM_ID,
            data: vec![],
            accounts: vec![],
        },
        light_system_instruction: Instruction {
            program_id: Pubkey::new_from_array(LIGHT_SYSTEM_PROGRAM_ID),
            data: light_invoke_cpi_instruction_data(output_accounts),
            accounts: light_system_accounts(),
        },
        system_instruction: Instruction {
            program_id: pubkey!("11111111111111111111111111111111"),
            data: vec![0; 12],
            accounts: vec![],
        },
        account_compression_instruction: Instruction {
            program_id: get_compression_program_id(),
            data: insert_into_queues_instruction_data(event),
            accounts: account_compression_accounts(),
        },
        shielded_event_noop_instruction: Instruction {
            program_id: NOOP_PROGRAM_ID,
            data: event_bytes,
            accounts: vec![],
        },
        batch_append_instruction: Instruction {
            program_id: get_compression_program_id(),
            data: vec![],
            accounts: vec![Pubkey::new_from_array(FIXTURE_UTXO_TREE)],
        },
        batch_append_noop_instruction: Instruction {
            program_id: NOOP_PROGRAM_ID,
            data: batch_append_event_data(event.outputs.len()),
            accounts: vec![],
        },
    }
}

fn validate_captured_event_matches_sidecar(
    event: &ShieldedPoolTxEvent,
    sidecar: &FixturePlaintextSidecar,
) -> Result<(), String> {
    if event.operation_commitment != sidecar.operation_commitment {
        return Err("captured event operation_commitment does not match sidecar".to_string());
    }
    if event.outputs.len() != sidecar.payloads.len() {
        return Err(format!(
            "captured event output count {} does not match sidecar payload count {}",
            event.outputs.len(),
            sidecar.payloads.len()
        ));
    }
    for (output, payload) in event.outputs.iter().zip(sidecar.payloads.iter()) {
        let recomputed = utxo_hash_for_payload(payload)?;
        if output.utxo_hash != recomputed {
            return Err(format!(
                "captured output {} utxo_hash does not match sidecar plaintext",
                output.output_index
            ));
        }
    }
    Ok(())
}

fn parse_pubkey(value: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(value).map_err(|err| format!("invalid pubkey {value}: {err}"))
}

fn decode_hex_0x(value: &str) -> Result<Vec<u8>, String> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(hex).map_err(|err| format!("invalid hex value: {err}"))
}

fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn light_fixture_output_accounts(
    event: &ShieldedPoolTxEvent,
) -> Vec<LightOutputCompressedAccountWithPackedContext> {
    event
        .outputs
        .iter()
        .map(|output| LightOutputCompressedAccountWithPackedContext {
            compressed_account: light_fixture_compressed_account(&output.utxo_hash),
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
    let leaf_index = FIXTURE_LEAF_INDEX_BASE + output_index as u32;
    light_fixture_compressed_account(utxo_hash)
        .hash(&LightPubkey::from(FIXTURE_UTXO_TREE), &leaf_index, true)
        .expect("fixture compressed account hash")
}

fn light_fixture_compressed_account(utxo_hash: &[u8; 32]) -> CompressedAccount {
    CompressedAccount {
        owner: LightPubkey::from(SHIELDED_POOL_TEST_PROGRAM_ID.to_bytes()),
        lamports: 0,
        address: None,
        data: Some(CompressedAccountData {
            discriminator: FIXTURE_COMPRESSED_ACCOUNT_DISCRIMINATOR,
            data: Vec::new(),
            data_hash: *utxo_hash,
        }),
    }
}

/// Compute the canonical UTXO commitment over the plaintext fields. This
/// hash is what `ShieldedUtxoOutputEvent.utxo_hash` must equal, and what the
/// Zone RPC projection re-checks. Inputs are reduced into BN254 Fr (top
/// byte cleared) since light-poseidon rejects out-of-field bytes.
pub fn utxo_hash_for_payload(payload: &FixturePlaintextPayload) -> Result<[u8; 32], String> {
    utxo_hash_for_payload_fields(payload)
}

fn utxo_hash_for_payload_fields(payload: &FixturePlaintextPayload) -> Result<[u8; 32], String> {
    let mut domain_bytes = [0u8; 32];
    domain_bytes[31] = payload.domain;
    let blinding_field = clear_top_byte(payload.blinding);
    let spl_bytes = u128_to_be_32(payload.spl_amount as u128);
    let sol_bytes = u128_to_be_32(payload.sol_amount as u128);
    poseidon_hash(&[
        &domain_bytes,
        &payload.owner_hash,
        &spl_bytes,
        &sol_bytes,
        &blinding_field,
        &payload.data_hash,
    ])
}

fn fixture_masp_program_owner_hash() -> [u8; 32] {
    let seed = u128_to_be_32(FIXTURE_MASP_INPUT_SEED as u128);
    poseidon_hash(&[&FIXTURE_MASP_PROGRAM_ID, &seed]).expect("fixture MASP program owner hash")
}

fn fixture_masp_data_hash(
    token_mint: [u8; 32],
    zone_config_hash: [u8; 32],
) -> Result<[u8; 32], String> {
    let token_mint_field = clear_top_byte(token_mint);
    let zone_field = clear_top_byte(zone_config_hash);
    poseidon_hash(&[&token_mint_field, &zone_field])
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

    fn fixture() -> CapturedShieldedPoolFixture {
        let owner = FixtureOwnerSpec {
            owner_pubkey: [0xAA; 32],
            token_mint: FIXTURE_LOCAL_DEV_TOKEN_MINT,
            spl_amount: FIXTURE_LOCAL_DEV_SPL_AMOUNT,
            sol_amount: FIXTURE_LOCAL_DEV_SOL_AMOUNT,
            blinding: FIXTURE_LOCAL_DEV_BLINDING,
        };
        FixtureBuilder::proofless_shield_one_output(Signature::default(), owner).build()
    }

    #[test]
    fn captured_event_round_trips_through_parser() {
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
    fn captured_proofless_append_shape_matches_program_test_order() {
        let f = fixture();
        assert_eq!(
            f.captured_transaction.to_transaction_info(),
            f.transaction_info
        );

        let first_group = &f.transaction_info.instruction_groups[0];
        assert_eq!(
            first_group.outer_instruction.program_id,
            SHIELDED_POOL_TEST_PROGRAM_ID
        );
        let first_group_programs = first_group
            .inner_instructions
            .iter()
            .map(|instruction| instruction.program_id)
            .collect::<Vec<_>>();
        assert_eq!(
            first_group_programs,
            vec![
                Pubkey::new_from_array(LIGHT_SYSTEM_PROGRAM_ID),
                pubkey!("11111111111111111111111111111111"),
                get_compression_program_id(),
                NOOP_PROGRAM_ID,
            ]
        );

        let decoded_event = ShieldedPoolTxEvent::from_event_bytes(
            &f.captured_transaction.shielded_event_noop_instruction.data,
        )
        .expect("decode captured shielded event");
        assert_eq!(decoded_event.zone_config_hash, f.event.zone_config_hash);
        assert_eq!(
            decoded_event.outputs[0].utxo_hash,
            FIXTURE_LOCAL_DEV_UTXO_HASH
        );
        assert_eq!(
            decoded_event.outputs[0].encrypted_utxo_hash,
            FIXTURE_LOCAL_DEV_ENCRYPTED_UTXO_HASH
        );

        let second_group = &f.transaction_info.instruction_groups[1];
        assert_eq!(
            second_group.outer_instruction.program_id,
            get_compression_program_id()
        );
        assert_eq!(
            second_group.outer_instruction.accounts,
            vec![Pubkey::new_from_array(FIXTURE_UTXO_TREE)]
        );
        assert_eq!(second_group.inner_instructions.len(), 1);
        assert_eq!(
            second_group.inner_instructions[0].program_id,
            NOOP_PROGRAM_ID
        );
        match MerkleTreeEvent::try_from_slice(&second_group.inner_instructions[0].data)
            .expect("decode captured batch append event")
        {
            MerkleTreeEvent::BatchAppend(batch) => {
                assert_eq!(batch.merkle_tree_pubkey, FIXTURE_UTXO_TREE);
                assert_eq!(batch.old_next_index, FIXTURE_LEAF_INDEX_BASE as u64);
                assert_eq!(batch.new_next_index, 1);
                assert_eq!(batch.sequence_number, FIXTURE_TREE_SEQUENCE);
            }
            other => panic!("expected batch append event, got {:?}", other),
        }
    }

    #[test]
    fn program_test_capture_snapshot_parses_through_photon_loader() {
        let snapshot = ProoflessAppendCaptureSnapshot::from_json_str(include_str!(
            "../../../tests/fixtures/shielded_pool_proofless_append_capture.json"
        ))
        .expect("decode program-test capture snapshot");
        assert_eq!(
            snapshot.source,
            "program-tests/system-cpi-v2-test/proofless_shielded_append_emits_light_and_shielded_events"
        );

        let owner = FixtureOwnerSpec {
            owner_pubkey: [0xAA; 32],
            token_mint: FIXTURE_LOCAL_DEV_TOKEN_MINT,
            spl_amount: FIXTURE_LOCAL_DEV_SPL_AMOUNT,
            sol_amount: FIXTURE_LOCAL_DEV_SOL_AMOUNT,
            blinding: FIXTURE_LOCAL_DEV_BLINDING,
        };
        let captured_transaction = snapshot
            .to_captured_transaction(Signature::default())
            .expect("convert program-test capture to Photon transaction");
        let f = FixtureBuilder::proofless_shield_one_output(Signature::default(), owner)
            .build_with_captured_transaction(captured_transaction)
            .expect("captured program-test event should match local sidecar");
        assert_eq!(
            snapshot.expected.utxo_hash,
            hex_0x(&f.event.outputs[0].utxo_hash)
        );
        assert_eq!(
            snapshot.expected.encrypted_utxo_hash,
            hex_0x(&f.event.outputs[0].encrypted_utxo_hash)
        );
        assert_eq!(
            snapshot.expected.operation_commitment,
            hex_0x(&f.event.operation_commitment)
        );

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
            .expect("program-test capture should parse through Light v2 parser");
        assert_eq!(public_events.len(), 1);
        let public_event = &public_events[0].event;
        assert_eq!(
            public_event.output_leaf_indices,
            vec![snapshot.expected.output_leaf_index]
        );
        assert_eq!(
            public_event.sequence_numbers[0].seq,
            snapshot.expected.tree_sequence
        );
        assert_eq!(
            hex_0x(&public_event.output_compressed_account_hashes[0]),
            snapshot.expected.compressed_account_hash
        );
        let compressed_data = public_event.output_compressed_accounts[0]
            .compressed_account
            .data
            .as_ref()
            .expect("captured output must have UTXO data hash");
        assert_eq!(
            hex_0x(&compressed_data.data_hash),
            snapshot.expected.utxo_hash
        );

        let contexts = vec![CompressedOutputContextRecord {
            compressed_output_index: 0,
            compressed_account_hash: public_event.output_compressed_account_hashes[0],
            tree: parse_pubkey(&snapshot.expected.utxo_tree).expect("snapshot UTXO tree pubkey"),
            leaf_index: snapshot.expected.output_leaf_index as u64,
            tree_sequence: snapshot.expected.tree_sequence,
            data_hash: Some(compressed_data.data_hash),
        }];
        let shielded_update = parse_shielded_pool_events(
            group,
            f.transaction_info.signature,
            100,
            &[SHIELDED_POOL_TEST_PROGRAM_ID],
            &contexts,
        );
        assert_eq!(shielded_update.shielded_tx_events.len(), 1);
        assert_eq!(shielded_update.shielded_outputs.len(), 1);
        let output = &shielded_update.shielded_outputs[0];
        assert_eq!(hex_0x(&output.utxo_hash), snapshot.expected.utxo_hash);
        assert_eq!(
            hex_0x(&output.compressed_account_hash),
            snapshot.expected.compressed_account_hash
        );
        assert_eq!(
            output.leaf_index,
            snapshot.expected.output_leaf_index as u64
        );
        assert_eq!(output.tree_sequence, snapshot.expected.tree_sequence);

        let batch_group = &f.transaction_info.instruction_groups[1];
        match MerkleTreeEvent::try_from_slice(&batch_group.inner_instructions[0].data)
            .expect("decode program-test generated batch append event")
        {
            MerkleTreeEvent::BatchAppend(batch) => {
                assert_eq!(
                    Pubkey::new_from_array(batch.merkle_tree_pubkey).to_string(),
                    snapshot.expected.utxo_tree
                );
                assert_eq!(
                    batch.old_next_index,
                    snapshot.expected.output_leaf_index as u64
                );
                assert_eq!(
                    batch.new_next_index,
                    snapshot.expected.output_leaf_index as u64 + 1
                );
                assert_eq!(
                    batch.sequence_number,
                    snapshot.expected.batch_append_sequence
                );
                assert_eq!(
                    batch
                        .output_queue_pubkey
                        .map(|pubkey| Pubkey::new_from_array(pubkey).to_string()),
                    Some(snapshot.expected.output_queue.clone())
                );
            }
            other => panic!("expected batch append event, got {:?}", other),
        }
    }

    #[test]
    fn program_test_spend_capture_snapshot_parses_through_photon_loader() {
        let snapshot = ProoflessSpendCaptureSnapshot::from_json_str(include_str!(
            "../../../tests/fixtures/shielded_pool_proofless_spend_capture.json"
        ))
        .expect("decode program-test spend capture snapshot");
        assert_eq!(
            snapshot.source,
            "program-tests/system-cpi-v2-test/proofless_shielded_spend_emits_shielded_nullifier_events"
        );
        snapshot
            .validate()
            .expect("program-test spend capture should be internally consistent");

        let captured_transaction = snapshot
            .to_captured_transaction(Signature::default())
            .expect("convert program-test spend capture to Photon transaction");
        let transaction_info = captured_transaction.to_transaction_info();
        let group = &transaction_info.instruction_groups[0];
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
            .expect("program-test spend capture should parse through Light v2 parser");
        assert_eq!(public_events.len(), 1);
        assert_eq!(public_events[0].event.output_compressed_accounts.len(), 0);
        assert_eq!(public_events[0].new_addresses.len(), 1);
        assert_eq!(
            hex_0x(public_events[0].new_addresses[0].mt_pubkey.array_ref()),
            snapshot.expected.nullifier_tree
        );

        let shielded_update = parse_shielded_pool_events(
            group,
            transaction_info.signature,
            101,
            &[SHIELDED_POOL_TEST_PROGRAM_ID],
            &[],
        );
        assert_eq!(shielded_update.shielded_tx_events.len(), 1);
        assert_eq!(shielded_update.shielded_outputs.len(), 0);
        assert_eq!(shielded_update.shielded_nullifier_events.len(), 1);

        let tx_event = &shielded_update.shielded_tx_events[0];
        assert_eq!(tx_event.tx_kind, ShieldedPoolTxKind::Transact);
        assert_eq!(
            tx_event
                .zone_config_hash
                .map(|zone_hash| hex_0x(&zone_hash)),
            Some(snapshot.expected.zone_config_hash.clone())
        );
        assert_eq!(
            tx_event
                .nullifier_chain
                .map(|nullifier_chain| hex_0x(&nullifier_chain)),
            Some(snapshot.expected.nullifier_chain.clone())
        );
        assert_eq!(
            tx_event
                .input_nullifiers
                .iter()
                .map(|nullifier| hex_0x(nullifier))
                .collect::<Vec<_>>(),
            vec![snapshot.expected.spend_nullifier.clone()]
        );

        let nullifier_event = &shielded_update.shielded_nullifier_events[0];
        assert_eq!(
            hex_0x(&nullifier_event.nullifier),
            snapshot.expected.spend_nullifier
        );
        assert_eq!(
            hex_0x(&nullifier_event.nullifier_tree),
            snapshot.expected.nullifier_tree
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
    fn local_dev_shielded_utxo_vector_is_pinned() {
        let f = fixture();
        let payload = &f.sidecar.payloads[0];
        let output = &f.event.outputs[0];
        assert_eq!(payload.data_hash, FIXTURE_LOCAL_DEV_DATA_HASH);
        assert_eq!(output.utxo_hash, FIXTURE_LOCAL_DEV_UTXO_HASH);
        assert_eq!(
            output.encrypted_utxo_hash,
            FIXTURE_LOCAL_DEV_ENCRYPTED_UTXO_HASH
        );
    }

    #[test]
    fn sidecar_round_trips_through_borsh() {
        let f = fixture();
        let bytes = encode_sidecar(&f.sidecar);
        let decoded: FixturePlaintextSidecar =
            FixturePlaintextSidecar::try_from_slice(&bytes).expect("decode sidecar");
        assert_eq!(decoded, f.sidecar);
    }

    fn hex_0x(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }
}
