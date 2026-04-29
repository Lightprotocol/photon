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
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use solana_signature::Signature;

use crate::ingester::parser::shielded_pool_events::{
    EncryptedTxEphemeralKey, EncryptedTxEphemeralKeyRole, FixturePlaintextPayload,
    FixturePlaintextSidecar, ShieldedPoolTxEvent, ShieldedPoolTxKind, ShieldedPublicDelta,
    ShieldedUtxoOutputEvent, SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR,
    SHIELDED_POOL_TX_EVENT_VERSION,
};
use crate::ingester::parser::{NOOP_PROGRAM_ID, SHIELDED_POOL_PROGRAM_ID};
use crate::ingester::typedefs::block_info::{Instruction, InstructionGroup, TransactionInfo};

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
                utxo_hash,
                utxo_tree: None,
                leaf_index: None,
                tree_sequence: None,
                encrypted_utxo,
                encrypted_utxo_hash,
                fmd_clue: None,
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

        // Build a TransactionInfo whose only instruction group is a
        // shielded-pool outer instruction carrying a Noop CPI with event
        // bytes. The parser must reject identical Noop bytes from unrelated
        // outer programs, so fixtures use the same allowlisted emitter as
        // production config.
        let outer = Instruction {
            program_id: SHIELDED_POOL_PROGRAM_ID,
            data: vec![],
            accounts: vec![],
        };
        let inner = Instruction {
            program_id: NOOP_PROGRAM_ID,
            data: event_bytes,
            accounts: vec![],
        };
        let transaction_info = TransactionInfo {
            instruction_groups: vec![InstructionGroup {
                outer_instruction: outer,
                inner_instructions: vec![inner],
            }],
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
        let state_update = parse_shielded_pool_events(
            &f.transaction_info.instruction_groups[0],
            Signature::default(),
            100,
            &[SHIELDED_POOL_PROGRAM_ID],
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
