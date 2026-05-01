//! Local/dev MASP verifier-instruction checks.
//!
//! The production verifier will be an on-chain program. This module gives the
//! PoC the same boundary locally: decode the relayer instruction data,
//! reconstruct MASP public-input hashes with the circuit's right-fold Poseidon
//! hashchain, and verify the roots carried by the TreeProof preimage.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::zone_rpc::local_relayer::{
    LocalRelayerRootContext, LocalTransactionCandidate, LocalVerifierInstructionData,
    LOCAL_VERIFIER_INSTRUCTION_TAG, LOCAL_VERIFIER_INSTRUCTION_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalVerifierError {
    Validation(String),
    Serialization(String),
    Hashing(String),
}

impl fmt::Display for LocalVerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(err) => write!(f, "local/dev verifier validation error: {err}"),
            Self::Serialization(err) => write!(f, "local/dev verifier serialization error: {err}"),
            Self::Hashing(err) => write!(f, "local/dev verifier hash error: {err}"),
        }
    }
}

impl Error for LocalVerifierError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalVerifierCheckResult {
    pub status: String,
    pub utxo_public_inputs_hash: String,
    pub tree_public_inputs_hash: String,
    pub utxo_tree_id: String,
    pub utxo_root: String,
    pub utxo_root_index: u64,
    pub utxo_root_sequence: u64,
    pub nullifier_tree_id: String,
    pub nullifier_root: String,
    pub nullifier_root_index: u64,
    pub nullifier_root_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaspUtxoVerifierInputs {
    pub sha_tx_hash: String,
    pub program_id_hashchain: String,
    pub seeds_hashchain: String,
    pub tx_hash: String,
    pub nullifier_chain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaspTreeVerifierInputs {
    pub state_roots: Vec<String>,
    pub nullifier_roots: Vec<String>,
    pub nullifiers: Vec<String>,
    pub account_owner_hash: Vec<String>,
    pub account_tree_hash: Vec<String>,
    pub account_discriminator: Vec<String>,
}

pub fn verifier_inputs_from_masp_payload(
    circuit_type: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, LocalVerifierError> {
    let payload_circuit_type = payload
        .get("circuitType")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            LocalVerifierError::Validation("MASP payload missing circuitType".to_string())
        })?;
    if payload_circuit_type != circuit_type {
        return Err(LocalVerifierError::Validation(format!(
            "MASP payload circuitType {payload_circuit_type} does not match {circuit_type}"
        )));
    }
    let witness = payload.get("localWitness").ok_or_else(|| {
        LocalVerifierError::Validation(format!(
            "{circuit_type} payload missing localWitness verifier preimage"
        ))
    })?;

    match circuit_type {
        "masp-utxo" => serde_json::to_value(MaspUtxoVerifierInputs {
            sha_tx_hash: required_string(witness, "shaTxHash")?,
            program_id_hashchain: required_string(witness, "programIdHashchain")?,
            seeds_hashchain: required_string(witness, "seedsHashchain")?,
            tx_hash: required_string(witness, "txHash")?,
            nullifier_chain: required_string(witness, "nullifierChain")?,
        })
        .map_err(|err| LocalVerifierError::Serialization(err.to_string())),
        "masp-tree" => serde_json::to_value(MaspTreeVerifierInputs {
            state_roots: required_string_array(witness, "stateRoots")?,
            nullifier_roots: required_string_array(witness, "nullifierRoots")?,
            nullifiers: required_string_array(witness, "nullifiers")?,
            account_owner_hash: required_string_array(witness, "accountOwnerHash")?,
            account_tree_hash: required_string_array(witness, "accountTreeHash")?,
            account_discriminator: required_string_array(witness, "accountDiscriminator")?,
        })
        .map_err(|err| LocalVerifierError::Serialization(err.to_string())),
        other => Err(LocalVerifierError::Validation(format!(
            "unsupported MASP verifier circuit type {other}"
        ))),
    }
}

pub fn compute_public_inputs_hash_from_verifier_inputs(
    circuit_type: &str,
    verifier_inputs: &serde_json::Value,
) -> Result<String, LocalVerifierError> {
    match circuit_type {
        "masp-utxo" => {
            let inputs = serde_json::from_value::<MaspUtxoVerifierInputs>(verifier_inputs.clone())
                .map_err(|err| {
                    LocalVerifierError::Validation(format!(
                        "masp-utxo verifier inputs are invalid: {err}"
                    ))
                })?;
            compute_masp_utxo_public_inputs_hash(&inputs)
        }
        "masp-tree" => {
            let inputs = serde_json::from_value::<MaspTreeVerifierInputs>(verifier_inputs.clone())
                .map_err(|err| {
                    LocalVerifierError::Validation(format!(
                        "masp-tree verifier inputs are invalid: {err}"
                    ))
                })?;
            compute_masp_tree_public_inputs_hash(&inputs)
        }
        other => Err(LocalVerifierError::Validation(format!(
            "unsupported MASP verifier circuit type {other}"
        ))),
    }
}

pub fn verify_public_inputs_hash(
    circuit_type: &str,
    public_inputs_hash: &str,
    verifier_inputs: &serde_json::Value,
) -> Result<String, LocalVerifierError> {
    let expected = normalize_field_decimal(public_inputs_hash, "publicInputsHash")?;
    let actual = compute_public_inputs_hash_from_verifier_inputs(circuit_type, verifier_inputs)?;
    if actual != expected {
        return Err(LocalVerifierError::Validation(format!(
            "{circuit_type} publicInputsHash mismatch: expected {expected}, reconstructed {actual}"
        )));
    }
    Ok(actual)
}

pub fn compute_masp_utxo_public_inputs_hash(
    inputs: &MaspUtxoVerifierInputs,
) -> Result<String, LocalVerifierError> {
    masp_hash_chain_decimal(&[
        inputs.sha_tx_hash.clone(),
        inputs.program_id_hashchain.clone(),
        inputs.seeds_hashchain.clone(),
        inputs.tx_hash.clone(),
        inputs.nullifier_chain.clone(),
    ])
}

pub fn compute_masp_tree_public_inputs_hash(
    inputs: &MaspTreeVerifierInputs,
) -> Result<String, LocalVerifierError> {
    validate_same_len(
        "stateRoots",
        &inputs.state_roots,
        "nullifiers",
        &inputs.nullifiers,
    )?;
    validate_same_len(
        "nullifierRoots",
        &inputs.nullifier_roots,
        "nullifiers",
        &inputs.nullifiers,
    )?;
    validate_same_len(
        "accountOwnerHash",
        &inputs.account_owner_hash,
        "nullifiers",
        &inputs.nullifiers,
    )?;
    validate_same_len(
        "accountTreeHash",
        &inputs.account_tree_hash,
        "nullifiers",
        &inputs.nullifiers,
    )?;
    validate_same_len(
        "accountDiscriminator",
        &inputs.account_discriminator,
        "nullifiers",
        &inputs.nullifiers,
    )?;

    let state_roots_chain = masp_hash_chain_decimal(&inputs.state_roots)?;
    let nullifier_roots_chain = masp_hash_chain_decimal(&inputs.nullifier_roots)?;
    let nullifier_chain = masp_hash_chain_decimal(&inputs.nullifiers)?;
    let owner_hash_chain = masp_hash_chain_decimal(&inputs.account_owner_hash)?;
    let tree_hash_chain = masp_hash_chain_decimal(&inputs.account_tree_hash)?;
    let discriminator_chain = masp_hash_chain_decimal(&inputs.account_discriminator)?;

    masp_hash_chain_decimal(&[
        state_roots_chain,
        nullifier_roots_chain,
        nullifier_chain,
        owner_hash_chain,
        tree_hash_chain,
        discriminator_chain,
    ])
}

pub fn verify_local_transaction_candidate(
    candidate: &LocalTransactionCandidate,
) -> Result<LocalVerifierCheckResult, LocalVerifierError> {
    if candidate.kind != "local-dev-verifier-instruction" {
        return Err(LocalVerifierError::Validation(format!(
            "unsupported transaction candidate kind {}",
            candidate.kind
        )));
    }
    if candidate.unsigned_transaction.instructions.len() != 1 {
        return Err(LocalVerifierError::Validation(
            "local verifier expects exactly one instruction".to_string(),
        ));
    }
    let instruction = &candidate.unsigned_transaction.instructions[0];
    if instruction.data_encoding != "hex-json" {
        return Err(LocalVerifierError::Validation(format!(
            "unsupported instruction data encoding {}",
            instruction.data_encoding
        )));
    }

    let instruction_data = decode_instruction_data(&instruction.data)?;
    if instruction_data.version != LOCAL_VERIFIER_INSTRUCTION_VERSION {
        return Err(LocalVerifierError::Validation(format!(
            "unsupported verifier instruction version {}",
            instruction_data.version
        )));
    }
    if instruction_data.tag != LOCAL_VERIFIER_INSTRUCTION_TAG {
        return Err(LocalVerifierError::Validation(format!(
            "unsupported verifier instruction tag {}",
            instruction_data.tag
        )));
    }

    let mut seen = HashSet::with_capacity(instruction_data.proof_bundle.len());
    let mut utxo_public_inputs_hash = None;
    let mut tree_public_inputs_hash = None;
    let mut tree_inputs = None;
    for proof in &instruction_data.proof_bundle {
        if !seen.insert(proof.circuit_type.as_str()) {
            return Err(LocalVerifierError::Validation(format!(
                "duplicate verifier proof circuitType {}",
                proof.circuit_type
            )));
        }
        let reconstructed = verify_public_inputs_hash(
            &proof.circuit_type,
            &proof.public_inputs_hash,
            &proof.verifier_inputs,
        )?;
        match proof.circuit_type.as_str() {
            "masp-utxo" => utxo_public_inputs_hash = Some(reconstructed),
            "masp-tree" => {
                tree_inputs = Some(
                    serde_json::from_value::<MaspTreeVerifierInputs>(proof.verifier_inputs.clone())
                        .map_err(|err| {
                            LocalVerifierError::Validation(format!(
                                "masp-tree verifier inputs are invalid: {err}"
                            ))
                        })?,
                );
                tree_public_inputs_hash = Some(reconstructed);
            }
            other => {
                return Err(LocalVerifierError::Validation(format!(
                    "unsupported verifier proof circuitType {other}"
                )));
            }
        }
    }

    for required in ["masp-utxo", "masp-tree"] {
        if !seen.contains(required) {
            return Err(LocalVerifierError::Validation(format!(
                "missing required verifier proof {required}"
            )));
        }
    }

    verify_tree_roots_match_context(
        tree_inputs
            .as_ref()
            .expect("masp-tree presence checked above"),
        &instruction_data.root_context,
    )?;

    Ok(LocalVerifierCheckResult {
        status: "verified".to_string(),
        utxo_public_inputs_hash: utxo_public_inputs_hash.expect("masp-utxo presence checked above"),
        tree_public_inputs_hash: tree_public_inputs_hash.expect("masp-tree presence checked above"),
        utxo_tree_id: instruction_data.root_context.utxo_tree_id,
        utxo_root: instruction_data.root_context.utxo_root,
        utxo_root_index: instruction_data.root_context.utxo_root_index,
        utxo_root_sequence: instruction_data.root_context.utxo_root_sequence,
        nullifier_tree_id: instruction_data.root_context.nullifier_tree_id,
        nullifier_root: instruction_data.root_context.nullifier_root,
        nullifier_root_index: instruction_data.root_context.nullifier_root_index,
        nullifier_root_sequence: instruction_data.root_context.nullifier_root_sequence,
    })
}

fn decode_instruction_data(
    instruction_data_hex: &str,
) -> Result<LocalVerifierInstructionData, LocalVerifierError> {
    let bytes = decode_hex(instruction_data_hex, "instruction.data")?;
    serde_json::from_slice::<LocalVerifierInstructionData>(&bytes)
        .map_err(|err| LocalVerifierError::Serialization(err.to_string()))
}

fn verify_tree_roots_match_context(
    inputs: &MaspTreeVerifierInputs,
    context: &LocalRelayerRootContext,
) -> Result<(), LocalVerifierError> {
    let utxo_root = normalize_field_decimal(&context.utxo_root, "rootContext.utxoRoot")?;
    let nullifier_root =
        normalize_field_decimal(&context.nullifier_root, "rootContext.nullifierRoot")?;
    if inputs.state_roots.is_empty() {
        return Err(LocalVerifierError::Validation(
            "masp-tree verifier inputs require stateRoots".to_string(),
        ));
    }
    for (index, root) in inputs.state_roots.iter().enumerate() {
        let root = normalize_field_decimal(root, &format!("stateRoots[{index}]"))?;
        if root != utxo_root {
            return Err(LocalVerifierError::Validation(format!(
                "stateRoots[{index}] does not match rootContext.utxoRoot"
            )));
        }
    }
    for (index, root) in inputs.nullifier_roots.iter().enumerate() {
        let root = normalize_field_decimal(root, &format!("nullifierRoots[{index}]"))?;
        if root != nullifier_root {
            return Err(LocalVerifierError::Validation(format!(
                "nullifierRoots[{index}] does not match rootContext.nullifierRoot"
            )));
        }
    }
    Ok(())
}

pub fn masp_hash_chain_decimal(values: &[String]) -> Result<String, LocalVerifierError> {
    if values.is_empty() {
        return Ok("0".to_string());
    }
    let mut hash = field_to_32(&values[values.len() - 1], "hashChain[last]")?;
    for (index, value) in values.iter().enumerate().rev().skip(1) {
        let left = field_to_32(value, &format!("hashChain[{index}]"))?;
        hash = poseidon_hash2(&left, &hash)?;
    }
    Ok(BigUint::from_bytes_be(&hash).to_str_radix(10))
}

fn poseidon_hash2(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], LocalVerifierError> {
    let mut hasher = Poseidon::<Fr>::new_circom(2)
        .map_err(|err| LocalVerifierError::Hashing(err.to_string()))?;
    hasher
        .hash_bytes_be(&[left.as_slice(), right.as_slice()])
        .map_err(|err| LocalVerifierError::Hashing(err.to_string()))
}

fn validate_same_len(
    left_name: &str,
    left: &[String],
    right_name: &str,
    right: &[String],
) -> Result<(), LocalVerifierError> {
    if left.len() != right.len() {
        return Err(LocalVerifierError::Validation(format!(
            "{left_name} length ({}) must match {right_name} length ({})",
            left.len(),
            right.len()
        )));
    }
    Ok(())
}

fn required_string(object: &serde_json::Value, field: &str) -> Result<String, LocalVerifierError> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            LocalVerifierError::Validation(format!("localWitness.{field} must be a string"))
        })
}

fn required_string_array(
    object: &serde_json::Value,
    field: &str,
) -> Result<Vec<String>, LocalVerifierError> {
    object
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            LocalVerifierError::Validation(format!("localWitness.{field} must be an array"))
        })?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                LocalVerifierError::Validation(format!(
                    "localWitness.{field}[{index}] must be a string"
                ))
            })
        })
        .collect()
}

fn normalize_field_decimal(value: &str, field: &str) -> Result<String, LocalVerifierError> {
    Ok(BigUint::from_bytes_be(&field_to_32(value, field)?).to_str_radix(10))
}

fn field_to_32(value: &str, field: &str) -> Result<[u8; 32], LocalVerifierError> {
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        BigUint::parse_bytes(hex.as_bytes(), 16)
    } else {
        BigUint::parse_bytes(value.as_bytes(), 10)
    }
    .ok_or_else(|| LocalVerifierError::Validation(format!("{field} is not a field element")))?;
    let bytes = parsed.to_bytes_be();
    if bytes.len() > 32 {
        return Err(LocalVerifierError::Validation(format!(
            "{field} must fit in 32 bytes"
        )));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, LocalVerifierError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|err| LocalVerifierError::Validation(format!("{field} is not valid hex: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_rpc::local_relayer::{
        LocalInstructionAccountMeta, LocalInstructionCandidate, LocalRelayerProofOutput,
        LocalUnsignedTransaction, LocalVerifierInstructionData,
    };

    #[test]
    fn masp_hash_chain_uses_right_fold_poseidon() {
        let result = masp_hash_chain_decimal(&["1".to_string(), "1".to_string()]).unwrap();
        assert_eq!(
            result,
            BigUint::parse_bytes(
                b"007af346e2d304279e79e0a9f3023f771294a78acb70e73f90afe27cad401e81",
                16
            )
            .unwrap()
            .to_str_radix(10)
        );
    }

    #[test]
    fn reconstructs_utxo_public_inputs_hash() {
        let inputs = MaspUtxoVerifierInputs {
            sha_tx_hash: "0".to_string(),
            program_id_hashchain: "0".to_string(),
            seeds_hashchain: "0".to_string(),
            tx_hash: "0".to_string(),
            nullifier_chain: "0".to_string(),
        };
        let hash = compute_masp_utxo_public_inputs_hash(&inputs).unwrap();
        assert!(BigUint::parse_bytes(hash.as_bytes(), 10).is_some());
    }

    #[test]
    fn verifies_instruction_candidate_public_inputs_and_roots() {
        let root_context = LocalRelayerRootContext {
            utxo_tree_id: hex_0x(&[0x11; 32]),
            utxo_root: hex_0x(&field_bytes(0x22)),
            utxo_root_index: 1,
            utxo_root_sequence: 65,
            nullifier_tree_id: hex_0x(&[0x33; 32]),
            nullifier_root: hex_0x(&field_bytes(0x44)),
            nullifier_root_index: 2,
            nullifier_root_sequence: 66,
            expires_after_slot: None,
        };
        let utxo_inputs = serde_json::to_value(MaspUtxoVerifierInputs {
            sha_tx_hash: "0".to_string(),
            program_id_hashchain: "0".to_string(),
            seeds_hashchain: "0".to_string(),
            tx_hash: "0".to_string(),
            nullifier_chain: "0".to_string(),
        })
        .unwrap();
        let tree_inputs = serde_json::to_value(MaspTreeVerifierInputs {
            state_roots: vec![normalize_field_decimal(&root_context.utxo_root, "root").unwrap()],
            nullifier_roots: vec![
                normalize_field_decimal(&root_context.nullifier_root, "root").unwrap(),
            ],
            nullifiers: vec!["7".to_string()],
            account_owner_hash: vec!["8".to_string()],
            account_tree_hash: vec!["9".to_string()],
            account_discriminator: vec!["10".to_string()],
        })
        .unwrap();
        let instruction = LocalVerifierInstructionData {
            version: LOCAL_VERIFIER_INSTRUCTION_VERSION,
            tag: LOCAL_VERIFIER_INSTRUCTION_TAG.to_string(),
            intent_hash: hex_0x(&[0x77; 32]),
            signer: "local-dev-signer".to_string(),
            root_context,
            proof_bundle: vec![
                LocalRelayerProofOutput {
                    circuit_type: "masp-utxo".to_string(),
                    public_inputs_hash: compute_public_inputs_hash_from_verifier_inputs(
                        "masp-utxo",
                        &utxo_inputs,
                    )
                    .unwrap(),
                    prover_job_id: None,
                    verifier_inputs: utxo_inputs,
                    proof_result: serde_json::json!({"proof":"ok"}),
                },
                LocalRelayerProofOutput {
                    circuit_type: "masp-tree".to_string(),
                    public_inputs_hash: compute_public_inputs_hash_from_verifier_inputs(
                        "masp-tree",
                        &tree_inputs,
                    )
                    .unwrap(),
                    prover_job_id: None,
                    verifier_inputs: tree_inputs,
                    proof_result: serde_json::json!({"proof":"ok"}),
                },
            ],
        };
        let data = hex_0x(&serde_json::to_vec(&instruction).unwrap());
        let candidate = LocalTransactionCandidate {
            kind: "local-dev-verifier-instruction".to_string(),
            verifier_program_id: "program".to_string(),
            message_hash: hex_0x(&[0u8; 32]),
            unsigned_transaction: LocalUnsignedTransaction {
                format: "local-json-v1".to_string(),
                recent_blockhash: None,
                fee_payer: "payer".to_string(),
                instructions: vec![LocalInstructionCandidate {
                    program_id: "program".to_string(),
                    accounts: Vec::<LocalInstructionAccountMeta>::new(),
                    data_encoding: "hex-json".to_string(),
                    data,
                }],
            },
            submission: "notSubmitted".to_string(),
            next_action: "none".to_string(),
        };

        let result = verify_local_transaction_candidate(&candidate).unwrap();
        assert_eq!(result.status, "verified");
    }

    fn hex_0x(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    fn field_bytes(last: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = last;
        out
    }
}
