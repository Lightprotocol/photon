//! Local/dev MASP request assembly for Zone RPC.
//!
//! This module is intentionally not a production witness builder. It gives the
//! local vertical slice a single Zone RPC-owned boundary for converting
//! `fetch_proof_inputs` + private decrypted rows + test-only witness secrets
//! into the MASP request/spec shapes accepted by prover-server.

use std::error::Error;
use std::fmt;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::zone_rpc::api::FetchProofInputsResponse;
use crate::zone_rpc::local_verifier::{
    compute_masp_tree_public_inputs_hash, compute_masp_utxo_public_inputs_hash,
    MaspTreeVerifierInputs, MaspUtxoVerifierInputs,
};
use crate::zone_rpc::private_api::ZoneDecryptedUtxoView;
use crate::zone_rpc::prover_client::ProverProofRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalMaspError {
    Validation(String),
    Serialization(String),
}

impl fmt::Display for LocalMaspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(err) => write!(f, "local/dev MASP validation error: {err}"),
            Self::Serialization(err) => write!(f, "local/dev MASP serialization error: {err}"),
        }
    }
}

impl Error for LocalMaspError {}

#[derive(Debug, Clone, Deserialize)]
pub struct MaspLocalDevProofPayloads {
    pub utxo: serde_json::Value,
    pub tree: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct LocalMaspWitnessSecrets {
    pub inputs: Vec<LocalMaspInputSecret>,
    pub outputs: Vec<LocalMaspOutputSecret>,
    pub nullifier_secret: [u8; 32],
    pub tx_blinding: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct LocalMaspInputSecret {
    pub owner: [u8; 32],
    pub spl_amount: u64,
    pub sol_amount: u64,
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub program_id: [u8; 32],
    pub seed: u64,
}

#[derive(Debug, Clone)]
pub struct LocalMaspOutputSecret {
    pub owner: [u8; 32],
    pub spl_amount: u64,
    pub sol_amount: u64,
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub owner_is_program: bool,
    pub owner_program_index: u64,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMaspZoneFixtureSpec {
    pub root_context: serde_json::Value,
    pub operation_commitment: String,
    pub nullifier_secret: String,
    pub tx_blinding: String,
    pub inputs: Vec<LocalMaspZoneInputSpec>,
    pub outputs: Vec<LocalMaspZoneOutputSpec>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMaspZoneInputSpec {
    pub owner: String,
    pub spl: String,
    pub sol: String,
    pub blinding: String,
    pub data_hash: String,
    pub seed: String,
    pub program_id: String,
    pub leaf_index: String,
    pub account_owner_hash: String,
    pub account_tree_hash: String,
    pub account_discriminator: String,
    pub state_root: String,
    pub state_path: Vec<String>,
    pub state_dirs: Vec<u8>,
    pub nullifier_root: String,
    pub nf_low_value: String,
    pub nf_next_value: String,
    pub nf_low_path: Vec<String>,
    pub nf_low_dirs: Vec<u8>,
    pub expected_utxo_hash: String,
    pub expected_spend_nullifier: String,
    pub expected_compressed_account_hash: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMaspZoneOutputSpec {
    pub owner: String,
    pub spl: String,
    pub sol: String,
    pub blinding: String,
    pub data_hash: String,
    pub owner_is_program: String,
    pub owner_program_index: String,
    pub seed: String,
}

pub fn build_local_dev_stub_proof_requests(
    proof_inputs: &FetchProofInputsResponse,
    decrypted_inputs: &[ZoneDecryptedUtxoView],
) -> Result<Vec<ProverProofRequest>, LocalMaspError> {
    Ok(vec![
        proof_request_from_payload(
            "masp-utxo",
            masp_utxo_payload_from_zone_inputs(proof_inputs, decrypted_inputs)?,
        )?,
        proof_request_from_payload(
            "masp-tree",
            masp_tree_payload_from_zone_inputs(proof_inputs)?,
        )?,
    ])
}

pub fn proof_requests_from_local_dev_payloads(
    payloads: MaspLocalDevProofPayloads,
) -> Result<Vec<ProverProofRequest>, LocalMaspError> {
    Ok(vec![
        proof_request_from_payload("masp-utxo", payloads.utxo)?,
        proof_request_from_payload("masp-tree", payloads.tree)?,
    ])
}

pub fn build_local_dev_zone_fixture_spec(
    proof_inputs: &FetchProofInputsResponse,
    decrypted_inputs: &[ZoneDecryptedUtxoView],
    secrets: &LocalMaspWitnessSecrets,
) -> Result<LocalMaspZoneFixtureSpec, LocalMaspError> {
    let ordered_inputs = decrypted_inputs_for_proof_order(proof_inputs, decrypted_inputs)?;
    if ordered_inputs.len() != secrets.inputs.len() {
        return Err(LocalMaspError::Validation(format!(
            "local/dev MASP secrets input count ({}) must match proof input count ({})",
            secrets.inputs.len(),
            ordered_inputs.len()
        )));
    }
    if secrets.outputs.is_empty() {
        return Err(LocalMaspError::Validation(
            "local/dev MASP requires at least one output secret".to_string(),
        ));
    }

    let inputs = proof_inputs
        .inputs
        .iter()
        .zip(ordered_inputs.iter())
        .zip(secrets.inputs.iter())
        .enumerate()
        .map(|(index, ((proof_input, decrypted), secret))| {
            if decrypted.owner_hash != hex_0x(&secret.owner) {
                return Err(LocalMaspError::Validation(format!(
                    "decrypted input {index} owner_hash does not match witness secret"
                )));
            }
            if decrypted.data_hash != hex_0x(&secret.data_hash) {
                return Err(LocalMaspError::Validation(format!(
                    "decrypted input {index} data_hash does not match witness secret"
                )));
            }
            if decrypted.spl_amount != secret.spl_amount.to_string() {
                return Err(LocalMaspError::Validation(format!(
                    "decrypted input {index} spl_amount does not match witness secret"
                )));
            }
            if decrypted.sol_amount != secret.sol_amount.to_string() {
                return Err(LocalMaspError::Validation(format!(
                    "decrypted input {index} sol_amount does not match witness secret"
                )));
            }

            let state_proof = proof_input
                .compressed_account_proof
                .as_ref()
                .ok_or_else(|| {
                    LocalMaspError::Validation(format!(
                        "proof input {index} is missing compressed account proof"
                    ))
                })?;
            let nullifier_proof = proof_input
                .nullifier_non_inclusion_proof
                .as_ref()
                .ok_or_else(|| {
                    LocalMaspError::Validation(format!(
                        "proof input {index} is missing nullifier non-inclusion proof"
                    ))
                })?;
            let spend_nullifier = proof_input.spend_nullifier.as_ref().ok_or_else(|| {
                LocalMaspError::Validation(format!(
                    "proof input {index} is missing spend nullifier"
                ))
            })?;

            Ok(LocalMaspZoneInputSpec {
                owner: decimal_from_bytes(&secret.owner),
                spl: secret.spl_amount.to_string(),
                sol: secret.sol_amount.to_string(),
                blinding: decimal_from_bytes(&secret.blinding),
                data_hash: decimal_from_bytes(&secret.data_hash),
                seed: secret.seed.to_string(),
                program_id: decimal_from_bytes(&secret.program_id),
                leaf_index: proof_input.leaf_index.to_string(),
                account_owner_hash: proof_input.account_owner_hash.clone(),
                account_tree_hash: proof_input.account_tree_hash.clone(),
                account_discriminator: proof_input.account_discriminator.clone(),
                state_root: decimal_from_hex_0x(&state_proof.root, "stateRoot")?,
                state_path: state_proof
                    .proof
                    .iter()
                    .enumerate()
                    .map(|(node_index, node)| {
                        decimal_from_hex_0x(node, &format!("statePath[{node_index}]"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                state_dirs: state_proof.path_directions.clone(),
                nullifier_root: decimal_from_hex_0x(&nullifier_proof.root, "nullifierRoot")?,
                nf_low_value: decimal_from_hex_0x(&nullifier_proof.low_value, "nfLowValue")?,
                nf_next_value: decimal_from_hex_0x(&nullifier_proof.next_value, "nfNextValue")?,
                nf_low_path: nullifier_proof
                    .proof
                    .iter()
                    .enumerate()
                    .map(|(node_index, node)| {
                        decimal_from_hex_0x(node, &format!("nfLowPath[{node_index}]"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                nf_low_dirs: nullifier_proof.path_directions.clone(),
                expected_utxo_hash: decimal_from_hex_0x(&proof_input.utxo_hash, "utxoHash")?,
                expected_spend_nullifier: decimal_from_hex_0x(spend_nullifier, "spendNullifier")?,
                expected_compressed_account_hash: decimal_from_hex_0x(
                    &proof_input.compressed_account_hash,
                    "compressedAccountHash",
                )?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(LocalMaspZoneFixtureSpec {
        root_context: root_context_json(proof_inputs)?,
        operation_commitment: operation_commitment_from_inputs(proof_inputs)?,
        nullifier_secret: decimal_from_bytes(&secrets.nullifier_secret),
        tx_blinding: decimal_from_bytes(&secrets.tx_blinding),
        inputs,
        outputs: secrets
            .outputs
            .iter()
            .map(|output| LocalMaspZoneOutputSpec {
                owner: decimal_from_bytes(&output.owner),
                spl: output.spl_amount.to_string(),
                sol: output.sol_amount.to_string(),
                blinding: decimal_from_bytes(&output.blinding),
                data_hash: decimal_from_bytes(&output.data_hash),
                owner_is_program: bool_decimal(output.owner_is_program).to_string(),
                owner_program_index: output.owner_program_index.to_string(),
                seed: output.seed.to_string(),
            })
            .collect(),
    })
}

fn masp_tree_payload_from_zone_inputs(
    proof_inputs: &FetchProofInputsResponse,
) -> Result<serde_json::Value, LocalMaspError> {
    let inputs = proof_inputs.inputs.as_slice();
    if inputs.is_empty() {
        return Err(LocalMaspError::Validation(
            "MASP tree request requires inputs".to_string(),
        ));
    }

    let in_commit = inputs
        .iter()
        .map(|input| decimal_from_hex_0x(&input.utxo_hash, "utxoHash"))
        .collect::<Result<Vec<_>, _>>()?;
    let account_owner_hash = inputs
        .iter()
        .map(|input| input.account_owner_hash.clone())
        .collect::<Vec<_>>();
    let account_tree_hash = inputs
        .iter()
        .map(|input| input.account_tree_hash.clone())
        .collect::<Vec<_>>();
    let account_discriminator = inputs
        .iter()
        .map(|input| input.account_discriminator.clone())
        .collect::<Vec<_>>();
    let state_path = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let proof = input.compressed_account_proof.as_ref().ok_or_else(|| {
                LocalMaspError::Validation(format!(
                    "proof input {index} is missing compressed account proof"
                ))
            })?;
            proof
                .proof
                .iter()
                .enumerate()
                .map(|(node_index, node)| {
                    decimal_from_hex_0x(node, &format!("statePath[{index}][{node_index}]"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let state_dirs = inputs
        .iter()
        .map(|input| {
            input
                .compressed_account_proof
                .as_ref()
                .ok_or_else(|| {
                    LocalMaspError::Validation(
                        "MASP tree request requires compressed account proofs".to_string(),
                    )
                })
                .map(|proof| {
                    proof
                        .path_directions
                        .iter()
                        .map(u8::to_string)
                        .collect::<Vec<_>>()
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let nf_low_value = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let proof = nullifier_proof(input, index)?;
            decimal_from_hex_0x(&proof.low_value, &format!("nfLowValue[{index}]"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let nf_next_value = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let proof = nullifier_proof(input, index)?;
            decimal_from_hex_0x(&proof.next_value, &format!("nfNextValue[{index}]"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let nf_low_path = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let proof = nullifier_proof(input, index)?;
            proof
                .proof
                .iter()
                .enumerate()
                .map(|(node_index, node)| {
                    decimal_from_hex_0x(node, &format!("nfLowPath[{index}][{node_index}]"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let nf_low_dirs = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let proof = nullifier_proof(input, index)?;
            Ok(proof
                .path_directions
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>())
        })
        .collect::<Result<Vec<_>, LocalMaspError>>()?;
    let state_roots = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let proof = input.compressed_account_proof.as_ref().ok_or_else(|| {
                LocalMaspError::Validation(format!(
                    "proof input {index} is missing compressed account proof"
                ))
            })?;
            decimal_from_hex_0x(&proof.root, &format!("stateRoots[{index}]"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let nullifier_roots = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let proof = nullifier_proof(input, index)?;
            decimal_from_hex_0x(&proof.root, &format!("nullifierRoots[{index}]"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let nullifiers = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            decimal_from_hex_0x(
                input.spends_nullifier_or_err(index)?,
                &format!("nullifiers[{index}]"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let verifier_inputs = MaspTreeVerifierInputs {
        state_roots: state_roots.clone(),
        nullifier_roots: nullifier_roots.clone(),
        nullifiers: nullifiers.clone(),
        account_owner_hash: account_owner_hash.clone(),
        account_tree_hash: account_tree_hash.clone(),
        account_discriminator: account_discriminator.clone(),
    };
    let public_inputs_hash = compute_masp_tree_public_inputs_hash(&verifier_inputs)
        .map_err(|err| LocalMaspError::Validation(err.to_string()))?;

    Ok(json!({
        "circuitType": "masp-tree",
        "nInputs": inputs.len(),
        "nOutputs": 0,
        "rootContext": root_context_json(proof_inputs)?,
        "operationCommitment": operation_commitment_from_inputs(proof_inputs)?,
        "publicInputsHash": public_inputs_hash,
        "localWitness": {
            "inCommit": in_commit,
            "accountOwnerHash": account_owner_hash,
            "accountTreeHash": account_tree_hash,
            "accountDiscriminator": account_discriminator,
            "statePath": state_path,
            "stateDirs": state_dirs,
            "domainDns": vec!["1".to_string(); inputs.len()],
            "nfLowValue": nf_low_value,
            "nfNextValue": nf_next_value,
            "nfLowPath": nf_low_path,
            "nfLowDirs": nf_low_dirs,
            "stateRoots": state_roots,
            "nullifierRoots": nullifier_roots,
            "nullifiers": nullifiers,
        }
    }))
}

fn masp_utxo_payload_from_zone_inputs(
    proof_inputs: &FetchProofInputsResponse,
    decrypted_inputs: &[ZoneDecryptedUtxoView],
) -> Result<serde_json::Value, LocalMaspError> {
    let ordered_inputs = decrypted_inputs_for_proof_order(proof_inputs, decrypted_inputs)?;
    let nullifiers = proof_inputs
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            decimal_from_hex_0x(
                input.spends_nullifier_or_err(index)?,
                &format!("nullifiers[{index}]"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let output_owner = ordered_inputs
        .first()
        .ok_or_else(|| {
            LocalMaspError::Validation(
                "MASP UTXO request requires at least one decrypted input".to_string(),
            )
        })?
        .owner_pubkey
        .clone();
    let output_data_hash = ordered_inputs
        .first()
        .ok_or_else(|| {
            LocalMaspError::Validation(
                "MASP UTXO request requires at least one decrypted input".to_string(),
            )
        })?
        .data_hash
        .clone();

    let verifier_inputs = MaspUtxoVerifierInputs {
        sha_tx_hash: "0".to_string(),
        program_id_hashchain: "0".to_string(),
        seeds_hashchain: "0".to_string(),
        tx_hash: "0".to_string(),
        nullifier_chain: "0".to_string(),
    };
    let public_inputs_hash = compute_masp_utxo_public_inputs_hash(&verifier_inputs)
        .map_err(|err| LocalMaspError::Validation(err.to_string()))?;

    Ok(json!({
        "circuitType": "masp-utxo",
        "nInputs": ordered_inputs.len(),
        "nOutputs": 1,
        "rootContext": root_context_json(proof_inputs)?,
        "operationCommitment": operation_commitment_from_inputs(proof_inputs)?,
        "publicInputsHash": public_inputs_hash,
        "localWitness": {
            "inOwner": ordered_inputs.iter().map(|input| decimal_from_hex_0x(&input.owner_pubkey, "ownerPubkey")).collect::<Result<Vec<_>, _>>()?,
            "inSpl": ordered_inputs.iter().map(|input| input.spl_amount.clone()).collect::<Vec<_>>(),
            "inSol": ordered_inputs.iter().map(|input| input.sol_amount.clone()).collect::<Vec<_>>(),
            "inBlinding": vec!["0".to_string(); ordered_inputs.len()],
            "inDataHash": ordered_inputs.iter().map(|input| decimal_from_hex_0x(&input.data_hash, "dataHash")).collect::<Result<Vec<_>, _>>()?,
            "inSeed": vec!["0".to_string(); ordered_inputs.len()],
            "inProgramId": vec!["0".to_string(); ordered_inputs.len()],
            "inLeafIndex": proof_inputs.inputs.iter().map(|input| input.leaf_index.to_string()).collect::<Vec<_>>(),
            "nullifierSecret": "1",
            "outOwner": vec![decimal_from_hex_0x(&output_owner, "outputOwner")?],
            "outSpl": vec![sum_decimal_strings(ordered_inputs.iter().map(|input| input.spl_amount.as_str()))?],
            "outSol": vec![sum_decimal_strings(ordered_inputs.iter().map(|input| input.sol_amount.as_str()))?],
            "outBlinding": vec!["0"],
            "outDataHash": vec![decimal_from_hex_0x(&output_data_hash, "outputDataHash")?],
            "outOwnerIsProgram": vec!["0"],
            "outOwnerProgramIndex": vec!["0"],
            "outSeed": vec!["0"],
            "txBlinding": "0",
            "pubX": ["0", "0"],
            "pubY": ["0", "0"],
            "sigR": ["0", "0"],
            "sigS": ["0", "0"],
            "nullifiers": nullifiers,
            "outputCommitments": vec!["0"],
            "txHash": "0",
            "seedsHashchain": "0",
            "programIdHashchain": "0",
            "shaTxHash": "0",
            "nullifierChain": "0",
        }
    }))
}

trait ProofInputExt {
    fn spends_nullifier_or_err(&self, index: usize) -> Result<&str, LocalMaspError>;
}

impl ProofInputExt for crate::zone_rpc::api::ProofInputUtxoView {
    fn spends_nullifier_or_err(&self, index: usize) -> Result<&str, LocalMaspError> {
        self.spend_nullifier.as_deref().ok_or_else(|| {
            LocalMaspError::Validation(format!("proof input {index} is missing spend nullifier"))
        })
    }
}

fn nullifier_proof(
    input: &crate::zone_rpc::api::ProofInputUtxoView,
    index: usize,
) -> Result<&crate::zone_rpc::api::NullifierNonInclusionProofView, LocalMaspError> {
    input.nullifier_non_inclusion_proof.as_ref().ok_or_else(|| {
        LocalMaspError::Validation(format!(
            "proof input {index} is missing nullifier non-inclusion proof"
        ))
    })
}

fn decrypted_inputs_for_proof_order<'a>(
    proof_inputs: &FetchProofInputsResponse,
    decrypted_inputs: &'a [ZoneDecryptedUtxoView],
) -> Result<Vec<&'a ZoneDecryptedUtxoView>, LocalMaspError> {
    proof_inputs
        .inputs
        .iter()
        .enumerate()
        .map(|(index, proof_input)| {
            decrypted_inputs
                .iter()
                .find(|decrypted| decrypted.utxo_hash == proof_input.utxo_hash)
                .ok_or_else(|| {
                    LocalMaspError::Validation(format!(
                        "missing decrypted UTXO for proof input {index} ({})",
                        proof_input.utxo_hash
                    ))
                })
        })
        .collect()
}

fn root_context_json(
    proof_inputs: &FetchProofInputsResponse,
) -> Result<serde_json::Value, LocalMaspError> {
    serde_json::to_value(proof_inputs.root_context.as_ref().ok_or_else(|| {
        LocalMaspError::Validation("MASP proof request requires root context".to_string())
    })?)
    .map_err(|err| LocalMaspError::Serialization(err.to_string()))
}

fn operation_commitment_from_inputs(
    proof_inputs: &FetchProofInputsResponse,
) -> Result<String, LocalMaspError> {
    let first = proof_inputs
        .inputs
        .first()
        .ok_or_else(|| {
            LocalMaspError::Validation("MASP proof request requires inputs".to_string())
        })?
        .operation_commitment
        .clone();
    if proof_inputs
        .inputs
        .iter()
        .any(|input| input.operation_commitment != first)
    {
        return Err(LocalMaspError::Validation(
            "local/dev MASP builder currently expects one operation commitment".to_string(),
        ));
    }
    Ok(first)
}

fn proof_request_from_payload(
    circuit_type: &str,
    payload: serde_json::Value,
) -> Result<ProverProofRequest, LocalMaspError> {
    let payload_circuit_type = payload
        .get("circuitType")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            LocalMaspError::Validation("MASP payload missing string circuitType".to_string())
        })?;
    if payload_circuit_type != circuit_type {
        return Err(LocalMaspError::Validation(format!(
            "MASP payload circuitType {payload_circuit_type} does not match {circuit_type}"
        )));
    }
    Ok(ProverProofRequest {
        circuit_type: circuit_type.to_string(),
        payload: serde_json::to_string(&payload)
            .map_err(|err| LocalMaspError::Serialization(err.to_string()))?,
    })
}

fn decimal_from_hex_0x(value: &str, field: &str) -> Result<String, LocalMaspError> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.is_empty() {
        return Ok("0".to_string());
    }
    BigUint::parse_bytes(hex.as_bytes(), 16)
        .map(|value| value.to_str_radix(10))
        .ok_or_else(|| LocalMaspError::Validation(format!("{field} is not valid hex")))
}

fn sum_decimal_strings<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<String, LocalMaspError> {
    let mut acc = BigUint::from(0u8);
    for value in values {
        let Some(parsed) = BigUint::parse_bytes(value.as_bytes(), 10) else {
            return Err(LocalMaspError::Validation(format!(
                "invalid decimal amount {value}"
            )));
        };
        acc += parsed;
    }
    Ok(acc.to_str_radix(10))
}

fn decimal_from_bytes(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_str_radix(10)
}

fn bool_decimal(value: bool) -> u8 {
    if value {
        1
    } else {
        0
    }
}

fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
