//! Local/dev relayer transaction-candidate assembly.
//!
//! This is not a Solana transport implementation. It is the boundary where
//! Zone RPC stops treating `submit_intent` as status bookkeeping and starts
//! building the verifier instruction payload from a signed intent, checked root
//! context, and completed MASP proof jobs.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use light_hasher::{sha256::Sha256, Hasher};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_pubkey::Pubkey;

use crate::zone_rpc::api::{SignedZoneIntent, ZoneJobStatus, ZoneProofJobView};
use crate::zone_rpc::local_verifier::{
    verify_public_inputs_hash, LocalVerifierCheckResult, LocalVerifierError,
};

pub const LOCAL_VERIFIER_INSTRUCTION_TAG: &str = "zone_masp_verify_v1";
pub const LOCAL_VERIFIER_INSTRUCTION_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalRelayerError {
    Validation(String),
    Serialization(String),
    Verifier(String),
}

impl fmt::Display for LocalRelayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(err) => write!(f, "local/dev relayer validation error: {err}"),
            Self::Serialization(err) => write!(f, "local/dev relayer serialization error: {err}"),
            Self::Verifier(err) => write!(f, "local/dev relayer verifier error: {err}"),
        }
    }
}

impl Error for LocalRelayerError {}

impl From<LocalVerifierError> for LocalRelayerError {
    fn from(err: LocalVerifierError) -> Self {
        Self::Verifier(err.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalRelayerIntentPayload {
    pub proof_job_id: String,
    pub root_context: LocalRelayerRootContext,
    pub verifier_accounts: LocalVerifierAccounts,
    pub recent_blockhash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalRelayerRootContext {
    pub utxo_tree_id: String,
    pub utxo_root: String,
    pub utxo_root_index: u64,
    pub utxo_root_sequence: u64,
    pub nullifier_tree_id: String,
    pub nullifier_root: String,
    pub nullifier_root_index: u64,
    pub nullifier_root_sequence: u64,
    pub expires_after_slot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalVerifierAccounts {
    pub verifier_program_id: String,
    pub fee_payer: String,
    pub relayer_authority: Option<String>,
    pub utxo_tree: Option<String>,
    pub nullifier_tree: Option<String>,
    pub zone_config: Option<String>,
    pub compression_program: Option<String>,
    pub noop_program: Option<String>,
    pub system_program: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalRelayerJobResult {
    pub status: String,
    pub intent_hash: String,
    pub signer: String,
    pub proof_job_id: String,
    pub root_status: String,
    pub refreshable: bool,
    pub transaction_candidate: LocalTransactionCandidate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_verifier: Option<LocalVerifierCheckResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalTransactionCandidate {
    pub kind: String,
    pub verifier_program_id: String,
    pub message_hash: String,
    pub unsigned_transaction: LocalUnsignedTransaction,
    pub submission: String,
    pub next_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalUnsignedTransaction {
    pub format: String,
    pub recent_blockhash: Option<String>,
    pub fee_payer: String,
    pub instructions: Vec<LocalInstructionCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalInstructionCandidate {
    pub program_id: String,
    pub accounts: Vec<LocalInstructionAccountMeta>,
    pub data_encoding: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalInstructionAccountMeta {
    pub name: String,
    pub address: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalVerifierInstructionData {
    pub version: u8,
    pub tag: String,
    pub intent_hash: String,
    pub signer: String,
    pub root_context: LocalRelayerRootContext,
    pub proof_bundle: Vec<LocalRelayerProofOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalRelayerProofOutput {
    pub circuit_type: String,
    pub public_inputs_hash: String,
    pub prover_job_id: Option<String>,
    pub verifier_inputs: serde_json::Value,
    pub proof_result: serde_json::Value,
}

pub fn proof_job_id_from_intent_payload(intent_payload: &str) -> Result<String, LocalRelayerError> {
    Ok(parse_intent_payload(intent_payload)?.proof_job_id)
}

pub fn build_local_relayer_job_result(
    intent: &SignedZoneIntent,
    proof_jobs: &[ZoneProofJobView],
) -> Result<LocalRelayerJobResult, LocalRelayerError> {
    let payload = parse_intent_payload(&intent.intent_payload)?;
    validate_hex_32(&intent.intent_hash, "intentHash")?;
    let proof_bundle = proof_bundle_from_jobs(proof_jobs)?;
    let verifier_program_id = validate_pubkey(
        &payload.verifier_accounts.verifier_program_id,
        "verifierProgramId",
    )?;
    let fee_payer = validate_pubkey(&payload.verifier_accounts.fee_payer, "feePayer")?;
    let accounts = instruction_accounts(&payload)?;

    let instruction_data = LocalVerifierInstructionData {
        version: LOCAL_VERIFIER_INSTRUCTION_VERSION,
        tag: LOCAL_VERIFIER_INSTRUCTION_TAG.to_string(),
        intent_hash: normalized_hex_32(&intent.intent_hash, "intentHash")?,
        signer: intent.signer.clone(),
        root_context: payload.root_context.clone(),
        proof_bundle,
    };
    let instruction_data_bytes = serde_json::to_vec(&instruction_data)
        .map_err(|err| LocalRelayerError::Serialization(err.to_string()))?;
    let message_hash = Sha256::hash(&instruction_data_bytes)
        .map_err(|err| LocalRelayerError::Serialization(err.to_string()))?;

    Ok(LocalRelayerJobResult {
        status: "localTransactionCandidateBuilt".to_string(),
        intent_hash: normalized_hex_32(&intent.intent_hash, "intentHash")?,
        signer: intent.signer.clone(),
        proof_job_id: payload.proof_job_id,
        root_status: "providedAndBoundToProofs".to_string(),
        refreshable: false,
        transaction_candidate: LocalTransactionCandidate {
            kind: "local-dev-verifier-instruction".to_string(),
            verifier_program_id: verifier_program_id.to_string(),
            message_hash: hex_0x(&message_hash),
            unsigned_transaction: LocalUnsignedTransaction {
                format: "local-json-v1".to_string(),
                recent_blockhash: payload.recent_blockhash,
                fee_payer: fee_payer.to_string(),
                instructions: vec![LocalInstructionCandidate {
                    program_id: verifier_program_id.to_string(),
                    accounts,
                    data_encoding: "hex-json".to_string(),
                    data: hex_0x(&instruction_data_bytes),
                }],
            },
            submission: "notSubmitted".to_string(),
            next_action: "sign and submit the transaction with a real Solana relayer transport"
                .to_string(),
        },
        local_verifier: None,
    })
}

fn parse_intent_payload(
    intent_payload: &str,
) -> Result<LocalRelayerIntentPayload, LocalRelayerError> {
    let payload =
        serde_json::from_str::<LocalRelayerIntentPayload>(intent_payload).map_err(|err| {
            LocalRelayerError::Validation(format!(
                "intentPayload is not valid local relayer JSON: {err}"
            ))
        })?;
    if payload.proof_job_id.is_empty() {
        return Err(LocalRelayerError::Validation(
            "intentPayload.proofJobId must be non-empty".to_string(),
        ));
    }
    validate_root_context(&payload.root_context)?;
    validate_verifier_accounts(&payload)?;
    Ok(payload)
}

fn validate_root_context(context: &LocalRelayerRootContext) -> Result<(), LocalRelayerError> {
    validate_hex_32(&context.utxo_tree_id, "rootContext.utxoTreeId")?;
    validate_hex_32(&context.utxo_root, "rootContext.utxoRoot")?;
    validate_hex_32(&context.nullifier_tree_id, "rootContext.nullifierTreeId")?;
    validate_hex_32(&context.nullifier_root, "rootContext.nullifierRoot")?;
    Ok(())
}

fn validate_verifier_accounts(
    payload: &LocalRelayerIntentPayload,
) -> Result<(), LocalRelayerError> {
    validate_pubkey(
        &payload.verifier_accounts.verifier_program_id,
        "verifierAccounts.verifierProgramId",
    )?;
    validate_pubkey(
        &payload.verifier_accounts.fee_payer,
        "verifierAccounts.feePayer",
    )?;
    validate_optional_pubkey(
        payload.verifier_accounts.relayer_authority.as_deref(),
        "verifierAccounts.relayerAuthority",
    )?;
    validate_optional_pubkey(
        payload.verifier_accounts.zone_config.as_deref(),
        "verifierAccounts.zoneConfig",
    )?;
    validate_optional_pubkey(
        payload.verifier_accounts.compression_program.as_deref(),
        "verifierAccounts.compressionProgram",
    )?;
    validate_optional_pubkey(
        payload.verifier_accounts.noop_program.as_deref(),
        "verifierAccounts.noopProgram",
    )?;
    validate_optional_pubkey(
        payload.verifier_accounts.system_program.as_deref(),
        "verifierAccounts.systemProgram",
    )?;

    let utxo_tree =
        pubkey_from_hex_32(&payload.root_context.utxo_tree_id, "rootContext.utxoTreeId")?;
    let nullifier_tree = pubkey_from_hex_32(
        &payload.root_context.nullifier_tree_id,
        "rootContext.nullifierTreeId",
    )?;
    if let Some(account) = payload.verifier_accounts.utxo_tree.as_deref() {
        let account = validate_pubkey(account, "verifierAccounts.utxoTree")?;
        if account != utxo_tree {
            return Err(LocalRelayerError::Validation(
                "verifierAccounts.utxoTree does not match rootContext.utxoTreeId".to_string(),
            ));
        }
    }
    if let Some(account) = payload.verifier_accounts.nullifier_tree.as_deref() {
        let account = validate_pubkey(account, "verifierAccounts.nullifierTree")?;
        if account != nullifier_tree {
            return Err(LocalRelayerError::Validation(
                "verifierAccounts.nullifierTree does not match rootContext.nullifierTreeId"
                    .to_string(),
            ));
        }
    }

    Ok(())
}

fn proof_bundle_from_jobs(
    proof_jobs: &[ZoneProofJobView],
) -> Result<Vec<LocalRelayerProofOutput>, LocalRelayerError> {
    if proof_jobs.is_empty() {
        return Err(LocalRelayerError::Validation(
            "proof job result must contain at least one proof".to_string(),
        ));
    }
    if proof_jobs
        .iter()
        .any(|job| job.status != ZoneJobStatus::Succeeded)
    {
        return Err(LocalRelayerError::Validation(
            "submit_intent requires a succeeded proof job".to_string(),
        ));
    }

    let mut seen = HashSet::with_capacity(proof_jobs.len());
    let mut outputs = Vec::with_capacity(proof_jobs.len());
    for job in proof_jobs {
        if !seen.insert(job.circuit_type.as_str()) {
            return Err(LocalRelayerError::Validation(format!(
                "proof job contains duplicate circuitType {}",
                job.circuit_type
            )));
        }
        let public_inputs_hash = job.public_inputs_hash.clone().ok_or_else(|| {
            LocalRelayerError::Validation(format!(
                "proof job {} is missing publicInputsHash metadata",
                job.circuit_type
            ))
        })?;
        validate_public_inputs_hash(&public_inputs_hash, &job.circuit_type)?;
        let verifier_inputs = job.verifier_inputs.clone().ok_or_else(|| {
            LocalRelayerError::Validation(format!(
                "proof job {} is missing verifierInputs metadata",
                job.circuit_type
            ))
        })?;
        verify_public_inputs_hash(&job.circuit_type, &public_inputs_hash, &verifier_inputs)?;
        let result = job.result.as_deref().ok_or_else(|| {
            LocalRelayerError::Validation(format!(
                "proof job {} is missing proof result",
                job.circuit_type
            ))
        })?;
        outputs.push(LocalRelayerProofOutput {
            circuit_type: job.circuit_type.clone(),
            public_inputs_hash,
            prover_job_id: job.prover_job_id.clone(),
            verifier_inputs,
            proof_result: serde_json::from_str(result).unwrap_or_else(|_| json!({ "raw": result })),
        });
    }

    for required in ["masp-utxo", "masp-tree"] {
        if !seen.contains(required) {
            return Err(LocalRelayerError::Validation(format!(
                "proof job is missing required {required} proof"
            )));
        }
    }

    outputs.sort_by(|left, right| left.circuit_type.cmp(&right.circuit_type));
    Ok(outputs)
}

fn instruction_accounts(
    payload: &LocalRelayerIntentPayload,
) -> Result<Vec<LocalInstructionAccountMeta>, LocalRelayerError> {
    let utxo_tree =
        pubkey_from_hex_32(&payload.root_context.utxo_tree_id, "rootContext.utxoTreeId")?;
    let nullifier_tree = pubkey_from_hex_32(
        &payload.root_context.nullifier_tree_id,
        "rootContext.nullifierTreeId",
    )?;
    let mut accounts = vec![
        account_meta(
            "feePayer",
            validate_pubkey(
                &payload.verifier_accounts.fee_payer,
                "verifierAccounts.feePayer",
            )?,
            true,
            true,
        ),
        account_meta("utxoTree", utxo_tree, false, false),
        account_meta("nullifierTree", nullifier_tree, false, true),
    ];
    push_optional_account(
        &mut accounts,
        "relayerAuthority",
        payload.verifier_accounts.relayer_authority.as_deref(),
        true,
        false,
    )?;
    push_optional_account(
        &mut accounts,
        "zoneConfig",
        payload.verifier_accounts.zone_config.as_deref(),
        false,
        false,
    )?;
    push_optional_account(
        &mut accounts,
        "compressionProgram",
        payload.verifier_accounts.compression_program.as_deref(),
        false,
        false,
    )?;
    push_optional_account(
        &mut accounts,
        "noopProgram",
        payload.verifier_accounts.noop_program.as_deref(),
        false,
        false,
    )?;
    push_optional_account(
        &mut accounts,
        "systemProgram",
        payload.verifier_accounts.system_program.as_deref(),
        false,
        false,
    )?;
    Ok(accounts)
}

fn push_optional_account(
    accounts: &mut Vec<LocalInstructionAccountMeta>,
    name: &str,
    address: Option<&str>,
    is_signer: bool,
    is_writable: bool,
) -> Result<(), LocalRelayerError> {
    if let Some(address) = address {
        accounts.push(account_meta(
            name,
            validate_pubkey(address, &format!("verifierAccounts.{name}"))?,
            is_signer,
            is_writable,
        ));
    }
    Ok(())
}

fn account_meta(
    name: &str,
    address: Pubkey,
    is_signer: bool,
    is_writable: bool,
) -> LocalInstructionAccountMeta {
    LocalInstructionAccountMeta {
        name: name.to_string(),
        address: address.to_string(),
        is_signer,
        is_writable,
    }
}

fn validate_public_inputs_hash(value: &str, field: &str) -> Result<(), LocalRelayerError> {
    let decimal = value.chars().all(|char| char.is_ascii_digit()) && !value.is_empty();
    if decimal {
        return Ok(());
    }
    validate_hex_32(value, &format!("{field}.publicInputsHash")).map(|_| ())
}

fn validate_optional_pubkey(value: Option<&str>, field: &str) -> Result<(), LocalRelayerError> {
    if let Some(value) = value {
        validate_pubkey(value, field)?;
    }
    Ok(())
}

fn validate_pubkey(value: &str, field: &str) -> Result<Pubkey, LocalRelayerError> {
    value.parse::<Pubkey>().map_err(|err| {
        LocalRelayerError::Validation(format!("{field} must be a Solana pubkey: {err}"))
    })
}

fn pubkey_from_hex_32(value: &str, field: &str) -> Result<Pubkey, LocalRelayerError> {
    Ok(Pubkey::new_from_array(decode_hex_32(value, field)?))
}

fn validate_hex_32(value: &str, field: &str) -> Result<(), LocalRelayerError> {
    decode_hex_32(value, field).map(|_| ())
}

fn normalized_hex_32(value: &str, field: &str) -> Result<String, LocalRelayerError> {
    Ok(hex_0x(&decode_hex_32(value, field)?))
}

fn decode_hex_32(value: &str, field: &str) -> Result<[u8; 32], LocalRelayerError> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(hex)
        .map_err(|err| LocalRelayerError::Validation(format!("{field} is not valid hex: {err}")))?;
    if bytes.len() != 32 {
        return Err(LocalRelayerError::Validation(format!(
            "{field} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload(proof_job_id: &str) -> String {
        serde_json::json!({
            "proofJobId": proof_job_id,
            "rootContext": {
                "utxoTreeId": hex_0x(&[0x11; 32]),
                "utxoRoot": hex_0x(&[0x22; 32]),
                "utxoRootIndex": 1,
                "utxoRootSequence": 65,
                "nullifierTreeId": hex_0x(&[0x33; 32]),
                "nullifierRoot": hex_0x(&[0x44; 32]),
                "nullifierRootIndex": 2,
                "nullifierRootSequence": 66,
                "expiresAfterSlot": null
            },
            "verifierAccounts": {
                "verifierProgramId": Pubkey::new_from_array([0x55; 32]).to_string(),
                "feePayer": Pubkey::new_from_array([0x66; 32]).to_string(),
                "utxoTree": Pubkey::new_from_array([0x11; 32]).to_string(),
                "nullifierTree": Pubkey::new_from_array([0x33; 32]).to_string()
            },
            "recentBlockhash": "local-dev-blockhash"
        })
        .to_string()
    }

    fn sample_intent() -> SignedZoneIntent {
        SignedZoneIntent {
            intent_hash: hex_0x(&[0x77; 32]),
            intent_payload: sample_payload("proof-1"),
            signer: "local-dev-signer".to_string(),
            signature: "local-dev-signature".to_string(),
        }
    }

    fn sample_proof_jobs() -> Vec<ZoneProofJobView> {
        ["masp-utxo", "masp-tree"]
            .into_iter()
            .map(|circuit_type| {
                let verifier_inputs = sample_verifier_inputs(circuit_type);
                let public_inputs_hash =
                    crate::zone_rpc::local_verifier::compute_public_inputs_hash_from_verifier_inputs(
                        circuit_type,
                        &verifier_inputs,
                    )
                    .unwrap();
                ZoneProofJobView {
                circuit_type: circuit_type.to_string(),
                prover_job_id: None,
                status: ZoneJobStatus::Succeeded,
                public_inputs_hash: Some(public_inputs_hash),
                verifier_inputs: Some(verifier_inputs),
                result: Some(r#"{"proof":"ok"}"#.to_string()),
                error: None,
                }
            })
            .collect()
    }

    fn sample_verifier_inputs(circuit_type: &str) -> serde_json::Value {
        match circuit_type {
            "masp-utxo" => serde_json::json!({
                "shaTxHash": "0",
                "programIdHashchain": "0",
                "seedsHashchain": "0",
                "txHash": "0",
                "nullifierChain": "0"
            }),
            "masp-tree" => serde_json::json!({
                "stateRoots": ["1"],
                "nullifierRoots": ["2"],
                "nullifiers": ["3"],
                "accountOwnerHash": ["4"],
                "accountTreeHash": ["5"],
                "accountDiscriminator": ["6"]
            }),
            _ => unreachable!(),
        }
    }

    #[test]
    fn extracts_proof_job_id_from_intent_payload() {
        assert_eq!(
            proof_job_id_from_intent_payload(&sample_payload("proof-42")).unwrap(),
            "proof-42"
        );
    }

    #[test]
    fn builds_verifier_instruction_candidate() {
        let result =
            build_local_relayer_job_result(&sample_intent(), &sample_proof_jobs()).unwrap();

        assert_eq!(result.status, "localTransactionCandidateBuilt");
        assert_eq!(
            result.transaction_candidate.kind,
            "local-dev-verifier-instruction"
        );
        assert_eq!(
            result
                .transaction_candidate
                .unsigned_transaction
                .instructions[0]
                .data_encoding,
            "hex-json"
        );
        assert!(result
            .transaction_candidate
            .unsigned_transaction
            .instructions[0]
            .data
            .starts_with("0x"));
    }

    #[test]
    fn rejects_missing_required_masp_proof() {
        let mut jobs = sample_proof_jobs();
        jobs.pop();

        let err = build_local_relayer_job_result(&sample_intent(), &jobs).unwrap_err();
        assert!(matches!(err, LocalRelayerError::Validation(_)));
    }
}
