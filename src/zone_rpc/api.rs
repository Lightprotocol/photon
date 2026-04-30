//! Design-level Zone RPC façade.
//!
//! This module exposes the API names from `zones/design.md`. Granular Photon
//! helpers and private-store selectors remain backing implementation details.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use sea_orm::{DatabaseConnection, EntityTrait};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::error::PhotonApiError;
use crate::api::method::get_shielded_utxos::{
    get_shielded_utxo, get_shielded_utxos_by_signature, get_shielded_utxos_by_tree,
    get_shielded_utxos_by_zone, GetShieldedUtxoRequest, GetShieldedUtxosBySignatureRequest,
    GetShieldedUtxosByTreeRequest, GetShieldedUtxosByZoneRequest, ShieldedUtxoListResponse,
};
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::common::typedefs::serializable_signature::SerializableSignature;
use crate::dao::generated::zone_configs;
use crate::zone_rpc::jobs::{LocalZoneJobStore, ZoneJobKind};
use crate::zone_rpc::private_api::{
    GetZoneUtxosByOwnerHashRequest, GetZoneUtxosByOwnerPubkeyRequest,
    ZoneDecryptedUtxoListResponse, ZoneQueryAuthorization, ZoneRpcPrivateApi,
    ZoneRpcPrivateApiError,
};
use crate::zone_rpc::prover_client::{
    ProverClientError, ProverProofClient, ProverProofMode, ProverProofRequest, ProverProofStatus,
    ProverProofSubmission,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneRpcApiError {
    Validation(String),
    Photon(String),
    Private(String),
    Prover(String),
    ProofInputUnavailable(String),
    JobNotFound(String),
    NotImplemented(&'static str),
}

impl fmt::Display for ZoneRpcApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(err) => write!(f, "zone rpc validation error: {err}"),
            Self::Photon(err) => write!(f, "photon backing API error: {err}"),
            Self::Private(err) => write!(f, "zone private API error: {err}"),
            Self::Prover(err) => write!(f, "zone prover error: {err}"),
            Self::ProofInputUnavailable(err) => write!(f, "proof input unavailable: {err}"),
            Self::JobNotFound(job_id) => write!(f, "zone rpc job not found: {job_id}"),
            Self::NotImplemented(method) => write!(f, "{method} is not implemented yet"),
        }
    }
}

impl Error for ZoneRpcApiError {}

impl From<PhotonApiError> for ZoneRpcApiError {
    fn from(err: PhotonApiError) -> Self {
        Self::Photon(err.to_string())
    }
}

impl From<ZoneRpcPrivateApiError> for ZoneRpcApiError {
    fn from(err: ZoneRpcPrivateApiError) -> Self {
        Self::Private(err.to_string())
    }
}

impl From<ProverClientError> for ZoneRpcApiError {
    fn from(err: ProverClientError) -> Self {
        Self::Prover(err.to_string())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FetchUtxosRequest {
    /// Hex-encoded 32-byte UTXO hash. Mutually exclusive with other selectors.
    pub utxo_hash: Option<String>,
    /// Hex-encoded 32-byte zone config hash. Mutually exclusive with other selectors.
    pub zone_config_hash: Option<String>,
    /// Solana transaction signature. Mutually exclusive with other selectors.
    pub signature: Option<SerializableSignature>,
    /// UTXO tree pubkey. Mutually exclusive with other selectors.
    pub utxo_tree: Option<SerializablePubkey>,
    pub limit: Option<u64>,
    pub before_slot: Option<u64>,
    pub before_leaf_index: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FetchDecryptedUtxosRequest {
    pub zone_config_hash: String,
    /// Hex-encoded owner hash. Mutually exclusive with `owner_pubkey`.
    pub owner_hash: Option<String>,
    /// Hex-encoded owner pubkey. Mutually exclusive with `owner_hash`.
    pub owner_pubkey: Option<String>,
    pub authorization: ZoneQueryAuthorization,
    pub include_spent: Option<bool>,
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FetchProofInputsRequest {
    pub zone_config_hash: String,
    pub input_utxo_hashes: Vec<String>,
    pub recent_root_preference: Option<String>,
    pub authorization: ZoneQueryAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FetchProofInputsResponse {
    pub zone_config_hash: String,
    pub recent_root_preference: Option<String>,
    pub inputs: Vec<ProofInputUtxoView>,
    pub root_context: Option<ProofRootContextView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProofInputUtxoView {
    pub utxo_hash: String,
    pub utxo_tree: String,
    pub leaf_index: u64,
    pub tree_sequence: u64,
    pub operation_commitment: String,
    pub encrypted_utxo_hash: String,
    pub nullifier_chain: Option<String>,
    pub input_nullifiers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProofRootContextView {
    pub utxo_root: String,
    pub nullifier_root: String,
    pub root_slot: u64,
    pub utxo_tree_sequence: u64,
    pub nullifier_tree_sequence: u64,
    pub expires_after_slot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedZoneIntent {
    pub intent_hash: String,
    pub intent_payload: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FetchProofsRequest {
    pub intent: SignedZoneIntent,
    #[serde(default)]
    pub proof_requests: Vec<ProverProofRequest>,
    pub prover_mode: Option<ProverProofMode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FetchProofsResponse {
    pub proof_job_id: String,
    pub proof_jobs: Vec<ZoneProofJobView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ZoneProofJobView {
    pub circuit_type: String,
    pub prover_job_id: Option<String>,
    pub status: ZoneJobStatus,
    pub result: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubmitIntentRequest {
    pub intent: SignedZoneIntent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubmitIntentResponse {
    pub relayer_job_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetProofJobRequest {
    pub proof_job_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRelayerJobRequest {
    pub relayer_job_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ZoneJobResponse {
    pub job_id: String,
    pub status: ZoneJobStatus,
    pub result: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ZoneJobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetZoneInfoRequest {
    pub zone_config_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetZoneInfoResponse {
    pub value: Option<ZoneInfoView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ZoneInfoView {
    pub zone_config_hash: String,
    pub first_seen_slot: u64,
    pub last_seen_slot: u64,
    pub metadata: Option<String>,
}

pub struct ZoneRpcApi {
    photon_conn: Arc<DatabaseConnection>,
    private_api: ZoneRpcPrivateApi,
    job_store: LocalZoneJobStore,
    proof_client: Option<ProverProofClient>,
}

impl ZoneRpcApi {
    pub fn new(photon_conn: Arc<DatabaseConnection>, private_api: ZoneRpcPrivateApi) -> Self {
        Self::with_job_store_and_proof_client(
            photon_conn,
            private_api,
            LocalZoneJobStore::default(),
            None,
        )
    }

    pub fn with_proof_client(
        photon_conn: Arc<DatabaseConnection>,
        private_api: ZoneRpcPrivateApi,
        proof_client: ProverProofClient,
    ) -> Self {
        Self::with_job_store_and_proof_client(
            photon_conn,
            private_api,
            LocalZoneJobStore::default(),
            Some(proof_client),
        )
    }

    pub fn with_job_store_and_proof_client(
        photon_conn: Arc<DatabaseConnection>,
        private_api: ZoneRpcPrivateApi,
        job_store: LocalZoneJobStore,
        proof_client: Option<ProverProofClient>,
    ) -> Self {
        Self {
            photon_conn,
            private_api,
            job_store,
            proof_client,
        }
    }

    pub async fn fetch_utxos(
        &self,
        request: FetchUtxosRequest,
    ) -> Result<ShieldedUtxoListResponse, ZoneRpcApiError> {
        match selected_fetch_utxo_filter(&request)? {
            FetchUtxosFilter::UtxoHash => {
                let response = get_shielded_utxo(
                    self.photon_conn.as_ref(),
                    GetShieldedUtxoRequest {
                        utxo_hash: request.utxo_hash.expect("selector validated"),
                    },
                )
                .await?;
                Ok(ShieldedUtxoListResponse {
                    context: response.context,
                    items: response.value.into_iter().collect(),
                })
            }
            FetchUtxosFilter::Zone => Ok(get_shielded_utxos_by_zone(
                self.photon_conn.as_ref(),
                GetShieldedUtxosByZoneRequest {
                    zone_config_hash: request.zone_config_hash.expect("selector validated"),
                    limit: request.limit,
                    before_slot: request.before_slot,
                },
            )
            .await?),
            FetchUtxosFilter::Signature => Ok(get_shielded_utxos_by_signature(
                self.photon_conn.as_ref(),
                GetShieldedUtxosBySignatureRequest {
                    signature: request.signature.expect("selector validated"),
                },
            )
            .await?),
            FetchUtxosFilter::Tree => Ok(get_shielded_utxos_by_tree(
                self.photon_conn.as_ref(),
                GetShieldedUtxosByTreeRequest {
                    utxo_tree: request.utxo_tree.expect("selector validated"),
                    limit: request.limit,
                    before_leaf_index: request.before_leaf_index,
                },
            )
            .await?),
        }
    }

    pub async fn fetch_decrypted_utxos(
        &self,
        request: FetchDecryptedUtxosRequest,
    ) -> Result<ZoneDecryptedUtxoListResponse, ZoneRpcApiError> {
        match selected_decrypted_selector(&request)? {
            FetchDecryptedUtxosSelector::OwnerHash => Ok(self
                .private_api
                .get_decrypted_utxos_by_owner_hash(GetZoneUtxosByOwnerHashRequest {
                    zone_config_hash: request.zone_config_hash,
                    owner_hash: request.owner_hash.expect("selector validated"),
                    authorization: request.authorization,
                    include_spent: request.include_spent,
                    limit: request.limit,
                })
                .await?),
            FetchDecryptedUtxosSelector::OwnerPubkey => Ok(self
                .private_api
                .get_decrypted_utxos_by_owner_pubkey(GetZoneUtxosByOwnerPubkeyRequest {
                    zone_config_hash: request.zone_config_hash,
                    owner_pubkey: request.owner_pubkey.expect("selector validated"),
                    authorization: request.authorization,
                    include_spent: request.include_spent,
                    limit: request.limit,
                })
                .await?),
        }
    }

    pub async fn fetch_proof_inputs(
        &self,
        request: FetchProofInputsRequest,
    ) -> Result<FetchProofInputsResponse, ZoneRpcApiError> {
        let zone_config_hash = decode_hex_32(&request.zone_config_hash, "zoneConfigHash")?;
        if request.input_utxo_hashes.is_empty() {
            return Err(ZoneRpcApiError::Validation(
                "fetch_proof_inputs requires at least one input_utxo_hash".to_string(),
            ));
        }
        if let Some(root) = &request.recent_root_preference {
            decode_hex_32(root, "recentRootPreference")?;
        }
        validate_authorization_shape(&request.authorization)?;

        let zone_config_hash_hex = hex_encode(&zone_config_hash);
        let mut inputs = Vec::with_capacity(request.input_utxo_hashes.len());
        for (index, utxo_hash) in request.input_utxo_hashes.iter().enumerate() {
            let utxo_hash_bytes = decode_hex_32(utxo_hash, &format!("inputUtxoHashes[{index}]"))?;
            let response = get_shielded_utxo(
                self.photon_conn.as_ref(),
                GetShieldedUtxoRequest {
                    utxo_hash: hex_encode(&utxo_hash_bytes),
                },
            )
            .await?;
            let record = response.value.ok_or_else(|| {
                ZoneRpcApiError::ProofInputUnavailable(format!(
                    "input UTXO {} is not indexed by Photon",
                    hex_encode(&utxo_hash_bytes)
                ))
            })?;
            if record.zone_config_hash.as_deref() != Some(zone_config_hash_hex.as_str()) {
                return Err(ZoneRpcApiError::Validation(format!(
                    "input UTXO {} does not belong to requested zone",
                    record.utxo_hash
                )));
            }

            inputs.push(ProofInputUtxoView {
                utxo_hash: record.utxo_hash,
                utxo_tree: record.utxo_tree,
                leaf_index: record.leaf_index,
                tree_sequence: record.sequence_number,
                operation_commitment: record.event.operation_commitment,
                encrypted_utxo_hash: record.encrypted_utxo_hash,
                nullifier_chain: record.event.nullifier_chain,
                input_nullifiers: record.event.input_nullifiers,
            });
        }

        Ok(FetchProofInputsResponse {
            zone_config_hash: zone_config_hash_hex,
            recent_root_preference: request.recent_root_preference,
            inputs,
            root_context: None,
        })
    }

    pub async fn fetch_proofs(
        &self,
        request: FetchProofsRequest,
    ) -> Result<FetchProofsResponse, ZoneRpcApiError> {
        validate_signed_intent(&request.intent)?;
        if request.proof_requests.is_empty() {
            return Err(ZoneRpcApiError::Validation(
                "fetch_proofs requires at least one prover proof request".to_string(),
            ));
        }
        let proof_client = self.proof_client.as_ref().ok_or_else(|| {
            ZoneRpcApiError::Prover("prover client is not configured".to_string())
        })?;
        let prover_mode = request.prover_mode.unwrap_or(ProverProofMode::Sync);

        let mut proof_jobs = Vec::with_capacity(request.proof_requests.len());
        for proof_request in request.proof_requests {
            let submission = proof_client
                .submit_proof(&proof_request, prover_mode)
                .await
                .map_err(ZoneRpcApiError::from)?;
            proof_jobs.push(ZoneProofJobView::from(submission));
        }

        let status = aggregate_proof_job_status(&proof_jobs);
        let result = serde_json::to_string(&proof_jobs)
            .map_err(|err| ZoneRpcApiError::Prover(err.to_string()))?;
        let job = self
            .job_store
            .create_job(ZoneJobKind::Proof, status, Some(result), None);
        Ok(FetchProofsResponse {
            proof_job_id: job.job_id,
            proof_jobs,
        })
    }

    pub async fn submit_intent(
        &self,
        request: SubmitIntentRequest,
    ) -> Result<SubmitIntentResponse, ZoneRpcApiError> {
        validate_signed_intent(&request.intent)?;
        let job = self.job_store.create_queued_job(ZoneJobKind::Relayer);
        Ok(SubmitIntentResponse {
            relayer_job_id: job.job_id,
        })
    }

    pub async fn get_proof_job(
        &self,
        request: GetProofJobRequest,
    ) -> Result<ZoneJobResponse, ZoneRpcApiError> {
        validate_job_id(&request.proof_job_id, "proofJobId")?;
        let job = self
            .job_store
            .get_job(&request.proof_job_id)
            .ok_or(ZoneRpcApiError::JobNotFound(request.proof_job_id))?;
        self.refresh_proof_job(job).await
    }

    pub async fn get_relayer_job(
        &self,
        request: GetRelayerJobRequest,
    ) -> Result<ZoneJobResponse, ZoneRpcApiError> {
        validate_job_id(&request.relayer_job_id, "relayerJobId")?;
        self.job_store
            .get_job(&request.relayer_job_id)
            .ok_or(ZoneRpcApiError::JobNotFound(request.relayer_job_id))
    }

    pub async fn get_zone_info(
        &self,
        request: GetZoneInfoRequest,
    ) -> Result<GetZoneInfoResponse, ZoneRpcApiError> {
        let zone_config_hash = decode_hex_32(&request.zone_config_hash, "zoneConfigHash")?;
        let value = zone_configs::Entity::find_by_id(zone_config_hash.to_vec())
            .one(self.photon_conn.as_ref())
            .await
            .map_err(|err| ZoneRpcApiError::Photon(err.to_string()))?
            .map(|model| ZoneInfoView {
                zone_config_hash: hex_encode(&model.zone_config_hash),
                first_seen_slot: model.first_seen_slot as u64,
                last_seen_slot: model.last_seen_slot as u64,
                metadata: model.metadata.as_deref().map(hex_encode),
            });
        Ok(GetZoneInfoResponse { value })
    }

    async fn refresh_proof_job(
        &self,
        mut job: ZoneJobResponse,
    ) -> Result<ZoneJobResponse, ZoneRpcApiError> {
        if matches!(job.status, ZoneJobStatus::Succeeded | ZoneJobStatus::Failed) {
            return Ok(job);
        }
        let Some(proof_client) = &self.proof_client else {
            return Ok(job);
        };
        let Some(result) = &job.result else {
            return Ok(job);
        };
        let mut proof_jobs = match serde_json::from_str::<Vec<ZoneProofJobView>>(result) {
            Ok(proof_jobs) => proof_jobs,
            Err(_) => return Ok(job),
        };
        let mut changed = false;
        for proof_job in &mut proof_jobs {
            if matches!(
                proof_job.status,
                ZoneJobStatus::Succeeded | ZoneJobStatus::Failed
            ) {
                continue;
            }
            let Some(prover_job_id) = proof_job.prover_job_id.clone() else {
                continue;
            };
            let status = proof_client
                .get_proof_status(&prover_job_id)
                .await
                .map_err(ZoneRpcApiError::from)?;
            *proof_job = ZoneProofJobView::from(status);
            changed = true;
        }
        if changed {
            job.status = aggregate_proof_job_status(&proof_jobs);
            job.result = Some(
                serde_json::to_string(&proof_jobs)
                    .map_err(|err| ZoneRpcApiError::Prover(err.to_string()))?,
            );
            if job.status == ZoneJobStatus::Failed {
                job.error = proof_jobs
                    .iter()
                    .find_map(|proof_job| proof_job.error.clone());
            }
            self.job_store.upsert_job(job.clone());
        }
        Ok(job)
    }
}

impl From<ProverProofSubmission> for ZoneProofJobView {
    fn from(submission: ProverProofSubmission) -> Self {
        Self {
            circuit_type: submission.circuit_type,
            prover_job_id: submission.prover_job_id,
            status: ZoneJobStatus::from(submission.status),
            result: submission.result,
            error: submission.error,
        }
    }
}

impl From<ProverProofStatus> for ZoneJobStatus {
    fn from(status: ProverProofStatus) -> Self {
        match status {
            ProverProofStatus::Queued => Self::Queued,
            ProverProofStatus::Running => Self::Running,
            ProverProofStatus::Succeeded => Self::Succeeded,
            ProverProofStatus::Failed => Self::Failed,
        }
    }
}

fn aggregate_proof_job_status(proof_jobs: &[ZoneProofJobView]) -> ZoneJobStatus {
    if proof_jobs
        .iter()
        .any(|job| matches!(job.status, ZoneJobStatus::Failed))
    {
        return ZoneJobStatus::Failed;
    }
    if proof_jobs
        .iter()
        .all(|job| matches!(job.status, ZoneJobStatus::Succeeded))
    {
        return ZoneJobStatus::Succeeded;
    }
    if proof_jobs
        .iter()
        .any(|job| matches!(job.status, ZoneJobStatus::Running))
    {
        return ZoneJobStatus::Running;
    }
    ZoneJobStatus::Queued
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchUtxosFilter {
    UtxoHash,
    Zone,
    Signature,
    Tree,
}

fn selected_fetch_utxo_filter(
    request: &FetchUtxosRequest,
) -> Result<FetchUtxosFilter, ZoneRpcApiError> {
    let mut selected = Vec::new();
    if request.utxo_hash.is_some() {
        selected.push(FetchUtxosFilter::UtxoHash);
    }
    if request.zone_config_hash.is_some() {
        selected.push(FetchUtxosFilter::Zone);
    }
    if request.signature.is_some() {
        selected.push(FetchUtxosFilter::Signature);
    }
    if request.utxo_tree.is_some() {
        selected.push(FetchUtxosFilter::Tree);
    }
    match selected.as_slice() {
        [filter] => Ok(*filter),
        [] => Err(ZoneRpcApiError::Validation(
            "fetch_utxos requires exactly one selector".to_string(),
        )),
        _ => Err(ZoneRpcApiError::Validation(
            "fetch_utxos selectors are mutually exclusive".to_string(),
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchDecryptedUtxosSelector {
    OwnerHash,
    OwnerPubkey,
}

fn selected_decrypted_selector(
    request: &FetchDecryptedUtxosRequest,
) -> Result<FetchDecryptedUtxosSelector, ZoneRpcApiError> {
    match (request.owner_hash.is_some(), request.owner_pubkey.is_some()) {
        (true, false) => Ok(FetchDecryptedUtxosSelector::OwnerHash),
        (false, true) => Ok(FetchDecryptedUtxosSelector::OwnerPubkey),
        (false, false) => Err(ZoneRpcApiError::Validation(
            "fetch_decrypted_utxos requires owner_hash or owner_pubkey".to_string(),
        )),
        (true, true) => Err(ZoneRpcApiError::Validation(
            "owner_hash and owner_pubkey are mutually exclusive".to_string(),
        )),
    }
}

fn validate_authorization_shape(
    authorization: &ZoneQueryAuthorization,
) -> Result<(), ZoneRpcApiError> {
    if authorization.requester.is_empty()
        || authorization.message.is_empty()
        || authorization.signature.is_empty()
    {
        return Err(ZoneRpcApiError::Validation(
            "authorization requester, message, and signature must be non-empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_signed_intent(intent: &SignedZoneIntent) -> Result<(), ZoneRpcApiError> {
    if intent.intent_hash.is_empty()
        || intent.intent_payload.is_empty()
        || intent.signer.is_empty()
        || intent.signature.is_empty()
    {
        return Err(ZoneRpcApiError::Validation(
            "intent_hash, intent_payload, signer, and signature must be non-empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_job_id(job_id: &str, field: &str) -> Result<(), ZoneRpcApiError> {
    if job_id.is_empty() {
        return Err(ZoneRpcApiError::Validation(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn decode_hex_32(input: &str, field: &str) -> Result<[u8; 32], ZoneRpcApiError> {
    let trimmed = input.trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|err| ZoneRpcApiError::Validation(format!("{field} is not valid hex: {err}")))?;
    if bytes.len() != 32 {
        return Err(ZoneRpcApiError::Validation(format!(
            "{field} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_utxos_requires_exactly_one_selector() {
        assert!(matches!(
            selected_fetch_utxo_filter(&FetchUtxosRequest::default()),
            Err(ZoneRpcApiError::Validation(_))
        ));

        let err = selected_fetch_utxo_filter(&FetchUtxosRequest {
            utxo_hash: Some(hex_encode(&[1u8; 32])),
            zone_config_hash: Some(hex_encode(&[2u8; 32])),
            ..FetchUtxosRequest::default()
        })
        .unwrap_err();
        assert!(matches!(err, ZoneRpcApiError::Validation(_)));

        let filter = selected_fetch_utxo_filter(&FetchUtxosRequest {
            zone_config_hash: Some(hex_encode(&[2u8; 32])),
            ..FetchUtxosRequest::default()
        })
        .unwrap();
        assert_eq!(filter, FetchUtxosFilter::Zone);
    }

    #[test]
    fn fetch_decrypted_utxos_requires_exactly_one_selector() {
        let authorization = ZoneQueryAuthorization {
            requester: "local-test".to_string(),
            message: "local-test-query".to_string(),
            signature: "local-test-signature".to_string(),
        };

        let base = FetchDecryptedUtxosRequest {
            zone_config_hash: hex_encode(&[1u8; 32]),
            owner_hash: None,
            owner_pubkey: None,
            authorization,
            include_spent: None,
            limit: None,
        };
        assert!(matches!(
            selected_decrypted_selector(&base),
            Err(ZoneRpcApiError::Validation(_))
        ));

        let mut valid = base.clone();
        valid.owner_hash = Some(hex_encode(&[2u8; 32]));
        assert_eq!(
            selected_decrypted_selector(&valid).unwrap(),
            FetchDecryptedUtxosSelector::OwnerHash
        );

        valid.owner_pubkey = Some(hex_encode(&[3u8; 32]));
        assert!(matches!(
            selected_decrypted_selector(&valid),
            Err(ZoneRpcApiError::Validation(_))
        ));
    }

    #[test]
    fn proof_input_request_validates_authorization_shape() {
        let err = validate_authorization_shape(&ZoneQueryAuthorization {
            requester: String::new(),
            message: "message".to_string(),
            signature: "signature".to_string(),
        })
        .unwrap_err();

        assert!(matches!(err, ZoneRpcApiError::Validation(_)));
    }

    #[test]
    fn intent_and_job_ids_validate_non_empty_fields() {
        let err = validate_signed_intent(&SignedZoneIntent {
            intent_hash: "hash".to_string(),
            intent_payload: String::new(),
            signer: "signer".to_string(),
            signature: "signature".to_string(),
        })
        .unwrap_err();
        assert!(matches!(err, ZoneRpcApiError::Validation(_)));

        assert!(matches!(
            validate_job_id("", "proofJobId"),
            Err(ZoneRpcApiError::Validation(_))
        ));
    }
}
