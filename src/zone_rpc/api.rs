//! Design-level Zone RPC façade.
//!
//! This module exposes the API names from `zones/design.md`. Granular Photon
//! helpers and private-store selectors remain backing implementation details.

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use light_compressed_account::hash_to_bn254_field_size_be;
use num_bigint::BigUint;
use sea_orm::{DatabaseConnection, EntityTrait, TransactionTrait};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::error::PhotonApiError;
use crate::api::method::get_compressed_account_proof::{
    get_compressed_account_proof_v2, GetCompressedAccountProofResponseValueV2,
};
use crate::api::method::get_multiple_new_address_proofs::{
    get_multiple_new_address_proofs_helper, AddressWithTree, MerkleContextWithNewAddressProof,
    MAX_ADDRESSES,
};
use crate::api::method::get_shielded_utxos::{
    get_shielded_utxo, get_shielded_utxos_by_signature, get_shielded_utxos_by_tree,
    get_shielded_utxos_by_zone, GetShieldedUtxoRequest, GetShieldedUtxosBySignatureRequest,
    GetShieldedUtxosByTreeRequest, GetShieldedUtxosByZoneRequest, ShieldedUtxoListResponse,
};
use crate::api::method::utils::HashRequest;
use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::common::typedefs::serializable_signature::SerializableSignature;
use crate::dao::generated::{accounts, tree_metadata, zone_configs};
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
    #[serde(default)]
    pub spend_nullifiers: Vec<String>,
    pub nullifier_tree: Option<SerializablePubkey>,
    pub utxo_root_sequence: Option<u64>,
    pub nullifier_root_sequence: Option<u64>,
    pub authorization: ZoneQueryAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FetchProofInputsResponse {
    pub zone_config_hash: String,
    pub utxo_root_sequence: Option<u64>,
    pub nullifier_root_sequence: Option<u64>,
    pub inputs: Vec<ProofInputUtxoView>,
    pub root_context: Option<ProofRootContextView>,
    pub root_context_status: ProofRootContextStatusView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProofInputUtxoView {
    pub utxo_hash: String,
    pub spend_nullifier: Option<String>,
    pub compressed_account_hash: String,
    pub account_owner_hash: String,
    pub account_tree_hash: String,
    pub account_discriminator: String,
    pub compressed_output_index: u32,
    pub utxo_tree: String,
    pub leaf_index: u64,
    pub tree_sequence: u64,
    pub tx_signature: SerializableSignature,
    pub slot: u64,
    pub event_index: u32,
    pub output_index: u8,
    pub operation_commitment: String,
    pub encrypted_utxo: String,
    pub encrypted_utxo_hash: String,
    pub nullifier_chain: Option<String>,
    pub input_nullifiers: Vec<String>,
    pub compressed_account_proof: Option<CompressedAccountProofView>,
    pub nullifier_non_inclusion_proof: Option<NullifierNonInclusionProofView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompressedAccountProofView {
    pub root: String,
    pub root_index: Option<u64>,
    pub proof: Vec<String>,
    pub path_directions: Vec<u8>,
    pub leaf_index: u32,
    pub hash: String,
    pub root_sequence: u64,
    pub prove_by_index: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NullifierNonInclusionProofView {
    pub nullifier: String,
    pub nullifier_tree: SerializablePubkey,
    pub root: String,
    pub root_index: u64,
    pub root_sequence: u64,
    pub low_value: String,
    pub next_value: String,
    pub next_index: u32,
    pub low_leaf_index: u32,
    pub proof: Vec<String>,
    pub path_directions: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProofRootContextView {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProofRootContextStatusView {
    pub is_available: bool,
    pub utxo_inclusion_proofs_available: bool,
    pub nullifier_context_available: bool,
    pub required_utxo_trees: Vec<ProofTreeRequirementView>,
    pub unavailable_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProofTreeRequirementView {
    pub utxo_tree: String,
    pub input_count: u64,
    pub min_leaf_index: u64,
    pub max_leaf_index: u64,
    pub max_tree_sequence: u64,
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
        validate_authorization_shape(&request.authorization)?;
        let spend_nullifiers = decode_spend_nullifiers(&request)?;

        let zone_config_hash_hex = hex_encode(&zone_config_hash);
        let mut inputs = Vec::with_capacity(request.input_utxo_hashes.len());
        let mut seen_input_hashes = HashSet::with_capacity(request.input_utxo_hashes.len());
        let mut unavailable_reasons = Vec::new();
        for (index, utxo_hash) in request.input_utxo_hashes.iter().enumerate() {
            let utxo_hash_bytes = decode_hex_32(utxo_hash, &format!("inputUtxoHashes[{index}]"))?;
            if !seen_input_hashes.insert(utxo_hash_bytes) {
                return Err(ZoneRpcApiError::Validation(format!(
                    "inputUtxoHashes[{index}] duplicates an earlier input"
                )));
            }
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

            let compressed_account_hash_bytes =
                decode_hex_32(&record.compressed_account_hash, "compressedAccountHash")?;
            let account_binding = fetch_light_account_binding(
                self.photon_conn.as_ref(),
                &compressed_account_hash_bytes,
            )
            .await?;
            let compressed_account_proof = match get_compressed_account_proof_v2(
                self.photon_conn.as_ref(),
                HashRequest {
                    hash: Hash(compressed_account_hash_bytes),
                },
            )
            .await
            {
                Ok(response) => Some(compressed_account_proof_view(response.value)),
                Err(PhotonApiError::RecordNotFound(err)) => {
                    unavailable_reasons.push(format!(
                        "compressed account proof unavailable for input {}: Record Not Found: {}",
                        record.utxo_hash, err
                    ));
                    None
                }
                Err(err) => return Err(ZoneRpcApiError::from(err)),
            };

            inputs.push(ProofInputUtxoView {
                utxo_hash: record.utxo_hash,
                spend_nullifier: spend_nullifiers
                    .as_ref()
                    .map(|nullifiers| hex_encode(&nullifiers[index])),
                compressed_account_hash: record.compressed_account_hash,
                account_owner_hash: account_binding.owner_hash,
                account_tree_hash: account_binding.tree_hash,
                account_discriminator: account_binding.discriminator,
                compressed_output_index: record.compressed_output_index,
                utxo_tree: record.utxo_tree,
                leaf_index: record.leaf_index,
                tree_sequence: record.sequence_number,
                tx_signature: record.signature,
                slot: record.slot,
                event_index: record.event_index,
                output_index: record.output_index,
                operation_commitment: record.event.operation_commitment,
                encrypted_utxo: record.encrypted_utxo,
                encrypted_utxo_hash: record.encrypted_utxo_hash,
                nullifier_chain: record.event.nullifier_chain,
                input_nullifiers: record.event.input_nullifiers,
                compressed_account_proof,
                nullifier_non_inclusion_proof: None,
            });
        }

        attach_utxo_root_indices(
            self.photon_conn.as_ref(),
            &mut inputs,
            &mut unavailable_reasons,
        )
        .await?;

        if let (Some(nullifier_tree), Some(spend_nullifiers)) =
            (request.nullifier_tree, spend_nullifiers.as_ref())
        {
            let nullifier_proofs = fetch_nullifier_non_inclusion_proofs(
                self.photon_conn.as_ref(),
                nullifier_tree,
                spend_nullifiers,
            )
            .await?;
            for (input, proof) in inputs.iter_mut().zip(nullifier_proofs) {
                input.nullifier_non_inclusion_proof = Some(proof);
            }
        } else {
            unavailable_reasons.push(
                "spendNullifiers and nullifierTree are required for nullifier non-inclusion context"
                    .to_string(),
            );
        }

        let utxo_inclusion_proofs_available = inputs.iter().all(|input| {
            input
                .compressed_account_proof
                .as_ref()
                .is_some_and(|proof| proof.root_index.is_some())
        });
        let nullifier_context_available = inputs
            .iter()
            .all(|input| input.nullifier_non_inclusion_proof.is_some());
        let requested_sequences_satisfied = validate_requested_root_sequences(
            &inputs,
            request.utxo_root_sequence,
            request.nullifier_root_sequence,
            &mut unavailable_reasons,
        );
        let mut root_context = build_root_context(&inputs, &mut unavailable_reasons);
        if !requested_sequences_satisfied {
            root_context = None;
        }

        let root_context_status = ProofRootContextStatusView {
            is_available: root_context.is_some(),
            utxo_inclusion_proofs_available,
            nullifier_context_available,
            required_utxo_trees: summarize_proof_tree_requirements(&inputs),
            unavailable_reasons,
        };

        Ok(FetchProofInputsResponse {
            zone_config_hash: zone_config_hash_hex,
            utxo_root_sequence: root_context
                .as_ref()
                .map(|context| context.utxo_root_sequence),
            nullifier_root_sequence: root_context
                .as_ref()
                .map(|context| context.nullifier_root_sequence),
            inputs,
            root_context,
            root_context_status,
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

struct LightAccountBindingView {
    owner_hash: String,
    tree_hash: String,
    discriminator: String,
}

async fn fetch_light_account_binding(
    conn: &DatabaseConnection,
    compressed_account_hash: &[u8; 32],
) -> Result<LightAccountBindingView, ZoneRpcApiError> {
    let account = accounts::Entity::find_by_id(compressed_account_hash.to_vec())
        .one(conn)
        .await
        .map_err(|err| ZoneRpcApiError::Photon(err.to_string()))?
        .ok_or_else(|| {
            ZoneRpcApiError::ProofInputUnavailable(format!(
                "compressed account {} is not indexed by Photon",
                hex_encode(compressed_account_hash)
            ))
        })?;

    let discriminator = account.discriminator_v2.ok_or_else(|| {
        ZoneRpcApiError::ProofInputUnavailable(format!(
            "compressed account {} has no account data discriminator",
            hex_encode(compressed_account_hash)
        ))
    })?;
    if discriminator.len() != 8 {
        return Err(ZoneRpcApiError::Photon(format!(
            "compressed account {} discriminator_v2 must be 8 bytes, got {}",
            hex_encode(compressed_account_hash),
            discriminator.len()
        )));
    }

    Ok(LightAccountBindingView {
        owner_hash: decimal_from_field_bytes(&hash_to_bn254_field_size_be(&account.owner)),
        tree_hash: decimal_from_field_bytes(&hash_to_bn254_field_size_be(&account.tree)),
        discriminator: BigUint::from_bytes_be(&discriminator).to_str_radix(10),
    })
}

fn compressed_account_proof_view(
    proof: GetCompressedAccountProofResponseValueV2,
) -> CompressedAccountProofView {
    CompressedAccountProofView {
        root: hex_encode(&proof.root.0),
        root_index: None,
        proof: proof.proof.iter().map(|node| hex_encode(&node.0)).collect(),
        path_directions: merkle_path_directions(proof.leaf_index as u64, proof.proof.len()),
        leaf_index: proof.leaf_index,
        hash: hex_encode(&proof.hash.0),
        root_sequence: proof.root_seq,
        prove_by_index: proof.prove_by_index,
    }
}

async fn attach_utxo_root_indices(
    conn: &DatabaseConnection,
    inputs: &mut [ProofInputUtxoView],
    unavailable_reasons: &mut Vec<String>,
) -> Result<(), ZoneRpcApiError> {
    for input in inputs {
        let Some(proof) = &mut input.compressed_account_proof else {
            continue;
        };
        let tree = decode_hex_32(&input.utxo_tree, "utxoTree")?;
        match root_index_for_tree(conn, &tree, proof.root_sequence).await? {
            Some(root_index) => proof.root_index = Some(root_index),
            None => unavailable_reasons.push(format!(
                "root history metadata unavailable for UTXO tree {}",
                input.utxo_tree
            )),
        }
    }
    Ok(())
}

async fn fetch_nullifier_non_inclusion_proofs(
    conn: &DatabaseConnection,
    nullifier_tree: SerializablePubkey,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<NullifierNonInclusionProofView>, ZoneRpcApiError> {
    let root_history_capacity =
        root_history_capacity_for_tree(conn, &nullifier_tree.to_bytes_vec())
            .await?
            .ok_or_else(|| {
                ZoneRpcApiError::Validation(format!(
                    "tree metadata not found for nullifierTree {}",
                    nullifier_tree
                ))
            })?;

    let tx = conn
        .begin()
        .await
        .map_err(|err| ZoneRpcApiError::Photon(err.to_string()))?;
    crate::api::set_transaction_isolation_if_needed(&tx)
        .await
        .map_err(|err| ZoneRpcApiError::Photon(err.to_string()))?;

    let addresses = nullifiers
        .iter()
        .map(|nullifier| AddressWithTree {
            address: SerializablePubkey::from(*nullifier),
            tree: nullifier_tree,
        })
        .collect::<Vec<_>>();
    let proofs =
        get_multiple_new_address_proofs_helper(&tx, addresses, MAX_ADDRESSES, true).await?;
    tx.commit()
        .await
        .map_err(|err| ZoneRpcApiError::Photon(err.to_string()))?;

    Ok(proofs
        .into_iter()
        .zip(nullifiers.iter().copied())
        .map(|(proof, nullifier)| {
            nullifier_non_inclusion_proof_view(
                proof,
                nullifier_tree,
                nullifier,
                root_history_capacity,
            )
        })
        .collect())
}

fn nullifier_non_inclusion_proof_view(
    proof: MerkleContextWithNewAddressProof,
    nullifier_tree: SerializablePubkey,
    nullifier: [u8; 32],
    root_history_capacity: u64,
) -> NullifierNonInclusionProofView {
    NullifierNonInclusionProofView {
        nullifier: hex_encode(&nullifier),
        nullifier_tree,
        root: hex_encode(&proof.root.0),
        root_index: proof.rootSeq % root_history_capacity,
        root_sequence: proof.rootSeq,
        low_value: hex_encode(&proof.lowerRangeAddress.to_bytes_vec()),
        next_value: hex_encode(&proof.higherRangeAddress.to_bytes_vec()),
        next_index: proof.nextIndex,
        low_leaf_index: proof.lowElementLeafIndex,
        proof: proof.proof.iter().map(|node| hex_encode(&node.0)).collect(),
        path_directions: merkle_path_directions(
            proof.lowElementLeafIndex as u64,
            proof.proof.len(),
        ),
    }
}

async fn root_index_for_tree(
    conn: &DatabaseConnection,
    tree: &[u8; 32],
    root_sequence: u64,
) -> Result<Option<u64>, ZoneRpcApiError> {
    let Some(root_history_capacity) = root_history_capacity_for_tree(conn, tree).await? else {
        return Ok(None);
    };
    Ok(Some(root_sequence % root_history_capacity))
}

async fn root_history_capacity_for_tree(
    conn: &DatabaseConnection,
    tree: &[u8],
) -> Result<Option<u64>, ZoneRpcApiError> {
    let model = tree_metadata::Entity::find_by_id(tree.to_vec())
        .one(conn)
        .await
        .map_err(|err| ZoneRpcApiError::Photon(err.to_string()))?;
    let Some(model) = model else {
        return Ok(None);
    };
    if model.root_history_capacity <= 0 {
        return Ok(None);
    }
    Ok(Some(model.root_history_capacity as u64))
}

fn build_root_context(
    inputs: &[ProofInputUtxoView],
    unavailable_reasons: &mut Vec<String>,
) -> Option<ProofRootContextView> {
    let mut utxo_context: Option<(String, String, u64, u64)> = None;
    let mut nullifier_context: Option<(String, String, u64, u64)> = None;

    for input in inputs {
        let proof = input.compressed_account_proof.as_ref()?;
        let root_index = proof.root_index?;
        let current = (
            input.utxo_tree.clone(),
            proof.root.clone(),
            root_index,
            proof.root_sequence,
        );
        match &utxo_context {
            Some(existing) if existing != &current => {
                unavailable_reasons.push(
                    "rootContext requires all input UTXOs to share the same UTXO root".to_string(),
                );
                return None;
            }
            None => utxo_context = Some(current),
            _ => {}
        }

        let proof = input.nullifier_non_inclusion_proof.as_ref()?;
        let current = (
            hex_encode(&proof.nullifier_tree.to_bytes_vec()),
            proof.root.clone(),
            proof.root_index,
            proof.root_sequence,
        );
        match &nullifier_context {
            Some(existing) if existing != &current => {
                unavailable_reasons.push(
                    "rootContext requires all spend nullifiers to share the same nullifier root"
                        .to_string(),
                );
                return None;
            }
            None => nullifier_context = Some(current),
            _ => {}
        }
    }

    let (utxo_tree_id, utxo_root, utxo_root_index, utxo_root_sequence) = utxo_context?;
    let (nullifier_tree_id, nullifier_root, nullifier_root_index, nullifier_root_sequence) =
        nullifier_context?;

    Some(ProofRootContextView {
        utxo_tree_id,
        utxo_root,
        utxo_root_index,
        utxo_root_sequence,
        nullifier_tree_id,
        nullifier_root,
        nullifier_root_index,
        nullifier_root_sequence,
        expires_after_slot: None,
    })
}

fn validate_requested_root_sequences(
    inputs: &[ProofInputUtxoView],
    requested_utxo_root_sequence: Option<u64>,
    requested_nullifier_root_sequence: Option<u64>,
    unavailable_reasons: &mut Vec<String>,
) -> bool {
    let mut satisfied = true;

    if let Some(requested) = requested_utxo_root_sequence {
        let actual = inputs
            .iter()
            .filter_map(|input| {
                input
                    .compressed_account_proof
                    .as_ref()
                    .map(|proof| proof.root_sequence)
            })
            .collect::<HashSet<_>>();
        if actual.is_empty() {
            unavailable_reasons.push(format!(
                "requested utxoRootSequence {requested} cannot be checked because UTXO inclusion proofs are unavailable"
            ));
            satisfied = false;
        } else if actual.len() != 1 || !actual.contains(&requested) {
            unavailable_reasons.push(format!(
                "requested utxoRootSequence {requested} does not match indexed UTXO proof sequence(s): {:?}",
                sorted_u64s(actual)
            ));
            satisfied = false;
        }
    }

    if let Some(requested) = requested_nullifier_root_sequence {
        let actual = inputs
            .iter()
            .filter_map(|input| {
                input
                    .nullifier_non_inclusion_proof
                    .as_ref()
                    .map(|proof| proof.root_sequence)
            })
            .collect::<HashSet<_>>();
        if actual.is_empty() {
            unavailable_reasons.push(format!(
                "requested nullifierRootSequence {requested} cannot be checked because nullifier non-inclusion proofs are unavailable"
            ));
            satisfied = false;
        } else if actual.len() != 1 || !actual.contains(&requested) {
            unavailable_reasons.push(format!(
                "requested nullifierRootSequence {requested} does not match indexed nullifier proof sequence(s): {:?}",
                sorted_u64s(actual)
            ));
            satisfied = false;
        }
    }

    satisfied
}

fn sorted_u64s(values: HashSet<u64>) -> Vec<u64> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_unstable();
    values
}

fn merkle_path_directions(leaf_index: u64, proof_len: usize) -> Vec<u8> {
    (0..proof_len)
        .map(|bit| ((leaf_index >> bit) & 1) as u8)
        .collect()
}

fn summarize_proof_tree_requirements(
    inputs: &[ProofInputUtxoView],
) -> Vec<ProofTreeRequirementView> {
    #[derive(Debug)]
    struct Acc {
        input_count: u64,
        min_leaf_index: u64,
        max_leaf_index: u64,
        max_tree_sequence: u64,
    }

    let mut by_tree = BTreeMap::<String, Acc>::new();
    for input in inputs {
        by_tree
            .entry(input.utxo_tree.clone())
            .and_modify(|acc| {
                acc.input_count += 1;
                acc.min_leaf_index = acc.min_leaf_index.min(input.leaf_index);
                acc.max_leaf_index = acc.max_leaf_index.max(input.leaf_index);
                acc.max_tree_sequence = acc.max_tree_sequence.max(input.tree_sequence);
            })
            .or_insert(Acc {
                input_count: 1,
                min_leaf_index: input.leaf_index,
                max_leaf_index: input.leaf_index,
                max_tree_sequence: input.tree_sequence,
            });
    }

    by_tree
        .into_iter()
        .map(|(utxo_tree, acc)| ProofTreeRequirementView {
            utxo_tree,
            input_count: acc.input_count,
            min_leaf_index: acc.min_leaf_index,
            max_leaf_index: acc.max_leaf_index,
            max_tree_sequence: acc.max_tree_sequence,
        })
        .collect()
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

fn decode_spend_nullifiers(
    request: &FetchProofInputsRequest,
) -> Result<Option<Vec<[u8; 32]>>, ZoneRpcApiError> {
    match (
        request.spend_nullifiers.is_empty(),
        request.nullifier_tree.is_some(),
    ) {
        (true, false) => Ok(None),
        (true, true) => Err(ZoneRpcApiError::Validation(
            "spendNullifiers are required when nullifierTree is set".to_string(),
        )),
        (false, false) => Err(ZoneRpcApiError::Validation(
            "nullifierTree is required when spendNullifiers are set".to_string(),
        )),
        (false, true) => {
            if request.spend_nullifiers.len() != request.input_utxo_hashes.len() {
                return Err(ZoneRpcApiError::Validation(format!(
                    "spendNullifiers length ({}) must match inputUtxoHashes length ({})",
                    request.spend_nullifiers.len(),
                    request.input_utxo_hashes.len()
                )));
            }
            let mut seen = HashSet::with_capacity(request.spend_nullifiers.len());
            let mut decoded = Vec::with_capacity(request.spend_nullifiers.len());
            for (index, nullifier) in request.spend_nullifiers.iter().enumerate() {
                let nullifier = decode_hex_32(nullifier, &format!("spendNullifiers[{index}]"))?;
                if !seen.insert(nullifier) {
                    return Err(ZoneRpcApiError::Validation(format!(
                        "spendNullifiers[{index}] duplicates an earlier nullifier"
                    )));
                }
                decoded.push(nullifier);
            }
            Ok(Some(decoded))
        }
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

fn decimal_from_field_bytes(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_str_radix(10)
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
    fn proof_input_request_validates_nullifier_context_shape() {
        let authorization = ZoneQueryAuthorization {
            requester: "local-test".to_string(),
            message: "local-test-query".to_string(),
            signature: "local-test-signature".to_string(),
        };
        let mut request = FetchProofInputsRequest {
            zone_config_hash: hex_encode(&[1u8; 32]),
            input_utxo_hashes: vec![hex_encode(&[2u8; 32])],
            spend_nullifiers: vec![hex_encode(&[3u8; 32])],
            nullifier_tree: None,
            utxo_root_sequence: None,
            nullifier_root_sequence: None,
            authorization,
        };
        assert!(matches!(
            decode_spend_nullifiers(&request),
            Err(ZoneRpcApiError::Validation(_))
        ));

        request.nullifier_tree = Some(SerializablePubkey::from([4u8; 32]));
        let decoded = decode_spend_nullifiers(&request).unwrap().unwrap();
        assert_eq!(decoded, vec![[3u8; 32]]);

        request.spend_nullifiers.push(hex_encode(&[5u8; 32]));
        assert!(matches!(
            decode_spend_nullifiers(&request),
            Err(ZoneRpcApiError::Validation(_))
        ));
    }

    #[test]
    fn merkle_path_directions_are_lsb_first() {
        assert_eq!(merkle_path_directions(0b10110, 5), vec![0, 1, 1, 0, 1]);
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
