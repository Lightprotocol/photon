use utoipa::ToSchema;
use serde::{Deserialize, Serialize};
use solana_client::client_error::reqwest;
use super::super::error::PhotonApiError;
use crate::prover::inclusion_inputs::InclusionInputs;
use crate::prover::non_inclusion_inputs::NonInclusionInputs;

pub const SERVER_ADDRESS: &str = "http://localhost:3001";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub enum ProofInputs {
    Inclusion(Vec<InclusionProofInputs>),
    NonInclusion(Vec<NonInclusionProofInputs>),
    Combined(CombinedProofInputs),
}

impl ProofInputs {
    pub fn endpoint(&self) -> &'static str {
        match self {
            ProofInputs::Inclusion(_) => "/inclusion",
            ProofInputs::NonInclusion(_) => "/noninclusion",
            ProofInputs::Combined(_) => "/combined",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ValidityProofRequest {
    pub proof_inputs: ProofInputs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InclusionProofInputs {
    pub root: String,
    pub leaf: String,
    pub in_path_indices: u32,
    pub in_path_elements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NonInclusionProofInputs {
    pub root: String,
    pub value: String,
    pub in_path_indices: u32,
    pub in_path_elements: Vec<String>,
    pub leaf_lower_range_value: String,
    pub leaf_higher_range_value: String,
    pub leaf_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CombinedProofInputs {
    pub inclusion: Vec<InclusionProofInputs>,
    pub non_inclusion: Vec<NonInclusionProofInputs>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ValidityProofResponse {
    pub proof: String,
}

const CONTENT_TYPE: &str = "text/plain; charset=utf-8";
async fn create_request(endpoint: &str, parsed_inputs: String) -> reqwest::Result<reqwest::Response> {
    let client = reqwest::Client::new();
    client.post(endpoint)
        .header("Content-Type", CONTENT_TYPE)
        .body(parsed_inputs)
        .send()
        .await
}

pub async fn get_validity_proof(request: ValidityProofRequest) -> Result<ValidityProofResponse, PhotonApiError> {
    let endpoint = &format!("{}{}", SERVER_ADDRESS, request.proof_inputs.endpoint());
    let parsed_inputs = match request.proof_inputs {
        ProofInputs::Inclusion(inputs) => InclusionInputs::new(&inputs).to_string(),
        ProofInputs::NonInclusion(inputs) => NonInclusionInputs::new(&inputs).to_string(),
        _ => panic!("Invalid proof params."),
    };
    let response_result = create_request(endpoint, parsed_inputs).await
        .map_err(|_| PhotonApiError::UnexpectedError("request failed".to_string()))?;

    let response = response_result.text().await
        .map_err(|e| PhotonApiError::UnexpectedError(e.to_string()))?;

    Ok(ValidityProofResponse {
        proof: response,
    })
}
