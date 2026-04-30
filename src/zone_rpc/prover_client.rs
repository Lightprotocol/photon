//! Client for the existing Light prover-server proof API.

use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ProverProofMode {
    Sync,
    Async,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProverProofRequest {
    pub circuit_type: String,
    /// JSON object forwarded to prover-server `/prove`.
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProverProofSubmission {
    pub circuit_type: String,
    pub prover_job_id: Option<String>,
    pub status: ProverProofStatus,
    /// Raw JSON returned by prover-server for sync results or async status.
    pub result: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ProverProofStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProverClientError {
    Validation(String),
    Http(String),
    Response(String),
}

impl fmt::Display for ProverClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(err) => write!(f, "prover request validation error: {err}"),
            Self::Http(err) => write!(f, "prover http error: {err}"),
            Self::Response(err) => write!(f, "prover response error: {err}"),
        }
    }
}

impl Error for ProverClientError {}

#[derive(Debug, Clone)]
pub struct ProverProofClient {
    base_url: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl ProverProofClient {
    pub fn new(base_url: impl Into<String>, api_key: Option<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key,
            client: reqwest::Client::new(),
        }
    }

    pub async fn submit_proof(
        &self,
        request: &ProverProofRequest,
        mode: ProverProofMode,
    ) -> Result<ProverProofSubmission, ProverClientError> {
        validate_prover_payload(request)?;
        let url = match mode {
            ProverProofMode::Sync => format!("{}/prove?sync=true", self.base_url),
            ProverProofMode::Async => format!("{}/prove?async=true", self.base_url),
        };
        let response = self
            .authorized(self.client.post(url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request.payload.clone())
            .send()
            .await
            .map_err(|err| ProverClientError::Http(err.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| ProverClientError::Http(err.to_string()))?;
        if !status.is_success() {
            return Err(ProverClientError::Response(format!(
                "prover returned HTTP {status}: {body}"
            )));
        }

        match mode {
            ProverProofMode::Sync => Ok(ProverProofSubmission {
                circuit_type: request.circuit_type.clone(),
                prover_job_id: None,
                status: ProverProofStatus::Succeeded,
                result: Some(body),
                error: None,
            }),
            ProverProofMode::Async => {
                let value = serde_json::from_str::<serde_json::Value>(&body).map_err(|err| {
                    ProverClientError::Response(format!("async response is not JSON: {err}"))
                })?;
                let prover_job_id = value
                    .get("job_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        ProverClientError::Response(
                            "async response missing string job_id".to_string(),
                        )
                    })?
                    .to_string();
                Ok(ProverProofSubmission {
                    circuit_type: request.circuit_type.clone(),
                    prover_job_id: Some(prover_job_id),
                    status: status_from_prover_value(value.get("status")),
                    result: Some(body),
                    error: None,
                })
            }
        }
    }

    pub async fn get_proof_status(
        &self,
        prover_job_id: &str,
    ) -> Result<ProverProofSubmission, ProverClientError> {
        if prover_job_id.is_empty() {
            return Err(ProverClientError::Validation(
                "prover_job_id must be non-empty".to_string(),
            ));
        }
        let url = format!("{}/prove/status?job_id={}", self.base_url, prover_job_id);
        let response = self
            .authorized(self.client.get(url))
            .send()
            .await
            .map_err(|err| ProverClientError::Http(err.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| ProverClientError::Http(err.to_string()))?;
        if !status.is_success() && status.as_u16() != 202 {
            return Err(ProverClientError::Response(format!(
                "prover status returned HTTP {status}: {body}"
            )));
        }
        let value = serde_json::from_str::<serde_json::Value>(&body)
            .map_err(|err| ProverClientError::Response(format!("status is not JSON: {err}")))?;
        let circuit_type = value
            .get("circuit_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let proof_status = status_from_prover_value(value.get("status"));
        let error = value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        Ok(ProverProofSubmission {
            circuit_type,
            prover_job_id: Some(prover_job_id.to_string()),
            status: proof_status,
            result: Some(body),
            error,
        })
    }

    fn authorized(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(api_key) => builder.header("X-API-Key", api_key),
            None => builder,
        }
    }
}

pub fn validate_prover_payload(request: &ProverProofRequest) -> Result<(), ProverClientError> {
    if request.circuit_type.is_empty() {
        return Err(ProverClientError::Validation(
            "circuit_type must be non-empty".to_string(),
        ));
    }
    let value = serde_json::from_str::<serde_json::Value>(&request.payload)
        .map_err(|err| ProverClientError::Validation(format!("payload is not JSON: {err}")))?;
    let object = value.as_object().ok_or_else(|| {
        ProverClientError::Validation("payload must be a JSON object".to_string())
    })?;
    let payload_circuit_type = object
        .get("circuitType")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ProverClientError::Validation("payload missing string circuitType".to_string())
        })?;
    if payload_circuit_type != request.circuit_type {
        return Err(ProverClientError::Validation(format!(
            "payload circuitType {payload_circuit_type} does not match request circuit_type {}",
            request.circuit_type
        )));
    }
    Ok(())
}

fn status_from_prover_value(value: Option<&serde_json::Value>) -> ProverProofStatus {
    match value.and_then(serde_json::Value::as_str) {
        Some("completed" | "succeeded" | "success") => ProverProofStatus::Succeeded,
        Some("running" | "processing" | "active") => ProverProofStatus::Running,
        Some("failed" | "error") => ProverProofStatus::Failed,
        _ => ProverProofStatus::Queued,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_circuit_type_inside_payload() {
        validate_prover_payload(&ProverProofRequest {
            circuit_type: "masp-utxo".to_string(),
            payload: r#"{"circuitType":"masp-utxo","nInputs":1,"nOutputs":1}"#.to_string(),
        })
        .unwrap();

        let err = validate_prover_payload(&ProverProofRequest {
            circuit_type: "masp-tree".to_string(),
            payload: r#"{"circuitType":"masp-utxo"}"#.to_string(),
        })
        .unwrap_err();
        assert!(matches!(err, ProverClientError::Validation(_)));
    }
}
