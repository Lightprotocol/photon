//! Zone RPC worker boundaries.
//!
//! These traits are intentionally production-shaped even while the first
//! prototype runs without a TEE. The RPC/database path should depend on these
//! interfaces, not on whether decryption/proving is local, remote, or enclave
//! backed.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use async_trait::async_trait;
use solana_signature::Signature;

use crate::ingester::parser::shielded_pool_events::EncryptedTxEphemeralKey;
use crate::ingester::parser::state_update::{ShieldedOutputRecord, ShieldedTxEventRecord};
use crate::zone_rpc::types::ZoneDecryptedUtxoRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneKeyRef {
    pub zone_config_hash: [u8; 32],
    pub key_id: u32,
    pub key_version: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ZoneAuditorKey {
    key_ref: ZoneKeyRef,
    key_material: Vec<u8>,
}

impl ZoneAuditorKey {
    pub fn new(key_ref: ZoneKeyRef, key_material: Vec<u8>) -> Result<Self, ZoneWorkerError> {
        if key_material.is_empty() {
            return Err(ZoneWorkerError::InvalidRequest(
                "auditor key material must not be empty".to_string(),
            ));
        }
        Ok(Self {
            key_ref,
            key_material,
        })
    }

    pub fn key_ref(&self) -> ZoneKeyRef {
        self.key_ref
    }

    pub fn key_material(&self) -> &[u8] {
        &self.key_material
    }
}

impl fmt::Debug for ZoneAuditorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneAuditorKey")
            .field("key_ref", &self.key_ref)
            .field("key_material", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneWorkerError {
    KeyNotFound(ZoneKeyRef),
    InvalidRequest(String),
    Decryption(String),
    Proof(String),
}

impl fmt::Display for ZoneWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound(key_ref) => write!(f, "zone auditor key not found: {key_ref:?}"),
            Self::InvalidRequest(err) => write!(f, "invalid zone worker request: {err}"),
            Self::Decryption(err) => write!(f, "zone decryption failed: {err}"),
            Self::Proof(err) => write!(f, "zone proof worker failed: {err}"),
        }
    }
}

impl Error for ZoneWorkerError {}

#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn get_auditor_key(&self, key_ref: ZoneKeyRef)
        -> Result<ZoneAuditorKey, ZoneWorkerError>;
}

#[derive(Clone, Default)]
pub struct InMemoryKeyProvider {
    keys: HashMap<ZoneKeyRef, ZoneAuditorKey>,
}

impl InMemoryKeyProvider {
    pub fn with_key(mut self, key: ZoneAuditorKey) -> Self {
        self.insert_key(key);
        self
    }

    pub fn insert_key(&mut self, key: ZoneAuditorKey) {
        self.keys.insert(key.key_ref(), key);
    }
}

impl fmt::Debug for InMemoryKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryKeyProvider")
            .field("key_count", &self.keys.len())
            .finish()
    }
}

#[async_trait]
impl KeyProvider for InMemoryKeyProvider {
    async fn get_auditor_key(
        &self,
        key_ref: ZoneKeyRef,
    ) -> Result<ZoneAuditorKey, ZoneWorkerError> {
        self.keys
            .get(&key_ref)
            .cloned()
            .ok_or(ZoneWorkerError::KeyNotFound(key_ref))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedUtxoInput {
    pub tx_signature: Signature,
    pub event_index: u32,
    pub output_index: u8,
    pub slot: u64,
    pub operation_commitment: [u8; 32],
    pub zone_config_hash: [u8; 32],
    pub tx_ephemeral_pubkey: [u8; 32],
    pub encrypted_tx_ephemeral_keys: Vec<EncryptedTxEphemeralKey>,
    pub utxo_hash: [u8; 32],
    pub utxo_tree: [u8; 32],
    pub leaf_index: u64,
    pub tree_sequence: u64,
    pub encrypted_utxo: Vec<u8>,
    pub encrypted_utxo_hash: [u8; 32],
}

impl EncryptedUtxoInput {
    pub fn from_records(
        event: &ShieldedTxEventRecord,
        output: &ShieldedOutputRecord,
    ) -> Result<Self, ZoneWorkerError> {
        if output.tx_signature != event.tx_signature || output.event_index != event.event_index {
            return Err(ZoneWorkerError::InvalidRequest(
                "shielded output does not belong to the supplied tx event".to_string(),
            ));
        }

        let zone_config_hash = match (event.zone_config_hash, output.zone_config_hash) {
            (Some(event_zone), Some(output_zone)) if event_zone == output_zone => event_zone,
            (Some(event_zone), None) => event_zone,
            (None, Some(output_zone)) => output_zone,
            (Some(_), Some(_)) => {
                return Err(ZoneWorkerError::InvalidRequest(
                    "shielded output zone does not match tx event zone".to_string(),
                ))
            }
            (None, None) => {
                return Err(ZoneWorkerError::InvalidRequest(
                    "zoned encrypted UTXO input is missing zone_config_hash".to_string(),
                ))
            }
        };

        Ok(Self {
            tx_signature: output.tx_signature,
            event_index: output.event_index,
            output_index: output.output_index,
            slot: output.slot,
            operation_commitment: event.operation_commitment,
            zone_config_hash,
            tx_ephemeral_pubkey: event.tx_ephemeral_pubkey,
            encrypted_tx_ephemeral_keys: event.encrypted_tx_ephemeral_keys.clone(),
            utxo_hash: output.utxo_hash,
            utxo_tree: output.utxo_tree,
            leaf_index: output.leaf_index,
            tree_sequence: output.tree_sequence,
            encrypted_utxo: output.encrypted_utxo.clone(),
            encrypted_utxo_hash: output.encrypted_utxo_hash,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptOutputsRequest {
    pub zone_config_hash: [u8; 32],
    pub outputs: Vec<EncryptedUtxoInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptOutputsResponse {
    pub decrypted_outputs: Vec<ZoneDecryptedUtxoRecord>,
}

#[async_trait]
pub trait Decryptor: Send + Sync {
    async fn decrypt_outputs(
        &self,
        request: DecryptOutputsRequest,
    ) -> Result<DecryptOutputsResponse, ZoneWorkerError>;
}

#[derive(Clone, Default)]
pub struct LocalPassthroughDecryptor {
    rows_by_utxo_hash: HashMap<[u8; 32], ZoneDecryptedUtxoRecord>,
}

impl LocalPassthroughDecryptor {
    pub fn new(
        rows: impl IntoIterator<Item = ZoneDecryptedUtxoRecord>,
    ) -> Result<Self, ZoneWorkerError> {
        let mut decryptor = Self::default();
        for row in rows {
            decryptor.insert(row)?;
        }
        Ok(decryptor)
    }

    pub fn insert(&mut self, row: ZoneDecryptedUtxoRecord) -> Result<(), ZoneWorkerError> {
        if let Some(existing) = self.rows_by_utxo_hash.get(&row.utxo_hash) {
            if existing != &row {
                return Err(ZoneWorkerError::Decryption(format!(
                    "conflicting local plaintext fixture for utxo_hash {}",
                    hex::encode(row.utxo_hash)
                )));
            }
            return Ok(());
        }
        self.rows_by_utxo_hash.insert(row.utxo_hash, row);
        Ok(())
    }
}

impl fmt::Debug for LocalPassthroughDecryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalPassthroughDecryptor")
            .field("row_count", &self.rows_by_utxo_hash.len())
            .finish()
    }
}

#[async_trait]
impl Decryptor for LocalPassthroughDecryptor {
    async fn decrypt_outputs(
        &self,
        request: DecryptOutputsRequest,
    ) -> Result<DecryptOutputsResponse, ZoneWorkerError> {
        if request.outputs.is_empty() {
            return Ok(DecryptOutputsResponse {
                decrypted_outputs: Vec::new(),
            });
        }

        let mut decrypted_outputs = Vec::with_capacity(request.outputs.len());
        for output in request.outputs {
            if output.zone_config_hash != request.zone_config_hash {
                return Err(ZoneWorkerError::InvalidRequest(
                    "encrypted output zone does not match decrypt request zone".to_string(),
                ));
            }

            let row = self
                .rows_by_utxo_hash
                .get(&output.utxo_hash)
                .ok_or_else(|| {
                    ZoneWorkerError::Decryption(format!(
                        "no local plaintext fixture for utxo_hash {}",
                        hex::encode(output.utxo_hash)
                    ))
                })?;
            validate_decrypted_row_matches_public_input(&output, row, request.zone_config_hash)?;
            decrypted_outputs.push(row.clone());
        }

        Ok(DecryptOutputsResponse { decrypted_outputs })
    }
}

fn validate_decrypted_row_matches_public_input(
    output: &EncryptedUtxoInput,
    row: &ZoneDecryptedUtxoRecord,
    zone_config_hash: [u8; 32],
) -> Result<(), ZoneWorkerError> {
    let matches = row.zone_config_hash == zone_config_hash
        && row.zone_config_hash == output.zone_config_hash
        && row.utxo_hash == output.utxo_hash
        && row.operation_commitment == output.operation_commitment
        && row.signature == output.tx_signature
        && row.event_index == output.event_index
        && row.output_index == output.output_index
        && row.slot == output.slot
        && row.utxo_tree == output.utxo_tree
        && row.leaf_index == output.leaf_index
        && row.tree_sequence == output.tree_sequence;

    if matches {
        Ok(())
    } else {
        Err(ZoneWorkerError::Decryption(format!(
            "decrypted fixture row does not bind to public output {}",
            hex::encode(output.utxo_hash)
        )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneProofKind {
    UtxoProof,
    TreeProof,
    BundledShieldedPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRootContext {
    pub utxo_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub root_slot: u64,
    pub root_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRequest {
    pub proof_kind: ZoneProofKind,
    pub zone_config_hash: [u8; 32],
    pub root_context: ZoneRootContext,
    pub input_utxos: Vec<ZoneDecryptedUtxoRecord>,
    pub output_utxo_hashes: Vec<[u8; 32]>,
    pub expected_public_inputs_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofResponse {
    pub proof_kind: ZoneProofKind,
    pub proof_bytes: Vec<u8>,
    pub public_inputs_hash: [u8; 32],
    pub worker_attestation: Option<Vec<u8>>,
}

#[async_trait]
pub trait ProofWorker: Send + Sync {
    async fn prove(&self, request: ProofRequest) -> Result<ProofResponse, ZoneWorkerError>;
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalStubProofWorker;

#[cfg(test)]
#[async_trait]
impl ProofWorker for LocalStubProofWorker {
    async fn prove(&self, request: ProofRequest) -> Result<ProofResponse, ZoneWorkerError> {
        if request.input_utxos.is_empty() && request.output_utxo_hashes.is_empty() {
            return Err(ZoneWorkerError::InvalidRequest(
                "proof request must contain at least one input or output".to_string(),
            ));
        }

        for row in &request.input_utxos {
            if row.zone_config_hash != request.zone_config_hash {
                return Err(ZoneWorkerError::Proof(
                    "input UTXO belongs to a different zone".to_string(),
                ));
            }
        }

        let public_inputs_hash = compute_stub_public_inputs_hash(&request);
        if let Some(expected) = request.expected_public_inputs_hash {
            if expected != public_inputs_hash {
                return Err(ZoneWorkerError::Proof(
                    "proof request public-input hash mismatch".to_string(),
                ));
            }
        }

        let mut proof_bytes = b"local-stub-zone-proof-v0".to_vec();
        proof_bytes.extend_from_slice(&[request.proof_kind as u8]);
        proof_bytes.extend_from_slice(&public_inputs_hash);

        Ok(ProofResponse {
            proof_kind: request.proof_kind,
            proof_bytes,
            public_inputs_hash,
            worker_attestation: None,
        })
    }
}

#[cfg(test)]
fn compute_stub_public_inputs_hash(request: &ProofRequest) -> [u8; 32] {
    let mut sink = StableFoldHash::default();
    sink.update(&[request.proof_kind as u8]);
    sink.update(&request.zone_config_hash);
    sink.update(&request.root_context.utxo_root);
    sink.update(&request.root_context.nullifier_root);
    sink.update(&request.root_context.root_slot.to_be_bytes());
    sink.update(&request.root_context.root_sequence.to_be_bytes());
    for row in &request.input_utxos {
        sink.update(&row.utxo_hash);
        sink.update(&row.operation_commitment);
        sink.update(&row.owner_hash);
        sink.update(&row.spl_amount.to_be_bytes());
        sink.update(&row.sol_amount.to_be_bytes());
    }
    for output_hash in &request.output_utxo_hashes {
        sink.update(output_hash);
    }
    sink.finish()
}

#[cfg(test)]
#[derive(Default)]
struct StableFoldHash {
    bytes: [u8; 32],
    offset: usize,
}

#[cfg(test)]
impl StableFoldHash {
    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            let index = self.offset % 32;
            self.bytes[index] = self.bytes[index]
                .wrapping_add(*byte)
                .rotate_left((self.offset % 8) as u32);
            self.offset += 1;
        }
    }

    fn finish(self) -> [u8; 32] {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_ref() -> ZoneKeyRef {
        ZoneKeyRef {
            zone_config_hash: [0x77; 32],
            key_id: 1,
            key_version: 2,
        }
    }

    fn record(seed: u8) -> ZoneDecryptedUtxoRecord {
        ZoneDecryptedUtxoRecord {
            utxo_hash: [seed; 32],
            operation_commitment: [seed.wrapping_add(1); 32],
            zone_config_hash: [0x77; 32],
            owner_pubkey: [0xaa; 32],
            owner_hash: [0xbb; 32],
            token_mint: [0xcc; 32],
            spl_amount: 1_000_000 + u64::from(seed),
            sol_amount: 42,
            data_hash: [0xdd; 32],
            slot: 100,
            signature: Signature::default(),
            event_index: 0,
            output_index: seed,
            utxo_tree: [0xee; 32],
            leaf_index: 123,
            tree_sequence: 456,
            spent: false,
        }
    }

    fn encrypted_input(row: &ZoneDecryptedUtxoRecord) -> EncryptedUtxoInput {
        EncryptedUtxoInput {
            tx_signature: row.signature,
            event_index: row.event_index,
            output_index: row.output_index,
            slot: row.slot,
            operation_commitment: row.operation_commitment,
            zone_config_hash: row.zone_config_hash,
            tx_ephemeral_pubkey: [0x11; 32],
            encrypted_tx_ephemeral_keys: Vec::new(),
            utxo_hash: row.utxo_hash,
            utxo_tree: row.utxo_tree,
            leaf_index: row.leaf_index,
            tree_sequence: row.tree_sequence,
            encrypted_utxo: vec![0x99],
            encrypted_utxo_hash: [0x22; 32],
        }
    }

    #[test]
    fn auditor_key_debug_redacts_secret_material() {
        let key = ZoneAuditorKey::new(key_ref(), vec![1, 2, 3, 4]).unwrap();
        let debug = format!("{key:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("1, 2, 3, 4"));
    }

    #[tokio::test]
    async fn in_memory_key_provider_returns_key() {
        let key = ZoneAuditorKey::new(key_ref(), vec![9; 32]).unwrap();
        let provider = InMemoryKeyProvider::default().with_key(key.clone());

        let fetched = provider.get_auditor_key(key_ref()).await.unwrap();

        assert_eq!(fetched, key);
    }

    #[tokio::test]
    async fn local_passthrough_decryptor_filters_requested_outputs() {
        let row_a = record(1);
        let row_b = record(2);
        let decryptor = LocalPassthroughDecryptor::new(vec![row_a.clone(), row_b]).unwrap();

        let response = decryptor
            .decrypt_outputs(DecryptOutputsRequest {
                zone_config_hash: row_a.zone_config_hash,
                outputs: vec![encrypted_input(&row_a)],
            })
            .await
            .unwrap();

        assert_eq!(response.decrypted_outputs, vec![row_a]);
    }

    #[tokio::test]
    async fn local_passthrough_decryptor_rejects_public_binding_mismatch() {
        let row = record(3);
        let mut input = encrypted_input(&row);
        input.event_index += 1;
        let decryptor = LocalPassthroughDecryptor::new(vec![row.clone()]).unwrap();

        let err = decryptor
            .decrypt_outputs(DecryptOutputsRequest {
                zone_config_hash: row.zone_config_hash,
                outputs: vec![input],
            })
            .await
            .unwrap_err();

        assert!(matches!(err, ZoneWorkerError::Decryption(_)));
    }

    #[tokio::test]
    async fn local_stub_proof_worker_is_deterministic() {
        let row = record(4);
        let request = ProofRequest {
            proof_kind: ZoneProofKind::BundledShieldedPool,
            zone_config_hash: row.zone_config_hash,
            root_context: ZoneRootContext {
                utxo_root: [0x01; 32],
                nullifier_root: [0x02; 32],
                root_slot: 100,
                root_sequence: 10,
            },
            input_utxos: vec![row.clone()],
            output_utxo_hashes: vec![[0x03; 32]],
            expected_public_inputs_hash: None,
        };
        let worker = LocalStubProofWorker;

        let first = worker.prove(request.clone()).await.unwrap();
        let second = worker.prove(request).await.unwrap();

        assert_eq!(first, second);
        assert_eq!(first.proof_kind, ZoneProofKind::BundledShieldedPool);
        assert!(first.proof_bytes.starts_with(b"local-stub-zone-proof-v0"));
    }
}
