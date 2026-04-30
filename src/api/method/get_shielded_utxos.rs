//! Public read APIs for the zoned shielded-pool indexer.
//!
//! These endpoints expose only the canonical, plaintext-free state Photon
//! has indexed: encrypted UTXO ciphertexts, public commitments, tree leaf
//! references, and zone metadata. They never return owner pubkeys, amounts,
//! blindings, the fixture-only plaintext sidecar, or anything else that
//! would let an unauthenticated caller link a UTXO to its owner.
//!
//! Plaintext projections live behind the Zone RPC sidecar and are
//! gated by user-signed requests, not by Photon.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use utoipa::ToSchema;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect};

use crate::api::error::PhotonApiError;
use crate::common::typedefs::context::Context;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::common::typedefs::serializable_signature::SerializableSignature;
use crate::dao::generated::{shielded_utxo_events, shielded_utxo_outputs};

/// Hard cap on rows returned by any single shielded UTXO list endpoint.
/// Aligned with the existing PAGE_LIMIT used elsewhere in the API surface.
pub const SHIELDED_UTXO_PAGE_LIMIT: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EncryptedTxEphemeralKeyView {
    /// Auditor / sender / recipient / protocol-auxiliary, encoded as the
    /// numeric tag used on chain so future viewing-key roles can be added
    /// without breaking the wire format.
    pub role: u8,
    pub key_id: u32,
    pub key_version: u32,
    /// 32-byte HPKE ephemeral pubkey, hex-encoded.
    pub hpke_ephemeral_pubkey: String,
    /// Hex-encoded ciphertext of the transaction ephemeral key for this
    /// recipient.
    pub encrypted_tx_ephemeral_key: String,
    /// 16-byte AES-GCM auth tag, hex-encoded.
    pub auth_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShieldedPublicDeltaView {
    /// 32-byte mint pubkey when the public delta is for an SPL mint; null
    /// for native SOL-only deltas.
    pub mint: Option<String>,
    /// i128 SPL amount as a decimal string (positive = deposit, negative =
    /// withdrawal). String avoids JSON number-precision loss.
    pub spl_amount: String,
    pub sol_amount: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShieldedUtxoRecord {
    /// Hex-encoded canonical UTXO commitment hash. Joins with output rows.
    pub utxo_hash: String,
    /// Index of the matching output in the Light public transaction event.
    pub compressed_output_index: u32,
    /// Hex-encoded compressed account hash from the Light public event.
    pub compressed_account_hash: String,
    /// 32-byte UTXO tree pubkey, hex-encoded.
    pub utxo_tree: String,
    pub leaf_index: u64,
    pub sequence_number: u64,
    /// Hex-encoded ciphertext for this output.
    pub encrypted_utxo: String,
    pub encrypted_utxo_hash: String,
    pub zone_config_hash: Option<String>,
    /// Slot the event landed in.
    pub slot: u64,
    /// Solana transaction signature that emitted the event, base58.
    pub signature: SerializableSignature,
    pub event_index: u32,
    pub output_index: u8,
    /// Top-level event metadata required by relayers / verifiers.
    pub event: ShieldedTxEventView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShieldedTxEventView {
    pub version: u8,
    pub instruction_tag: u8,
    /// Numeric `tx_kind` matching `ShieldedPoolTxKind` on chain (0 =
    /// proofless_shield, 1 = transact, 2 = zone_transact, 3 =
    /// zone_authority_transact).
    pub tx_kind: u8,
    pub protocol_config: String,
    pub zone_config_hash: Option<String>,
    pub tx_ephemeral_pubkey: String,
    pub encrypted_tx_ephemeral_keys: Vec<EncryptedTxEphemeralKeyView>,
    pub operation_commitment: String,
    pub public_inputs_hash: Option<String>,
    pub utxo_public_inputs_hash: Option<String>,
    pub tree_public_inputs_hash: Option<String>,
    pub nullifier_chain: Option<String>,
    /// Hex-encoded list of input nullifiers, in event order.
    pub input_nullifiers: Vec<String>,
    pub public_delta: ShieldedPublicDeltaView,
    pub relayer_fee: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShieldedUtxoResponse {
    pub context: Context,
    pub value: Option<ShieldedUtxoRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShieldedUtxoListResponse {
    pub context: Context,
    pub items: Vec<ShieldedUtxoRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetShieldedUtxoRequest {
    /// Hex-encoded 32-byte UTXO commitment hash.
    pub utxo_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetShieldedUtxosByZoneRequest {
    /// Hex-encoded 32-byte zone config hash.
    pub zone_config_hash: String,
    /// Optional cap on returned rows. Server clamps to
    /// `SHIELDED_UTXO_PAGE_LIMIT`.
    pub limit: Option<u64>,
    /// When set, return rows with `slot < before_slot` (descending).
    pub before_slot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetShieldedUtxosBySignatureRequest {
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetShieldedUtxosByTreeRequest {
    /// Base58 UTXO tree pubkey.
    pub utxo_tree: SerializablePubkey,
    pub limit: Option<u64>,
    pub before_leaf_index: Option<u64>,
}

pub async fn get_shielded_utxo(
    conn: &DatabaseConnection,
    request: GetShieldedUtxoRequest,
) -> Result<ShieldedUtxoResponse, PhotonApiError> {
    let context = Context::extract(conn).await?;
    let utxo_hash = decode_hex_32(&request.utxo_hash, "utxoHash")?;

    let output = shielded_utxo_outputs::Entity::find()
        .filter(shielded_utxo_outputs::Column::UtxoHash.eq(utxo_hash.to_vec()))
        .one(conn)
        .await?;

    let value = match output {
        Some(out) => {
            let mut records = build_records(conn, std::slice::from_ref(&out)).await?;
            records.pop()
        }
        None => None,
    };

    Ok(ShieldedUtxoResponse { context, value })
}

pub async fn get_shielded_utxos_by_zone(
    conn: &DatabaseConnection,
    request: GetShieldedUtxosByZoneRequest,
) -> Result<ShieldedUtxoListResponse, PhotonApiError> {
    let context = Context::extract(conn).await?;
    let zone_hash = decode_hex_32(&request.zone_config_hash, "zoneConfigHash")?;

    let limit = request
        .limit
        .unwrap_or(SHIELDED_UTXO_PAGE_LIMIT)
        .min(SHIELDED_UTXO_PAGE_LIMIT);

    let mut query = shielded_utxo_outputs::Entity::find()
        .filter(shielded_utxo_outputs::Column::ZoneConfigHash.eq(zone_hash.to_vec()));
    if let Some(before_slot) = request.before_slot {
        query = query.filter(shielded_utxo_outputs::Column::Slot.lt(before_slot as i64));
    }
    let outputs = query
        .order_by_desc(shielded_utxo_outputs::Column::Slot)
        .order_by_desc(shielded_utxo_outputs::Column::OutputIndex)
        .limit(limit)
        .all(conn)
        .await?;

    let items = build_records(conn, &outputs).await?;

    Ok(ShieldedUtxoListResponse { context, items })
}

pub async fn get_shielded_utxos_by_signature(
    conn: &DatabaseConnection,
    request: GetShieldedUtxosBySignatureRequest,
) -> Result<ShieldedUtxoListResponse, PhotonApiError> {
    let context = Context::extract(conn).await?;
    let sig_bytes: [u8; 64] = request.signature.0.into();

    let outputs = shielded_utxo_outputs::Entity::find()
        .filter(shielded_utxo_outputs::Column::TxSignature.eq(sig_bytes.to_vec()))
        .order_by_asc(shielded_utxo_outputs::Column::EventIndex)
        .order_by_asc(shielded_utxo_outputs::Column::OutputIndex)
        .all(conn)
        .await?;

    let items = build_records(conn, &outputs).await?;

    Ok(ShieldedUtxoListResponse { context, items })
}

pub async fn get_shielded_utxos_by_tree(
    conn: &DatabaseConnection,
    request: GetShieldedUtxosByTreeRequest,
) -> Result<ShieldedUtxoListResponse, PhotonApiError> {
    let context = Context::extract(conn).await?;
    let tree_bytes = request.utxo_tree.to_bytes_vec();

    let limit = request
        .limit
        .unwrap_or(SHIELDED_UTXO_PAGE_LIMIT)
        .min(SHIELDED_UTXO_PAGE_LIMIT);

    let mut query = shielded_utxo_outputs::Entity::find()
        .filter(shielded_utxo_outputs::Column::UtxoTree.eq(tree_bytes.clone()));
    if let Some(before_leaf_index) = request.before_leaf_index {
        query = query.filter(shielded_utxo_outputs::Column::LeafIndex.lt(before_leaf_index as i64));
    }
    let outputs = query
        .order_by_desc(shielded_utxo_outputs::Column::LeafIndex)
        .limit(limit)
        .all(conn)
        .await?;

    let items = build_records(conn, &outputs).await?;

    Ok(ShieldedUtxoListResponse { context, items })
}

async fn build_records(
    conn: &DatabaseConnection,
    outputs: &[shielded_utxo_outputs::Model],
) -> Result<Vec<ShieldedUtxoRecord>, PhotonApiError> {
    if outputs.is_empty() {
        return Ok(Vec::new());
    }

    let tx_signatures = outputs
        .iter()
        .map(|output| output.tx_signature.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let event_indexes = outputs
        .iter()
        .map(|output| output.event_index)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let events = shielded_utxo_events::Entity::find()
        .filter(shielded_utxo_events::Column::TxSignature.is_in(tx_signatures))
        .filter(shielded_utxo_events::Column::EventIndex.is_in(event_indexes))
        .all(conn)
        .await?;
    let events_by_key = events
        .into_iter()
        .map(|event| ((event.tx_signature.clone(), event.event_index), event))
        .collect::<HashMap<_, _>>();

    let mut records = Vec::with_capacity(outputs.len());
    for output in outputs {
        let event = events_by_key
            .get(&(output.tx_signature.clone(), output.event_index))
            .ok_or_else(|| {
                PhotonApiError::UnexpectedError(format!(
                    "shielded_utxo_events row missing for tx={:?} event_index={}",
                    output.tx_signature, output.event_index
                ))
            })?;
        records.push(record_from_models(output, event)?);
    }
    Ok(records)
}

fn record_from_models(
    output: &shielded_utxo_outputs::Model,
    event: &shielded_utxo_events::Model,
) -> Result<ShieldedUtxoRecord, PhotonApiError> {
    let signature = signature_from_bytes(&output.tx_signature)?;
    let event_view = ShieldedTxEventView {
        version: event.version as u8,
        instruction_tag: event.instruction_tag as u8,
        tx_kind: event.tx_kind as u8,
        protocol_config: hex_encode(&event.protocol_config),
        zone_config_hash: event.zone_config_hash.as_deref().map(hex_encode),
        tx_ephemeral_pubkey: hex_encode(&event.tx_ephemeral_pubkey),
        encrypted_tx_ephemeral_keys: decode_encrypted_keys(&event.encrypted_tx_ephemeral_keys)?,
        operation_commitment: hex_encode(&event.operation_commitment),
        public_inputs_hash: event.public_inputs_hash.as_deref().map(hex_encode),
        utxo_public_inputs_hash: event.utxo_public_inputs_hash.as_deref().map(hex_encode),
        tree_public_inputs_hash: event.tree_public_inputs_hash.as_deref().map(hex_encode),
        nullifier_chain: event.nullifier_chain.as_deref().map(hex_encode),
        input_nullifiers: decode_input_nullifiers(&event.input_nullifiers)?,
        public_delta: ShieldedPublicDeltaView {
            mint: event.public_delta_mint.as_deref().map(hex_encode),
            spl_amount: i128_from_be_bytes(&event.public_delta_spl)?.to_string(),
            sol_amount: i128_from_be_bytes(&event.public_delta_sol)?.to_string(),
        },
        relayer_fee: event.relayer_fee.map(|f| f as u64),
    };

    Ok(ShieldedUtxoRecord {
        utxo_hash: hex_encode(&output.utxo_hash),
        compressed_output_index: output.compressed_output_index as u32,
        compressed_account_hash: hex_encode(&output.compressed_account_hash),
        utxo_tree: hex_encode(&output.utxo_tree),
        leaf_index: output.leaf_index as u64,
        sequence_number: output.tree_sequence as u64,
        encrypted_utxo: hex_encode(&output.encrypted_utxo),
        encrypted_utxo_hash: hex_encode(&output.encrypted_utxo_hash),
        zone_config_hash: output.zone_config_hash.as_deref().map(hex_encode),
        slot: output.slot as u64,
        signature,
        event_index: output.event_index as u32,
        output_index: output.output_index as u8,
        event: event_view,
    })
}

fn decode_encrypted_keys(bytes: &[u8]) -> Result<Vec<EncryptedTxEphemeralKeyView>, PhotonApiError> {
    use crate::ingester::parser::shielded_pool_events::EncryptedTxEphemeralKey;
    use borsh::BorshDeserialize;
    let keys: Vec<EncryptedTxEphemeralKey> = Vec::<EncryptedTxEphemeralKey>::try_from_slice(bytes)
        .map_err(|err| {
            PhotonApiError::UnexpectedError(format!(
                "failed to decode encrypted_tx_ephemeral_keys blob: {}",
                err
            ))
        })?;
    Ok(keys
        .into_iter()
        .map(|k| EncryptedTxEphemeralKeyView {
            role: k.role as u8,
            key_id: k.key_id,
            key_version: k.key_version,
            hpke_ephemeral_pubkey: hex_encode(&k.hpke_ephemeral_pubkey),
            encrypted_tx_ephemeral_key: hex_encode(&k.encrypted_tx_ephemeral_key),
            auth_tag: hex_encode(&k.auth_tag),
        })
        .collect())
}

fn decode_input_nullifiers(bytes: &[u8]) -> Result<Vec<String>, PhotonApiError> {
    use borsh::BorshDeserialize;
    let nullifiers: Vec<[u8; 32]> = Vec::<[u8; 32]>::try_from_slice(bytes).map_err(|err| {
        PhotonApiError::UnexpectedError(format!("failed to decode input_nullifiers blob: {}", err))
    })?;
    Ok(nullifiers.iter().map(|n| hex_encode(n)).collect())
}

fn i128_from_be_bytes(bytes: &[u8]) -> Result<i128, PhotonApiError> {
    if bytes.len() != 16 {
        return Err(PhotonApiError::UnexpectedError(format!(
            "expected 16-byte i128 BE blob, got {}",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(bytes);
    Ok(i128::from_be_bytes(buf))
}

fn decode_hex_32(input: &str, field: &str) -> Result<[u8; 32], PhotonApiError> {
    let trimmed = input.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|err| {
        PhotonApiError::ValidationError(format!("{} is not valid hex: {}", field, err))
    })?;
    if bytes.len() != 32 {
        return Err(PhotonApiError::ValidationError(format!(
            "{} must be 32 bytes, got {}",
            field,
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn signature_from_bytes(bytes: &[u8]) -> Result<SerializableSignature, PhotonApiError> {
    if bytes.len() != 64 {
        return Err(PhotonApiError::UnexpectedError(format!(
            "tx_signature must be 64 bytes, got {}",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(bytes);
    Ok(SerializableSignature(solana_signature::Signature::from(
        buf,
    )))
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
