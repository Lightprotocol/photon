//! Private Zone RPC query surface.
//!
//! This is deliberately not registered on Photon public RPC. It is the
//! sidecar-facing API over the private decrypted store; production exposure
//! must add request authorization before binding this to a network listener.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::zone_rpc::private_db::{SqlZonePrivateStore, ZonePrivateDbError};
use crate::zone_rpc::types::ZoneDecryptedUtxoRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneRpcPrivateApiError {
    Validation(String),
    PrivateDb(String),
}

impl fmt::Display for ZoneRpcPrivateApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(err) => write!(f, "zone private api validation error: {err}"),
            Self::PrivateDb(err) => write!(f, "zone private db error: {err}"),
        }
    }
}

impl Error for ZoneRpcPrivateApiError {}

impl From<ZonePrivateDbError> for ZoneRpcPrivateApiError {
    fn from(err: ZonePrivateDbError) -> Self {
        Self::PrivateDb(err.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetZoneUtxosByOwnerHashRequest {
    pub zone_config_hash: String,
    pub owner_hash: String,
    pub authorization: ZoneQueryAuthorization,
    pub include_spent: Option<bool>,
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetZoneUtxosByOwnerPubkeyRequest {
    pub zone_config_hash: String,
    pub owner_pubkey: String,
    pub authorization: ZoneQueryAuthorization,
    pub include_spent: Option<bool>,
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ZoneQueryAuthorization {
    /// Hex-encoded public key, viewing key, or enclave-issued principal that
    /// the concrete authorizer understands.
    pub requester: String,
    /// Domain-separated message signed by `requester`.
    pub message: String,
    /// Signature over `message`. The concrete authorizer owns signature
    /// scheme validation so this API is not coupled to one wallet format yet.
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZonePrivateQueryKind {
    OwnerHash,
    OwnerPubkey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZonePrivateQueryAuthorizationContext {
    pub zone_config_hash: [u8; 32],
    pub query_kind: ZonePrivateQueryKind,
    pub selector: [u8; 32],
    pub authorization: ZoneQueryAuthorization,
}

#[async_trait]
pub trait ZoneQueryAuthorizer: Send + Sync {
    async fn authorize(
        &self,
        context: ZonePrivateQueryAuthorizationContext,
    ) -> Result<(), ZoneRpcPrivateApiError>;
}

#[cfg(any(test, feature = "zone-rpc-prototype"))]
#[derive(Debug, Default)]
pub struct LocalAllowAllZoneQueryAuthorizer;

#[cfg(any(test, feature = "zone-rpc-prototype"))]
#[async_trait]
impl ZoneQueryAuthorizer for LocalAllowAllZoneQueryAuthorizer {
    async fn authorize(
        &self,
        _context: ZonePrivateQueryAuthorizationContext,
    ) -> Result<(), ZoneRpcPrivateApiError> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ZoneDecryptedUtxoListResponse {
    pub items: Vec<ZoneDecryptedUtxoView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ZoneDecryptedUtxoView {
    pub utxo_hash: String,
    pub operation_commitment: String,
    pub zone_config_hash: String,
    pub owner_pubkey: String,
    pub owner_hash: String,
    pub token_mint: String,
    /// Decimal string to avoid JSON number precision loss in clients.
    pub spl_amount: String,
    pub sol_amount: String,
    pub data_hash: String,
    pub slot: u64,
    /// Base58 Solana transaction signature.
    pub signature: String,
    pub event_index: u32,
    pub output_index: u8,
    pub leaf_index: Option<u64>,
    pub tree_sequence: Option<u64>,
    pub spent: bool,
}

pub struct ZoneRpcPrivateApi {
    store: SqlZonePrivateStore,
    authorizer: Arc<dyn ZoneQueryAuthorizer>,
}

impl ZoneRpcPrivateApi {
    pub fn new(store: SqlZonePrivateStore, authorizer: Arc<dyn ZoneQueryAuthorizer>) -> Self {
        Self { store, authorizer }
    }

    #[cfg(any(test, feature = "zone-rpc-prototype"))]
    pub fn new_unchecked_for_local_testing(store: SqlZonePrivateStore) -> Self {
        Self::new(store, Arc::new(LocalAllowAllZoneQueryAuthorizer))
    }

    pub async fn get_decrypted_utxos_by_owner_hash(
        &self,
        request: GetZoneUtxosByOwnerHashRequest,
    ) -> Result<ZoneDecryptedUtxoListResponse, ZoneRpcPrivateApiError> {
        let zone_config_hash = decode_hex_32(&request.zone_config_hash, "zoneConfigHash")?;
        let owner_hash = decode_hex_32(&request.owner_hash, "ownerHash")?;
        self.authorizer
            .authorize(ZonePrivateQueryAuthorizationContext {
                zone_config_hash,
                query_kind: ZonePrivateQueryKind::OwnerHash,
                selector: owner_hash,
                authorization: request.authorization,
            })
            .await?;
        let rows = self
            .store
            .fetch_decrypted_utxos_by_owner_hash(
                zone_config_hash,
                owner_hash,
                request.include_spent.unwrap_or(false),
                request
                    .limit
                    .unwrap_or(crate::zone_rpc::private_db::ZONE_PRIVATE_PAGE_LIMIT),
            )
            .await?;
        Ok(ZoneDecryptedUtxoListResponse {
            items: rows.iter().map(view_from_record).collect(),
        })
    }

    pub async fn get_decrypted_utxos_by_owner_pubkey(
        &self,
        request: GetZoneUtxosByOwnerPubkeyRequest,
    ) -> Result<ZoneDecryptedUtxoListResponse, ZoneRpcPrivateApiError> {
        let zone_config_hash = decode_hex_32(&request.zone_config_hash, "zoneConfigHash")?;
        let owner_pubkey = decode_hex_32(&request.owner_pubkey, "ownerPubkey")?;
        self.authorizer
            .authorize(ZonePrivateQueryAuthorizationContext {
                zone_config_hash,
                query_kind: ZonePrivateQueryKind::OwnerPubkey,
                selector: owner_pubkey,
                authorization: request.authorization,
            })
            .await?;
        let rows = self
            .store
            .fetch_decrypted_utxos_by_owner_pubkey(
                zone_config_hash,
                owner_pubkey,
                request.include_spent.unwrap_or(false),
                request
                    .limit
                    .unwrap_or(crate::zone_rpc::private_db::ZONE_PRIVATE_PAGE_LIMIT),
            )
            .await?;
        Ok(ZoneDecryptedUtxoListResponse {
            items: rows.iter().map(view_from_record).collect(),
        })
    }
}

fn view_from_record(row: &ZoneDecryptedUtxoRecord) -> ZoneDecryptedUtxoView {
    ZoneDecryptedUtxoView {
        utxo_hash: hex_encode(&row.utxo_hash),
        operation_commitment: hex_encode(&row.operation_commitment),
        zone_config_hash: hex_encode(&row.zone_config_hash),
        owner_pubkey: hex_encode(&row.owner_pubkey),
        owner_hash: hex_encode(&row.owner_hash),
        token_mint: hex_encode(&row.token_mint),
        spl_amount: row.spl_amount.to_string(),
        sol_amount: row.sol_amount.to_string(),
        data_hash: hex_encode(&row.data_hash),
        slot: row.slot,
        signature: row.signature.to_string(),
        event_index: row.event_index,
        output_index: row.output_index,
        leaf_index: row.leaf_index,
        tree_sequence: row.tree_sequence,
        spent: row.spent,
    }
}

fn decode_hex_32(input: &str, field: &str) -> Result<[u8; 32], ZoneRpcPrivateApiError> {
    let trimmed = input.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|err| {
        ZoneRpcPrivateApiError::Validation(format!("{field} is not valid hex: {err}"))
    })?;
    if bytes.len() != 32 {
        return Err(ZoneRpcPrivateApiError::Validation(format!(
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
    use crate::zone_rpc::private_db::{migrate_zone_private_db, SqlZonePrivateStore};
    use sea_orm::Database;
    use solana_signature::Signature;
    use std::sync::Mutex;

    async fn api() -> ZoneRpcPrivateApi {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        migrate_zone_private_db(&conn).await.unwrap();
        ZoneRpcPrivateApi::new_unchecked_for_local_testing(SqlZonePrivateStore::new(conn))
    }

    fn record(seed: u8) -> ZoneDecryptedUtxoRecord {
        ZoneDecryptedUtxoRecord {
            utxo_hash: [seed; 32],
            operation_commitment: [seed.wrapping_add(1); 32],
            zone_config_hash: [0x77; 32],
            owner_pubkey: [0xaa; 32],
            owner_hash: [0xbb; 32],
            token_mint: [0xcc; 32],
            spl_amount: u64::MAX,
            sol_amount: 42,
            data_hash: [0xdd; 32],
            slot: 100,
            signature: Signature::default(),
            event_index: 0,
            output_index: seed,
            leaf_index: Some(123),
            tree_sequence: Some(456),
            spent: false,
        }
    }

    fn authorization() -> ZoneQueryAuthorization {
        ZoneQueryAuthorization {
            requester: "local-test".to_string(),
            message: "local-test-query".to_string(),
            signature: "local-test-signature".to_string(),
        }
    }

    #[test]
    fn decodes_hex_with_optional_prefix() {
        assert_eq!(
            decode_hex_32(&hex_encode(&[7u8; 32]), "field").unwrap(),
            [7u8; 32]
        );
        assert_eq!(
            decode_hex_32(&hex::encode([8u8; 32]), "field").unwrap(),
            [8u8; 32]
        );
    }

    #[test]
    fn rejects_wrong_hash_length() {
        let err = decode_hex_32("0x1234", "field").unwrap_err();

        assert!(matches!(err, ZoneRpcPrivateApiError::Validation(_)));
    }

    #[tokio::test]
    async fn fetches_by_owner_hash() {
        let api = api().await;
        let row = record(1);
        api.store.upsert(row.clone()).await.unwrap();

        let response = api
            .get_decrypted_utxos_by_owner_hash(GetZoneUtxosByOwnerHashRequest {
                zone_config_hash: hex_encode(&row.zone_config_hash),
                owner_hash: hex_encode(&row.owner_hash),
                authorization: authorization(),
                include_spent: None,
                limit: Some(10),
            })
            .await
            .unwrap();

        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].utxo_hash, hex_encode(&row.utxo_hash));
        assert_eq!(response.items[0].spl_amount, u64::MAX.to_string());
        assert_eq!(response.items[0].sol_amount, "42");
    }

    #[tokio::test]
    async fn fetches_by_owner_pubkey_and_hides_spent_by_default() {
        let api = api().await;
        let row = record(2);
        api.store.upsert(row.clone()).await.unwrap();
        api.store.mark_spent(row.utxo_hash).await.unwrap();

        let visible = api
            .get_decrypted_utxos_by_owner_pubkey(GetZoneUtxosByOwnerPubkeyRequest {
                zone_config_hash: hex_encode(&row.zone_config_hash),
                owner_pubkey: hex_encode(&row.owner_pubkey),
                authorization: authorization(),
                include_spent: None,
                limit: Some(10),
            })
            .await
            .unwrap();
        assert!(visible.items.is_empty());

        let with_spent = api
            .get_decrypted_utxos_by_owner_pubkey(GetZoneUtxosByOwnerPubkeyRequest {
                zone_config_hash: hex_encode(&row.zone_config_hash),
                owner_pubkey: hex_encode(&row.owner_pubkey),
                authorization: authorization(),
                include_spent: Some(true),
                limit: Some(10),
            })
            .await
            .unwrap();
        assert_eq!(with_spent.items.len(), 1);
        assert!(with_spent.items[0].spent);
    }

    #[derive(Default)]
    struct RecordingAuthorizer {
        seen: Mutex<Vec<ZonePrivateQueryAuthorizationContext>>,
    }

    #[async_trait]
    impl ZoneQueryAuthorizer for RecordingAuthorizer {
        async fn authorize(
            &self,
            context: ZonePrivateQueryAuthorizationContext,
        ) -> Result<(), ZoneRpcPrivateApiError> {
            self.seen.lock().unwrap().push(context);
            Ok(())
        }
    }

    #[tokio::test]
    async fn calls_authorizer_before_private_query() {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        migrate_zone_private_db(&conn).await.unwrap();
        let row = record(3);
        let store = SqlZonePrivateStore::new(conn);
        store.upsert(row.clone()).await.unwrap();
        let authorizer = Arc::new(RecordingAuthorizer::default());
        let api = ZoneRpcPrivateApi::new(store, authorizer.clone());

        api.get_decrypted_utxos_by_owner_hash(GetZoneUtxosByOwnerHashRequest {
            zone_config_hash: hex_encode(&row.zone_config_hash),
            owner_hash: hex_encode(&row.owner_hash),
            authorization: authorization(),
            include_spent: None,
            limit: Some(10),
        })
        .await
        .unwrap();

        let seen = authorizer.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].zone_config_hash, row.zone_config_hash);
        assert_eq!(seen[0].query_kind, ZonePrivateQueryKind::OwnerHash);
        assert_eq!(seen[0].selector, row.owner_hash);
    }
}
