//! Private Zone RPC persistence prototype.
//!
//! This schema is intentionally separate from Photon public tables. It stores
//! the narrow decrypted query projection after plaintext/hash verification and
//! excludes blinding values, spend secrets, and extended plaintext bytes.

use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DeriveIden, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait, Set,
};
use sea_orm_migration::prelude::{ColumnDef, DbErr, Index, SchemaManager, Table};
use sea_orm_migration::sea_query;
use solana_signature::Signature;

use crate::zone_rpc::types::ZoneDecryptedUtxoRecord;

pub const ZONE_PRIVATE_PAGE_LIMIT: u64 = 1000;

pub async fn migrate_zone_private_db(conn: &DatabaseConnection) -> Result<(), DbErr> {
    let manager = SchemaManager::new(conn);

    manager
        .create_table(
            Table::create()
                .table(ZoneDecryptedUtxos::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::UtxoHash)
                        .binary_len(32)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::OperationCommitment)
                        .binary_len(32)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::ZoneConfigHash)
                        .binary_len(32)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::OwnerPubkey)
                        .binary_len(32)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::OwnerHash)
                        .binary_len(32)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::TokenMint)
                        .binary_len(32)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::SplAmount)
                        .binary_len(8)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::SolAmount)
                        .binary_len(8)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::DataHash)
                        .binary_len(32)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::Slot)
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::Signature)
                        .binary_len(64)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::EventIndex)
                        .integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::OutputIndex)
                        .small_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::UtxoTree)
                        .binary_len(32)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::LeafIndex)
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::TreeSequence)
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::Spent)
                        .boolean()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::CreatedAtUnixMillis)
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ZoneDecryptedUtxos::UpdatedAtUnixMillis)
                        .big_integer()
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_zone_decrypted_utxos_owner_hash")
                .table(ZoneDecryptedUtxos::Table)
                .col(ZoneDecryptedUtxos::ZoneConfigHash)
                .col(ZoneDecryptedUtxos::OwnerHash)
                .col(ZoneDecryptedUtxos::Spent)
                .col(ZoneDecryptedUtxos::Slot)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_zone_decrypted_utxos_owner_pubkey")
                .table(ZoneDecryptedUtxos::Table)
                .col(ZoneDecryptedUtxos::ZoneConfigHash)
                .col(ZoneDecryptedUtxos::OwnerPubkey)
                .col(ZoneDecryptedUtxos::Spent)
                .col(ZoneDecryptedUtxos::Slot)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_zone_decrypted_utxos_output")
                .table(ZoneDecryptedUtxos::Table)
                .col(ZoneDecryptedUtxos::Signature)
                .col(ZoneDecryptedUtxos::EventIndex)
                .col(ZoneDecryptedUtxos::OutputIndex)
                .unique()
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_zone_decrypted_utxos_tree_leaf")
                .table(ZoneDecryptedUtxos::Table)
                .col(ZoneDecryptedUtxos::UtxoTree)
                .col(ZoneDecryptedUtxos::LeafIndex)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_zone_decrypted_utxos_op_commit")
                .table(ZoneDecryptedUtxos::Table)
                .col(ZoneDecryptedUtxos::OperationCommitment)
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(Debug)]
pub enum ZonePrivateDbError {
    Db(DbErr),
    InvalidModel(String),
    UtxoAlreadyExistsWithDifferentPayload([u8; 32]),
    Clock(String),
}

impl fmt::Display for ZonePrivateDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Db(err) => write!(f, "zone private db error: {err}"),
            Self::InvalidModel(err) => write!(f, "invalid zone private db row: {err}"),
            Self::UtxoAlreadyExistsWithDifferentPayload(_) => {
                write!(f, "utxo already exists with a different private payload")
            }
            Self::Clock(err) => write!(f, "failed to read system clock: {err}"),
        }
    }
}

impl Error for ZonePrivateDbError {}

impl From<DbErr> for ZonePrivateDbError {
    fn from(err: DbErr) -> Self {
        Self::Db(err)
    }
}

pub struct SqlZonePrivateStore {
    conn: DatabaseConnection,
}

impl SqlZonePrivateStore {
    pub fn new(conn: DatabaseConnection) -> Self {
        Self { conn }
    }

    pub async fn migrate(&self) -> Result<(), ZonePrivateDbError> {
        migrate_zone_private_db(&self.conn).await?;
        Ok(())
    }

    pub async fn upsert_many(
        &self,
        rows: impl IntoIterator<Item = ZoneDecryptedUtxoRecord>,
    ) -> Result<(), ZonePrivateDbError> {
        for row in rows {
            self.upsert(row).await?;
        }
        Ok(())
    }

    pub async fn upsert(&self, row: ZoneDecryptedUtxoRecord) -> Result<(), ZonePrivateDbError> {
        if let Some(existing) = zone_decrypted_utxos::Entity::find_by_id(row.utxo_hash.to_vec())
            .one(&self.conn)
            .await?
        {
            let existing = record_from_model(existing)?;
            if !same_immutable_projection(&existing, &row) {
                return Err(ZonePrivateDbError::UtxoAlreadyExistsWithDifferentPayload(
                    row.utxo_hash,
                ));
            }
            return Ok(());
        }

        let now = now_unix_millis()?;
        let query = zone_decrypted_utxos::Entity::insert(active_model_from_record(&row, now)?)
            .on_conflict(
                OnConflict::columns([zone_decrypted_utxos::Column::UtxoHash])
                    .do_nothing()
                    .to_owned(),
            )
            .build(self.conn.get_database_backend());
        self.conn.execute(query).await?;
        Ok(())
    }

    pub async fn fetch_decrypted_utxos_by_owner_hash(
        &self,
        zone_config_hash: [u8; 32],
        owner_hash: [u8; 32],
        include_spent: bool,
        limit: u64,
    ) -> Result<Vec<ZoneDecryptedUtxoRecord>, ZonePrivateDbError> {
        let mut query = zone_decrypted_utxos::Entity::find()
            .filter(zone_decrypted_utxos::Column::ZoneConfigHash.eq(zone_config_hash.to_vec()))
            .filter(zone_decrypted_utxos::Column::OwnerHash.eq(owner_hash.to_vec()));
        if !include_spent {
            query = query.filter(zone_decrypted_utxos::Column::Spent.eq(false));
        }
        query
            .order_by_desc(zone_decrypted_utxos::Column::Slot)
            .order_by_asc(zone_decrypted_utxos::Column::EventIndex)
            .order_by_asc(zone_decrypted_utxos::Column::OutputIndex)
            .limit(limit.min(ZONE_PRIVATE_PAGE_LIMIT))
            .all(&self.conn)
            .await?
            .into_iter()
            .map(record_from_model)
            .collect()
    }

    pub async fn fetch_decrypted_utxos_by_owner_pubkey(
        &self,
        zone_config_hash: [u8; 32],
        owner_pubkey: [u8; 32],
        include_spent: bool,
        limit: u64,
    ) -> Result<Vec<ZoneDecryptedUtxoRecord>, ZonePrivateDbError> {
        let mut query = zone_decrypted_utxos::Entity::find()
            .filter(zone_decrypted_utxos::Column::ZoneConfigHash.eq(zone_config_hash.to_vec()))
            .filter(zone_decrypted_utxos::Column::OwnerPubkey.eq(owner_pubkey.to_vec()));
        if !include_spent {
            query = query.filter(zone_decrypted_utxos::Column::Spent.eq(false));
        }
        query
            .order_by_desc(zone_decrypted_utxos::Column::Slot)
            .order_by_asc(zone_decrypted_utxos::Column::EventIndex)
            .order_by_asc(zone_decrypted_utxos::Column::OutputIndex)
            .limit(limit.min(ZONE_PRIVATE_PAGE_LIMIT))
            .all(&self.conn)
            .await?
            .into_iter()
            .map(record_from_model)
            .collect()
    }

    pub async fn mark_spent(&self, utxo_hash: [u8; 32]) -> Result<bool, ZonePrivateDbError> {
        let now = now_unix_millis()?;
        let result = zone_decrypted_utxos::Entity::update_many()
            .col_expr(zone_decrypted_utxos::Column::Spent, Expr::value(true))
            .col_expr(
                zone_decrypted_utxos::Column::UpdatedAtUnixMillis,
                Expr::value(now),
            )
            .filter(zone_decrypted_utxos::Column::UtxoHash.eq(utxo_hash.to_vec()))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected > 0)
    }
}

fn active_model_from_record(
    row: &ZoneDecryptedUtxoRecord,
    now_unix_millis: i64,
) -> Result<zone_decrypted_utxos::ActiveModel, ZonePrivateDbError> {
    Ok(zone_decrypted_utxos::ActiveModel {
        utxo_hash: Set(row.utxo_hash.to_vec()),
        operation_commitment: Set(row.operation_commitment.to_vec()),
        zone_config_hash: Set(row.zone_config_hash.to_vec()),
        owner_pubkey: Set(row.owner_pubkey.to_vec()),
        owner_hash: Set(row.owner_hash.to_vec()),
        token_mint: Set(row.token_mint.to_vec()),
        spl_amount: Set(row.spl_amount.to_be_bytes().to_vec()),
        sol_amount: Set(row.sol_amount.to_be_bytes().to_vec()),
        data_hash: Set(row.data_hash.to_vec()),
        slot: Set(i64_from_u64("slot", row.slot)?),
        signature: Set(Into::<[u8; 64]>::into(row.signature).to_vec()),
        event_index: Set(i32_from_u32("event_index", row.event_index)?),
        output_index: Set(i16::from(row.output_index)),
        utxo_tree: Set(row.utxo_tree.to_vec()),
        leaf_index: Set(i64_from_u64("leaf_index", row.leaf_index)?),
        tree_sequence: Set(i64_from_u64("tree_sequence", row.tree_sequence)?),
        spent: Set(row.spent),
        created_at_unix_millis: Set(now_unix_millis),
        updated_at_unix_millis: Set(now_unix_millis),
    })
}

fn record_from_model(
    model: zone_decrypted_utxos::Model,
) -> Result<ZoneDecryptedUtxoRecord, ZonePrivateDbError> {
    Ok(ZoneDecryptedUtxoRecord {
        utxo_hash: bytes32("utxo_hash", &model.utxo_hash)?,
        operation_commitment: bytes32("operation_commitment", &model.operation_commitment)?,
        zone_config_hash: bytes32("zone_config_hash", &model.zone_config_hash)?,
        owner_pubkey: bytes32("owner_pubkey", &model.owner_pubkey)?,
        owner_hash: bytes32("owner_hash", &model.owner_hash)?,
        token_mint: bytes32("token_mint", &model.token_mint)?,
        spl_amount: u64_from_be_bytes("spl_amount", &model.spl_amount)?,
        sol_amount: u64_from_be_bytes("sol_amount", &model.sol_amount)?,
        data_hash: bytes32("data_hash", &model.data_hash)?,
        slot: u64_from_i64("slot", model.slot)?,
        signature: Signature::from(bytes64("signature", &model.signature)?),
        event_index: u32_from_i32("event_index", model.event_index)?,
        output_index: u8_from_i16("output_index", model.output_index)?,
        utxo_tree: bytes32("utxo_tree", &model.utxo_tree)?,
        leaf_index: u64_from_i64("leaf_index", model.leaf_index)?,
        tree_sequence: u64_from_i64("tree_sequence", model.tree_sequence)?,
        spent: model.spent,
    })
}

fn same_immutable_projection(
    existing: &ZoneDecryptedUtxoRecord,
    incoming: &ZoneDecryptedUtxoRecord,
) -> bool {
    let mut existing = existing.clone();
    let mut incoming = incoming.clone();
    existing.spent = false;
    incoming.spent = false;
    existing == incoming
}

fn now_unix_millis() -> Result<i64, ZonePrivateDbError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| ZonePrivateDbError::Clock(err.to_string()))?;
    let millis = duration.as_millis();
    if millis > i64::MAX as u128 {
        return Err(ZonePrivateDbError::Clock(
            "unix millis overflowed i64".to_string(),
        ));
    }
    Ok(millis as i64)
}

fn bytes32(field: &str, bytes: &[u8]) -> Result<[u8; 32], ZonePrivateDbError> {
    if bytes.len() != 32 {
        return Err(ZonePrivateDbError::InvalidModel(format!(
            "{field} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn bytes64(field: &str, bytes: &[u8]) -> Result<[u8; 64], ZonePrivateDbError> {
    if bytes.len() != 64 {
        return Err(ZonePrivateDbError::InvalidModel(format!(
            "{field} must be 64 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn u64_from_be_bytes(field: &str, bytes: &[u8]) -> Result<u64, ZonePrivateDbError> {
    if bytes.len() != 8 {
        return Err(ZonePrivateDbError::InvalidModel(format!(
            "{field} must be 8 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(out))
}

fn i64_from_u64(field: &str, value: u64) -> Result<i64, ZonePrivateDbError> {
    if value > i64::MAX as u64 {
        return Err(ZonePrivateDbError::InvalidModel(format!(
            "{field} value {value} does not fit i64"
        )));
    }
    Ok(value as i64)
}

fn u64_from_i64(field: &str, value: i64) -> Result<u64, ZonePrivateDbError> {
    if value < 0 {
        return Err(ZonePrivateDbError::InvalidModel(format!(
            "{field} value {value} is negative"
        )));
    }
    Ok(value as u64)
}

fn i32_from_u32(field: &str, value: u32) -> Result<i32, ZonePrivateDbError> {
    if value > i32::MAX as u32 {
        return Err(ZonePrivateDbError::InvalidModel(format!(
            "{field} value {value} does not fit i32"
        )));
    }
    Ok(value as i32)
}

fn u32_from_i32(field: &str, value: i32) -> Result<u32, ZonePrivateDbError> {
    if value < 0 {
        return Err(ZonePrivateDbError::InvalidModel(format!(
            "{field} value {value} is negative"
        )));
    }
    Ok(value as u32)
}

fn u8_from_i16(field: &str, value: i16) -> Result<u8, ZonePrivateDbError> {
    if value < 0 || value > u8::MAX as i16 {
        return Err(ZonePrivateDbError::InvalidModel(format!(
            "{field} value {value} does not fit u8"
        )));
    }
    Ok(value as u8)
}

#[derive(DeriveIden)]
enum ZoneDecryptedUtxos {
    Table,
    UtxoHash,
    OperationCommitment,
    ZoneConfigHash,
    OwnerPubkey,
    OwnerHash,
    TokenMint,
    SplAmount,
    SolAmount,
    DataHash,
    Slot,
    Signature,
    EventIndex,
    OutputIndex,
    UtxoTree,
    LeafIndex,
    TreeSequence,
    Spent,
    CreatedAtUnixMillis,
    UpdatedAtUnixMillis,
}

mod zone_decrypted_utxos {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
    #[sea_orm(table_name = "zone_decrypted_utxos")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub utxo_hash: Vec<u8>,
        pub operation_commitment: Vec<u8>,
        pub zone_config_hash: Vec<u8>,
        pub owner_pubkey: Vec<u8>,
        pub owner_hash: Vec<u8>,
        pub token_mint: Vec<u8>,
        pub spl_amount: Vec<u8>,
        pub sol_amount: Vec<u8>,
        pub data_hash: Vec<u8>,
        pub slot: i64,
        pub signature: Vec<u8>,
        pub event_index: i32,
        pub output_index: i16,
        pub utxo_tree: Vec<u8>,
        pub leaf_index: i64,
        pub tree_sequence: i64,
        pub spent: bool,
        pub created_at_unix_millis: i64,
        pub updated_at_unix_millis: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> SqlZonePrivateStore {
        let conn = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let store = SqlZonePrivateStore::new(conn);
        store.migrate().await.unwrap();
        store
    }

    fn record(seed: u8) -> ZoneDecryptedUtxoRecord {
        ZoneDecryptedUtxoRecord {
            utxo_hash: [seed; 32],
            operation_commitment: [seed.wrapping_add(1); 32],
            zone_config_hash: [0x77; 32],
            owner_pubkey: [0xaa; 32],
            owner_hash: [0xbb; 32],
            token_mint: [0xcc; 32],
            spl_amount: u64::MAX - 7,
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

    #[tokio::test]
    async fn stores_and_fetches_by_owner_hash() {
        let store = store().await;
        let row = record(1);

        store.upsert_many(vec![row.clone()]).await.unwrap();
        store.upsert_many(vec![row.clone()]).await.unwrap();

        let fetched = store
            .fetch_decrypted_utxos_by_owner_hash(row.zone_config_hash, row.owner_hash, false, 10)
            .await
            .unwrap();
        assert_eq!(fetched, vec![row]);
    }

    #[tokio::test]
    async fn stores_and_fetches_by_owner_pubkey() {
        let store = store().await;
        let row = record(2);

        store.upsert(row.clone()).await.unwrap();

        let fetched = store
            .fetch_decrypted_utxos_by_owner_pubkey(
                row.zone_config_hash,
                row.owner_pubkey,
                false,
                10,
            )
            .await
            .unwrap();
        assert_eq!(fetched, vec![row]);
    }

    #[tokio::test]
    async fn spent_rows_are_hidden_by_default() {
        let store = store().await;
        let row = record(3);

        store.upsert(row.clone()).await.unwrap();
        assert!(store.mark_spent(row.utxo_hash).await.unwrap());

        assert!(store
            .fetch_decrypted_utxos_by_owner_hash(row.zone_config_hash, row.owner_hash, false, 10)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .fetch_decrypted_utxos_by_owner_hash(row.zone_config_hash, row.owner_hash, true, 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn conflicting_payload_is_rejected() {
        let store = store().await;
        let row = record(4);
        let mut conflicting = row.clone();
        conflicting.spl_amount -= 1;

        store.upsert(row).await.unwrap();
        let err = store.upsert(conflicting).await.unwrap_err();
        assert!(matches!(
            err,
            ZonePrivateDbError::UtxoAlreadyExistsWithDifferentPayload(_)
        ));
    }

    #[tokio::test]
    async fn reimport_does_not_clear_spent_state() {
        let store = store().await;
        let row = record(5);

        store.upsert(row.clone()).await.unwrap();
        assert!(store.mark_spent(row.utxo_hash).await.unwrap());
        store.upsert(row.clone()).await.unwrap();

        let fetched = store
            .fetch_decrypted_utxos_by_owner_hash(row.zone_config_hash, row.owner_hash, true, 10)
            .await
            .unwrap();
        assert_eq!(fetched.len(), 1);
        assert!(fetched[0].spent);
    }
}
